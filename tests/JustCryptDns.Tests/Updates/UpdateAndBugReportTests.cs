using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Updates;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Updates;

public sealed class UpdateAndBugReportTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-update-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public UpdateAndBugReportTests()
    {
        _paths = new AppPaths(_root);
        _paths.EnsureCreated();
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void AppVersionComparer_OrdersSemVerAndPrereleasesProperly()
    {
        Assert.Equal("1.3.0", AppVersionComparer.NormalizeVersion("v1.3.0+abc123"));
        Assert.True(AppVersionComparer.IsNewer("v1.4.0", "1.3.0"));
        Assert.True(AppVersionComparer.IsNewer("1.3.0", "1.3.0-beta.2"));
        Assert.True(AppVersionComparer.IsNewer("1.3.0-beta.2", "1.3.0-beta.1"));
        Assert.False(AppVersionComparer.IsNewer("1.3.0", "v1.3.0"));
        Assert.False(AppVersionComparer.IsNewer("1.2.1", "1.3.0"));
    }

    [Fact]
    public async Task GitHubUpdateService_DetectsUpdateAndSelectsPortableZipWithChecksums()
    {
        var json = """
        {
          "tag_name": "v1.4.0",
          "name": "JustCryptDns 1.4.0",
          "body": "- Faster DNS cache\n- Better bypass",
          "draft": false,
          "prerelease": false,
          "published_at": "2026-11-20T05:00:00Z",
          "html_url": "https://github.com/longtygu/JustCryptDns/releases/tag/v1.4.0",
          "assets": [
            {
              "name": "JustCryptDns-1.4.0-win-x64-setup.exe",
              "browser_download_url": "https://downloads.test/setup.exe",
              "size": 70000000
            },
            {
              "name": "JustCryptDns-1.4.0-win-x64-portable.zip",
              "browser_download_url": "https://downloads.test/portable.zip",
              "size": 65000000
            },
            {
              "name": "SHA256SUMS.txt",
              "browser_download_url": "https://downloads.test/SHA256SUMS.txt",
              "size": 128
            }
          ]
        }
        """;

        using var settings = new SettingsService(new MemoryStore(new AppSettings()), NullLogger<SettingsService>.Instance);
        using var http = new HttpClient(new FakeHttpHandler(req =>
        {
            Assert.Contains("JustCryptDns/", req.Headers.UserAgent.ToString(), StringComparison.Ordinal);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
        }));

        using var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http, currentVersionOverride: "1.3.0");
        UpdateCheckResult? eventResult = null;
        updater.UpdateCheckCompleted += (_, r) => eventResult = r;

        var result = await updater.CheckForUpdatesAsync();
        Assert.Equal(UpdateCheckStatus.UpdateAvailable, result.Status);
        Assert.NotNull(result.Release);
        Assert.Equal("1.4.0", result.Release!.Version);
        Assert.Equal(UpdatePackageKind.PortableZip, result.Release.PreferredAsset?.Kind);
        Assert.Equal("https://downloads.test/portable.zip", result.Release.PreferredAsset?.DownloadUrl);
        Assert.Equal("https://downloads.test/SHA256SUMS.txt", result.Release.PreferredAsset?.ChecksumsUrl);
        Assert.NotNull(eventResult);
        Assert.NotNull(settings.Current.Updates.LastCheckedUtc);
    }

    [Fact]
    public async Task GitHubUpdateService_HandlesUpToDate_NoReleases_AndRateLimit()
    {
        using var settings = new SettingsService(new MemoryStore(new AppSettings()), NullLogger<SettingsService>.Instance);

        // 1. UpToDate
        using (var http = new HttpClient(new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"tag_name":"v1.3.0","name":"v1.3.0","draft":false,"prerelease":false,"assets":[]}""", Encoding.UTF8, "application/json"),
        })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http, currentVersionOverride: "1.3.0"))
        {
            var res = await updater.CheckForUpdatesAsync();
            Assert.Equal(UpdateCheckStatus.UpToDate, res.Status);
        }

        // 2. No releases published (404 -> [] )
        using (var http = new HttpClient(new FakeHttpHandler(req => req.RequestUri!.AbsolutePath.EndsWith("/latest", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]", Encoding.UTF8, "application/json") })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http, currentVersionOverride: "1.3.0"))
        {
            var res = await updater.CheckForUpdatesAsync();
            Assert.Equal(UpdateCheckStatus.NoReleasesPublished, res.Status);
        }

        // 3. Rate limited (403 + X-RateLimit-Remaining: 0)
        using (var http = new HttpClient(new FakeHttpHandler(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Forbidden);
            resp.Headers.TryAddWithoutValidation("X-RateLimit-Remaining", "0");
            return resp;
        })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http, currentVersionOverride: "1.3.0"))
        {
            var res = await updater.CheckForUpdatesAsync();
            Assert.Equal(UpdateCheckStatus.RateLimited, res.Status);
        }
    }

    [Fact]
    public async Task DownloadAndPrepareAsync_StreamsProgress_VerifiesSha256_AndExtractsStaging()
    {
        var zipBytes = CreateTestUpdateZip(includeExe: true);
        var realSha256 = Convert.ToHexString(SHA256.HashData(zipBytes)).ToLowerInvariant();
        var sumsText = $"{realSha256}  JustCryptDns-1.4.0-win-x64-portable.zip\n";

        using var settings = new SettingsService(new MemoryStore(new AppSettings()), NullLogger<SettingsService>.Instance);
        using var http = new HttpClient(new FakeHttpHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri == "https://downloads.test/SHA256SUMS.txt")
            {
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(sumsText) };
            }

            var content = new ByteArrayContent(zipBytes);
            content.Headers.ContentLength = zipBytes.Length;
            content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        }));

        using var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http, currentVersionOverride: "1.3.0");
        var release = new UpdateReleaseInfo(
            "v1.4.0",
            "1.4.0",
            "1.4.0",
            "Notes",
            DateTimeOffset.UtcNow,
            BugReportBuilder.GitHubRepoUrl,
            false,
            new UpdateAssetInfo("JustCryptDns-1.4.0-win-x64-portable.zip", "https://downloads.test/portable.zip", zipBytes.Length, UpdatePackageKind.PortableZip, "https://downloads.test/SHA256SUMS.txt"));

        var reports = new List<UpdateDownloadProgress>();
        var progress = new SyncProgress(reports);
        var prepared = await updater.DownloadAndPrepareAsync(release, progress);

        Assert.True(prepared.ChecksumVerified);
        Assert.Equal(realSha256, prepared.ActualSha256);
        Assert.NotNull(prepared.StagingDirectory);
        Assert.True(File.Exists(Path.Combine(prepared.StagingDirectory!, "JustCryptDns.exe")));
        Assert.Contains(reports, r => r.ProgressPercent >= 99.9);
    }

    [Fact]
    public async Task DownloadAndPrepareAsync_RejectsTamperedSha256_MissingExe_AndCleansPartOnCancel()
    {
        var validZip = CreateTestUpdateZip(includeExe: true);
        var badZip = CreateTestUpdateZip(includeExe: false);
        var badSums = $"{new string('0', 64)}  JustCryptDns-1.4.0-win-x64-portable.zip\n";

        using var settings = new SettingsService(new MemoryStore(new AppSettings()), NullLogger<SettingsService>.Instance);

        // 1. Tampered SHA-256 deletes package
        using (var http = new HttpClient(new FakeHttpHandler(req => req.RequestUri!.AbsoluteUri.EndsWith("SHA256SUMS.txt", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(badSums) }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(validZip) })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http))
        {
            var rel = new UpdateReleaseInfo("v1.4.0", "1.4.0", "1.4.0", "", DateTimeOffset.UtcNow, "", false,
                new UpdateAssetInfo("JustCryptDns-1.4.0-win-x64-portable.zip", "https://downloads.test/a.zip", validZip.Length, UpdatePackageKind.PortableZip, "https://downloads.test/SHA256SUMS.txt"));
            await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAndPrepareAsync(rel));
            Assert.False(File.Exists(Path.Combine(_paths.UpdatesDirectory, "1.4.0", "JustCryptDns-1.4.0-win-x64-portable.zip")));
        }

        // 2. Missing JustCryptDns.exe throws and cleans staging
        using (var http = new HttpClient(new FakeHttpHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(badZip) })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http))
        {
            var rel = new UpdateReleaseInfo("v1.5.0", "1.5.0", "1.5.0", "", DateTimeOffset.UtcNow, "", false,
                new UpdateAssetInfo("JustCryptDns-1.5.0-win-x64-portable.zip", "https://downloads.test/b.zip", badZip.Length, UpdatePackageKind.PortableZip, null));
            await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadAndPrepareAsync(rel));
            Assert.False(Directory.Exists(Path.Combine(_paths.UpdatesDirectory, "1.5.0", "staging")));
        }

        // 3. Cancellation leaves zero .part files
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using (var http = new HttpClient(new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(validZip) })))
        using (var updater = new GitHubUpdateService(_paths, settings, NullLogger<GitHubUpdateService>.Instance, http))
        {
            var rel = new UpdateReleaseInfo("v1.6.0", "1.6.0", "1.6.0", "", DateTimeOffset.UtcNow, "", false,
                new UpdateAssetInfo("JustCryptDns-1.6.0-win-x64-portable.zip", "https://downloads.test/c.zip", validZip.Length, UpdatePackageKind.PortableZip, null));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => updater.DownloadAndPrepareAsync(rel, cancellationToken: cts.Token));
            Assert.Empty(Directory.GetFiles(_paths.UpdatesDirectory, "*.part", SearchOption.AllDirectories));
        }
    }

    [Fact]
    public void BugReportBuilder_SanitizesPaths_BuildsClampedGitHubUrl_AndFacebookMessage()
    {
        var masked = BugReportBuilder.SanitizeLogLine(@"Failed reading C:\Users\LONGTYGU\AppData\Local\JustCryptDns\settings.json");
        Assert.Equal(@"Failed reading C:\Users\<user>\AppData\Local\JustCryptDns\settings.json", masked);

        var longLogs = Enumerable.Range(0, 120)
            .Select(i => $@"[ERR] Step {i}: file at C:\Users\LONGTYGU\folder\{new string('x', 80)}")
            .ToList();
        var diagnostics = new BugDiagnosticsSnapshot(
            "1.3.0",
            "Windows 11",
            "Running (Serving)",
            "Cloudflare [DnsOverHttps]",
            "Running (WinProxyApplied=True)",
            "AllWebsitesSmart",
            "Ethernet (Ethernet, Up)",
            longLogs);
        var draft = new BugReportDraft(
            BugReportCategory.DpiBypass,
            "Steam hung",
            "Steam store fails on TLS.",
            IncludeDiagnostics: true,
            AttachedImagePaths:
            [
                @"C:\Users\LONGTYGU\Pictures\err1.png",
                @"C:\Users\LONGTYGU\Desktop\err2.jpg",
            ]);

        var markdown = BugReportBuilder.BuildGitHubMarkdown(draft, diagnostics);
        Assert.Contains("DPI Bypass & Split-Tunnel", markdown, StringComparison.Ordinal);
        Assert.Contains(@"C:\Users\<user>", markdown, StringComparison.Ordinal);
        Assert.Contains("err1.png", markdown, StringComparison.Ordinal);
        Assert.Contains("err2.jpg", markdown, StringComparison.Ordinal);
        Assert.DoesNotContain("LONGTYGU", markdown, StringComparison.OrdinalIgnoreCase);

        var url = BugReportBuilder.BuildGitHubIssueUrl(draft, diagnostics);
        Assert.StartsWith(BugReportBuilder.GitHubNewIssueUrl, url, StringComparison.Ordinal);
        Assert.DoesNotContain("labels=", url, StringComparison.OrdinalIgnoreCase);
        Assert.True(url.Length <= BugReportBuilder.MaxGitHubIssueUrlLength,
            $"Expected GitHub URL <= {BugReportBuilder.MaxGitHubIssueUrlLength} chars, got {url.Length}");

        var fb = BugReportBuilder.BuildFacebookMessage(draft, diagnostics);
        Assert.Contains("[JustCryptDns v1.3.0 - DPI Bypass & Split-Tunnel] Steam hung", fb, StringComparison.Ordinal);
        Assert.Contains("err1.png", fb, StringComparison.Ordinal);
        Assert.Contains(@"C:\Users\<user>", fb, StringComparison.Ordinal);
        Assert.DoesNotContain("LONGTYGU", fb, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SettingsV13File_MigratesCleanlyToV14WithUpdateDefaults()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 13, "general": { "language": "vi" } }""");
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var loaded = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, loaded.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);
        Assert.Equal(LanguageCodes.Vietnamese, loaded.Settings.General.Language);
        Assert.True(loaded.Settings.Updates.AutoCheckOnStartup);
        Assert.Equal("longtygu", loaded.Settings.Updates.RepositoryOwner);
        Assert.Equal("JustCryptDns", loaded.Settings.Updates.RepositoryName);
    }

    private static byte[] CreateTestUpdateZip(bool includeExe)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var readme = zip.CreateEntry("README.md");
            using (var w = new StreamWriter(readme.Open()))
            {
                w.Write("JustCryptDns test");
            }

            if (includeExe)
            {
                var exe = zip.CreateEntry("JustCryptDns.exe");
                using var bw = new BinaryWriter(exe.Open());
                bw.Write("MZ-TEST-PAYLOAD"u8.ToArray());
            }
        }

        return ms.ToArray();
    }

    private sealed class SyncProgress(List<UpdateDownloadProgress> target) : IProgress<UpdateDownloadProgress>
    {
        public void Report(UpdateDownloadProgress value) => target.Add(value);
    }

    private sealed class FakeHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(responder(request));
        }
    }

    private sealed class MemoryStore(AppSettings settings) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(settings.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings value, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
