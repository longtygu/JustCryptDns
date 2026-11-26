using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Updates;

/// <summary>
/// Checks GitHub Releases for new JustCryptDns versions, downloads and SHA-256-verifies release packages
/// with real-time throughput telemetry, and launches a non-destructive in-place updater script.
/// </summary>
public sealed class GitHubUpdateService : IUpdateService, IDisposable
{
    private const int StreamBufferSize = 65536;
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(150);

    private readonly IAppPaths _paths;
    private readonly ISettingsService _settings;
    private readonly ILogger<GitHubUpdateService> _logger;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly string? _installDirectoryOverride;

    public GitHubUpdateService(
        IAppPaths paths,
        ISettingsService settings,
        ILogger<GitHubUpdateService> logger,
        HttpClient? httpClient = null,
        string? currentVersionOverride = null,
        string? installDirectoryOverride = null)
    {
        _paths = paths;
        _settings = settings;
        _logger = logger;
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? CreateDefaultHttpClient();
        _installDirectoryOverride = installDirectoryOverride;
        CurrentVersion = ResolveCurrentVersion(currentVersionOverride);
    }

    public string CurrentVersion { get; }

    public UpdateCheckResult? LatestResult { get; private set; }

    public event EventHandler<UpdateCheckResult>? UpdateCheckCompleted;

    public async Task<UpdateCheckResult> CheckForUpdatesAsync(
        bool includePrereleases = false,
        CancellationToken cancellationToken = default)
    {
        var checkedAt = DateTimeOffset.UtcNow;
        var updateSettings = _settings.Current.Updates;
        var owner = string.IsNullOrWhiteSpace(updateSettings.RepositoryOwner)
            ? UpdateSettings.DefaultRepositoryOwner
            : updateSettings.RepositoryOwner.Trim();
        var repo = string.IsNullOrWhiteSpace(updateSettings.RepositoryName)
            ? UpdateSettings.DefaultRepositoryName
            : updateSettings.RepositoryName.Trim();

        try
        {
            UpdateReleaseInfo? release = null;

            if (!includePrereleases)
            {
                var latestUrl = $"https://api.github.com/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repo)}/releases/latest";
                using var latestResponse = await SendGitHubApiGetAsync(latestUrl, cancellationToken).ConfigureAwait(false);
                if (IsRateLimited(latestResponse))
                {
                    return PublishResult(new UpdateCheckResult(
                        UpdateCheckStatus.RateLimited,
                        CurrentVersion,
                        null,
                        checkedAt,
                        "GitHub API rate limit exceeded. Please try again later."));
                }

                if (latestResponse.IsSuccessStatusCode)
                {
                    await using var stream = await latestResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                    using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (TryParseRelease(doc.RootElement, includePrereleases: false, out var parsed))
                    {
                        release = parsed;
                    }
                }
                else if (latestResponse.StatusCode != HttpStatusCode.NotFound)
                {
                    var detail = $"GitHub API returned {(int)latestResponse.StatusCode} ({latestResponse.ReasonPhrase}).";
                    return PublishResult(new UpdateCheckResult(UpdateCheckStatus.Error, CurrentVersion, null, checkedAt, detail));
                }
            }

            if (release is null)
            {
                var listUrl = $"https://api.github.com/repos/{Uri.EscapeDataString(owner)}/{Uri.EscapeDataString(repo)}/releases?per_page=10";
                using var listResponse = await SendGitHubApiGetAsync(listUrl, cancellationToken).ConfigureAwait(false);
                if (IsRateLimited(listResponse))
                {
                    return PublishResult(new UpdateCheckResult(
                        UpdateCheckStatus.RateLimited,
                        CurrentVersion,
                        null,
                        checkedAt,
                        "GitHub API rate limit exceeded. Please try again later."));
                }

                if (listResponse.StatusCode == HttpStatusCode.NotFound)
                {
                    return PublishResult(new UpdateCheckResult(UpdateCheckStatus.NoReleasesPublished, CurrentVersion, null, checkedAt));
                }

                if (!listResponse.IsSuccessStatusCode)
                {
                    var detail = $"GitHub API returned {(int)listResponse.StatusCode} ({listResponse.ReasonPhrase}).";
                    return PublishResult(new UpdateCheckResult(UpdateCheckStatus.Error, CurrentVersion, null, checkedAt, detail));
                }

                await using var stream = await listResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var element in doc.RootElement.EnumerateArray())
                    {
                        if (TryParseRelease(element, includePrereleases, out var parsed))
                        {
                            release = parsed;
                            break;
                        }
                    }
                }
            }

            _settings.UpdateDeferred(s => s.Updates.LastCheckedUtc = checkedAt);

            if (release is null)
            {
                return PublishResult(new UpdateCheckResult(UpdateCheckStatus.NoReleasesPublished, CurrentVersion, null, checkedAt));
            }

            var isNewer = AppVersionComparer.IsNewer(release.Version, CurrentVersion);
            var status = isNewer ? UpdateCheckStatus.UpdateAvailable : UpdateCheckStatus.UpToDate;
            return PublishResult(new UpdateCheckResult(status, CurrentVersion, release, checkedAt));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            _logger.LogWarning(ex, "Update check against {Owner}/{Repo} failed.", owner, repo);
            return PublishResult(new UpdateCheckResult(UpdateCheckStatus.Error, CurrentVersion, null, checkedAt, ex.Message));
        }
    }

    public async Task<PreparedUpdatePackage> DownloadAndPrepareAsync(
        UpdateReleaseInfo release,
        IProgress<UpdateDownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(release);
        var asset = release.PreferredAsset
            ?? throw new InvalidOperationException("The selected release does not include a downloadable Windows package asset.");

        if (!IsSafeHttpsUrl(asset.DownloadUrl))
        {
            throw new InvalidOperationException("Refusing to download update asset over a non-HTTPS URL.");
        }

        if (!string.IsNullOrWhiteSpace(asset.ChecksumsUrl) && !IsSafeHttpsUrl(asset.ChecksumsUrl))
        {
            throw new InvalidOperationException("Refusing to download update checksums over a non-HTTPS URL.");
        }

        var safeVersion = SanitizePathSegment(release.Version);
        var versionDir = Path.Combine(_paths.UpdatesDirectory, safeVersion);
        Directory.CreateDirectory(versionDir);

        var safeFileName = Path.GetFileName(asset.FileName);
        if (string.IsNullOrWhiteSpace(safeFileName))
        {
            safeFileName = asset.Kind == UpdatePackageKind.PortableZip
                ? $"JustCryptDns-{safeVersion}-win-x64-portable.zip"
                : $"JustCryptDns-{safeVersion}-win-x64-setup.exe";
        }

        var targetPath = Path.Combine(versionDir, safeFileName);
        var partPath = targetPath + ".part";

        try
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, asset.DownloadUrl))
            {
                request.Headers.TryAddWithoutValidation("User-Agent", $"JustCryptDns/{CurrentVersion}");
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));

                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                    .ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                var totalBytes = response.Content.Headers.ContentLength ?? asset.SizeBytes;
                if (totalBytes < 0)
                {
                    totalBytes = asset.SizeBytes;
                }

                await using (var remoteStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false))
                await using (var fileStream = new FileStream(partPath, FileMode.Create, FileAccess.Write, FileShare.None, StreamBufferSize, useAsync: true))
                {
                    var buffer = new byte[StreamBufferSize];
                    long totalRead = 0;
                    long windowRead = 0;
                    double emaInstantBps = 0;
                    var totalWatch = Stopwatch.StartNew();
                    var windowWatch = Stopwatch.StartNew();

                    while (true)
                    {
                        var read = await remoteStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                        totalRead += read;
                        windowRead += read;

                        if (windowWatch.Elapsed >= ProgressInterval)
                        {
                            var windowSec = Math.Max(0.001, windowWatch.Elapsed.TotalSeconds);
                            var instantSample = windowRead / windowSec;
                            emaInstantBps = emaInstantBps <= 0 ? instantSample : (0.35 * instantSample) + (0.65 * emaInstantBps);

                            var avgBps = totalRead / Math.Max(0.001, totalWatch.Elapsed.TotalSeconds);
                            var pct = totalBytes > 0 ? Math.Clamp(totalRead * 100.0 / totalBytes, 0.0, 100.0) : 0.0;
                            TimeSpan? eta = avgBps > 1.0 && totalBytes > totalRead
                                ? TimeSpan.FromSeconds((totalBytes - totalRead) / avgBps)
                                : null;

                            progress?.Report(new UpdateDownloadProgress(totalRead, totalBytes, pct, emaInstantBps, avgBps, eta));
                            windowRead = 0;
                            windowWatch.Restart();
                        }
                    }

                    await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);

                    var finalAvgBps = totalRead / Math.Max(0.001, totalWatch.Elapsed.TotalSeconds);
                    var finalInstant = emaInstantBps > 0 ? emaInstantBps : finalAvgBps;
                    var finalTotal = totalBytes > 0 ? Math.Max(totalBytes, totalRead) : totalRead;
                    progress?.Report(new UpdateDownloadProgress(totalRead, finalTotal, 100.0, finalInstant, finalAvgBps, TimeSpan.Zero));
                }
            }

            if (File.Exists(targetPath))
            {
                File.Delete(targetPath);
            }

            File.Move(partPath, targetPath);
        }
        catch
        {
            TryDeleteFile(partPath);
            throw;
        }

        var actualSha256 = await ComputeFileSha256Async(targetPath, cancellationToken).ConfigureAwait(false);
        string? expectedSha256 = null;
        var checksumVerified = false;

        if (!string.IsNullOrWhiteSpace(asset.ChecksumsUrl))
        {
            expectedSha256 = await FetchExpectedSha256Async(asset.ChecksumsUrl, safeFileName, cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(expectedSha256))
            {
                if (!string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
                {
                    TryDeleteFile(targetPath);
                    throw new InvalidDataException(
                        $"SHA-256 verification failed for '{safeFileName}'. Expected {expectedSha256}, actual {actualSha256}.");
                }

                checksumVerified = true;
            }
        }

        string? stagingRoot = null;
        if (asset.Kind == UpdatePackageKind.PortableZip)
        {
            var extractRoot = Path.Combine(versionDir, "staging");
            if (Directory.Exists(extractRoot))
            {
                Directory.Delete(extractRoot, recursive: true);
            }

            ZipFile.ExtractToDirectory(targetPath, extractRoot, overwriteFiles: true);
            stagingRoot = FindAppRootInStaging(extractRoot);
            if (stagingRoot is null)
            {
                Directory.Delete(extractRoot, recursive: true);
                throw new InvalidDataException("Downloaded update archive does not contain JustCryptDns.exe.");
            }

            // Never carry portable.flag into an installed or protected system deployment (prevents switching %ProgramData% to %ProgramFiles%\data).
            if (!_paths.IsPortableMode || AppPaths.IsProtectedSystemDirectory(AppContext.BaseDirectory))
            {
                TryDeleteFile(Path.Combine(stagingRoot, "portable.flag"));
            }
        }

        _logger.LogInformation(
            "Prepared update package {Version} at {Path} (ChecksumVerified={Verified}).",
            release.Version,
            targetPath,
            checksumVerified);

        return new PreparedUpdatePackage(
            release.Version,
            targetPath,
            asset.Kind,
            stagingRoot,
            checksumVerified,
            expectedSha256,
            actualSha256);
    }

    public bool LaunchPreparedUpdate(PreparedUpdatePackage package, out string? errorMessage)
    {
        ArgumentNullException.ThrowIfNull(package);
        errorMessage = null;

        try
        {
            if (package.Kind == UpdatePackageKind.InstallerExe)
            {
                if (!File.Exists(package.PackagePath))
                {
                    errorMessage = "Downloaded installer package was not found on disk.";
                    return false;
                }

                var psi = new ProcessStartInfo(package.PackagePath, "/SILENT /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS")
                {
                    UseShellExecute = true,
                };
                using var proc = Process.Start(psi);
                if (proc is null)
                {
                    errorMessage = "Failed to start the downloaded installer.";
                    return false;
                }

                return true;
            }

            if (string.IsNullOrWhiteSpace(package.StagingDirectory)
                || !File.Exists(Path.Combine(package.StagingDirectory, "JustCryptDns.exe")))
            {
                errorMessage = "Prepared update staging directory is missing JustCryptDns.exe.";
                return false;
            }

            var targetDir = ResolveInstallDirectory();
            var versionDir = Path.GetDirectoryName(package.PackagePath) ?? Path.Combine(_paths.UpdatesDirectory, SanitizePathSegment(package.Version));
            var scriptPath = Path.Combine(versionDir, "apply-update.ps1");
            var scriptContent = BuildPortableUpdateScript(
                waitPid: Environment.ProcessId,
                sourceDir: package.StagingDirectory,
                targetDir: targetDir,
                cleanupDir: versionDir,
                isPortableMode: _paths.IsPortableMode);

            // UTF-8 BOM guarantees Windows PowerShell 5.1 reads non-ASCII install paths reliably.
            File.WriteAllText(scriptPath, scriptContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            var requiresElevation = !CanWriteToDirectory(targetDir);
            var psExePath = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe")
                : "powershell.exe";
            if (OperatingSystem.IsWindows() && !File.Exists(psExePath))
            {
                psExePath = "powershell.exe";
            }

            var psPsi = new ProcessStartInfo(
                psExePath,
                $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{scriptPath}\"")
            {
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            if (requiresElevation)
            {
                psPsi.Verb = "runas";
            }

            using var updaterProc = Process.Start(psPsi);
            if (updaterProc is null)
            {
                errorMessage = "Failed to start the background PowerShell updater.";
                return false;
            }

            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            errorMessage = "Administrator permission prompt (UAC) was cancelled.";
            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException)
        {
            _logger.LogError(ex, "Failed to launch prepared update for version {Version}.", package.Version);
            errorMessage = ex.Message;
            return false;
        }
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private UpdateCheckResult PublishResult(UpdateCheckResult result)
    {
        LatestResult = result;
        UpdateCheckCompleted?.Invoke(this, result);
        return result;
    }

    private async Task<HttpResponseMessage> SendGitHubApiGetAsync(string url, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", $"JustCryptDns/{CurrentVersion}");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        request.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");
        return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsRateLimited(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return true;
        }

        if (response.StatusCode == HttpStatusCode.Forbidden
            && response.Headers.TryGetValues("X-RateLimit-Remaining", out var values)
            && values.Any(v => string.Equals(v.Trim(), "0", StringComparison.Ordinal)))
        {
            return true;
        }

        return false;
    }

    private static bool TryParseRelease(JsonElement element, bool includePrereleases, out UpdateReleaseInfo? release)
    {
        release = null;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var isDraft = element.TryGetProperty("draft", out var draftProp) && draftProp.ValueKind == JsonValueKind.True;
        if (isDraft)
        {
            return false;
        }

        var isPrerelease = element.TryGetProperty("prerelease", out var preProp) && preProp.ValueKind == JsonValueKind.True;
        if (isPrerelease && !includePrereleases)
        {
            return false;
        }

        var tagName = GetStringProperty(element, "tag_name") ?? string.Empty;
        var name = GetStringProperty(element, "name");
        if (string.IsNullOrWhiteSpace(tagName) && string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var version = AppVersionComparer.NormalizeVersion(string.IsNullOrWhiteSpace(tagName) ? name : tagName);
        var effectiveTitle = string.IsNullOrWhiteSpace(name) ? $"JustCryptDns {version}" : name.Trim();
        var body = GetStringProperty(element, "body") ?? string.Empty;
        var rawHtmlUrl = GetStringProperty(element, "html_url");
        var htmlUrl = IsSafeHttpsUrl(rawHtmlUrl) ? rawHtmlUrl! : BugReportBuilder.GitHubRepoUrl + "/releases";

        var publishedAt = DateTimeOffset.UtcNow;
        var rawDate = GetStringProperty(element, "published_at") ?? GetStringProperty(element, "created_at");
        if (!string.IsNullOrWhiteSpace(rawDate)
            && DateTimeOffset.TryParse(rawDate, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsedDate))
        {
            publishedAt = parsedDate.ToUniversalTime();
        }

        var preferredAsset = SelectPreferredAsset(element);
        release = new UpdateReleaseInfo(
            TagName: string.IsNullOrWhiteSpace(tagName) ? version : tagName,
            Version: version,
            Name: effectiveTitle,
            ReleaseNotes: body,
            PublishedAtUtc: publishedAt,
            HtmlUrl: htmlUrl,
            IsPrerelease: isPrerelease,
            PreferredAsset: preferredAsset);
        return true;
    }

    private static UpdateAssetInfo? SelectPreferredAsset(JsonElement releaseElement)
    {
        if (!releaseElement.TryGetProperty("assets", out var assetsProp) || assetsProp.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        string? checksumsUrl = null;
        var candidates = new List<(int Priority, string FileName, string Url, long Size, UpdatePackageKind Kind)>();

        foreach (var item in assetsProp.EnumerateArray())
        {
            var fileName = GetStringProperty(item, "name");
            var url = GetStringProperty(item, "browser_download_url");
            if (string.IsNullOrWhiteSpace(fileName) || string.IsNullOrWhiteSpace(url) || !IsSafeHttpsUrl(url))
            {
                continue;
            }

            if (fileName.Contains("SHA256SUMS", StringComparison.OrdinalIgnoreCase))
            {
                checksumsUrl ??= url;
                continue;
            }

            var size = item.TryGetProperty("size", out var sizeProp) && sizeProp.TryGetInt64(out var parsedSize)
                ? parsedSize
                : 0L;

            if (fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var priority = fileName.Contains("win-x64", StringComparison.OrdinalIgnoreCase) && fileName.Contains("portable", StringComparison.OrdinalIgnoreCase)
                    ? 1
                    : fileName.Contains("win-x64", StringComparison.OrdinalIgnoreCase)
                        ? 2
                        : 3;
                candidates.Add((priority, fileName, url, size, UpdatePackageKind.PortableZip));
            }
            else if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                var priority = fileName.Contains("win-x64", StringComparison.OrdinalIgnoreCase) && fileName.Contains("setup", StringComparison.OrdinalIgnoreCase)
                    ? 4
                    : 5;
                candidates.Add((priority, fileName, url, size, UpdatePackageKind.InstallerExe));
            }
        }

        if (candidates.Count == 0)
        {
            return null;
        }

        var best = candidates.OrderBy(c => c.Priority).First();
        return new UpdateAssetInfo(best.FileName, best.Url, best.Size, best.Kind, checksumsUrl);
    }

    private async Task<string?> FetchExpectedSha256Async(string checksumsUrl, string assetFileName, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, checksumsUrl);
        request.Headers.TryAddWithoutValidation("User-Agent", $"JustCryptDns/{CurrentVersion}");

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        foreach (var rawLine in content.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = rawLine.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
            {
                continue;
            }

            var hash = parts[0].Trim();
            var entryName = parts[1].Trim().TrimStart('*');
            if (hash.Length == 64 && string.Equals(Path.GetFileName(entryName), assetFileName, StringComparison.OrdinalIgnoreCase))
            {
                return hash.ToLowerInvariant();
            }
        }

        return null;
    }

    private static async Task<string> ComputeFileSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, StreamBufferSize, useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? FindAppRootInStaging(string extractRoot)
    {
        if (File.Exists(Path.Combine(extractRoot, "JustCryptDns.exe")))
        {
            return extractRoot;
        }

        foreach (var subDir in Directory.EnumerateDirectories(extractRoot))
        {
            if (File.Exists(Path.Combine(subDir, "JustCryptDns.exe")))
            {
                return subDir;
            }
        }

        return null;
    }

    private string ResolveInstallDirectory()
    {
        if (!string.IsNullOrWhiteSpace(_installDirectoryOverride))
        {
            return Path.GetFullPath(_installDirectoryOverride);
        }

        var processDir = Path.GetDirectoryName(Environment.ProcessPath);
        return !string.IsNullOrWhiteSpace(processDir)
            ? processDir
            : AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static bool CanWriteToDirectory(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probeFile = Path.Combine(directory, $".jcd-write-probe-{Guid.NewGuid():N}.tmp");
            using (File.Create(probeFile))
            {
            }

            File.Delete(probeFile);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static bool IsSafeHttpsUrl(string? url) =>
        !string.IsNullOrWhiteSpace(url)
        && Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)
        && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    internal static string BuildPortableUpdateScript(int waitPid, string sourceDir, string targetDir, string cleanupDir, bool isPortableMode = true)
    {
        static string EscapePs(string value) => value.Replace("'", "''", StringComparison.Ordinal);
        var skipPortableFlagLiteral = isPortableMode ? "$false" : "$true";

        return $$"""
$ErrorActionPreference = 'Stop'
$WaitPid = {{waitPid}}
$SourceDir = '{{EscapePs(sourceDir)}}'
$TargetDir = '{{EscapePs(targetDir)}}'
$CleanupDir = '{{EscapePs(cleanupDir)}}'
$SkipPortableFlag = {{skipPortableFlagLiteral}}
$ExeName = 'JustCryptDns.exe'
$ServiceName = 'JustCryptDnsService'

$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    $proc = Get-Process -Id $WaitPid -ErrorAction SilentlyContinue
    if ($null -eq $proc) { break }
    Start-Sleep -Milliseconds 250
}

$restartService = $false
try {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -eq 'Running') {
        $wmi = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if ($null -ne $wmi -and $wmi.PathName -and $wmi.PathName.IndexOf($TargetDir, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            $restartService = $true
        }
    }
} catch { }

if (-not (Test-Path -LiteralPath $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$sourceRoot = $SourceDir.TrimEnd('\', '/')
Get-ChildItem -LiteralPath $SourceDir -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
    if ($SkipPortableFlag -and ($rel -ieq 'portable.flag')) { return }
    $dest = Join-Path $TargetDir $rel
    $destParent = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $destParent)) {
        New-Item -ItemType Directory -Path $destParent -Force | Out-Null
    }
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
            break
        } catch {
            if ($attempt -eq 6) { throw }
            Start-Sleep -Milliseconds 500
        }
    }
}

if ($restartService) {
    try { & sc.exe config $ServiceName start= auto | Out-Null } catch { }
    try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
}

$targetExe = Join-Path $TargetDir $ExeName
if (Test-Path -LiteralPath $targetExe) {
    Start-Process -FilePath $targetExe -WorkingDirectory $TargetDir
}

if ($CleanupDir -and (Test-Path -LiteralPath $CleanupDir)) {
    Remove-Item -LiteralPath $CleanupDir -Recurse -Force -ErrorAction SilentlyContinue
}
""";
    }

    private static string ResolveCurrentVersion(string? overrideVersion)
    {
        if (!string.IsNullOrWhiteSpace(overrideVersion))
        {
            return AppVersionComparer.NormalizeVersion(overrideVersion);
        }

        var infoVersion = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVersion))
        {
            return AppVersionComparer.NormalizeVersion(infoVersion);
        }

        var assemblyVersion = typeof(GitHubUpdateService).Assembly.GetName().Version?.ToString(3);
        return AppVersionComparer.NormalizeVersion(assemblyVersion ?? "1.3.0");
    }

    private static HttpClient CreateDefaultHttpClient() =>
        new() { Timeout = TimeSpan.FromMinutes(10) };

    private static string? GetStringProperty(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;

    private static string SanitizePathSegment(string input)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var clean = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            clean.Append(Array.IndexOf(invalid, ch) >= 0 ? '_' : ch);
        }

        var result = clean.ToString().Trim('.', ' ');
        return string.IsNullOrWhiteSpace(result) ? "unknown" : result;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
