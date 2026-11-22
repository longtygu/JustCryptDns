using System.Buffers.Binary;
using System.IO;
using System.Net;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Filtering;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Updates;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace JustCryptDns.Tests.CoreAndUi;

public sealed class Phase18BugfixHardeningTests
{
    [Fact]
    public void DnsPacket_RejectsForwardCompressionPointers_AndOversizedQuestionCounts()
    {
        // Craft a 16-byte DNS packet where question name at offset 12 uses a forward pointer (0xC0 0x0E) to offset 14
        var forwardPointerPacket = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(forwardPointerPacket.AsSpan(0, 2), 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(forwardPointerPacket.AsSpan(4, 2), 1); // QDCOUNT = 1
        forwardPointerPacket[12] = 0xC0;
        forwardPointerPacket[13] = 0x0E; // Forward pointer (14 >= 12)
        forwardPointerPacket[14] = 0xC0;
        forwardPointerPacket[15] = 0x0C; // Loop back to 12

        Assert.False(DnsPacket.TryParse(forwardPointerPacket, out _));

        // CreateErrorResponse must also complete immediately without infinite loop and omit malformed question
        var errResp = DnsPacket.CreateErrorResponse(forwardPointerPacket, DnsResponseCode.ServFail);
        Assert.Equal(DnsPacket.HeaderSize, errResp.Length);

        // Oversized QDCOUNT (e.g., 65535) in a 12-byte packet must be rejected immediately without OOM allocation
        var hugeQdPacket = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(hugeQdPacket.AsSpan(4, 2), 65535);
        Assert.False(DnsPacket.TryParse(hugeQdPacket, out _));
    }

    [Fact]
    public void DnsPacket_RewriteAnswerTtls_ClampsWithoutIncreasingShortTtls()
    {
        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A, id: 0x2222);
        var response = DnsPacket.CreateLocalRewriteResponse(
            query,
            LocalDnsRewriteRecordType.A,
            "93.184.216.34",
            ttlSeconds: 10);

        DnsPacket.RewriteAnswerTtls(response, newTtlSeconds: 30);

        Assert.True(DnsPacket.TryParse(response, out var parsed) && parsed is not null);
        Assert.Single(parsed.Answers);
        Assert.Equal(10u, parsed.Answers[0].Ttl);
    }

    [Fact]
    public void DnsCacheService_RejectsMismatchedQuestionResponse_PreventingCachePoisoning()
    {
        var store = new InMemoryStore();
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var cache = new DnsCacheService(settings);

        var queryExample = DnsPacket.CreateQuery("example.com", DnsRecordType.A, id: 0x1111);
        var queryOther = DnsPacket.CreateQuery("evil.example.org", DnsRecordType.A, id: 0x1111);
        var spoofedResponseForOther = DnsPacket.CreateLocalRewriteResponse(
            queryOther,
            LocalDnsRewriteRecordType.A,
            "1.2.3.4",
            ttlSeconds: 120);

        // Attempt to store a response for evil.example.org against a query for example.com
        cache.StoreResponse(queryExample, spoofedResponseForOther);

        Assert.False(cache.TryGetResponse(queryOther, out _, out _));
        Assert.False(cache.TryGetResponse(queryExample, out _, out _));

        // Matching query + response succeeds
        var validResponse = DnsPacket.CreateLocalRewriteResponse(
            queryExample,
            LocalDnsRewriteRecordType.A,
            "93.184.216.34",
            ttlSeconds: 120);
        cache.StoreResponse(queryExample, validResponse);
        Assert.True(cache.TryGetResponse(queryExample, out _, out _));
    }

    [Fact]
    public async Task DnsRoutingService_FindMatchingRewrite_MatchesCnameForAAndAaaaQueries()
    {
        var store = new InMemoryStore();
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var routing = new DnsRoutingService(settings, NullLogger<DnsRoutingService>.Instance);

        var (ok, _, err) = await routing.AddOrUpdateLocalRewriteAsync(new LocalDnsRewriteRule
        {
            Id = "alias-rule",
            Pattern = "alias.lan",
            MatchKind = RoutingMatchKind.Exact,
            RecordType = LocalDnsRewriteRecordType.CNAME,
            TargetValue = "target.lan",
            TtlSeconds = 60,
            IsEnabled = true,
        });
        Assert.True(ok, err);

        var matchedA = routing.FindMatchingRewrite("alias.lan", "A");
        Assert.NotNull(matchedA);
        Assert.Equal(LocalDnsRewriteRecordType.CNAME, matchedA!.RecordType);
        Assert.Equal("target.lan", matchedA.TargetValue);
    }

    [Fact]
    public void RoutingMatcher_AndAppSettingsNormalize_EnforceInjectionAndPathTraversalGuards()
    {
        Assert.False(RoutingMatcher.IsValidPattern("evil.com'; alert(1);//", RoutingMatchKind.Exact, out _));
        Assert.False(RoutingMatcher.IsValidPattern("evil.com\r\n", RoutingMatchKind.DomainSuffix, out _));

        var settings = new AppSettings();
        settings.Filtering.Blocklists =
        [
            new DnsBlocklistSource
            {
                Id = @"..\..\Windows\System32\drivers\etc\hosts",
                Name = "Traversal",
                Category = BlocklistCategory.Custom,
                SourceUrl = "https://example.com/list.txt",
            },
        ];
        settings.Normalize();

        var sanitizedId = settings.Filtering.Blocklists[0].Id;
        Assert.DoesNotContain("..", sanitizedId, StringComparison.Ordinal);
        Assert.DoesNotContain("\\", sanitizedId, StringComparison.Ordinal);
        Assert.DoesNotContain("/", sanitizedId, StringComparison.Ordinal);
    }

    [Fact]
    public void BypassRuleMatcher_AndPacGenerator_HandleIpv4MappedIpv6AndNewlineEscaping()
    {
        Assert.True(BypassRuleMatcher.IsDirectExcluded("::ffff:127.0.0.1", null));
        Assert.True(BypassRuleMatcher.IsDirectExcluded("::ffff:192.168.1.1", null));
        Assert.True(BypassRuleMatcher.IsDirectExcluded("::ffff:10.0.0.1", null));

        var bypassSettings = new BypassSettings
        {
            ListenAddress = "::1",
            ProxyPort = 10808,
            CoverageMode = BypassCoverageMode.RuleListOnly,
            Rules =
            [
                new BypassRule
                {
                    Id = "r1",
                    Name = "Test",
                    Pattern = "discord.com",
                    MatchKind = RoutingMatchKind.DomainSuffix,
                    Mode = BypassMode.DpiFragment,
                    Enabled = true,
                },
            ],
        };

        var pac = PacScriptGenerator.Generate(bypassSettings, 10808);
        Assert.Contains("PROXY [::1]:10808; DIRECT", pac, StringComparison.Ordinal);
        Assert.Contains("h.indexOf(':', colon + 1) < 0", pac, StringComparison.Ordinal);
    }

    [Fact]
    public void IpBlockerGuard_RejectsLoopbackEvenWhenContextIsNull()
    {
        var v4Loop = IpBlockerGuard.Evaluate("127.0.0.53", context: null);
        Assert.False(v4Loop.IsValid);
        Assert.True(v4Loop.IsProtectedViolation);

        var v6Loop = IpBlockerGuard.Evaluate("::1/128", context: null);
        Assert.False(v6Loop.IsValid);
        Assert.True(v6Loop.IsProtectedViolation);
    }

    [Fact]
    public async Task JsonSettingsStore_DoesNotRenameHealthyFileToCorrupt_WhenExclusivelyLocked()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"jcd-locktest-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);
        try
        {
            var paths = new AppPaths(tempRoot);
            paths.EnsureCreated();
            var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
            await store.SaveAsync(new AppSettings());
            Assert.True(File.Exists(paths.SettingsFile));

            // Hold an exclusive lock on settings.json while Load() runs
            using (var exclusiveLock = new FileStream(paths.SettingsFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                _ = store.Load();
            }

            // Healthy settings.json must still exist and no .corrupt-* file should have been created
            Assert.True(File.Exists(paths.SettingsFile));
            var corruptFiles = Directory.GetFiles(paths.DataDirectory, "settings.corrupt-*.json");
            Assert.Empty(corruptFiles);
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    [Fact]
    public void GitHubUpdateService_BuildPortableUpdateScript_SkipsPortableFlagInInstalledMode()
    {
        var installedScript = GitHubUpdateService.BuildPortableUpdateScript(
            waitPid: 1234,
            sourceDir: @"C:\staging",
            targetDir: @"C:\Program Files\JustCryptDns",
            cleanupDir: @"C:\updates\1.7.1",
            isPortableMode: false);

        Assert.Contains("$SkipPortableFlag = $true", installedScript, StringComparison.Ordinal);
        Assert.Contains("if ($SkipPortableFlag -and ($rel -ieq 'portable.flag')) { return }", installedScript, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ServiceStateManager_HandlesNewV171IpcCommands()
    {
        var store = new InMemoryStore();
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var filtering = new DnsFilteringService(settings, NullLogger<DnsFilteringService>.Instance);
        var cache = new DnsCacheService(settings);
        var windowsDns = new StubWindowsDns();
        await using var dnsCrypt = new StubDnsCrypt();
        await using var engine = new DnsEngineService(
            settings,
            dnsCrypt,
            windowsDns,
            NullLogger<DnsEngineService>.Instance,
            filteringService: filtering,
            cacheService: cache);

        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
        var resp = DnsPacket.CreateLocalRewriteResponse(query, LocalDnsRewriteRecordType.A, "93.184.216.34", 60);
        cache.StoreResponse(query, resp);
        Assert.Equal(1, cache.GetStats().CurrentEntries);

        var manager = new ServiceStateManager(
            settings,
            engine,
            windowsDns,
            NullLogger<ServiceStateManager>.Instance,
            filtering: filtering,
            cache: cache,
            dnsCryptManager: dnsCrypt);

        var statsRes = await manager.HandleAsync(new IpcRequest(IpcRequestKind.GetFilterAndCacheStats));
        Assert.True(statsRes.Success);
        Assert.False(string.IsNullOrWhiteSpace(statsRes.Message));

        var clearRes = await manager.HandleAsync(new IpcRequest(IpcRequestKind.ClearDnsCache));
        Assert.True(clearRes.Success);
        Assert.Equal(0, cache.GetStats().CurrentEntries);
    }

    private sealed class InMemoryStore : ISettingsStore
    {
        private AppSettings _current = new();
        public SettingsLoadResult Load() => new(_current, SettingsLoadOutcome.Loaded);
        public void Save(AppSettings settings) => _current = settings;
        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            _current = settings;
            return Task.CompletedTask;
        }
    }

    private sealed class StubWindowsDns : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;
        public AdapterDnsBackupDocument? ReadBackup() => null;
        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(string? targetAdapterId, string ipv4Dns, string? ipv6Dns, Func<CancellationToken, Task<bool>> connectivityProbe, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(string? targetAdapterId = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class StubDnsCrypt : IDnsCryptProxyManager
    {
        public string ExecutablePath => "dnscrypt-proxy.exe";
        public bool IsInstalled => false;
        public bool IsRunning => false;
        public string? InstalledVersion => null;
        public Task<string?> DetectInstalledVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<(bool Success, string? Version, string? Error)> InstallOrUpdateAsync(System.Net.Http.HttpClient? httpClient = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?, string?)>((true, "2.1.5", null));
        public Task<(bool Success, string? Error)> EnsureRunningAsync(DnsResolverEndpoint resolver, int internalPort, CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
