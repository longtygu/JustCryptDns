using System.Text.Json;
using System.Text.Json.Nodes;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Diagnostics;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Network.Diagnostics;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace JustCryptDns.Tests.CoreAndUi;

public sealed class Phase19OperationModesAndAnalyticsTests
{
    [Fact]
    public void SettingsMigration_V18ToV19_AddsOperationModeDefaultsWithoutDataLoss()
    {
        var json = """
        {
          "schemaVersion": 18,
          "filtering": {
            "customBlockedDomains": ["ads.custom.test"],
            "allowlist": [{ "domain": "safe.custom.test", "note": "keep" }]
          }
        }
        """;
        var doc = JsonNode.Parse(json)!.AsObject();
        var migrator = new SettingsMigrator();

        var migrated = migrator.Migrate(doc);

        Assert.True(migrated);
        Assert.Equal(AppSettings.CurrentSchemaVersion, SettingsMigrator.ReadVersion(doc));

        var settings = doc.Deserialize<AppSettings>(SettingsJson.Options)!.Normalize();
        Assert.Equal(AppOperationMode.Balanced, settings.OperationMode.ActiveMode);
        Assert.Contains("ads.custom.test", settings.Filtering.CustomBlockedDomains);
        Assert.Contains(settings.Filtering.Allowlist, a => a.Domain == "safe.custom.test");

        Assert.Equal("cloudflare-udp", settings.OperationMode.GetProfile(AppOperationMode.HighSpeed).ResolverId);
        Assert.False(settings.OperationMode.GetProfile(AppOperationMode.HighSpeed).EnableFiltering);

        var gaming = settings.OperationMode.GetProfile(AppOperationMode.Gaming);
        Assert.Equal("cloudflare-doh", gaming.ResolverId);
        Assert.True(gaming.EnableGamingEngine);
        Assert.True(gaming.MinimizeVisualEffects);
        Assert.Equal(MonitoringMode.PowerSaving, gaming.MonitoringMode);

        var security = settings.OperationMode.GetProfile(AppOperationMode.Security);
        Assert.Equal("quad9-doh", security.ResolverId);
        Assert.True(security.ForceEncryptedOnly);
        Assert.True(security.EnableDnsLeakGuard);
        Assert.True(security.EnableAllBuiltInBlocklists);
        Assert.True(security.AutoBlockDetectedThreats);
    }

    [Fact]
    public void OperationModeSettings_PerModeCustomizationAndReset_AreIsolated()
    {
        var settings = new AppSettings().Normalize();
        var gaming = settings.OperationMode.GetProfile(AppOperationMode.Gaming);
        gaming.ResolverId = "google-doh";
        gaming.CacheMaxEntries = 12000;

        Assert.Equal("google-doh", settings.OperationMode.GetProfile(AppOperationMode.Gaming).ResolverId);
        Assert.Equal("cloudflare-udp", settings.OperationMode.GetProfile(AppOperationMode.HighSpeed).ResolverId);

        settings.OperationMode.ResetModeToDefault(AppOperationMode.Gaming);
        Assert.Equal("cloudflare-doh", settings.OperationMode.GetProfile(AppOperationMode.Gaming).ResolverId);
        Assert.Equal(8192, settings.OperationMode.GetProfile(AppOperationMode.Gaming).CacheMaxEntries);
    }

    [Fact]
    public void OperationModeEvaluator_PrioritizesGamingAndSecurity_WithAntiFlapCooldown()
    {
        var evaluator = new OperationModeEvaluator();
        var rules = new AutoModeRulesSettings
        {
            SwitchToGamingOnFullscreenGame = true,
            SwitchToSecurityOnThreatOrSpike = true,
            HighBlockRateThresholdPerMinute = 40,
            CooldownSeconds = 20,
            CustomGameProcessNames = ["mycustomgame.exe"],
        };
        rules.Normalize();

        var t0 = new DateTimeOffset(2026, 11, 23, 10, 0, 0, TimeSpan.Zero);

        // Normal state -> Balanced
        var d0 = evaluator.Evaluate(new AutoModeSignals(false, "chrome", false, 2, false), rules, t0);
        Assert.Equal(AppOperationMode.Balanced, d0.EffectiveMode);

        // Custom game process detected -> immediate escalation to Gaming
        var d1 = evaluator.Evaluate(new AutoModeSignals(false, "MyCustomGame", false, 5, false), rules, t0.AddSeconds(5));
        Assert.Equal(AppOperationMode.Gaming, d1.EffectiveMode);
        Assert.Equal(AutoModeReason.KnownGameProcessDetected, d1.Reason);
        Assert.True(d1.Changed);

        // Brief Alt-Tab out of game after 10s (< 20s cooldown) -> stays in Gaming (anti-flap!)
        var d2 = evaluator.Evaluate(new AutoModeSignals(false, "explorer", false, 2, false), rules, t0.AddSeconds(15));
        Assert.Equal(AppOperationMode.Gaming, d2.EffectiveMode);
        Assert.False(d2.Changed);

        // Clear for >= 20s -> returns smoothly to Balanced
        var d3 = evaluator.Evaluate(new AutoModeSignals(false, "explorer", false, 2, false), rules, t0.AddSeconds(26));
        Assert.Equal(AppOperationMode.Balanced, d3.EffectiveMode);
        Assert.True(d3.Changed);

        // Blocked query spike >= 40/min -> immediate escalation to Security
        var d4 = evaluator.Evaluate(new AutoModeSignals(false, "chrome", false, 55, false), rules, t0.AddSeconds(30));
        Assert.Equal(AppOperationMode.Security, d4.EffectiveMode);
        Assert.Equal(AutoModeReason.HighBlockedQuerySpike, d4.Reason);
        Assert.True(d4.Changed);
    }

    [Fact]
    public void NetworkDiagnostics_DeltaSequence_AnalyticsAndSpamDetection_WorkAccurately()
    {
        var settings = new InMemorySettingsService(new AppSettings
        {
            Performance = new PerformanceSettings { MonitoringMode = MonitoringMode.Performance },
        }.Normalize());
        Assert.Equal(5000, settings.Current.Performance.GetMonitorBufferLimit());

        using var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        using var diag = new NetworkDiagnosticsService(settings, resolvers, new StubNetworkInfoService());

        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 25; i++)
        {
            diag.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = now,
                Domain = "spam.tracker.test",
                RecordType = "A",
                Outcome = "Blocked",
                ResolverName = "EasyPrivacy",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 0.0,
                ResponseCode = "NxDomain",
                AnswerSummary = "NXDOMAIN (Blocked)",
                MatchedRule = "EasyPrivacy",
            });
        }

        diag.RecordMonitorEntry(new LiveQueryMonitorEntry
        {
            Timestamp = now,
            Domain = "example.com",
            RecordType = "A",
            Outcome = "Allowed",
            ResolverName = "Cloudflare",
            Protocol = DnsProtocol.DnsOverHttps,
            LatencyMs = 14.2,
            ResponseCode = "NoError",
            AnswerSummary = "93.184.216.34",
        });

        var all = diag.GetMonitorEntries();
        Assert.Equal(26, all.Count);
        Assert.True(all[0].SequenceId > all[^1].SequenceId);

        var delta = diag.GetMonitorEntriesSince(all[5].SequenceId, 100);
        Assert.Equal(5, delta.Count);

        var analytics = diag.GetQueryAnalyticsSnapshot(10);
        Assert.Equal(26, analytics.TotalObservedQueries);
        Assert.Equal(25, analytics.TotalBlockedQueries);
        Assert.Equal(2, analytics.UniqueDomainCount);
        Assert.Equal("spam.tracker.test", analytics.TopBlocked[0].Domain);
        Assert.True(analytics.TopBlocked[0].IsHighFrequency);

        diag.ClearMonitorEntries();
        Assert.Empty(diag.GetMonitorEntries());
        Assert.Equal(0, diag.GetQueryAnalyticsSnapshot(10).TotalObservedQueries);
    }

    [Fact]
    public void DnsEngine_ExtractResponseMetadata_ParsesAnswersAndRcode()
    {
        var query = DnsPacket.CreateQuery("dev.local", DnsRecordType.A);
        var answerWire = DnsPacket.CreateLocalRewriteResponse(query, LocalDnsRewriteRecordType.A, "192.168.1.50", 60);

        var (rcode, summary) = DnsEngineService.ExtractResponseMetadata(answerWire);
        Assert.Equal("NoError", rcode);
        Assert.Contains("192.168.1.50", summary);

        var nxWire = DnsPacket.CreateErrorResponse(query, DnsResponseCode.NxDomain);
        var (nxCode, nxSummary) = DnsEngineService.ExtractResponseMetadata(nxWire);
        Assert.Equal("NxDomain", nxCode);
        Assert.Equal("NxDomain", nxSummary);
    }

    [Fact]
    public void CsvExportHelper_NeutralizesFormulaInjectionAndEscapesCommas()
    {
        var entries = new[]
        {
            new LiveQueryMonitorEntry
            {
                SequenceId = 1,
                Timestamp = new DateTimeOffset(2026, 11, 23, 12, 0, 0, TimeSpan.Zero),
                Domain = "=CMD|' /C calc'!A0",
                RecordType = "TXT",
                Outcome = "Allowed",
                ResolverName = "Cloudflare, Inc.",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 12.5,
                ResponseCode = "NoError",
                AnswerSummary = "+HYPERLINK(\"http://evil\")",
                MatchedRule = "@rule",
            },
        };

        var csv = CsvExportHelper.SerializeQueries(entries);
        Assert.Contains("'=CMD|' /C calc'!A0", csv);
        Assert.Contains("\"Cloudflare, Inc.\"", csv);
        Assert.Contains("'+HYPERLINK(\"\"http://evil\"\")", csv);
        Assert.Contains("'@rule", csv);
    }

    [Fact]
    public async Task ServiceStateManager_IpcSupportsDeltaLiveQueriesAndAnalyticsSnapshot()
    {
        var settings = new InMemorySettingsService(new AppSettings().Normalize());
        using var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        using var diag = new NetworkDiagnosticsService(settings, resolvers, new StubNetworkInfoService());

        for (var i = 0; i < 4; i++)
        {
            diag.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = DateTimeOffset.UtcNow,
                Domain = $"host{i}.example.test",
                RecordType = "A",
                Outcome = i == 0 ? "Blocked" : "Allowed",
                ResolverName = "Cloudflare",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 8.0,
            });
        }

        var manager = new ServiceStateManager(
            settings,
            new StubDnsEngine(),
            new StubWindowsDnsManager(),
            NullLogger<ServiceStateManager>.Instance,
            diagnostics: diag);

        var deltaResp = await manager.HandleAsync(new IpcRequest(IpcRequestKind.GetLiveQueriesSnapshot, StringValue: "after=2&limit=10"));
        Assert.True(deltaResp.Success);
        var deltaItems = JsonSerializer.Deserialize<List<LiveQueryMonitorEntry>>(deltaResp.Message!, SettingsJson.Options)!;
        Assert.Equal(2, deltaItems.Count);
        Assert.All(deltaItems, item => Assert.True(item.SequenceId > 2));

        var analyticsResp = await manager.HandleAsync(new IpcRequest(IpcRequestKind.GetQueryAnalyticsSnapshot, StringValue: "10"));
        Assert.True(analyticsResp.Success);
        var analytics = JsonSerializer.Deserialize<QueryAnalyticsSnapshot>(analyticsResp.Message!, SettingsJson.Options)!;
        Assert.Equal(4, analytics.TotalObservedQueries);
        Assert.Equal(1, analytics.TotalBlockedQueries);
    }

    private sealed class InMemorySettingsService : ISettingsService
    {
        public InMemorySettingsService(AppSettings initial) => Current = initial;

        public AppSettings Current { get; private set; }

        public SettingsLoadOutcome LoadOutcome => SettingsLoadOutcome.Loaded;

        public event EventHandler<AppSettings>? Changed;

        public event EventHandler<Exception>? SaveFailed { add { } remove { } }

        public Task UpdateAsync(Action<AppSettings> mutate, CancellationToken cancellationToken = default)
        {
            UpdateDeferred(mutate);
            return Task.CompletedTask;
        }

        public void UpdateDeferred(Action<AppSettings> mutate)
        {
            var clone = Current.Clone();
            mutate(clone);
            Current = clone.Normalize();
            Changed?.Invoke(this, Current);
        }

        public Task FlushAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<bool> ReloadFromDiskAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class StubNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged { add { } remove { } }

        public NetworkSnapshot GetSnapshot() => new([], null, LocalConnectivity.Offline, DateTimeOffset.UtcNow);

        public Task<NetworkSnapshot> RefreshAsync(CancellationToken cancellationToken = default) => Task.FromResult(GetSnapshot());
    }

    private sealed class StubDnsEngine : IDnsEngine
    {
        public event EventHandler<DnsEngineRuntimeStats>? StateChanged { add { } remove { } }

        public DnsEngineRuntimeStats GetStats() => new()
        {
            State = DnsEngineState.Stopped,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        };

        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));

        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 1, "cloudflare-doh", DnsProtocol.DnsOverHttps, null));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 1.0, "OK"));

        public Task<IReadOnlyList<System.Net.IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<System.Net.IPAddress>>([]);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class StubWindowsDnsManager : IWindowsDnsManager
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
}
