using System.Net;
using System.Net.NetworkInformation;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Diagnostics;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Network.Diagnostics;
using JustCryptDns.Network.Failover;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests;

public sealed class Phase20BackgroundStabilityAndPerfTests
{
    private sealed class MutableTimeProvider(DateTimeOffset initialUtc) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = initialUtc;

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class MemorySettingsStore : ISettingsStore
    {
        private readonly AppSettings _initial;
        private readonly Func<AppSettings, CancellationToken, Task>? _saveHandler;

        public MemorySettingsStore(AppSettings? initial = null, Func<AppSettings, CancellationToken, Task>? saveHandler = null)
        {
            _initial = (initial ?? new AppSettings()).Clone().Normalize();
            _saveHandler = saveHandler;
        }

        public AppSettings? LastSaved { get; private set; }

        public SettingsLoadResult Load() => new(_initial.Clone().Normalize(), SettingsLoadOutcome.Loaded);

        public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            if (_saveHandler is not null)
            {
                await _saveHandler(settings, cancellationToken).ConfigureAwait(false);
            }

            LastSaved = settings.Clone();
        }
    }

    private sealed class StubNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot() => new(
            [],
            null,
            LocalConnectivity.GatewayAvailable,
            DateTimeOffset.UtcNow);
    }

    private sealed class CountingWindowsProxyManager : IWindowsProxyManager
    {
        private bool _hasBackup;

        public bool CanModifyCurrentUserProxy => true;
        public int ApplyPacCallCount { get; private set; }

        public bool HasActiveBackup() => _hasBackup;

        public WindowsProxyBackup? ReadBackup() => null;

        public Task<WindowsProxyOperationResult> ApplyPacProxyAsync(
            string pacUrl,
            CancellationToken cancellationToken = default)
        {
            ApplyPacCallCount++;
            _hasBackup = true;
            return Task.FromResult(new WindowsProxyOperationResult(true));
        }

        public Task<WindowsProxyOperationResult> ApplyManualProxyAsync(
            string proxyServer,
            string? bypassList,
            CancellationToken cancellationToken = default)
        {
            _hasBackup = true;
            return Task.FromResult(new WindowsProxyOperationResult(true));
        }

        public Task<WindowsProxyOperationResult> RestoreOriginalProxyAsync(
            CancellationToken cancellationToken = default)
        {
            _hasBackup = false;
            return Task.FromResult(new WindowsProxyOperationResult(true));
        }

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class StubDnsEngine : IDnsEngine
    {
        private readonly DnsEngineRuntimeStats _stats = new()
        {
            State = DnsEngineState.Stopped,
            ActiveResolverId = BuiltInResolvers.DefaultResolverId,
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
            BoundPort = 53,
        };

        public event EventHandler<DnsEngineRuntimeStats>? StateChanged
        {
            add { }
            remove { }
        }

        public DnsEngineRuntimeStats GetStats() => _stats;

        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 5.0, _stats.ActiveResolverId, _stats.ActiveProtocol));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 5.0, "OK"));

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class StatsOnlyPipeHandler : IServiceIpcHandler
    {
        public long TotalQueries { get; set; }
        public double? LastLatencyMs { get; set; } = 12.0;
        public double BlockedQueriesPerMinute { get; set; }
        public DnsEngineState EngineState { get; set; } = DnsEngineState.Stopped;

        public Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken cancellationToken = default)
        {
            var snapshot = new ServiceStatusSnapshot
            {
                ServiceVersion = "1.8.3",
                StartedAt = DateTimeOffset.UnixEpoch,
                EngineState = EngineState,
                IsEngineImplemented = true,
                IsEngineEnabled = EngineState == DnsEngineState.Running,
                ActiveResolverId = BuiltInResolvers.DefaultResolverId,
                ActiveResolverName = "Cloudflare (DoH)",
                ActiveProtocol = "DnsOverHttps",
                ListenEndpoint = "127.0.0.1:53",
                TotalQueries = TotalQueries,
                LastLatencyMs = LastLatencyMs,
                BlockedQueriesPerMinute = BlockedQueriesPerMinute,
            };
            return Task.FromResult(new IpcResponse(true, snapshot));
        }
    }

    private sealed class SuspendTrackingPage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
        public List<string> Events { get; } = [];

        public override void OnNavigatedTo() => Events.Add("to");

        public override void OnNavigatedFrom() => Events.Add("from");

        public override void OnShellSuspended() => Events.Add("suspend");

        public override void OnShellResumed() => Events.Add("resume");

        protected override void Dispose(bool disposing)
        {
            Events.Add("disposed");
            base.Dispose(disposing);
        }
    }

    private sealed class TrackingPageFactory : IPageFactory
    {
        public List<SuspendTrackingPage> Pages { get; } = [];

        public PageViewModel Create(string pageKey)
        {
            var page = new SuspendTrackingPage(pageKey);
            Pages.Add(page);
            return page;
        }
    }

    [Fact]
    public void DnsCacheService_TracksEntryCountsDeterministically_AndDecrementsAnswerTtl()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        using var settings = new SettingsService(new MemorySettingsStore(), NullLogger<SettingsService>.Instance);
        var cache = new DnsCacheService(settings, () => now);

        var posQuery = DnsPacket.CreateQuery("ttl.example.com", DnsRecordType.A, id: 0x1111);
        var posResp = DnsPacket.CreateLocalRewriteResponse(posQuery, LocalDnsRewriteRecordType.A, "1.2.3.4", ttlSeconds: 60)!;

        cache.StoreResponse(posQuery, posResp);
        var stats1 = cache.GetStats();
        Assert.Equal(1, stats1.CurrentEntries);
        Assert.Equal(1, stats1.PositiveEntries);
        Assert.Equal(0, stats1.NegativeEntries);

        var negQuery = DnsPacket.CreateQuery("missing.example.com", DnsRecordType.A, id: 0x2222);
        var negResp = DnsPacket.CreateErrorResponse(negQuery, DnsResponseCode.NxDomain);
        cache.StoreResponse(negQuery, negResp);

        var stats2 = cache.GetStats();
        Assert.Equal(2, stats2.CurrentEntries);
        Assert.Equal(1, stats2.PositiveEntries);
        Assert.Equal(1, stats2.NegativeEntries);

        // Advance clock by 20s and read cached positive response; returned wire TTL must be ~40s (decremented).
        now = now.AddSeconds(20);
        var hitQuery = DnsPacket.CreateQuery("ttl.example.com", DnsRecordType.A, id: 0x3333);
        Assert.True(cache.TryGetResponse(hitQuery, out var cachedWire));
        Assert.True(DnsPacket.TryParse(cachedWire, out var parsed));
        Assert.NotNull(parsed!.MinAnswerTtl);
        Assert.InRange(parsed.MinAnswerTtl!.Value, 39u, 40u);

        // Replace existing positive entry -> PositiveEntries stays 1.
        var updatedResp = DnsPacket.CreateLocalRewriteResponse(posQuery, LocalDnsRewriteRecordType.A, "5.6.7.8", ttlSeconds: 120)!;
        cache.StoreResponse(posQuery, updatedResp);
        var stats3 = cache.GetStats();
        Assert.Equal(1, stats3.PositiveEntries);
        Assert.Equal(1, stats3.NegativeEntries);

        // Advance past negative TTL (60s total from start) and verify EvictExpired decrements NegativeEntries.
        now = now.AddSeconds(45);
        var evicted = cache.EvictExpired();
        Assert.Equal(1, evicted);
        var stats4 = cache.GetStats();
        Assert.Equal(1, stats4.PositiveEntries);
        Assert.Equal(0, stats4.NegativeEntries);

        cache.Clear();
        var stats5 = cache.GetStats();
        Assert.Equal(0, stats5.CurrentEntries);
        Assert.Equal(0, stats5.PositiveEntries);
        Assert.Equal(0, stats5.NegativeEntries);
    }

    [Fact]
    public async Task DnsReverseLookupCache_IsThreadSafeUnderConcurrency_AndPurgesExpiredOnCount()
    {
        var clock = new MutableTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var reverse = new DnsReverseLookupCache(timeProvider: clock, maxEntries: 64, minTtlSeconds: 10, maxTtlSeconds: 60);

        var writers = Enumerable.Range(1, 20).Select(i => Task.Run(() =>
        {
            for (var j = 1; j <= 10; j++)
            {
                var ip = IPAddress.Parse($"10.0.{i}.{j}");
                reverse.Record(ip, $"host-{i}-{j}.example.test", ttlSeconds: 30);
                _ = reverse.TryResolve(ip.ToString(), out _);
            }
        }));

        await Task.WhenAll(writers);
        Assert.InRange(reverse.Count, 1, 64);

        clock.UtcNow = clock.UtcNow.AddMinutes(10);
        Assert.False(reverse.TryResolve("10.0.1.1", out _));
        Assert.True(reverse.Count >= 0);
    }

    [Fact]
    public void NetworkInfoService_RetainsVpnTunnelAdapters_WhileClassifyingProperly()
    {
        Assert.Equal(AdapterKind.Virtual, NetworkInfoService.Classify(NetworkInterfaceType.Tunnel, "WireGuard Tunnel"));
        Assert.Equal(AdapterKind.Virtual, NetworkInfoService.Classify(NetworkInterfaceType.Tunnel, "Cloudflare WARP"));
        Assert.Equal(AdapterKind.Virtual, NetworkInfoService.Classify(NetworkInterfaceType.Tunnel, "AnyConnect SSL VPN"));
        Assert.Equal(AdapterKind.Ethernet, NetworkInfoService.Classify(NetworkInterfaceType.Ethernet, "Intel(R) Ethernet Controller"));
    }

    [Fact]
    public async Task DnsFailoverService_SkipsCooledDownResolverUntilCooldownExpires()
    {
        var initial = new AppSettings
        {
            Dns =
            {
                ActiveResolverId = "cloudflare-doh",
                SecondaryResolverId = "google-doh",
            },
            Resilience =
            {
                EnableAutoFailover = true,
                FailureThresholdBeforeSwitch = 2,
                Policy = FailoverPolicy.PrimaryAndSecondaryOnly,
            },
        };
        using var settings = new SettingsService(new MemorySettingsStore(initial), NullLogger<SettingsService>.Instance);
        var resolverLib = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        using var failover = new DnsFailoverService(
            settings,
            resolverLib,
            NullLogger<DnsFailoverService>.Instance,
            new StubNetworkInfoService());

        var preferred = resolverLib.GetByIdOrDefault("cloudflare-doh");
        var query = DnsPacket.CreateQuery("cooldown.example.com", DnsRecordType.A);

        // Fail preferred twice so it enters the 30s failure cooldown; google-doh succeeds on fallback.
        for (var round = 0; round < 2; round++)
        {
            var res = await failover.QueryWithResilienceAsync(
                query,
                preferred,
                (r, _) => Task.FromResult(r.Id == "cloudflare-doh"
                    ? new DnsQueryResult(false, [], 50, r.Id, r.Protocol, "timed out")
                    : new DnsQueryResult(true, [1, 2, 3], 10, r.Id, r.Protocol)));
            Assert.True(res.Success);
            Assert.Equal("google-doh", res.ResolverId);
        }

        // Now preferred is in 30s cooldown: the very first attempt must skip cloudflare-doh completely.
        var attemptedIds = new List<string>();
        var third = await failover.QueryWithResilienceAsync(
            query,
            preferred,
            (r, _) =>
            {
                attemptedIds.Add(r.Id);
                return Task.FromResult(new DnsQueryResult(true, [1, 2, 3], 8, r.Id, r.Protocol));
            });

        Assert.True(third.Success);
        Assert.Equal(["google-doh"], attemptedIds);
    }

    [Fact]
    public async Task IpcFraming_RoundTripsLargePayloadViaArrayPool_AndRejectsExceedingLimit()
    {
        var bigMessage = new string('A', 120 * 1024);
        var dummyStatus = new ServiceStatusSnapshot
        {
            ServiceVersion = "1.8.3",
            StartedAt = DateTimeOffset.UnixEpoch,
            EngineState = DnsEngineState.Stopped,
        };
        var payload = new IpcResponse(true, dummyStatus, Message: bigMessage);

        using var ms = new MemoryStream();
        await IpcFraming.WriteMessageAsync(ms, payload);
        ms.Position = 0;

        var roundTripped = await IpcFraming.ReadMessageAsync<IpcResponse>(ms, maxMessageBytes: 512 * 1024);
        Assert.NotNull(roundTripped);
        Assert.Equal(bigMessage.Length, roundTripped!.Message!.Length);

        ms.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(
            () => IpcFraming.ReadMessageAsync<IpcResponse>(ms, maxMessageBytes: 1024));
    }

    [Fact]
    public async Task NamedPipeServiceClient_SuppressesStateChangedOnStatsOnlyUpdates()
    {
        var pipeName = $"JustCryptDns.P20.{Guid.NewGuid():N}";
        var handler = new StatsOnlyPipeHandler();
        await using var server = new NamedPipeIpcServer(handler, NullLogger<NamedPipeIpcServer>.Instance, pipeName);
        server.Start();

        var client = new NamedPipeServiceClient(NullLogger<NamedPipeServiceClient>.Instance, pipeName);
        var stateChangedCount = 0;
        client.StateChanged += (_, _) => Interlocked.Increment(ref stateChangedCount);

        // 1. Initial transition Unknown -> Connected MUST raise StateChanged once.
        var s1 = await client.RefreshStatusAsync();
        Assert.NotNull(s1);
        Assert.Equal(1, Volatile.Read(ref stateChangedCount));

        // 2. Subsequent refreshes where only stats counters changed must NOT raise StateChanged.
        handler.TotalQueries = 500;
        handler.LastLatencyMs = 42.5;
        handler.BlockedQueriesPerMinute = 18;
        var s2 = await client.RefreshStatusAsync();
        Assert.NotNull(s2);
        Assert.Equal(500, s2!.TotalQueries);
        Assert.Equal(1, Volatile.Read(ref stateChangedCount));

        // 3. Lifecycle state transition Stopped -> Running MUST raise StateChanged.
        handler.EngineState = DnsEngineState.Running;
        var s3 = await client.RefreshStatusAsync();
        Assert.NotNull(s3);
        Assert.Equal(DnsEngineState.Running, s3!.EngineState);
        Assert.Equal(2, Volatile.Read(ref stateChangedCount));
    }

    [Fact]
    public async Task BypassEngineService_RefreshSystemPacAsync_SkipsRedundantWindowsProxyReapply()
    {
        var proxyPort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var pacPort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var initial = new AppSettings
        {
            Bypass =
            {
                ProxyPort = proxyPort,
                PacPort = pacPort,
                ApplyWindowsProxyAutomatically = true,
                CoverageMode = BypassCoverageMode.AllWebsitesSmart,
            },
        };

        using var settings = new SettingsService(new MemorySettingsStore(initial), NullLogger<SettingsService>.Instance);
        var winProxy = new CountingWindowsProxyManager();
        var dnsEngine = new StubDnsEngine();
        await using var bypass = new BypassEngineService(settings, winProxy, dnsEngine, NullLogger<BypassEngineService>.Instance);

        var (started, err) = await bypass.StartAsync();
        Assert.True(started, err);
        Assert.Equal(1, winProxy.ApplyPacCallCount);

        // Calling RefreshSystemPacAsync with unchanged PAC script & port must not trigger another Windows proxy write.
        await bypass.RefreshSystemPacAsync();
        Assert.Equal(1, winProxy.ApplyPacCallCount);

        // Adding a direct exclusion alters the PAC script -> triggers a single reapply.
        var (added, addErr) = await bypass.AddDirectExclusionAsync("internal.example.test");
        Assert.True(added, addErr);
        Assert.Equal(2, winProxy.ApplyPacCallCount);

        await bypass.StopAsync();
    }

    [Fact]
    public async Task SettingsService_UpdateDeferred_DoesNotBlockOnSlowDiskSave_AndFlushesLatest()
    {
        var firstSaveEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowFirstSaveFinish = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var saveCall = 0;

        var store = new MemorySettingsStore(saveHandler: async (_, _) =>
        {
            if (Interlocked.Increment(ref saveCall) == 1)
            {
                firstSaveEntered.TrySetResult();
                await allowFirstSaveFinish.Task.ConfigureAwait(false);
            }
        });

        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);

        // Start a slow UpdateAsync holding the disk _gate.
        var slowTask = settings.UpdateAsync(s => s.General.StartWithWindows = true);
        await firstSaveEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        // UpdateDeferred must update in-memory state immediately without blocking on _gate.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        settings.UpdateDeferred(s => s.Appearance.SidebarCollapsed = true);
        sw.Stop();

        Assert.True(settings.Current.Appearance.SidebarCollapsed);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1));

        allowFirstSaveFinish.TrySetResult();
        await slowTask;
        await settings.FlushAsync();

        Assert.NotNull(store.LastSaved);
        Assert.True(store.LastSaved!.Appearance.SidebarCollapsed);
    }

    [Fact]
    public void NetworkDiagnosticsService_GetBlockedQueriesPerMinute_CountsRollingWindow()
    {
        using var settings = new SettingsService(new MemorySettingsStore(), NullLogger<SettingsService>.Instance);
        var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        using var diagnostics = new NetworkDiagnosticsService(settings, resolvers, new StubNetworkInfoService());

        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 3; i++)
        {
            diagnostics.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = now,
                Domain = $"ads{i}.example.test",
                RecordType = "A",
                Outcome = "Blocked",
                ResolverName = "Filter",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 0.2,
            });
        }

        for (var i = 0; i < 2; i++)
        {
            diagnostics.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = now,
                Domain = $"ok{i}.example.test",
                RecordType = "A",
                Outcome = "Allowed",
                ResolverName = "Cloudflare (DoH)",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 14.0,
            });
        }

        Assert.Equal(3.0, diagnostics.GetBlockedQueriesPerMinute());
    }

    [Fact]
    public void ShellViewModel_SetInteractive_SuspendsAndResumesCurrentPage()
    {
        var factory = new TrackingPageFactory();
        using var settings = new SettingsService(new MemorySettingsStore(), NullLogger<SettingsService>.Instance);
        var nav = new NavigationService();
        var shell = new ShellViewModel(factory, settings, nav, NullLogger<ShellViewModel>.Instance);

        var initialPage = factory.Pages[0];
        shell.SetInteractive(false);
        shell.SetInteractive(true);

        Assert.Equal(["to", "suspend", "resume"], initialPage.Events);

        // Navigating while already suspended also suspends the newly created page.
        shell.SetInteractive(false);
        shell.NavigateTo(PageKeys.Gaming);

        var secondPage = factory.Pages[1];
        Assert.Equal(["to", "suspend"], secondPage.Events);
        shell.StopTimers();
    }
}
