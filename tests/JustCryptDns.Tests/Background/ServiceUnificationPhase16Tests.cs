using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Network.Diagnostics;
using JustCryptDns.Network.Failover;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Background;

public sealed class ServiceUnificationPhase16Tests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(Path.GetTempPath(), "jcd-phase16", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch (IOException)
        {
            // Ignore transient cleanup lock on Windows.
        }
        catch (UnauthorizedAccessException)
        {
            // Ignore transient cleanup failure.
        }
    }

    [Fact]
    public void AppPaths_ResolvesSharedPortableAndCustomRootsCorrectly()
    {
        var customDir = Path.Combine(_tempRoot, "custom");
        var customPaths = new AppPaths(customDir);
        Assert.False(customPaths.IsPortableMode);
        Assert.Equal(Path.GetFullPath(customDir), customPaths.DataDirectory);
        Assert.Equal(Path.Combine(customPaths.DataDirectory, "proxy-backup.json"), customPaths.ProxyBackupFile);

        var portableAppDir = Path.Combine(_tempRoot, "portable-app");
        Directory.CreateDirectory(portableAppDir);
        File.WriteAllText(Path.Combine(portableAppDir, AppPaths.PortableFlagFileName), "portable");

        var portablePaths = new AppPaths(null, portableAppDir);
        portablePaths.EnsureCreated();
        Assert.True(portablePaths.IsPortableMode);
        Assert.Equal(Path.Combine(portableAppDir, "data"), portablePaths.DataDirectory);
        Assert.Equal(Path.Combine(portablePaths.DataDirectory, "proxy-backup.json"), portablePaths.ProxyBackupFile);
        Assert.True(Directory.Exists(portablePaths.LogsDirectory));
        Assert.True(Directory.Exists(portablePaths.EngineDirectory));
        Assert.True(Directory.Exists(portablePaths.UpdatesDirectory));

        var installedAppDir = Path.Combine(_tempRoot, "installed-app");
        Directory.CreateDirectory(installedAppDir);
        var installedPaths = new AppPaths(null, installedAppDir);
        Assert.False(installedPaths.IsPortableMode);
        var expectedShared = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AppPaths.ProductFolderName);
        var expectedPerUserProxy = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppPaths.ProductFolderName,
            "proxy-backup.json");
        Assert.Equal(expectedShared, installedPaths.DataDirectory);
        Assert.Equal(expectedPerUserProxy, installedPaths.ProxyBackupFile);
    }

    [Fact]
    public void AppPaths_TryMigrateLegacyUserDataToShared_MigratesOnceAndSkipsSubsequentRuns()
    {
        var legacyDir = Path.Combine(_tempRoot, "legacy-local");
        var sharedDir = Path.Combine(_tempRoot, "shared-progdata");
        Directory.CreateDirectory(Path.Combine(legacyDir, "engine"));
        File.WriteAllText(Path.Combine(legacyDir, "settings.json"), "{\"marker\":\"from-v152\"}");
        File.WriteAllText(Path.Combine(legacyDir, "dns-backup.json"), "{\"backup\":1}");
        File.WriteAllText(Path.Combine(legacyDir, "engine", "dnscrypt-proxy.exe"), "stub-binary");

        var sharedPaths = new AppPaths(sharedDir);
        var migratedFirst = sharedPaths.TryMigrateLegacyUserDataToShared(legacyDir);

        Assert.True(migratedFirst);
        Assert.Equal("{\"marker\":\"from-v152\"}", File.ReadAllText(sharedPaths.SettingsFile));
        Assert.Equal("{\"backup\":1}", File.ReadAllText(sharedPaths.DnsBackupFile));
        Assert.Equal("stub-binary", File.ReadAllText(Path.Combine(sharedPaths.EngineDirectory, "dnscrypt-proxy.exe")));

        File.WriteAllText(Path.Combine(legacyDir, "settings.json"), "{\"marker\":\"stale-overwrite\"}");
        var migratedSecond = sharedPaths.TryMigrateLegacyUserDataToShared(legacyDir);

        Assert.False(migratedSecond);
        Assert.Equal("{\"marker\":\"from-v152\"}", File.ReadAllText(sharedPaths.SettingsFile));
    }

    [Fact]
    public async Task SettingsService_ReloadFromDiskAsync_AppliesExternalChangesAndRaisesChanged()
    {
        var root = Path.Combine(_tempRoot, "settings-reload");
        var paths = new AppPaths(root);
        paths.EnsureCreated();

        var initialStore = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var externalWriter = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);

        var initial = initialStore.Load();
        using var service = new SettingsService(initialStore, NullLogger<SettingsService>.Instance, initial);

        var changedCount = 0;
        service.Changed += (_, _) => Interlocked.Increment(ref changedCount);

        var updated = new AppSettings();
        updated.Dns.ActiveResolverId = "quad9-doh";
        updated.Dns.ListenPort = 15353;
        await externalWriter.SaveAsync(updated);

        var reloaded = await service.ReloadFromDiskAsync();

        Assert.True(reloaded);
        Assert.Equal("quad9-doh", service.Current.Dns.ActiveResolverId);
        Assert.Equal(15353, service.Current.Dns.ListenPort);
        Assert.True(Volatile.Read(ref changedCount) >= 1);
    }

    [Fact]
    public async Task ServiceStateManager_HandlesReloadAndExtendedIpcSnapshots()
    {
        var root = Path.Combine(_tempRoot, "ssm-ipc");
        var paths = new AppPaths(root);
        paths.EnsureCreated();

        var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var externalWriter = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var freePort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var initialSettings = new AppSettings
        {
            General = { AutoStartDnsEngine = false, EnableGamingModeOnStartup = false },
            Dns = { ListenPort = freePort },
        };
        await externalWriter.SaveAsync(initialSettings);

        using var settingsService = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var winDns = new FakeWindowsDnsManager();
        var winProxy = new FakeWindowsProxyManager { CanModifyCurrentUserProxy = false };
        var netInfo = new FakeNetworkInfoService();
        var resolverLib = new ResolverLibraryService(settingsService, NullLogger<ResolverLibraryService>.Instance);
        using var failover = new DnsFailoverService(settingsService, resolverLib, NullLogger<DnsFailoverService>.Instance, netInfo);
        using var diagnostics = new NetworkDiagnosticsService(settingsService, resolverLib, netInfo);
        await using var dnsCrypt = new DnsCryptProxyManager(paths, NullLogger<DnsCryptProxyManager>.Instance);
        await using var dnsEngine = new DnsEngineService(
            settingsService,
            dnsCrypt,
            winDns,
            NullLogger<DnsEngineService>.Instance,
            resolverLibrary: resolverLib,
            failoverService: failover,
            diagnosticsService: diagnostics,
            networkInfo: netInfo);
        await using var bypassEngine = new BypassEngineService(
            settingsService,
            winProxy,
            dnsEngine,
            NullLogger<BypassEngineService>.Instance);

        var stateManager = new ServiceStateManager(
            settingsService,
            dnsEngine,
            winDns,
            NullLogger<ServiceStateManager>.Instance,
            bypassEngine: bypassEngine,
            networkInfo: netInfo,
            resolverLibrary: resolverLib,
            diagnostics: diagnostics,
            failover: failover);

        var ext = initialSettings.Clone();
        ext.Dns.ListenPort = 15359;
        await externalWriter.SaveAsync(ext);

        var reloadResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration));
        Assert.True(reloadResp.Success);
        Assert.Equal(15359, settingsService.Current.Dns.ListenPort);

        var engStatsResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.GetEngineDetailedStats));
        Assert.True(engStatsResp.Success);
        var engStats = JsonSerializer.Deserialize<DnsEngineRuntimeStats>(engStatsResp.Message!, SettingsJson.Options);
        Assert.NotNull(engStats);
        Assert.Equal(DnsEngineState.Stopped, engStats!.State);

        var bypassStatsResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.GetBypassDetailedStats));
        Assert.True(bypassStatsResp.Success);
        var bypassStats = JsonSerializer.Deserialize<BypassRuntimeStats>(bypassStatsResp.Message!, SettingsJson.Options);
        Assert.NotNull(bypassStats);

        var bypassEventsResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.GetBypassEventsSnapshot));
        Assert.True(bypassEventsResp.Success);
        Assert.NotNull(JsonSerializer.Deserialize<List<BypassConnectionEvent>>(bypassEventsResp.Message!, SettingsJson.Options));

        var liveResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.GetLiveQueriesSnapshot));
        Assert.True(liveResp.Success);
        Assert.NotNull(JsonSerializer.Deserialize<List<LiveQueryMonitorEntry>>(liveResp.Message!, SettingsJson.Options));

        var failoverResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.GetFailoverEventsSnapshot));
        Assert.True(failoverResp.Success);
        Assert.NotNull(JsonSerializer.Deserialize<List<FailoverEventEntry>>(failoverResp.Message!, SettingsJson.Options));

        var proxyTestResp = await stateManager.HandleAsync(new IpcRequest(IpcRequestKind.TestLocalProxy));
        Assert.False(proxyTestResp.Success);
        var testRes = JsonSerializer.Deserialize<LocalProxyTestResult>(proxyTestResp.Message!, SettingsJson.Options);
        Assert.NotNull(testRes);
        Assert.False(testRes!.Success);
    }

    [Fact]
    public async Task HybridProxies_DelegateToConnectedServiceAndLeaveServiceRunningOnDispose()
    {
        var root = Path.Combine(_tempRoot, "hybrid");
        var paths = new AppPaths(root);
        paths.EnsureCreated();

        var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var settingsDoc = new AppSettings
        {
            Dns = { ListenPort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback) },
            Bypass =
            {
                ApplyWindowsProxyAutomatically = true,
                WindowsProxyMode = WindowsProxyMode.AutoPac,
            },
        };
        await store.SaveAsync(settingsDoc);

        using var settingsService = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var winDns = new FakeWindowsDnsManager();
        var winProxy = new FakeWindowsProxyManager { CanModifyCurrentUserProxy = true };
        await using var dnsCrypt = new DnsCryptProxyManager(paths, NullLogger<DnsCryptProxyManager>.Instance);
        await using var localDns = new DnsEngineService(settingsService, dnsCrypt, winDns, NullLogger<DnsEngineService>.Instance);
        await using var localBypass = new BypassEngineService(settingsService, winProxy, localDns, NullLogger<BypassEngineService>.Instance);

        var fakeClient = new FakeServiceClient();
        await using var hybridDns = new HybridDnsEngineProxy(
            localDns,
            fakeClient,
            settingsService,
            NullLogger<HybridDnsEngineProxy>.Instance);
        await using var hybridBypass = new HybridBypassEngineProxy(
            localBypass,
            fakeClient,
            winProxy,
            settingsService,
            NullLogger<HybridBypassEngineProxy>.Instance);

        var (dnsStarted, _) = await hybridDns.StartAsync();
        Assert.True(dnsStarted);
        Assert.Equal(DnsEngineState.Stopped, localDns.GetStats().State);
        Assert.Equal(DnsEngineState.Running, hybridDns.GetStats().State);
        Assert.Contains(fakeClient.Requests, r => r.Kind == IpcRequestKind.SetEngineEnabled && r.BoolValue == true);

        var (switched, _) = await hybridDns.SwitchResolverAsync("google-doh");
        Assert.True(switched);
        Assert.Contains(fakeClient.Requests, r => r.Kind == IpcRequestKind.ReloadConfiguration && r.StringValue == "google-doh");

        var (bypassStarted, _) = await hybridBypass.StartAsync();
        Assert.True(bypassStarted);
        Assert.Equal(BypassEngineState.Stopped, localBypass.GetStats().State);
        Assert.Equal(BypassEngineState.Running, hybridBypass.GetStats().State);
        Assert.True(hybridBypass.GetStats().WindowsProxyApplied);
        Assert.Equal(1, winProxy.ApplyPacCallCount);
        Assert.Equal("http://127.0.0.1:10810/proxy.pac?v=2", winProxy.LastPacUrl);

        await hybridBypass.EnsureUserProxySynchronizedAsync();
        Assert.Equal(1, winProxy.ApplyPacCallCount);

        await hybridBypass.StopAsync();
        Assert.Contains(fakeClient.Requests, r => r.Kind == IpcRequestKind.SetBypassEnabled && r.BoolValue == false);
        Assert.False(hybridBypass.GetStats().WindowsProxyApplied);
        Assert.Equal(1, winProxy.RestoreCallCount);

        await hybridBypass.StartAsync();
        fakeClient.Requests.Clear();
        await hybridDns.StopLocalFallbackOnlyAsync();
        await hybridBypass.StopLocalFallbackOnlyAsync();
        await hybridDns.DisposeAsync();
        await hybridBypass.DisposeAsync();

        Assert.DoesNotContain(fakeClient.Requests, r => r.Kind == IpcRequestKind.SetEngineEnabled && r.BoolValue == false);
        Assert.DoesNotContain(fakeClient.Requests, r => r.Kind == IpcRequestKind.SetBypassEnabled && r.BoolValue == false);
    }

    [Fact]
    public async Task LocalSmartBypassProxy_SlowTlsThresholdAndCleanSocketDisposal()
    {
        Assert.True(LocalSmartBypassProxy.ShouldLearnDirectForSlowFragmentedTls(102.6, 1090.7));
        Assert.True(LocalSmartBypassProxy.ShouldLearnDirectForSlowFragmentedTls(15.0, 950.0));
        Assert.False(LocalSmartBypassProxy.ShouldLearnDirectForSlowFragmentedTls(250.0, 950.0));
        Assert.False(LocalSmartBypassProxy.ShouldLearnDirectForSlowFragmentedTls(5.0, 700.0));

        await using var dns = new FakeDnsEngine();
        var matcher = new BypassRuleMatcher();
        var settings = new BypassSettings();
        settings.Normalize();
        var proxy = new LocalSmartBypassProxy(
            IPAddress.Loopback,
            0,
            () => 0,
            () => settings,
            () => false,
            matcher,
            new UpstreamTunnelConnector(dns),
            static (_, _, _, _, _, _, _) => { },
            NullLogger.Instance);
        proxy.Start();

        using var activeClient = new TcpClient();
        await activeClient.ConnectAsync(IPAddress.Loopback, proxy.BoundPort);
        await Task.Delay(50);

        var sw = Stopwatch.StartNew();
        await proxy.DisposeAsync();
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < 1500, $"Expected fast socket teardown, took {sw.ElapsedMilliseconds} ms.");
    }

    [Fact]
    public async Task UnencryptedDnsGuard_FlagsOnlyWhenRunningWithUdpTcpAndSwitchesToDoh()
    {
        var root = Path.Combine(_tempRoot, "udp-guard");
        var paths = new AppPaths(root);
        paths.EnsureCreated();

        var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var initial = store.Load();
        using var settingsService = new SettingsService(store, NullLogger<SettingsService>.Instance, initial);
        using var dnsEngine = new FakeDnsEngine();
        await using var dnsCrypt = new DnsCryptProxyManager(paths, NullLogger<DnsCryptProxyManager>.Instance);

        using var dashboard = new DashboardViewModel(
            new FakeNetworkInfoService(),
            dnsEngine,
            new NavigationService(),
            NullLogger<DashboardViewModel>.Instance,
            settings: settingsService);

        using var dnsManager = new DnsManagerViewModel(
            dnsEngine,
            dnsCrypt,
            new FakeWindowsDnsManager(),
            settingsService);

        dashboard.OnNavigatedTo();
        dnsManager.OnNavigatedTo();

        dnsEngine.SetStats(DnsEngineState.Stopped, BuiltInResolvers.GetByIdOrDefault("cloudflare-udp"));
        Assert.False(dashboard.IsUnencryptedDnsActive);
        Assert.False(dnsManager.IsUnencryptedDnsActive);

        dnsEngine.SetStats(DnsEngineState.Running, BuiltInResolvers.GetByIdOrDefault(BuiltInResolvers.DefaultResolverId));
        Assert.False(dashboard.IsUnencryptedDnsActive);
        Assert.False(dnsManager.IsUnencryptedDnsActive);

        dnsEngine.SetStats(DnsEngineState.Running, BuiltInResolvers.GetByIdOrDefault("cloudflare-udp"));
        Assert.True(dashboard.IsUnencryptedDnsActive);
        Assert.True(dnsManager.IsUnencryptedDnsActive);

        await dashboard.SwitchToEncryptedDnsCommand.ExecuteAsync(null);
        Assert.Equal(BuiltInResolvers.DefaultResolverId, dnsEngine.GetStats().ActiveResolverId);
        Assert.False(dashboard.IsUnencryptedDnsActive);

        dnsEngine.SetStats(DnsEngineState.Running, BuiltInResolvers.GetByIdOrDefault("google-udp"));
        Assert.True(dnsManager.IsUnencryptedDnsActive);

        await dnsManager.SwitchToEncryptedDnsCommand.ExecuteAsync(null);
        Assert.Equal(BuiltInResolvers.DefaultResolverId, dnsEngine.GetStats().ActiveResolverId);
        Assert.False(dnsManager.IsUnencryptedDnsActive);

        dashboard.OnNavigatedFrom();
        dnsManager.OnNavigatedFrom();
    }

    private sealed class FakeNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot() => new([], null, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
    }

    private sealed class FakeWindowsDnsManager : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;
        public AdapterDnsBackupDocument? ReadBackup() => null;

        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
            string? targetAdapterId,
            string ipv4Dns,
            string? ipv6Dns,
            Func<CancellationToken, Task<bool>> connectivityProbe,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));

        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(
            string? targetAdapterId = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeWindowsProxyManager : IWindowsProxyManager
    {
        private bool _hasBackup;

        public bool CanModifyCurrentUserProxy { get; init; } = true;
        public int ApplyPacCallCount { get; private set; }
        public int RestoreCallCount { get; private set; }
        public string? LastPacUrl { get; private set; }

        public bool HasActiveBackup() => _hasBackup;
        public WindowsProxyBackup? ReadBackup() => null;

        public Task<WindowsProxyOperationResult> ApplyPacProxyAsync(
            string pacUrl,
            CancellationToken cancellationToken = default)
        {
            ApplyPacCallCount++;
            LastPacUrl = pacUrl;
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
            RestoreCallCount++;
            _hasBackup = false;
            return Task.FromResult(new WindowsProxyOperationResult(true));
        }

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class FakeDnsEngine : IDnsEngine, IDisposable
    {
        private DnsEngineRuntimeStats _stats = new()
        {
            State = DnsEngineState.Stopped,
            ActiveResolverId = BuiltInResolvers.DefaultResolverId,
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
            BoundPort = 53,
        };

        public event EventHandler<DnsEngineRuntimeStats>? StateChanged;

        public void SetStats(DnsEngineState state, DnsResolverEndpoint resolver)
        {
            _stats = _stats with
            {
                State = state,
                ActiveResolverId = resolver.Id,
                ActiveResolverName = resolver.Name,
                ActiveProtocol = resolver.Protocol,
            };
            StateChanged?.Invoke(this, _stats);
        }

        public DnsEngineRuntimeStats GetStats() => _stats;

        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default)
        {
            _stats = _stats with { State = DnsEngineState.Running };
            StateChanged?.Invoke(this, _stats);
            return Task.FromResult<(bool, string?)>((true, null));
        }

        public Task StopAsync(CancellationToken cancellationToken = default)
        {
            _stats = _stats with { State = DnsEngineState.Stopped };
            StateChanged?.Invoke(this, _stats);
            return Task.CompletedTask;
        }

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) =>
            StartAsync(cancellationToken);

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default)
        {
            var resolver = BuiltInResolvers.GetByIdOrDefault(resolverId);
            SetStats(_stats.State, resolver);
            return Task.FromResult<(bool, string?)>((true, null));
        }

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 12.0, _stats.ActiveResolverId, _stats.ActiveProtocol));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 10.0, "OK"));

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        public void Dispose() { }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeServiceClient : IServiceClient
    {
        private bool _dnsRunning;
        private bool _bypassRunning;
        private string _resolverId = BuiltInResolvers.DefaultResolverId;

        public List<IpcRequest> Requests { get; } = [];
        public ServiceConnectionState ConnectionState => ServiceConnectionState.Connected;
        public ServiceStatusSnapshot? LastStatus => BuildSnapshot();

        public event EventHandler? StateChanged
        {
            add { }
            remove { }
        }

        public Task<IpcResponse?> SendAsync(IpcRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            string? message = null;
            switch (request.Kind)
            {
                case IpcRequestKind.SetEngineEnabled:
                    _dnsRunning = request.BoolValue ?? true;
                    break;
                case IpcRequestKind.SetBypassEnabled:
                    _bypassRunning = request.BoolValue ?? true;
                    break;
                case IpcRequestKind.ReloadConfiguration when !string.IsNullOrWhiteSpace(request.StringValue):
                    _resolverId = request.StringValue;
                    break;
                case IpcRequestKind.GetEngineDetailedStats:
                {
                    var resolver = BuiltInResolvers.GetByIdOrDefault(_resolverId);
                    var stats = new DnsEngineRuntimeStats
                    {
                        State = _dnsRunning ? DnsEngineState.Running : DnsEngineState.Stopped,
                        ActiveResolverId = resolver.Id,
                        ActiveResolverName = resolver.Name,
                        ActiveProtocol = resolver.Protocol,
                        ListenEndpoint = "127.0.0.1:53",
                        BoundPort = 53,
                    };
                    message = JsonSerializer.Serialize(stats, SettingsJson.Options);
                    break;
                }
                case IpcRequestKind.GetBypassDetailedStats:
                {
                    var stats = new BypassRuntimeStats
                    {
                        State = _bypassRunning ? BypassEngineState.Running : BypassEngineState.Stopped,
                        ProxyEndpoint = "127.0.0.1:10808",
                        PacUrl = "http://127.0.0.1:10810/proxy.pac?v=2",
                        BoundProxyPort = 10808,
                        BoundPacPort = 10810,
                    };
                    message = JsonSerializer.Serialize(stats, SettingsJson.Options);
                    break;
                }
                case IpcRequestKind.GetBypassEventsSnapshot:
                    message = "[]";
                    break;
            }

            return Task.FromResult<IpcResponse?>(new IpcResponse(true, BuildSnapshot(), Message: message));
        }

        public Task<ServiceStatusSnapshot?> RefreshStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<ServiceStatusSnapshot?>(BuildSnapshot());

        private ServiceStatusSnapshot BuildSnapshot() => new()
        {
            ServiceVersion = "1.6.0",
            StartedAt = DateTimeOffset.UtcNow,
            EngineState = _dnsRunning ? DnsEngineState.Running : DnsEngineState.Stopped,
            IsEngineImplemented = true,
            IsEngineEnabled = _dnsRunning,
            ActiveResolverId = _resolverId,
            IsBypassRunning = _bypassRunning,
            BypassEndpoint = "127.0.0.1:10808",
        };
    }
}
