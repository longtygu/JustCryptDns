using System.Net;
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
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests;

public sealed class Phase21CrashFixAndServiceReconnectTests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(Path.GetTempPath(), "jcd-phase21", Guid.NewGuid().ToString("N"));

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
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed class MemorySettingsStore(AppSettings? initial = null) : ISettingsStore
    {
        private readonly AppSettings _initial = (initial ?? new AppSettings()).Clone().Normalize();

        public SettingsLoadResult Load() => new(_initial.Clone().Normalize(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeWindowsDnsManager : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;

        public AdapterDnsBackupDocument? ReadBackup() => null;

        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
            string? targetAdapterId,
            string ipv4Loopback,
            string? ipv6Loopback,
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
        public bool CanModifyCurrentUserProxy => false;

        public bool HasActiveBackup() => false;

        public WindowsProxyBackup? ReadBackup() => null;

        public Task<WindowsProxyOperationResult> ApplyPacProxyAsync(string pacUrl, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsProxyOperationResult(true));

        public Task<WindowsProxyOperationResult> ApplyManualProxyAsync(string proxyServer, string? bypassList, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsProxyOperationResult(true));

        public Task<WindowsProxyOperationResult> RestoreOriginalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsProxyOperationResult(true));

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class StubNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot() => new([], null, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
    }

    private sealed class LateStartingServiceClient : IServiceClient
    {
        private bool _serviceOnline;
        private bool _dnsRunning;
        private bool _bypassRunning;

        public int RefreshCallCount { get; private set; }
        public List<IpcRequest> SentRequests { get; } = [];

        public ServiceConnectionState ConnectionState { get; private set; } = ServiceConnectionState.ServiceNotRunning;

        public ServiceStatusSnapshot? LastStatus { get; private set; }

        public event EventHandler? StateChanged;

        public void BringServiceOnline(bool dnsRunning = true, bool bypassRunning = true)
        {
            _serviceOnline = true;
            _dnsRunning = dnsRunning;
            _bypassRunning = bypassRunning;
        }

        public Task<ServiceStatusSnapshot?> RefreshStatusAsync(CancellationToken cancellationToken = default)
        {
            RefreshCallCount++;
            if (!_serviceOnline)
            {
                return Task.FromResult<ServiceStatusSnapshot?>(null);
            }

            var wasConnected = ConnectionState == ServiceConnectionState.Connected;
            ConnectionState = ServiceConnectionState.Connected;
            LastStatus = BuildSnapshot();
            if (!wasConnected)
            {
                StateChanged?.Invoke(this, EventArgs.Empty);
            }

            return Task.FromResult<ServiceStatusSnapshot?>(LastStatus);
        }

        public Task<IpcResponse?> SendAsync(IpcRequest request, CancellationToken cancellationToken = default)
        {
            SentRequests.Add(request);
            if (!_serviceOnline)
            {
                return Task.FromResult<IpcResponse?>(null);
            }

            string? message = null;
            switch (request.Kind)
            {
                case IpcRequestKind.SetEngineEnabled:
                    _dnsRunning = request.BoolValue ?? true;
                    break;
                case IpcRequestKind.SetBypassEnabled:
                    _bypassRunning = request.BoolValue ?? true;
                    break;
                case IpcRequestKind.GetEngineDetailedStats:
                    message = JsonSerializer.Serialize(new DnsEngineRuntimeStats
                    {
                        State = _dnsRunning ? DnsEngineState.Running : DnsEngineState.Stopped,
                        ActiveResolverId = BuiltInResolvers.DefaultResolverId,
                        ActiveResolverName = "Cloudflare (DoH)",
                        ActiveProtocol = DnsProtocol.DnsOverHttps,
                        ListenEndpoint = "127.0.0.2:53",
                        BoundPort = 53,
                    }, SettingsJson.Options);
                    break;
                case IpcRequestKind.GetBypassDetailedStats:
                    message = JsonSerializer.Serialize(new BypassRuntimeStats
                    {
                        State = _bypassRunning ? BypassEngineState.Running : BypassEngineState.Stopped,
                        ProxyEndpoint = "127.0.0.1:10808",
                        PacUrl = "http://127.0.0.1:10809/proxy.pac?v=1",
                        BoundProxyPort = 10808,
                        BoundPacPort = 10809,
                    }, SettingsJson.Options);
                    break;
            }

            LastStatus = BuildSnapshot();
            return Task.FromResult<IpcResponse?>(new IpcResponse(true, LastStatus, Message: message));
        }

        private ServiceStatusSnapshot BuildSnapshot() => new()
        {
            ServiceVersion = "1.8.4",
            StartedAt = DateTimeOffset.UtcNow,
            EngineState = _dnsRunning ? DnsEngineState.Running : DnsEngineState.Stopped,
            IsEngineImplemented = true,
            IsEngineEnabled = _dnsRunning,
            ActiveResolverId = BuiltInResolvers.DefaultResolverId,
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = "DnsOverHttps",
            ListenEndpoint = "127.0.0.2:53",
            IsBypassRunning = _bypassRunning,
            BypassEndpoint = "127.0.0.1:10808",
            BypassPacUrl = "http://127.0.0.1:10809/proxy.pac?v=1",
            BoundProxyPort = 10808,
            BoundPacPort = 10809,
        };
    }

    private sealed class FailingDnsEngine : IDnsEngine
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
            Task.FromResult<(bool, string?)>((false, "Port 53 is already in use."));

        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) =>
            StartAsync(cancellationToken);

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(false, [], 0, _stats.ActiveResolverId, _stats.ActiveProtocol, "stopped"));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((false, 0.0, "stopped"));

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([]);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class DummyPage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
    }

    private sealed class DelegatePageFactory(Func<string, PageViewModel> create) : IPageFactory
    {
        public PageViewModel Create(string pageKey) => create(pageKey);
    }

    [Fact]
    public async Task NetworkTelemetryService_RapidResumeAndPauseWhilePinging_NeverThrowsNullReferenceException()
    {
        using var telemetry = new NetworkTelemetryService();
        // Wait until SamplingLoopAsync emits a sample and parks on PeriodicTimer.WaitForNextTickAsync(ct),
        // whose synchronous cancellation callback previously re-entered StopLoopLocked() and caused NullReferenceException.
        telemetry.ConfigureTargets(primaryAdapterId: null, preferredPingHost: "1.1.1.1");

        var firstSampleReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        telemetry.SampleReceived += (_, _) => firstSampleReceived.TrySetResult();

        telemetry.Resume();
        await Task.WhenAny(firstSampleReceived.Task, Task.Delay(3000));
        await Task.Delay(50);

        // Must NOT throw NullReferenceException even when PeriodicTimer cancellation resumes SamplingLoopAsync synchronously.
        telemetry.Pause();
        Assert.False(telemetry.IsActive);

        for (var i = 0; i < 20; i++)
        {
            telemetry.Resume();
            await Task.Delay(i % 2 == 0 ? 15 : 40);
            telemetry.Pause();
        }

        Assert.False(telemetry.IsActive);

        // Concurrent Resume + Pause stress check.
        telemetry.Resume();
        await Task.Delay(25);
        await Task.WhenAll(
            Task.Run(() => telemetry.Pause()),
            Task.Run(() => telemetry.Pause()));
        Assert.False(telemetry.IsActive);
    }

    [Fact]
    public async Task HybridDnsEngineProxy_StartAsync_ReprobesLateServiceInsteadOfStartingLocalEngine()
    {
        var paths = new AppPaths(Path.Combine(_tempRoot, "dns-reprobe"));
        paths.EnsureCreated();
        var freePort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        using var settings = new SettingsService(
            new MemorySettingsStore(new AppSettings { Dns = { ListenPort = freePort, ConfigureWindowsAdapter = false } }),
            NullLogger<SettingsService>.Instance);
        await using var dnsCrypt = new DnsCryptProxyManager(paths, NullLogger<DnsCryptProxyManager>.Instance);
        await using var localDns = new DnsEngineService(
            settings,
            dnsCrypt,
            new FakeWindowsDnsManager(),
            NullLogger<DnsEngineService>.Instance);

        var serviceClient = new LateStartingServiceClient();
        await using var hybrid = new HybridDnsEngineProxy(
            localDns,
            serviceClient,
            settings,
            NullLogger<HybridDnsEngineProxy>.Instance);

        // Service was unavailable at boot, then came online later.
        Assert.False(hybrid.IsDelegatingToService);
        serviceClient.BringServiceOnline(dnsRunning: true);

        var (ok, err) = await hybrid.StartAsync();

        Assert.True(ok, err);
        Assert.True(serviceClient.RefreshCallCount >= 1);
        Assert.True(hybrid.IsDelegatingToService);
        Assert.Equal(DnsEngineState.Stopped, localDns.GetStats().State);
        Assert.Contains(serviceClient.SentRequests, r => r.Kind == IpcRequestKind.SetEngineEnabled && r.BoolValue == true);
    }

    [Fact]
    public async Task HybridBypassEngineProxy_StartAsync_ReprobesLateServiceInsteadOfStartingLocalEngine()
    {
        var proxyPort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var pacPort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        using var settings = new SettingsService(
            new MemorySettingsStore(new AppSettings { Bypass = { ProxyPort = proxyPort, PacPort = pacPort, ApplyWindowsProxyAutomatically = false } }),
            NullLogger<SettingsService>.Instance);
        var winProxy = new FakeWindowsProxyManager();
        var failingDns = new FailingDnsEngine();
        await using var localBypass = new BypassEngineService(
            settings,
            winProxy,
            failingDns,
            NullLogger<BypassEngineService>.Instance);

        var serviceClient = new LateStartingServiceClient();
        await using var hybrid = new HybridBypassEngineProxy(
            localBypass,
            serviceClient,
            winProxy,
            settings,
            NullLogger<HybridBypassEngineProxy>.Instance);

        Assert.False(hybrid.IsDelegatingToService);
        serviceClient.BringServiceOnline(dnsRunning: true, bypassRunning: true);

        var (ok, err) = await hybrid.StartAsync();

        Assert.True(ok, err);
        Assert.True(serviceClient.RefreshCallCount >= 1);
        Assert.True(hybrid.IsDelegatingToService);
        Assert.Equal(BypassEngineState.Stopped, localBypass.GetStats().State);
        Assert.Contains(serviceClient.SentRequests, r => r.Kind == IpcRequestKind.SetBypassEnabled && r.BoolValue == true);
    }

    [Fact]
    public async Task DashboardViewModel_ToggleEngineFailureNavigatesAwayWithActiveTelemetry_DoesNotCrash()
    {
        using var settings = new SettingsService(new MemorySettingsStore(), NullLogger<SettingsService>.Instance);
        using var telemetry = new NetworkTelemetryService();
        telemetry.ConfigureTargets(primaryAdapterId: null, preferredPingHost: "1.1.1.1");

        var firstSampleReceived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        telemetry.SampleReceived += (_, _) => firstSampleReceived.TrySetResult();

        var nav = new NavigationService();
        var failingDns = new FailingDnsEngine();
        DashboardViewModel? dashboard = null;

        var factory = new DelegatePageFactory(key =>
        {
            if (key == PageKeys.Dashboard)
            {
                dashboard = new DashboardViewModel(
                    new StubNetworkInfoService(),
                    failingDns,
                    nav,
                    NullLogger<DashboardViewModel>.Instance,
                    settings: settings,
                    telemetry: telemetry);
                return dashboard;
            }

            return new DummyPage(key);
        });

        var shell = new ShellViewModel(factory, settings, nav, NullLogger<ShellViewModel>.Instance);
        Assert.NotNull(dashboard);

        dashboard!.SetLiveTelemetryActive(true);
        await Task.WhenAny(firstSampleReceived.Task, Task.Delay(3000));
        await Task.Delay(50);

        // ToggleEngine fails -> navigates to DnsManager -> triggers DashboardViewModel.OnNavigatedFrom() -> telemetry.Pause().
        await dashboard.ToggleEngineCommand.ExecuteAsync(null);

        Assert.Equal(PageKeys.DnsManager, shell.CurrentPageKey);
        Assert.False(telemetry.IsActive);
        shell.StopTimers();
    }

    private sealed class TrackingExternalBackupWindowsDns : IWindowsDnsManager
    {
        public int RestoreCallCount { get; private set; }

        public bool HasActiveBackup() => true;

        public AdapterDnsBackupDocument? ReadBackup() => null;

        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
            string? targetAdapterId,
            string ipv4Loopback,
            string? ipv6Loopback,
            Func<CancellationToken, Task<bool>> connectivityProbe,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));

        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(
            string? targetAdapterId = null,
            CancellationToken cancellationToken = default)
        {
            RestoreCallCount++;
            return Task.FromResult(new WindowsDnsOperationResult(true));
        }

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class TrackingExternalBackupWindowsProxy : IWindowsProxyManager
    {
        public bool CanModifyCurrentUserProxy => true;
        public int RestoreCallCount { get; private set; }

        public bool HasActiveBackup() => true;

        public WindowsProxyBackup? ReadBackup() => null;

        public Task<WindowsProxyOperationResult> ApplyPacProxyAsync(string pacUrl, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsProxyOperationResult(true));

        public Task<WindowsProxyOperationResult> ApplyManualProxyAsync(string proxyServer, string? bypassList, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsProxyOperationResult(true));

        public Task<WindowsProxyOperationResult> RestoreOriginalProxyAsync(CancellationToken cancellationToken = default)
        {
            RestoreCallCount++;
            return Task.FromResult(new WindowsProxyOperationResult(true));
        }

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    [Fact]
    public async Task HybridProxies_DisposeAsyncWhenLocalIdle_DoesNotWipeServiceOwnedWindowsDnsOrProxy()
    {
        var paths = new AppPaths(Path.Combine(_tempRoot, "dispose-idle"));
        paths.EnsureCreated();
        using var settings = new SettingsService(new MemorySettingsStore(), NullLogger<SettingsService>.Instance);
        var trackingDns = new TrackingExternalBackupWindowsDns();
        var trackingProxy = new TrackingExternalBackupWindowsProxy();
        await using var dnsCrypt = new DnsCryptProxyManager(paths, NullLogger<DnsCryptProxyManager>.Instance);

        var localDns = new DnsEngineService(settings, dnsCrypt, trackingDns, NullLogger<DnsEngineService>.Instance);
        var localBypass = new BypassEngineService(settings, trackingProxy, localDns, NullLogger<BypassEngineService>.Instance);
        var serviceClient = new LateStartingServiceClient();
        serviceClient.BringServiceOnline(dnsRunning: true, bypassRunning: true);
        await serviceClient.RefreshStatusAsync();

        var hybridDns = new HybridDnsEngineProxy(localDns, serviceClient, settings, NullLogger<HybridDnsEngineProxy>.Instance);
        var hybridBypass = new HybridBypassEngineProxy(localBypass, serviceClient, trackingProxy, settings, NullLogger<HybridBypassEngineProxy>.Instance);

        // Simulate UI exiting cleanly while JustCryptDnsService continues running in the background.
        await hybridBypass.DisposeAsync();
        await hybridDns.DisposeAsync();

        Assert.Equal(0, trackingDns.RestoreCallCount);
        Assert.Equal(0, trackingProxy.RestoreCallCount);
    }

    [Fact]
    public void DashboardViewModel_FormatTrafficWarning_ShowsActualListenIpForAdapterNotConfigured()
    {
        var warning = DashboardViewModel.FormatTrafficWarning(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Running,
            ActiveResolverId = BuiltInResolvers.DefaultResolverId,
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.2:53",
            BoundPort = 53,
            TrafficStatus = SystemTrafficStatus.AdapterNotConfigured,
        });

        Assert.NotNull(warning);
        Assert.Contains("127.0.0.2", warning!, StringComparison.Ordinal);
        Assert.DoesNotContain("127.0.0.1", warning!, StringComparison.Ordinal);
    }
}
