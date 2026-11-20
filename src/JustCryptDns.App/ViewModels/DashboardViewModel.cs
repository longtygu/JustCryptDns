using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Controls;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public enum IpFamilyStatus
{
    None,
    LinkLocal,
    Configured,
    Global,
}

/// <summary>
/// Dashboard displaying verified DNS engine state, real query metrics, and local network adapter status.
/// </summary>
public sealed partial class DashboardViewModel : PageViewModel
{
    private const int MaxDashboardQueries = 60;

    private readonly INetworkInfoService _network;
    private readonly IDnsEngine _dnsEngine;
    private readonly INavigationService _navigation;
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly IDnsFilteringService? _filtering;
    private readonly ISettingsService? _settings;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly INetworkTelemetryService? _telemetry;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly INetworkDiagnosticsService? _diagnostics;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _cts;
    private string _activeResolverId = string.Empty;
    private long _lastBypassUiTick;
    private BypassRuntimeStats? _pendingBypassStats;
    private int _bypassFlushScheduled;

    [ObservableProperty] private NetworkAdapterInfo? _primaryAdapter;
    [ObservableProperty] private LocalConnectivity _connectivity = LocalConnectivity.Offline;
    [ObservableProperty] private IpFamilyStatus _ipv4Status;
    [ObservableProperty] private IpFamilyStatus _ipv6Status;
    [ObservableProperty] private DateTimeOffset? _lastUpdated;
    [ObservableProperty] private bool _hasSnapshot;

    [ObservableProperty] private DnsEngineState _engineState = DnsEngineState.Stopped;
    [ObservableProperty] private DnsProtocol _activeProtocol = DnsProtocol.DnsOverHttps;
    [ObservableProperty] private string _activeResolverName = string.Empty;
    [ObservableProperty] private string _listenEndpoint = "127.0.0.1:53";
    [ObservableProperty] private string _latencyDisplay = "—";
    [ObservableProperty] private string _totalQueriesDisplay = "—";
    [ObservableProperty] private string _blockedQueriesDisplay = "—";
    [ObservableProperty] private string _cacheHitDisplay = "—";
    [ObservableProperty] private double _latencyMsValue;
    [ObservableProperty] private double _latencyMaxScale = 200;
    [ObservableProperty] private string _latencyScaleLabel = "200ms";
    [ObservableProperty] private GaugeSeverity _latencySeverity = GaugeSeverity.Neutral;
    [ObservableProperty] private double _totalQueriesValue;
    [ObservableProperty] private double _totalQueriesMaxScale = 100;
    [ObservableProperty] private string _totalQueriesScaleLabel = "100";
    [ObservableProperty] private double _blockedQueriesValue;
    [ObservableProperty] private double _blockedQueriesMaxScale = 50;
    [ObservableProperty] private string _blockedQueriesScaleLabel = "50";
    [ObservableProperty] private double _cacheHitPercentValue;
    [ObservableProperty] private GaugeSeverity _cacheHitSeverity = GaugeSeverity.Neutral;
    [ObservableProperty] private string _pingDisplay = "—";
    [ObservableProperty] private string _downloadSpeedDisplay = "0 Kbps";
    [ObservableProperty] private string _uploadSpeedDisplay = "0 Kbps";
    [ObservableProperty] private double _networkStabilityPercentValue;
    [ObservableProperty] private string _networkStabilityDisplay = "—";
    [ObservableProperty] private string _packetLossSummaryDisplay = "—";
    [ObservableProperty] private GaugeSeverity _stabilitySeverity = GaugeSeverity.Neutral;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsTelemetryActive))]
    private bool _isTelemetryPaused;

    [ObservableProperty] private bool _isQueryLogPaused;
    [ObservableProperty] private StatusPulseStyle _statusPulseStyle = StatusPulseStyle.Breathing;
    [ObservableProperty] private bool _isFilteringActive;
    [ObservableProperty] private SystemTrafficStatus _trafficStatus = SystemTrafficStatus.Stopped;
    [ObservableProperty] private string? _trafficWarningBanner;
    [ObservableProperty] private string? _suggestedLoopbackIp;
    [ObservableProperty] private string? _conflictingServiceName;
    [ObservableProperty] private string? _testProxyFeedback;
    [ObservableProperty] private string? _engineError;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsBypassRunning))]
    [NotifyPropertyChangedFor(nameof(ProtectionStatusLocKey))]
    private BypassEngineState _bypassState = BypassEngineState.Stopped;

    [ObservableProperty] private string _bypassEndpoint = "127.0.0.1:10808";
    [ObservableProperty] private WindowsProxyMode _bypassWindowsProxyMode = WindowsProxyMode.AutoPac;
    [ObservableProperty] private BypassCoverageMode _bypassCoverageMode = BypassCoverageMode.AllWebsitesSmart;
    [ObservableProperty] private bool _bypassWindowsApplied;
    [ObservableProperty] private string _bypassDpiCountDisplay = "—";
    [ObservableProperty] private string _bypassTunnelCountDisplay = "—";
    [ObservableProperty] private string _bypassLearnedCountDisplay = "0";

    public DashboardViewModel(
        INetworkInfoService network,
        IDnsEngine dnsEngine,
        INavigationService navigation,
        ILogger<DashboardViewModel> logger,
        IDnsFilteringService? filtering = null,
        ISettingsService? settings = null,
        IBypassEngineService? bypassEngine = null,
        INetworkTelemetryService? telemetry = null,
        IResolverLibraryService? resolverLibrary = null,
        INetworkDiagnosticsService? diagnostics = null)
        : base("Nav_Dashboard", "Page_Dashboard_Subtitle")
    {
        _network = network;
        _dnsEngine = dnsEngine;
        _navigation = navigation;
        _logger = logger;
        _filtering = filtering;
        _settings = settings;
        _bypassEngine = bypassEngine;
        _telemetry = telemetry;
        _resolverLibrary = resolverLibrary;
        _diagnostics = diagnostics;
        _ui = SynchronizationContext.Current;
        StatusPulseStyle = _settings?.Current.Appearance.StatusPulseStyle ?? StatusPulseStyle.Breathing;
        IsFilteringActive = _filtering?.IsFilteringEnabled ?? false;
        PacketLossSummaryDisplay = LocalizationManager.Instance["Dash_Stability_Measuring"];
        ApplyEngineStats(dnsEngine.GetStats());
        if (_bypassEngine is not null)
        {
            ApplyBypassStats(_bypassEngine.GetStats());
        }

        RefreshRecentQueries();
    }

    public event EventHandler<NetworkTelemetrySample>? TelemetrySampleArrived;

    public ObservableCollection<LiveQueryMonitorEntry> RecentQueries { get; } = [];

    public bool HasRecentQueries => RecentQueries.Count > 0;

    public bool IsTelemetryActive => !IsTelemetryPaused;

    public bool IsEngineAvailable => true;

    public bool IsEngineRunning => EngineState is DnsEngineState.Running or DnsEngineState.Degraded;

    public bool IsBypassRunning => BypassState is BypassEngineState.Running or BypassEngineState.Degraded;

    public string ProtectionStatusLocKey => EngineState switch
    {
        DnsEngineState.Stopped => "Dash_Status_Stopped",
        DnsEngineState.Running => IsBypassRunning ? "Dash_Status_RunningBypassOn" : "Dash_Status_RunningBypassOff",
        DnsEngineState.Degraded => IsBypassRunning ? "Dash_Status_DegradedBypassOn" : "Dash_Status_DegradedBypassOff",
        DnsEngineState.Starting => "EngineState_Starting",
        DnsEngineState.Stopping => "EngineState_Stopping",
        _ => "EngineState_NotImplemented",
    };

    public IReadOnlyList<NetworkTelemetrySample> GetInitialTelemetrySamples() => _telemetry?.GetRecentSamples() ?? [];

    public void SetLiveTelemetryActive(bool active)
    {
        IsTelemetryPaused = !active;
        if (_telemetry is not null)
        {
            if (active)
            {
                UpdateTelemetryTargets();
                _telemetry.Resume();
            }
            else
            {
                _telemetry.Pause();
            }
        }

        if (active && !IsQueryLogPaused && _diagnostics is not null)
        {
            if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
            {
                dispatcher.BeginInvoke(RefreshRecentQueries);
            }
            else
            {
                RefreshRecentQueries();
            }
        }
    }

    public override void OnNavigatedTo()
    {
        _cts = new CancellationTokenSource();
        _network.NetworkChanged += OnNetworkChanged;
        _dnsEngine.StateChanged += OnEngineStateChanged;
        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged += OnBypassStateChanged;
            ApplyBypassStats(_bypassEngine.GetStats());
        }

        if (_settings is not null)
        {
            _settings.Changed -= OnSettingsChanged;
            _settings.Changed += OnSettingsChanged;
            StatusPulseStyle = _settings.Current.Appearance.StatusPulseStyle;
        }

        if (_telemetry is not null)
        {
            _telemetry.SampleReceived -= OnTelemetrySampleReceived;
            _telemetry.SampleReceived += OnTelemetrySampleReceived;
            var recent = _telemetry.GetRecentSamples();
            if (recent.Count > 0)
            {
                ApplyTelemetrySample(recent[^1]);
            }
        }

        if (_diagnostics is not null)
        {
            _diagnostics.QueryObserved -= OnQueryObserved;
            _diagnostics.QueryObserved += OnQueryObserved;
            RefreshRecentQueries();
        }

        ApplyEngineStats(_dnsEngine.GetStats());
        _ = RefreshCommand.ExecuteAsync(null);
    }

    public override void OnNavigatedFrom()
    {
        _network.NetworkChanged -= OnNetworkChanged;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged -= OnBypassStateChanged;
        }

        if (_settings is not null)
        {
            _settings.Changed -= OnSettingsChanged;
        }

        if (_telemetry is not null)
        {
            _telemetry.SampleReceived -= OnTelemetrySampleReceived;
            _telemetry.Pause();
        }

        if (_diagnostics is not null)
        {
            _diagnostics.QueryObserved -= OnQueryObserved;
        }

        _cts?.Cancel();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _network.NetworkChanged -= OnNetworkChanged;
            _dnsEngine.StateChanged -= OnEngineStateChanged;
            if (_bypassEngine is not null)
            {
                _bypassEngine.StateChanged -= OnBypassStateChanged;
            }

            if (_settings is not null)
            {
                _settings.Changed -= OnSettingsChanged;
            }

            if (_telemetry is not null)
            {
                _telemetry.SampleReceived -= OnTelemetrySampleReceived;
                _telemetry.Pause();
            }

            if (_diagnostics is not null)
            {
                _diagnostics.QueryObserved -= OnQueryObserved;
            }

            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }

        base.Dispose(disposing);
    }

    partial void OnEngineStateChanged(DnsEngineState value)
    {
        OnPropertyChanged(nameof(IsEngineRunning));
        OnPropertyChanged(nameof(ProtectionStatusLocKey));
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleEngineAsync()
    {
        if (IsEngineRunning)
        {
            await _dnsEngine.StopAsync();
            if (_bypassEngine is not null && IsBypassRunning)
            {
                await _bypassEngine.StopAsync();
            }
        }
        else
        {
            var (ok, _) = await _dnsEngine.StartAsync();
            if (!ok)
            {
                _navigation.Navigate(PageKeys.DnsManager);
            }
            else
            {
                _ = _dnsEngine.ProbeActiveResolverAsync();
                if (_bypassEngine is not null
                    && (_settings?.Current.Bypass.IsBypassEnabled ?? true)
                    && (_settings?.Current.Bypass.AutoStartWithDnsEngine ?? true)
                    && !IsBypassRunning)
                {
                    var (_, bypassWarn) = await _bypassEngine.StartAsync();
                    if (!string.IsNullOrWhiteSpace(bypassWarn))
                    {
                        EngineError ??= bypassWarn;
                    }
                }
            }
        }

        ApplyEngineStats(_dnsEngine.GetStats());
        if (_bypassEngine is not null)
        {
            ApplyBypassStats(_bypassEngine.GetStats());
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleBypassAsync()
    {
        if (_bypassEngine is null)
        {
            return;
        }

        if (IsBypassRunning)
        {
            await _bypassEngine.StopAsync();
        }
        else
        {
            var (ok, err) = await _bypassEngine.StartAsync();
            if (!ok && !string.IsNullOrWhiteSpace(err))
            {
                EngineError = err;
            }
        }

        ApplyBypassStats(_bypassEngine.GetStats());
    }

    [RelayCommand]
    private void OpenBypass() => _navigation.Navigate(PageKeys.Bypass);

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task TestLocalProxyAsync()
    {
        TestProxyFeedback = null;
        var (_, _, summary) = await _dnsEngine.TestLocalProxyAsync();
        TestProxyFeedback = summary;
        ApplyEngineStats(_dnsEngine.GetStats());
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task UseAlternateLoopbackPort53Async()
    {
        if (_settings is null || string.IsNullOrWhiteSpace(SuggestedLoopbackIp))
        {
            return;
        }

        var targetIp = SuggestedLoopbackIp;
        EngineError = null;
        TestProxyFeedback = null;
        await _settings.UpdateAsync(s =>
        {
            s.Dns.ListenAddress = targetIp;
            s.Dns.ListenPort = 53;
            s.Dns.EnableIpv6 = false;
            s.Dns.ConfigureWindowsAdapter = true;
        });

        var (ok, err) = await _dnsEngine.RestartAsync();
        if (ok)
        {
            _ = _dnsEngine.ProbeActiveResolverAsync();
            TestProxyFeedback = Localization.LocalizationManager.Instance.Format("TrafficFix_AlternateLoopbackSuccess", targetIp);
        }
        else
        {
            EngineError = err;
        }

        ApplyEngineStats(_dnsEngine.GetStats());
        await RefreshAsync();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task StopConflictingServiceAndUsePort53Async()
    {
        if (_settings is null || string.IsNullOrWhiteSpace(ConflictingServiceName))
        {
            return;
        }

        EngineError = null;
        TestProxyFeedback = null;
        var svcName = ConflictingServiceName;
        var (stopped, stopErr) = await PortConflictDetector.StopConflictingServiceAsync(svcName);
        if (!stopped)
        {
            EngineError = stopErr;
            return;
        }

        await _settings.UpdateAsync(s =>
        {
            s.Dns.ListenAddress = DnsSettings.DefaultListenAddress;
            s.Dns.ListenPort = 53;
        });

        var (ok, err) = await _dnsEngine.RestartAsync();
        if (ok)
        {
            _ = _dnsEngine.ProbeActiveResolverAsync();
            TestProxyFeedback = Localization.LocalizationManager.Instance.Format("TrafficFix_ServiceStoppedSuccess", svcName);
        }
        else
        {
            EngineError = err;
        }

        ApplyEngineStats(_dnsEngine.GetStats());
        await RefreshAsync();
    }

    [RelayCommand]
    private void OpenDnsManager() => _navigation.Navigate(PageKeys.DnsManager);

    [RelayCommand]
    private void ToggleQueryLogPause() => IsQueryLogPaused = !IsQueryLogPaused;

    [RelayCommand]
    private void ClearRecentQueries()
    {
        _diagnostics?.ClearMonitorEntries();
        RecentQueries.Clear();
        OnPropertyChanged(nameof(HasRecentQueries));
    }

    [RelayCommand]
    private void OpenMonitor() => _navigation.Navigate(PageKeys.Monitor);

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RefreshAsync()
    {
        var token = _cts?.Token ?? CancellationToken.None;
        try
        {
            var snapshot = await Task.Run(_network.GetSnapshot, token);
            if (token.IsCancellationRequested)
            {
                return;
            }

            Apply(snapshot);
        }
        catch (OperationCanceledException)
        {
            // Page was left.
        }
        catch (Exception ex) when (ex is System.Net.NetworkInformation.NetworkInformationException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Failed to read network adapters.");
        }
    }

    internal void Apply(NetworkSnapshot snapshot)
    {
        PrimaryAdapter = snapshot.PrimaryAdapter;
        Connectivity = snapshot.Connectivity;
        Ipv4Status = EvaluateIPv4(snapshot.PrimaryAdapter);
        Ipv6Status = EvaluateIPv6(snapshot.PrimaryAdapter);
        LastUpdated = snapshot.CapturedAt;
        HasSnapshot = true;
        UpdateTelemetryTargets();
    }

    internal void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveProtocol = stats.ActiveProtocol;
        ActiveResolverName = stats.ActiveResolverName;
        _activeResolverId = stats.ActiveResolverId;
        ListenEndpoint = stats.ListenEndpoint;
        LatencyDisplay = stats.LastLatencyMs is { } ms ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms") : "—";
        TotalQueriesDisplay = stats.TotalQueries > 0 || IsEngineRunning
            ? stats.TotalQueries.ToString("N0", CultureInfo.CurrentCulture)
            : "—";
        BlockedQueriesDisplay = stats.BlockedQueries > 0 || IsEngineRunning
            ? stats.BlockedQueries.ToString("N0", CultureInfo.CurrentCulture)
            : "—";
        CacheHitDisplay = stats.TotalQueries > 0 || IsEngineRunning
            ? string.Create(CultureInfo.InvariantCulture, $"{stats.CacheHitRatioPercent:0.#}%")
            : "—";

        LatencyMsValue = stats.LastLatencyMs ?? 0;
        LatencyMaxScale = stats.LastLatencyMs is > 200 ? GaugeMath.ComputeAutoScaleMax(stats.LastLatencyMs.Value, 200) : 200;
        LatencyScaleLabel = string.Create(CultureInfo.InvariantCulture, $"{LatencyMaxScale:0}ms");
        LatencySeverity = GaugeMath.EvaluateLatencySeverity(stats.LastLatencyMs);

        TotalQueriesValue = stats.TotalQueries;
        TotalQueriesMaxScale = GaugeMath.ComputeAutoScaleMax(stats.TotalQueries, 100);
        TotalQueriesScaleLabel = GaugeMath.FormatCompactScaleLabel(TotalQueriesMaxScale);

        BlockedQueriesValue = stats.BlockedQueries;
        BlockedQueriesMaxScale = GaugeMath.ComputeAutoScaleMax(stats.BlockedQueries, 50);
        BlockedQueriesScaleLabel = GaugeMath.FormatCompactScaleLabel(BlockedQueriesMaxScale);

        CacheHitPercentValue = stats.TotalQueries > 0 || IsEngineRunning
            ? Math.Clamp(stats.CacheHitRatioPercent, 0.0, 100.0)
            : 0.0;
        CacheHitSeverity = GaugeMath.EvaluateCacheHitSeverity(stats.CacheHitRatioPercent, stats.TotalQueries);

        TrafficStatus = stats.TrafficStatus;
        SuggestedLoopbackIp = stats.SuggestedLoopbackIp;
        ConflictingServiceName = stats.Port53ServiceName;
        TrafficWarningBanner = stats.TrafficStatus switch
        {
            SystemTrafficStatus.NonStandardPort => Localization.LocalizationManager.Instance.Format(
                "TrafficWarn_NonStandardPort",
                stats.BoundPort,
                stats.Port53OwnerDescription ?? Localization.LocalizationManager.Instance["Common_Unknown"]),
            SystemTrafficStatus.AdapterNotConfigured => Localization.LocalizationManager.Instance["TrafficWarn_AdapterNotConfigured"],
            _ => null,
        };
        EngineError = stats.LastError;
        UpdateTelemetryTargets();
    }

    internal static IpFamilyStatus EvaluateIPv4(NetworkAdapterInfo? adapter)
    {
        if (adapter is null || adapter.IPv4Addresses.Count == 0)
        {
            return IpFamilyStatus.None;
        }

        // 169.254.0.0/16 = APIPA (no DHCP lease).
        return adapter.IPv4Addresses.All(a => a.GetAddressBytes() is [169, 254, ..])
            ? IpFamilyStatus.LinkLocal
            : IpFamilyStatus.Configured;
    }

    internal static IpFamilyStatus EvaluateIPv6(NetworkAdapterInfo? adapter)
    {
        if (adapter is null || adapter.IPv6Addresses.Count == 0)
        {
            return IpFamilyStatus.None;
        }

        return adapter.HasGlobalIPv6 ? IpFamilyStatus.Global : IpFamilyStatus.LinkLocal;
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        if (_ui is null)
        {
            return;
        }

        _ui.Post(_ => _ = RefreshCommand.ExecuteAsync(null), null);
    }

    private void OnEngineStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyEngineStats(stats));
        }
        else
        {
            ApplyEngineStats(stats);
        }
    }

    internal void ApplyBypassStats(BypassRuntimeStats stats)
    {
        BypassState = stats.State;
        BypassEndpoint = stats.ProxyEndpoint;
        BypassWindowsProxyMode = stats.ActiveWindowsProxyMode;
        BypassCoverageMode = stats.CoverageMode;
        BypassWindowsApplied = stats.WindowsProxyApplied;
        BypassDpiCountDisplay = stats.DpiBypassedConnections > 0 || IsBypassRunning
            ? stats.DpiBypassedConnections.ToString("N0", CultureInfo.CurrentCulture)
            : "—";
        BypassTunnelCountDisplay = stats.TunneledConnections > 0 || IsBypassRunning
            ? stats.TunneledConnections.ToString("N0", CultureInfo.CurrentCulture)
            : "—";
        BypassLearnedCountDisplay = stats.LearnedHostCount.ToString("N0", CultureInfo.CurrentCulture);
    }

    private void OnBypassStateChanged(object? sender, BypassRuntimeStats stats)
    {
        var now = Environment.TickCount64;
        if (stats.State != BypassState || now - Interlocked.Read(ref _lastBypassUiTick) >= 250)
        {
            Interlocked.Exchange(ref _lastBypassUiTick, now);
            _pendingBypassStats = null;
            DispatchBypassStats(stats);
            return;
        }

        _pendingBypassStats = stats;
        if (Interlocked.CompareExchange(ref _bypassFlushScheduled, 1, 0) == 0)
        {
            _ = FlushPendingBypassStatsAsync();
        }
    }

    private async Task FlushPendingBypassStatsAsync()
    {
        await Task.Delay(250).ConfigureAwait(false);
        Interlocked.Exchange(ref _bypassFlushScheduled, 0);
        if (_pendingBypassStats is { } latest)
        {
            Interlocked.Exchange(ref _lastBypassUiTick, Environment.TickCount64);
            _pendingBypassStats = null;
            DispatchBypassStats(latest);
        }
    }

    private void DispatchBypassStats(BypassRuntimeStats stats)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyBypassStats(stats));
        }
        else
        {
            ApplyBypassStats(stats);
        }
    }

    internal void ApplyTelemetrySample(NetworkTelemetrySample sample)
    {
        PingDisplay = sample.PingMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
        DownloadSpeedDisplay = NetworkTelemetryService.FormatThroughput(sample.DownloadBytesPerSecond);
        UploadSpeedDisplay = NetworkTelemetryService.FormatThroughput(sample.UploadBytesPerSecond);

        NetworkStabilityPercentValue = sample.StabilityPercent ?? 0.0;
        NetworkStabilityDisplay = sample.StabilityPercent is { } stab && sample.TotalPingProbes > 0
            ? string.Create(CultureInfo.InvariantCulture, $"{stab:0.#}%")
            : "—";
        PacketLossSummaryDisplay = sample.PacketLossPercent is { } loss && sample.TotalPingProbes > 0
            ? LocalizationManager.Instance.Format("Dash_Stability_LossFormat", Math.Round(loss, 1))
            : LocalizationManager.Instance["Dash_Stability_Measuring"];
        StabilitySeverity = GaugeMath.EvaluateStabilitySeverity(
            sample.StabilityPercent,
            sample.PacketLossPercent,
            sample.TotalPingProbes);

        TelemetrySampleArrived?.Invoke(this, sample);
    }

    internal void RefreshRecentQueries()
    {
        if (_diagnostics is null)
        {
            return;
        }

        RecentQueries.Clear();
        foreach (var entry in _diagnostics.GetMonitorEntries().Take(MaxDashboardQueries))
        {
            RecentQueries.Add(entry);
        }

        OnPropertyChanged(nameof(HasRecentQueries));
    }

    private void OnQueryObserved(object? sender, LiveQueryMonitorEntry entry)
    {
        if (IsTelemetryPaused || IsQueryLogPaused)
        {
            return;
        }

        void Insert()
        {
            RecentQueries.Insert(0, entry);
            while (RecentQueries.Count > MaxDashboardQueries)
            {
                RecentQueries.RemoveAt(RecentQueries.Count - 1);
            }

            OnPropertyChanged(nameof(HasRecentQueries));
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Insert);
        }
        else
        {
            Insert();
        }
    }

    private void OnTelemetrySampleReceived(object? sender, NetworkTelemetrySample sample)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyTelemetrySample(sample));
        }
        else
        {
            ApplyTelemetrySample(sample);
        }
    }

    private void UpdateTelemetryTargets()
    {
        if (_telemetry is null)
        {
            return;
        }

        string? preferredPingHost = null;
        if (!string.IsNullOrWhiteSpace(_activeResolverId) && _resolverLibrary is not null)
        {
            preferredPingHost = _resolverLibrary.GetByIdOrDefault(_activeResolverId).PrimaryIp;
        }

        _telemetry.ConfigureTargets(PrimaryAdapter?.Id, preferredPingHost);
    }

    private void OnSettingsChanged(object? sender, AppSettings settings)
    {
        void Sync() => StatusPulseStyle = settings.Appearance.StatusPulseStyle;
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }
}
