using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
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
    private readonly INetworkInfoService _network;
    private readonly IDnsEngine _dnsEngine;
    private readonly INavigationService _navigation;
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly IDnsFilteringService? _filtering;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _cts;

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
    [ObservableProperty] private bool _isFilteringActive;
    [ObservableProperty] private SystemTrafficStatus _trafficStatus = SystemTrafficStatus.Stopped;
    [ObservableProperty] private string? _trafficWarningBanner;
    [ObservableProperty] private string? _testProxyFeedback;
    [ObservableProperty] private string? _engineError;

    public DashboardViewModel(
        INetworkInfoService network,
        IDnsEngine dnsEngine,
        INavigationService navigation,
        ILogger<DashboardViewModel> logger,
        IDnsFilteringService? filtering = null)
        : base("Nav_Dashboard", "Page_Dashboard_Subtitle")
    {
        _network = network;
        _dnsEngine = dnsEngine;
        _navigation = navigation;
        _logger = logger;
        _filtering = filtering;
        _ui = SynchronizationContext.Current;
        IsFilteringActive = _filtering?.IsFilteringEnabled ?? false;
        ApplyEngineStats(dnsEngine.GetStats());
    }

    public bool IsEngineAvailable => true;

    public bool IsEngineRunning => EngineState is DnsEngineState.Running or DnsEngineState.Degraded;

    public override void OnNavigatedTo()
    {
        _cts = new CancellationTokenSource();
        _network.NetworkChanged += OnNetworkChanged;
        _dnsEngine.StateChanged += OnEngineStateChanged;
        ApplyEngineStats(_dnsEngine.GetStats());
        _ = RefreshCommand.ExecuteAsync(null);
    }

    public override void OnNavigatedFrom()
    {
        _network.NetworkChanged -= OnNetworkChanged;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
        _cts?.Cancel();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _network.NetworkChanged -= OnNetworkChanged;
            _dnsEngine.StateChanged -= OnEngineStateChanged;
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }

        base.Dispose(disposing);
    }

    partial void OnEngineStateChanged(DnsEngineState value) => OnPropertyChanged(nameof(IsEngineRunning));

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleEngineAsync()
    {
        if (IsEngineRunning)
        {
            await _dnsEngine.StopAsync();
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
            }
        }

        ApplyEngineStats(_dnsEngine.GetStats());
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task TestLocalProxyAsync()
    {
        TestProxyFeedback = null;
        var (_, _, summary) = await _dnsEngine.TestLocalProxyAsync();
        TestProxyFeedback = summary;
        ApplyEngineStats(_dnsEngine.GetStats());
    }

    [RelayCommand]
    private void OpenDnsManager() => _navigation.Navigate(PageKeys.DnsManager);

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
    }

    internal void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveProtocol = stats.ActiveProtocol;
        ActiveResolverName = stats.ActiveResolverName;
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
        TrafficStatus = stats.TrafficStatus;
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
}
