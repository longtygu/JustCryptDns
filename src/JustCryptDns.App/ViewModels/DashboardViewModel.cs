using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.Core.Interfaces;
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
/// Dashboard. In Phase 1 only local adapter information is real; engine metrics are explicitly reported as unavailable.
/// </summary>
public sealed partial class DashboardViewModel : PageViewModel
{
    private readonly INetworkInfoService _network;
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly SynchronizationContext? _ui;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private NetworkAdapterInfo? _primaryAdapter;

    [ObservableProperty]
    private LocalConnectivity _connectivity = LocalConnectivity.Offline;

    [ObservableProperty]
    private IpFamilyStatus _ipv4Status;

    [ObservableProperty]
    private IpFamilyStatus _ipv6Status;

    [ObservableProperty]
    private DateTimeOffset? _lastUpdated;

    [ObservableProperty]
    private bool _hasSnapshot;

    public DashboardViewModel(INetworkInfoService network, ILogger<DashboardViewModel> logger)
        : base("Nav_Dashboard", "Page_Dashboard_Subtitle")
    {
        _network = network;
        _logger = logger;
        _ui = SynchronizationContext.Current;
    }

    /// <summary>The DNS engine is implemented in Phase 4; until then it is reported as unavailable.</summary>
    public bool IsEngineAvailable => false;

    public override void OnNavigatedTo()
    {
        _cts = new CancellationTokenSource();
        _network.NetworkChanged += OnNetworkChanged;
        _ = RefreshCommand.ExecuteAsync(null);
    }

    public override void OnNavigatedFrom()
    {
        _network.NetworkChanged -= OnNetworkChanged;
        _cts?.Cancel();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _network.NetworkChanged -= OnNetworkChanged;
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
        }

        base.Dispose(disposing);
    }

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
}
