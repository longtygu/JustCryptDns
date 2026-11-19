using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed partial class DiagnosticsViewModel : PageViewModel
{
    private readonly INetworkDiagnosticsService _diagnostics;
    private readonly IDnsFailoverService _failover;
    private readonly INetworkInfoService _network;
    private readonly IDnsEngine _dnsEngine;

    // Local diagnostics properties
    [ObservableProperty] private string _adapterName = "—";
    [ObservableProperty] private string _localIp = "—";
    [ObservableProperty] private string _gateway = "—";
    [ObservableProperty] private string _activeDnsServers = "—";
    [ObservableProperty] private string _ipv4StatusText = "—";
    [ObservableProperty] private string _ipv6StatusText = "—";
    [ObservableProperty] private LocalConnectivity _localConnectivity = LocalConnectivity.Offline;
    [ObservableProperty] private DnsEngineState _engineState = DnsEngineState.Stopped;
    [ObservableProperty] private string _activeResolverName = "—";
    [ObservableProperty] private DnsProtocol _activeProtocol = DnsProtocol.DnsOverHttps;
    [ObservableProperty] private string _lastLatencyText = "—";

    // External test inputs & outputs
    [ObservableProperty] private string _lookupDomain = "cloudflare.com";
    [ObservableProperty] private string _selectedRecordType = "A";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _lookupSummary;
    [ObservableProperty] private string? _externalTestResult;
    [ObservableProperty] private string? _restrictionSummary;
    [ObservableProperty] private string? _errorMessage;

    public DiagnosticsViewModel(
        INetworkDiagnosticsService diagnostics,
        IDnsFailoverService failover,
        INetworkInfoService network,
        IDnsEngine dnsEngine)
        : base("Nav_Diagnostics", "Page_Diagnostics_Subtitle")
    {
        _diagnostics = diagnostics;
        _failover = failover;
        _network = network;
        _dnsEngine = dnsEngine;

        RefreshLocalSnapshot();
    }

    public IReadOnlyList<string> RecordTypes { get; } = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"];

    public ObservableCollection<DnsLookupRecordItem> LookupRecords { get; } = [];

    public ObservableCollection<ResolverComparisonEntry> ComparisonResults { get; } = [];

    public override void OnNavigatedTo()
    {
        _dnsEngine.StateChanged += OnEngineStateChanged;
        RefreshLocalSnapshot();
    }

    public override void OnNavigatedFrom()
    {
        _dnsEngine.StateChanged -= OnEngineStateChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _dnsEngine.StateChanged -= OnEngineStateChanged;
        }

        base.Dispose(disposing);
    }

    [RelayCommand]
    private void RefreshLocalSnapshot()
    {
        var snap = _network.GetSnapshot();
        LocalConnectivity = snap.Connectivity;
        var adapter = snap.PrimaryAdapter;
        if (adapter is not null)
        {
            AdapterName = adapter.Name;
            LocalIp = adapter.IPv4Addresses.Count > 0 ? string.Join(", ", adapter.IPv4Addresses) : "—";
            Gateway = adapter.Gateways.Count > 0 ? string.Join(", ", adapter.Gateways) : "—";
            ActiveDnsServers = adapter.DnsServers.Count > 0 ? string.Join(", ", adapter.DnsServers) : "—";
            Ipv4StatusText = adapter.IPv4Addresses.Count > 0 ? "Configured" : "None";
            Ipv6StatusText = adapter.HasGlobalIPv6 ? "Global" : adapter.IPv6Addresses.Count > 0 ? "Link-local" : "None";
        }
        else
        {
            AdapterName = "—";
            LocalIp = "—";
            Gateway = "—";
            ActiveDnsServers = "—";
            Ipv4StatusText = "None";
            Ipv6StatusText = "None";
        }

        ApplyEngineStats(_dnsEngine.GetStats());
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunLookupAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var report = await _diagnostics.LookupAsync(LookupDomain, SelectedRecordType);
            LookupRecords.Clear();
            foreach (var rec in report.Records)
            {
                LookupRecords.Add(rec);
            }

            if (report.Success)
            {
                LookupSummary = LocalizationManager.Instance.Format(
                    "Diag_Lookup_Summary",
                    report.Domain,
                    report.RecordType,
                    report.ResponseCode,
                    report.LatencyMs,
                    report.ResolverName,
                    report.Records.Count);
            }
            else
            {
                ErrorMessage = report.ErrorMessage;
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDnssecTestAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var report = await _diagnostics.TestDnssecAsync();
            ExternalTestResult = report.Summary;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDohTestAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var (_, _, summary) = await _diagnostics.TestDohConnectivityAsync();
            ExternalTestResult = summary;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDnsCryptTestAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var (_, _, summary) = await _diagnostics.TestDnsCryptConnectivityAsync();
            ExternalTestResult = summary;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunLeakTestAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var report = await _diagnostics.RunDnsLeakTestAsync();
            ExternalTestResult = report.Summary;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunRestrictionScanAsync()
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var report = await _failover.DiagnoseNetworkRestrictionsAsync();
            RestrictionSummary = $"UDP/53={(report.Udp53Reachable ? "OK" : "Blocked")} · TCP/53={(report.Tcp53Reachable ? "OK" : "Blocked")} · DoH/443={(report.Doh443Reachable ? "OK" : "Failed")} · DoT/853={(report.Dot853Reachable ? "OK" : "Failed")} · DNSCrypt={(report.DnsCryptReachable ? "OK" : "Failed")} — {report.Summary}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CompareResolversAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var results = await _diagnostics.CompareResolversAsync(LookupDomain, SelectedRecordType);
            ComparisonResults.Clear();
            foreach (var r in results)
            {
                ComparisonResults.Add(r);
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckPropagationAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        try
        {
            var results = await _diagnostics.CheckPropagationAsync(LookupDomain, SelectedRecordType);
            ComparisonResults.Clear();
            foreach (var r in results)
            {
                ComparisonResults.Add(r);
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveResolverName = stats.ActiveResolverName;
        ActiveProtocol = stats.ActiveProtocol;
        LastLatencyText = stats.LastLatencyMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
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
