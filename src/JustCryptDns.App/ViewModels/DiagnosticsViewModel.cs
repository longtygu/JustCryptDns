using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed record DiagnosticLogEntry(
    DateTimeOffset Timestamp,
    DiagnosticTestCategory Category,
    string CategoryKey,
    DiagnosticStepOutcome Outcome,
    string OutcomeKey,
    string Target,
    string LatencyText,
    string DetailText);

public sealed partial class DiagnosticsViewModel : PageViewModel
{
    private const int MaxScanLogEntries = 300;

    private readonly INetworkDiagnosticsService _diagnostics;
    private readonly IDnsFailoverService _failover;
    private readonly INetworkInfoService _network;
    private readonly IDnsEngine _dnsEngine;
    private readonly DispatcherTimer? _elapsedTimer;
    private CancellationTokenSource? _activeTestCts;
    private DateTimeOffset _testStartedAt;

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
    [ObservableProperty] private DiagnosticTestCategory _activeTestKind = DiagnosticTestCategory.None;
    [ObservableProperty] private bool _hasScanPanel;
    [ObservableProperty] private bool _scanWasCancelled;
    [ObservableProperty] private bool _scanIsIndeterminate;
    [ObservableProperty] private double _scanProgressPercent;
    [ObservableProperty] private string _scanHeaderKey = "Diag_Scan_Header_Idle";
    [ObservableProperty] private string _scanCurrentTarget = "—";
    [ObservableProperty] private string _scanStepCounterText = "0 / 0";
    [ObservableProperty] private string _scanElapsedDisplay = "0.0s";
    [ObservableProperty] private int _scanPassCount;
    [ObservableProperty] private int _scanFailCount;
    [ObservableProperty] private string? _diagnosticLogClipboardText;
    [ObservableProperty] private string? _lookupSummary;
    [ObservableProperty] private string? _externalTestResult;
    [ObservableProperty] private string? _restrictionSummary;
    [ObservableProperty] private string? _browserDohSummary;
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

        if (Application.Current?.Dispatcher is { } dispatcher)
        {
            _elapsedTimer = new DispatcherTimer(DispatcherPriority.Normal, dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(200),
            };
            _elapsedTimer.Tick += (_, _) =>
            {
                if (IsBusy)
                {
                    ScanElapsedDisplay = string.Create(
                        CultureInfo.InvariantCulture,
                        $"{Math.Max(0.0, (DateTimeOffset.Now - _testStartedAt).TotalSeconds):0.0}s");
                }
            };
        }

        RefreshLocalSnapshot();
    }

    public IReadOnlyList<string> RecordTypes { get; } = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"];

    public ObservableCollection<DnsLookupRecordItem> LookupRecords { get; } = [];

    public ObservableCollection<ResolverComparisonEntry> ComparisonResults { get; } = [];

    public ObservableCollection<DiagnosticLogEntry> ScanLogs { get; } = [];

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
            _elapsedTimer?.Stop();
            _activeTestCts?.Cancel();
            _activeTestCts?.Dispose();
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

    [RelayCommand]
    private void CancelTest()
    {
        _activeTestCts?.Cancel();
    }

    [RelayCommand]
    private void ClearScanLog()
    {
        if (IsBusy)
        {
            return;
        }

        ScanLogs.Clear();
        DiagnosticLogClipboardText = null;
        ScanPassCount = 0;
        ScanFailCount = 0;
        HasScanPanel = false;
        ActiveTestKind = DiagnosticTestCategory.None;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunLookupAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        var token = StartSession(DiagnosticTestCategory.Lookup, indeterminate: true,
            $"{LookupDomain} ({SelectedRecordType})",
            $"Querying {LookupDomain} ({SelectedRecordType})...");
        try
        {
            var report = await _diagnostics.LookupAsync(LookupDomain, SelectedRecordType, cancellationToken: token);
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

                ScanProgressPercent = 100;
                AddStepLog(DiagnosticTestCategory.Lookup, DiagnosticStepOutcome.Pass,
                    $"{report.ResolverName} ({report.Protocol})", report.LatencyMs,
                    $"RCODE={report.ResponseCode}, AD={report.AuthenticDataBit}, {report.Records.Count} record(s)");

                foreach (var rec in report.Records.Take(10))
                {
                    AddStepLog(DiagnosticTestCategory.Lookup, DiagnosticStepOutcome.Info,
                        $"{rec.Name} [{rec.RecordType}]", null,
                        $"TTL {rec.Ttl}s → {rec.Value}");
                }
            }
            else
            {
                ErrorMessage = report.ErrorMessage;
                AddStepLog(DiagnosticTestCategory.Lookup, DiagnosticStepOutcome.Fail,
                    report.ResolverName, report.LatencyMs > 0 ? report.LatencyMs : null,
                    report.ErrorMessage ?? report.ResponseCode);
            }

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Lookup, DiagnosticStepOutcome.Fail, LookupDomain, null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDnssecTestAsync()
    {
        var resolver = ActiveResolverName;
        var token = StartSession(DiagnosticTestCategory.Dnssec, indeterminate: true,
            resolver, "Querying DNSSEC signed zone (cloudflare.com) with DO=1...");
        try
        {
            var report = await _diagnostics.TestDnssecAsync(cancellationToken: token);
            ExternalTestResult = report.Summary;
            ScanProgressPercent = 100;

            AddStepLog(DiagnosticTestCategory.Dnssec,
                report.SignedDomainVerified ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Fail,
                report.ResolverName,
                report.LatencyMs > 0 ? report.LatencyMs : null,
                $"SupportsDnssec={report.SupportsDnssecValidation} · {report.Summary}");

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Dnssec, DiagnosticStepOutcome.Fail, resolver, null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDohTestAsync()
    {
        var token = StartSession(DiagnosticTestCategory.Doh, indeterminate: true,
            "DoH HTTPS/443", "Testing TLS + HTTP/2 DNS-over-HTTPS connectivity...");
        try
        {
            var (ok, latencyMs, summary) = await _diagnostics.TestDohConnectivityAsync(cancellationToken: token);
            ExternalTestResult = summary;
            ScanProgressPercent = 100;

            AddStepLog(DiagnosticTestCategory.Doh,
                ok ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Fail,
                "DoH HTTPS/443",
                latencyMs > 0 ? latencyMs : null,
                summary);

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Doh, DiagnosticStepOutcome.Fail, "DoH HTTPS/443", null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDnsCryptTestAsync()
    {
        var token = StartSession(DiagnosticTestCategory.DnsCrypt, indeterminate: true,
            "DNSCrypt", "Validating sdns:// stamp & testing DNSCrypt relay connectivity...");
        try
        {
            var (ok, latencyMs, summary) = await _diagnostics.TestDnsCryptConnectivityAsync(cancellationToken: token);
            ExternalTestResult = summary;
            ScanProgressPercent = 100;

            AddStepLog(DiagnosticTestCategory.DnsCrypt,
                ok ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Fail,
                "DNSCrypt Relay",
                latencyMs > 0 ? latencyMs : null,
                summary);

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.DnsCrypt, DiagnosticStepOutcome.Fail, "DNSCrypt", null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunLeakTestAsync()
    {
        var token = StartSession(DiagnosticTestCategory.Leak, indeterminate: true,
            AdapterName, "Inspecting Windows adapter DNS bindings & upstream encryption...");
        try
        {
            var report = await _diagnostics.RunDnsLeakTestAsync(token);
            ExternalTestResult = report.Summary;
            ScanProgressPercent = 100;

            AddStepLog(DiagnosticTestCategory.Leak,
                report.IsAdapterUsingLocalProxy ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Warning,
                "OS Adapter DNS",
                null,
                report.AdapterDnsServers.Count > 0 ? string.Join(", ", report.AdapterDnsServers) : "None");

            AddStepLog(DiagnosticTestCategory.Leak,
                report.IsLeakDetected ? DiagnosticStepOutcome.Fail : DiagnosticStepOutcome.Pass,
                $"{report.ActiveEncryptedResolver} ({report.ActiveProtocol})",
                null,
                report.Summary);

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Leak, DiagnosticStepOutcome.Fail, AdapterName, null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunRestrictionScanAsync()
    {
        var token = StartSession(DiagnosticTestCategory.Restrictions, indeterminate: true,
            "UDP/53 · TCP/53 · DoH · DoT · DNSCrypt",
            "Probing ISP / firewall port filtering across DNS protocols...");
        try
        {
            var report = await _failover.DiagnoseNetworkRestrictionsAsync(token);
            RestrictionSummary = $"UDP/53={(report.Udp53Reachable ? "OK" : "Blocked")} · TCP/53={(report.Tcp53Reachable ? "OK" : "Blocked")} · DoH/443={(report.Doh443Reachable ? "OK" : "Failed")} · DoT/853={(report.Dot853Reachable ? "OK" : "Failed")} · DNSCrypt={(report.DnsCryptReachable ? "OK" : "Failed")} — {report.Summary}";
            ScanProgressPercent = 100;
            ScanStepCounterText = "5 / 5";

            AddStepLog(DiagnosticTestCategory.Restrictions,
                report.Udp53Reachable ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Warning,
                "UDP / 53 (Plain DNS)", null, report.Udp53Reachable ? "Reachable" : "Blocked or filtered");
            AddStepLog(DiagnosticTestCategory.Restrictions,
                report.Tcp53Reachable ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Warning,
                "TCP / 53 (Plain DNS)", null, report.Tcp53Reachable ? "Reachable" : "Blocked or filtered");
            AddStepLog(DiagnosticTestCategory.Restrictions,
                report.Doh443Reachable ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Fail,
                "DoH / 443 (HTTPS)", null, report.Doh443Reachable ? "Reachable (Recommended if ISP filters DNS)" : "Unreachable / TLS blocked");
            AddStepLog(DiagnosticTestCategory.Restrictions,
                report.Dot853Reachable ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Warning,
                "DoT / 853 (TLS)", null, report.Dot853Reachable ? "Reachable" : "Port 853 filtered");
            AddStepLog(DiagnosticTestCategory.Restrictions,
                report.DnsCryptReachable ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Warning,
                "DNSCrypt (443/UDP+TCP)", null, report.DnsCryptReachable ? "Reachable" : "Unreachable or no DNSCrypt listener");
            AddStepLog(DiagnosticTestCategory.Restrictions,
                DiagnosticStepOutcome.Info,
                "Recommendation", null, report.Summary);

            FinishSession(cancelled: false);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Restrictions, DiagnosticStepOutcome.Fail, "Restrictions Scan", null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CompareResolversAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        var token = StartSession(DiagnosticTestCategory.Compare, indeterminate: false,
            $"{LookupDomain} ({SelectedRecordType})",
            $"Comparing enabled resolvers for {LookupDomain} ({SelectedRecordType})...");
        try
        {
            var progress = new Progress<DiagnosticStepProgress>(HandleStreamingStepProgress);
            var results = await _diagnostics.CompareResolversAsync(LookupDomain, SelectedRecordType, progress, token);
            ComparisonResults.Clear();
            foreach (var r in results)
            {
                ComparisonResults.Add(r);
            }

            if (results.Count > 0 && results[0].Success)
            {
                AddStepLog(DiagnosticTestCategory.Compare, DiagnosticStepOutcome.Info,
                    "Fastest Resolver", results[0].LatencyMs,
                    $"{results[0].ResolverName} → {results[0].PrimaryAnswerSummary}");
            }

            FinishSession(cancelled: token.IsCancellationRequested);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Compare, DiagnosticStepOutcome.Fail, LookupDomain, null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task CheckPropagationAsync()
    {
        if (string.IsNullOrWhiteSpace(LookupDomain))
        {
            return;
        }

        var token = StartSession(DiagnosticTestCategory.Propagation, indeterminate: false,
            $"{LookupDomain} ({SelectedRecordType})",
            $"Checking global DNS propagation for {LookupDomain} ({SelectedRecordType})...");
        try
        {
            var progress = new Progress<DiagnosticStepProgress>(HandleStreamingStepProgress);
            var results = await _diagnostics.CheckPropagationAsync(LookupDomain, SelectedRecordType, progress, token);
            ComparisonResults.Clear();
            foreach (var r in results)
            {
                ComparisonResults.Add(r);
            }

            var distinctAnswers = results
                .Where(r => r.Success)
                .Select(r => r.PrimaryAnswerSummary)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (distinctAnswers.Count == 1)
            {
                AddStepLog(DiagnosticTestCategory.Propagation, DiagnosticStepOutcome.Pass,
                    "Global Consistency", null,
                    $"Consistent answer across all responding resolvers: {distinctAnswers[0]}");
            }
            else if (distinctAnswers.Count > 1)
            {
                AddStepLog(DiagnosticTestCategory.Propagation, DiagnosticStepOutcome.Warning,
                    "Global Consistency", null,
                    $"Propagating ({distinctAnswers.Count} different answers seen): {string.Join(" | ", distinctAnswers.Take(3))}");
            }

            FinishSession(cancelled: token.IsCancellationRequested);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.Propagation, DiagnosticStepOutcome.Fail, LookupDomain, null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunBrowserDohCheckAsync()
    {
        var token = StartSession(
            DiagnosticTestCategory.BrowserDoh,
            indeterminate: true,
            "Browser DoH Audit",
            "Inspecting Chrome, Edge, and Firefox DoH bypass policies and canary status...");
        try
        {
            var report = await _diagnostics.CheckBrowserDohBypassAsync(token);
            BrowserDohSummary = report.Summary;
            var outcome = report.BrowserPolicyDetected || !report.FirefoxCanaryBlocked
                ? DiagnosticStepOutcome.Warning
                : DiagnosticStepOutcome.Pass;
            AddStepLog(DiagnosticTestCategory.BrowserDoh, outcome, "Browser DoH Policies", null, report.Summary);
            foreach (var finding in report.Findings)
            {
                AddStepLog(DiagnosticTestCategory.BrowserDoh, DiagnosticStepOutcome.Warning, "Policy Detail", null, finding);
            }

            FinishSession(cancelled: token.IsCancellationRequested);
        }
        catch (OperationCanceledException)
        {
            FinishSession(cancelled: true);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            AddStepLog(DiagnosticTestCategory.BrowserDoh, DiagnosticStepOutcome.Fail, "Browser DoH Policies", null, ex.Message);
            FinishSession(cancelled: false);
        }
    }

    private CancellationToken StartSession(
        DiagnosticTestCategory category,
        bool indeterminate,
        string initialTarget,
        string initialDetail)
    {
        _activeTestCts?.Dispose();
        _activeTestCts = new CancellationTokenSource();

        IsBusy = true;
        HasScanPanel = true;
        ActiveTestKind = category;
        ScanWasCancelled = false;
        ScanIsIndeterminate = indeterminate;
        ScanProgressPercent = indeterminate ? 0 : 2;
        ScanHeaderKey = "Diag_Scan_Header_Running";
        ScanCurrentTarget = initialTarget;
        ScanStepCounterText = indeterminate ? "..." : "0 / 0";
        ScanElapsedDisplay = "0.0s";
        ErrorMessage = null;
        _testStartedAt = DateTimeOffset.Now;
        _elapsedTimer?.Start();

        AddStepLog(category, DiagnosticStepOutcome.Running, initialTarget, null, initialDetail);
        return _activeTestCts.Token;
    }

    private void FinishSession(bool cancelled)
    {
        _elapsedTimer?.Stop();
        ScanElapsedDisplay = string.Create(
            CultureInfo.InvariantCulture,
            $"{Math.Max(0.0, (DateTimeOffset.Now - _testStartedAt).TotalSeconds):0.0}s");
        ScanWasCancelled = cancelled;
        if (cancelled)
        {
            ScanHeaderKey = "Diag_Scan_Header_Cancelled";
            AddStepLog(ActiveTestKind, DiagnosticStepOutcome.Warning, ScanCurrentTarget, null, "Cancelled by user.");
        }
        else
        {
            ScanHeaderKey = "Diag_Scan_Header_Done";
            ScanProgressPercent = 100;
        }

        DiagnosticLogClipboardText = BuildClipboardLog();
        IsBusy = false;
    }

    private void HandleStreamingStepProgress(DiagnosticStepProgress p)
    {
        ScanCurrentTarget = p.Target;
        ScanStepCounterText = string.Create(CultureInfo.InvariantCulture, $"{p.CompletedSteps} / {p.TotalSteps}");
        if (p.TotalSteps > 0)
        {
            ScanProgressPercent = Math.Clamp(p.CompletedSteps * 100.0 / p.TotalSteps, 0, 100);
        }

        if (p.Outcome == DiagnosticStepOutcome.Running)
        {
            return;
        }

        AddStepLog(p.Category, p.Outcome, p.Target, p.LatencyMs, p.Detail);
    }

    private void AddStepLog(
        DiagnosticTestCategory category,
        DiagnosticStepOutcome outcome,
        string target,
        double? latencyMs,
        string detail)
    {
        if (outcome == DiagnosticStepOutcome.Pass)
        {
            ScanPassCount++;
        }
        else if (outcome == DiagnosticStepOutcome.Fail)
        {
            ScanFailCount++;
        }

        var latencyText = latencyMs is { } ms && ms > 0
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.0} ms")
            : "—";

        ScanLogs.Insert(0, new DiagnosticLogEntry(
            DateTimeOffset.Now,
            category,
            "Diag_Cat_" + category,
            outcome,
            "Diag_Outcome_" + outcome,
            target,
            latencyText,
            detail));

        while (ScanLogs.Count > MaxScanLogEntries)
        {
            ScanLogs.RemoveAt(ScanLogs.Count - 1);
        }
    }

    private string BuildClipboardLog()
    {
        var sb = new StringBuilder();
        foreach (var e in ScanLogs.Reverse())
        {
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"[{e.Timestamp:HH:mm:ss}] [{e.Category}] [{e.Outcome}] {e.Target} ({e.LatencyText}) — {e.DetailText}");
        }

        return sb.ToString().TrimEnd();
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
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyEngineStats(stats));
        }
        else
        {
            ApplyEngineStats(stats);
        }
    }
}
