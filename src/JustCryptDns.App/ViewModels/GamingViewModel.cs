using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed record GamingBenchmarkLogEntry(
    DateTimeOffset Timestamp,
    string Outcome,
    string OutcomeKey,
    string ProtocolBadge,
    string ResolverName,
    string Domain,
    string LatencyText,
    string DetailText);

public sealed partial class GamingViewModel : PageViewModel
{
    private const int MaxBenchmarkLogEntries = 300;

    private readonly IGamingEngineService _gaming;
    private readonly IResolverLibraryService _resolvers;
    private readonly IDnsEngine _dnsEngine;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly DispatcherTimer? _benchmarkElapsedTimer;
    private CancellationTokenSource? _benchmarkCts;
    private DateTimeOffset _benchmarkStartedAt;
    private bool _loading;

    [ObservableProperty] private bool _isGamingModeEnabled;
    [ObservableProperty] private bool _isSessionPinned;
    [ObservableProperty] private GamingSelectionProfile _selectedOptimizationProfile;
    [ObservableProperty] private GamingPlatformProfile _selectedGamingProfile;
    [ObservableProperty] private DnsResolverEndpoint? _selectedOverrideResolver;
    [ObservableProperty] private string _activeGamingResolverName = string.Empty;
    [ObservableProperty] private string _activeProfileDomainsPreview = string.Empty;
    [ObservableProperty] private string _liveLatencyText = "—";
    [ObservableProperty] private string _liveCacheHitText = "0%";
    [ObservableProperty] private long _liveTotalQueries;
    [ObservableProperty] private bool _isBenchmarking;
    [ObservableProperty] private bool _hasBenchmarkPanel;
    [ObservableProperty] private bool _benchmarkWasCancelled;
    [ObservableProperty] private double _benchmarkProgressPercent;
    [ObservableProperty] private string _benchmarkCounterText = "0 / 0";
    [ObservableProperty] private string _benchmarkQueryCounterText = "0 / 0";
    [ObservableProperty] private string _benchmarkCurrentTarget = "—";
    [ObservableProperty] private string _benchmarkElapsedDisplay = "0.0s";
    [ObservableProperty] private string _benchmarkHeaderKey = "Gaming_Bench_Header_Running";
    [ObservableProperty] private int _benchmarkSuccessQueries;
    [ObservableProperty] private int _benchmarkFailedQueries;
    [ObservableProperty] private string? _benchmarkLogClipboardText;
    [ObservableProperty] private string? _benchmarkProgressText;
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string _newProfileName = string.Empty;
    [ObservableProperty] private string _newProfileDomains = string.Empty;
    [ObservableProperty] private bool _isBypassActive;
    [ObservableProperty] private string _bypassSynergySummary = string.Empty;

    public GamingViewModel(
        IGamingEngineService gaming,
        IResolverLibraryService resolvers,
        IDnsEngine dnsEngine,
        IBypassEngineService? bypassEngine = null)
        : base("Nav_Gaming", "Page_Gaming_Subtitle")
    {
        _gaming = gaming;
        _resolvers = resolvers;
        _dnsEngine = dnsEngine;
        _bypassEngine = bypassEngine;

        if (Application.Current?.Dispatcher is { } dispatcher)
        {
            _benchmarkElapsedTimer = new DispatcherTimer(DispatcherPriority.Normal, dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(200),
            };
            _benchmarkElapsedTimer.Tick += (_, _) =>
            {
                if (IsBenchmarking)
                {
                    BenchmarkElapsedDisplay = string.Create(
                        CultureInfo.InvariantCulture,
                        $"{Math.Max(0.0, (DateTimeOffset.Now - _benchmarkStartedAt).TotalSeconds):0.0}s");
                }
            };
        }

        _loading = true;
        _isGamingModeEnabled = _gaming.IsGamingModeEnabled;
        _selectedOptimizationProfile = _gaming.SelectionProfile;
        _selectedGamingProfile = _gaming.GetActiveGamingProfile();
        _loading = false;

        RefreshAll();
    }

    public ObservableCollection<GamingPlatformProfile> GamingProfiles { get; } = [];

    public ObservableCollection<ResolverBenchmarkResult> BenchmarkResults { get; } = [];

    public ObservableCollection<GamingBenchmarkLogEntry> BenchmarkLogs { get; } = [];

    public IReadOnlyList<GamingSelectionProfile> OptimizationProfiles { get; } = Enum.GetValues<GamingSelectionProfile>();

    public IReadOnlyList<DnsResolverEndpoint> AvailableResolvers => _resolvers.GetEnabled();

    public override void OnNavigatedTo()
    {
        _gaming.GamingStateChanged += OnGamingStateChanged;
        _dnsEngine.StateChanged += OnEngineStateChanged;
        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged += OnBypassStateChanged;
        }

        RefreshAll();
    }

    public override void OnNavigatedFrom()
    {
        _gaming.GamingStateChanged -= OnGamingStateChanged;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged -= OnBypassStateChanged;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _benchmarkElapsedTimer?.Stop();
            _benchmarkCts?.Cancel();
            _benchmarkCts?.Dispose();
            _gaming.GamingStateChanged -= OnGamingStateChanged;
            _dnsEngine.StateChanged -= OnEngineStateChanged;
            if (_bypassEngine is not null)
            {
                _bypassEngine.StateChanged -= OnBypassStateChanged;
            }
        }

        base.Dispose(disposing);
    }

    partial void OnIsGamingModeEnabledChanged(bool value)
    {
        if (!_loading)
        {
            _ = ToggleGamingModeInternalAsync(value);
        }
    }

    partial void OnSelectedOptimizationProfileChanged(GamingSelectionProfile value)
    {
        if (!_loading)
        {
            _ = _gaming.SetSelectionProfileAsync(value);
        }
    }

    partial void OnSelectedGamingProfileChanged(GamingPlatformProfile value)
    {
        if (_loading || value is null)
        {
            return;
        }

        ActiveProfileDomainsPreview = string.Join(", ", value.Domains);
        _ = _gaming.SetActiveGamingProfileAsync(value.Id);
    }

    partial void OnSelectedOverrideResolverChanged(DnsResolverEndpoint? value)
    {
        if (_loading)
        {
            return;
        }

        _ = _gaming.SetManualOverrideResolverAsync(value?.Id);
    }

    [RelayCommand]
    private async Task ClearManualOverrideAsync()
    {
        _loading = true;
        SelectedOverrideResolver = null;
        _loading = false;
        await _gaming.SetManualOverrideResolverAsync(null);
        RefreshAll();
    }

    [RelayCommand]
    private void CancelBenchmark()
    {
        _benchmarkCts?.Cancel();
    }

    [RelayCommand]
    private void ClearBenchmarkLog()
    {
        if (IsBenchmarking)
        {
            return;
        }

        BenchmarkLogs.Clear();
        BenchmarkLogClipboardText = null;
        HasBenchmarkPanel = false;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunBenchmarkAsync()
    {
        _benchmarkCts?.Dispose();
        _benchmarkCts = new CancellationTokenSource();

        IsBenchmarking = true;
        HasBenchmarkPanel = true;
        BenchmarkWasCancelled = false;
        ErrorMessage = null;
        StatusMessage = null;
        BenchmarkLogs.Clear();
        BenchmarkLogClipboardText = null;
        BenchmarkProgressPercent = 0;
        BenchmarkCounterText = "0 / 0";
        BenchmarkQueryCounterText = "0 / 0";
        BenchmarkCurrentTarget = "—";
        BenchmarkElapsedDisplay = "0.0s";
        BenchmarkSuccessQueries = 0;
        BenchmarkFailedQueries = 0;
        BenchmarkHeaderKey = "Gaming_Bench_Header_Running";
        BenchmarkProgressText = LocalizationManager.Instance["Gaming_Bench_Running"];
        _benchmarkStartedAt = DateTimeOffset.Now;
        _benchmarkElapsedTimer?.Start();

        try
        {
            var progress = new Progress<GamingBenchmarkProgress>(HandleBenchmarkProgress);
            var results = await _gaming.RunBenchmarkAsync(roundsPerDomain: 2, detailedProgress: progress, _benchmarkCts.Token);

            BenchmarkResults.Clear();
            foreach (var r in results)
            {
                BenchmarkResults.Add(r);
            }

            if (BenchmarkWasCancelled)
            {
                BenchmarkHeaderKey = "Gaming_Bench_Header_Cancelled";
                StatusMessage = LocalizationManager.Instance.Format("Gaming_Bench_CancelledSummary", results.Count);
            }
            else
            {
                BenchmarkHeaderKey = "Gaming_Bench_Header_Done";
                BenchmarkProgressPercent = 100;
                var best = _gaming.SelectBestBenchmarkResult(results, SelectedOptimizationProfile);
                StatusMessage = best is not null
                    ? LocalizationManager.Instance.Format("Gaming_Bench_Recommended", best.ResolverName, best.AverageLatencyMs, best.P95LatencyMs, best.ReliabilityScore)
                    : LocalizationManager.Instance["Gaming_Bench_Done"];
            }

            BenchmarkLogClipboardText = BuildBenchmarkClipboardText();
            RefreshAll();
        }
        catch (OperationCanceledException)
        {
            BenchmarkWasCancelled = true;
            BenchmarkHeaderKey = "Gaming_Bench_Header_Cancelled";
            BenchmarkLogClipboardText = BuildBenchmarkClipboardText();
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
            BenchmarkHeaderKey = "Gaming_Bench_Header_Done";
            BenchmarkLogClipboardText = BuildBenchmarkClipboardText();
        }
        finally
        {
            _benchmarkElapsedTimer?.Stop();
            BenchmarkElapsedDisplay = string.Create(
                CultureInfo.InvariantCulture,
                $"{Math.Max(0.0, (DateTimeOffset.Now - _benchmarkStartedAt).TotalSeconds):0.0}s");
            BenchmarkProgressText = null;
            IsBenchmarking = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ApplyBenchmarkResolverAsync(ResolverBenchmarkResult? item)
    {
        if (item is null)
        {
            return;
        }

        await _gaming.SetManualOverrideResolverAsync(item.ResolverId);
        await _dnsEngine.SwitchResolverAsync(item.ResolverId);
        StatusMessage = LocalizationManager.Instance.Format("Resolvers_Msg_PrimarySet", item.ResolverName);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddCustomProfileAsync()
    {
        if (string.IsNullOrWhiteSpace(NewProfileName) || string.IsNullOrWhiteSpace(NewProfileDomains))
        {
            return;
        }

        var domains = NewProfileDomains.Split([',', ';', ' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var (ok, profile, err) = await _gaming.AddCustomGamingProfileAsync(NewProfileName, domains);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        NewProfileName = string.Empty;
        NewProfileDomains = string.Empty;
        ErrorMessage = null;
        StatusMessage = LocalizationManager.Instance.Format("Routing_Msg_ProfileCreated", profile!.Name);
        RefreshAll();
    }

    public void RefreshAll()
    {
        _loading = true;
        try
        {
            IsGamingModeEnabled = _gaming.IsGamingModeEnabled;
            IsSessionPinned = _gaming.IsSessionPinned;
            SelectedOptimizationProfile = _gaming.SelectionProfile;
            OnPropertyChanged(nameof(AvailableResolvers));

            var profiles = _gaming.GetGamingProfiles();
            var activeProfile = _gaming.GetActiveGamingProfile();
            GamingProfiles.Clear();
            foreach (var p in profiles)
            {
                GamingProfiles.Add(p);
            }

            SelectedGamingProfile = GamingProfiles.FirstOrDefault(p => string.Equals(p.Id, activeProfile.Id, StringComparison.OrdinalIgnoreCase)) ?? GamingProfiles[0];
            ActiveProfileDomainsPreview = string.Join(", ", SelectedGamingProfile.Domains);

            var overrideId = _gaming.ManualOverrideResolverId;
            SelectedOverrideResolver = string.IsNullOrWhiteSpace(overrideId)
                ? null
                : AvailableResolvers.FirstOrDefault(r => string.Equals(r.Id, overrideId, StringComparison.OrdinalIgnoreCase));

            ActiveGamingResolverName = _gaming.GetSelectedGamingResolver().Name;

            if (BenchmarkResults.Count == 0)
            {
                foreach (var r in _gaming.GetLastBenchmarkResults())
                {
                    BenchmarkResults.Add(r);
                }
            }

            ApplyEngineStats(_dnsEngine.GetStats());
            ApplyBypassSynergy();
        }
        finally
        {
            _loading = false;
        }
    }

    private void HandleBenchmarkProgress(GamingBenchmarkProgress p)
    {
        BenchmarkCounterText = string.Create(CultureInfo.InvariantCulture, $"{p.CompletedResolvers} / {p.TotalResolvers}");
        BenchmarkQueryCounterText = string.Create(CultureInfo.InvariantCulture, $"{p.CompletedQueries} / {p.TotalQueries}");
        if (p.TotalQueries > 0)
        {
            BenchmarkProgressPercent = Math.Clamp(p.CompletedQueries * 100.0 / p.TotalQueries, 0, 100);
        }

        switch (p.Stage)
        {
            case GamingBenchmarkProgressStage.ResolverStarted:
                BenchmarkCurrentTarget = $"{p.ResolverName} ({FormatProtocolBadge(p.Protocol)})";
                break;

            case GamingBenchmarkProgressStage.DomainProbed:
                BenchmarkCurrentTarget = $"{p.ResolverName} · {p.Domain} (R{p.Round}/{p.TotalRounds})";
                if (p.Success)
                {
                    BenchmarkSuccessQueries++;
                }
                else
                {
                    BenchmarkFailedQueries++;
                }

                var outcome = p.Success ? "Ok" : p.TimedOut ? "Timeout" : "Failed";
                var outcomeKey = p.Success
                    ? "Gaming_Bench_Outcome_Ok"
                    : p.TimedOut ? "Gaming_Bench_Outcome_Timeout" : "Gaming_Bench_Outcome_Failed";
                var latencyText = p.LatencyMs > 0
                    ? string.Create(CultureInfo.InvariantCulture, $"{p.LatencyMs:0.0} ms")
                    : "—";
                var detail = p.Success
                    ? string.Create(CultureInfo.InvariantCulture, $"R{p.Round}/{p.TotalRounds} · OK")
                    : (string.IsNullOrWhiteSpace(p.Error) ? "Failed" : p.Error);

                AddBenchmarkLogEntry(new GamingBenchmarkLogEntry(
                    p.Timestamp,
                    outcome,
                    outcomeKey,
                    FormatProtocolBadge(p.Protocol),
                    p.ResolverName,
                    p.Domain,
                    latencyText,
                    detail));
                break;

            case GamingBenchmarkProgressStage.ResolverCompleted:
                AddBenchmarkLogEntry(new GamingBenchmarkLogEntry(
                    p.Timestamp,
                    p.Success ? "Summary" : "Failed",
                    p.Success ? "Gaming_Bench_Outcome_Summary" : "Gaming_Bench_Outcome_Failed",
                    FormatProtocolBadge(p.Protocol),
                    p.ResolverName,
                    "AVG / SCORE",
                    p.Success ? string.Create(CultureInfo.InvariantCulture, $"{p.AverageLatencyMs:0.0} ms") : "—",
                    string.Create(CultureInfo.InvariantCulture, $"Score {p.ReliabilityScore:0.0} · {p.CompletedResolvers}/{p.TotalResolvers}")));
                break;

            case GamingBenchmarkProgressStage.Cancelled:
                BenchmarkWasCancelled = true;
                break;
        }
    }

    private void AddBenchmarkLogEntry(GamingBenchmarkLogEntry entry)
    {
        BenchmarkLogs.Insert(0, entry);
        while (BenchmarkLogs.Count > MaxBenchmarkLogEntries)
        {
            BenchmarkLogs.RemoveAt(BenchmarkLogs.Count - 1);
        }
    }

    private string BuildBenchmarkClipboardText()
    {
        var sb = new StringBuilder();
        foreach (var e in BenchmarkLogs.Reverse())
        {
            sb.AppendLine(CultureInfo.InvariantCulture,
                $"[{e.Timestamp:HH:mm:ss}] [{e.Outcome}] [{e.ProtocolBadge}] {e.ResolverName} | {e.Domain} | {e.LatencyText} | {e.DetailText}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatProtocolBadge(DnsProtocol protocol) => protocol switch
    {
        DnsProtocol.DnsOverHttps => "DoH",
        DnsProtocol.DnsOverTls => "DoT",
        DnsProtocol.DnsCrypt => "DNSCrypt",
        _ => "UDP/TCP",
    };

    private void ApplyBypassSynergy()
    {
        if (_bypassEngine is null)
        {
            IsBypassActive = false;
            BypassSynergySummary = LocalizationManager.Instance["Gaming_BypassSynergy_Inactive"];
            return;
        }

        var stats = _bypassEngine.GetStats();
        IsBypassActive = stats.State is BypassEngineState.Running or BypassEngineState.Degraded;
        BypassSynergySummary = IsBypassActive
            ? LocalizationManager.Instance.Format("Gaming_BypassSynergy_Active", stats.ProxyEndpoint)
            : LocalizationManager.Instance["Gaming_BypassSynergy_Inactive"];
    }

    private void OnBypassStateChanged(object? sender, BypassRuntimeStats stats)
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(ApplyBypassSynergy);
        }
        else
        {
            ApplyBypassSynergy();
        }
    }

    private void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        LiveLatencyText = stats.LastLatencyMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
        LiveCacheHitText = string.Create(CultureInfo.InvariantCulture, $"{stats.CacheHitRatioPercent:0.#}%");
        LiveTotalQueries = stats.TotalQueries;
    }

    private async Task ToggleGamingModeInternalAsync(bool enabled)
    {
        var (ok, err) = await _gaming.SetGamingModeAsync(enabled);
        if (!ok)
        {
            ErrorMessage = err;
        }

        RefreshAll();
    }

    private void OnGamingStateChanged(object? sender, EventArgs e)
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(RefreshAll);
        }
        else
        {
            RefreshAll();
        }
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
