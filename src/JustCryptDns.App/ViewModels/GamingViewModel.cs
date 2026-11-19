using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed partial class GamingViewModel : PageViewModel
{
    private readonly IGamingEngineService _gaming;
    private readonly IResolverLibraryService _resolvers;
    private readonly IDnsEngine _dnsEngine;
    private readonly IBypassEngineService? _bypassEngine;
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

        _loading = true;
        _isGamingModeEnabled = _gaming.IsGamingModeEnabled;
        _selectedOptimizationProfile = _gaming.SelectionProfile;
        _selectedGamingProfile = _gaming.GetActiveGamingProfile();
        _loading = false;

        RefreshAll();
    }

    public ObservableCollection<GamingPlatformProfile> GamingProfiles { get; } = [];

    public ObservableCollection<ResolverBenchmarkResult> BenchmarkResults { get; } = [];

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

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunBenchmarkAsync()
    {
        IsBenchmarking = true;
        ErrorMessage = null;
        BenchmarkProgressText = LocalizationManager.Instance["Gaming_Bench_Running"];
        try
        {
            var progress = new Progress<(int Completed, int Total, string CurrentResolver)>(p =>
            {
                BenchmarkProgressText = LocalizationManager.Instance.Format("Gaming_Bench_Progress", p.Completed, p.Total, p.CurrentResolver);
            });

            var results = await _gaming.RunBenchmarkAsync(roundsPerDomain: 2, progress: progress);
            BenchmarkResults.Clear();
            foreach (var r in results)
            {
                BenchmarkResults.Add(r);
            }

            var best = _gaming.SelectBestBenchmarkResult(results, SelectedOptimizationProfile);
            if (best is not null)
            {
                StatusMessage = LocalizationManager.Instance.Format("Gaming_Bench_Recommended", best.ResolverName, best.AverageLatencyMs, best.P95LatencyMs, best.ReliabilityScore);
            }
            else
            {
                StatusMessage = LocalizationManager.Instance["Gaming_Bench_Done"];
            }

            RefreshAll();
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
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
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
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
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
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
