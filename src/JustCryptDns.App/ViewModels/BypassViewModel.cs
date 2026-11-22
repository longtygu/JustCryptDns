using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.ViewModels;

public sealed partial class BypassRuleItemViewModel : ObservableObject
{
    private readonly Func<string, bool, Task> _onToggleEnabled;
    private readonly Func<BypassRule, BypassMode, Task> _onChangeMode;
    private bool _suppressCallbacks;

    [ObservableProperty] private bool _enabled;
    [ObservableProperty] private BypassMode _mode;

    public BypassRuleItemViewModel(
        BypassRule rule,
        Func<string, bool, Task> onToggleEnabled,
        Func<BypassRule, BypassMode, Task> onChangeMode)
    {
        Rule = rule;
        _onToggleEnabled = onToggleEnabled;
        _onChangeMode = onChangeMode;
        _suppressCallbacks = true;
        _enabled = rule.Enabled;
        _mode = rule.Mode;
        _suppressCallbacks = false;
    }

    public BypassRule Rule { get; private set; }

    public string Id => Rule.Id;

    public string Name => Rule.Name;

    public string Pattern => Rule.Pattern;

    public RoutingMatchKind MatchKind => Rule.MatchKind;

    public string Category => Rule.Category;

    public bool IsBuiltIn => Rule.IsBuiltIn;

    public bool CanDelete => !Rule.IsBuiltIn;

    partial void OnEnabledChanged(bool value)
    {
        if (!_suppressCallbacks)
        {
            Rule = Rule with { Enabled = value };
            _ = _onToggleEnabled(Rule.Id, value);
        }
    }

    partial void OnModeChanged(BypassMode value)
    {
        if (!_suppressCallbacks)
        {
            Rule = Rule with { Mode = value };
            _ = _onChangeMode(Rule, value);
        }
    }
}

public sealed partial class BypassViewModel : PageViewModel
{
    private const int MaxUiEvents = 120;

    private readonly IBypassEngineService _bypassEngine;
    private readonly IWindowsProxyManager _windowsProxy;
    private readonly ISettingsService _settings;
    private readonly IServiceClient? _serviceClient;
    private DispatcherTimer? _servicePollTimer;
    private bool _isServicePollInFlight;
    private bool _loading;
    private long _lastStatsUiTick;
    private BypassRuntimeStats? _pendingStats;
    private int _statsFlushScheduled;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsEngineRunning))]
    private BypassEngineState _engineState = BypassEngineState.Stopped;

    [ObservableProperty] private string _proxyEndpoint = "127.0.0.1:10808";
    [ObservableProperty] private string _pacUrl = "http://127.0.0.1:10809/proxy.pac";
    [ObservableProperty] private bool _windowsProxyApplied;
    [ObservableProperty] private bool _hasProxyBackup;
    [ObservableProperty] private BypassCoverageMode _activeCoverageMode = BypassCoverageMode.AllWebsitesSmart;
    [ObservableProperty] private string _dpiBypassedDisplay = "0";
    [ObservableProperty] private string _tunneledDisplay = "0";
    [ObservableProperty] private string _autoFallbacksDisplay = "0";
    [ObservableProperty] private string _selfHealedDisplay = "0";
    [ObservableProperty] private string _learnedCountDisplay = "0";
    [ObservableProperty] private string _activeAndDirectDisplay = "0 / 0";
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;

    // Live Domain Bypass Tester
    [ObservableProperty] private string _testDomainInput = "store.steampowered.com";
    [ObservableProperty] private bool _isTesting;
    [ObservableProperty] private BypassTestResult? _lastTestResult;
    [ObservableProperty] private string? _batchTestSummary;

    // DPI Engine & Windows Proxy Settings
    [ObservableProperty] private BypassCoverageMode _selectedCoverageMode = BypassCoverageMode.AllWebsitesSmart;
    [ObservableProperty] private bool _enableSmartSelfHealing = true;
    [ObservableProperty] private bool _autoStartWithDnsEngine = true;
    [ObservableProperty] private bool _applyWindowsProxyAutomatically = true;
    [ObservableProperty] private bool _resolveTargetViaLocalDns = true;
    [ObservableProperty] private bool _fragmentHttpHostHeader = true;
    [ObservableProperty] private bool _autoFallbackToTunnelOnDpiFailure = true;
    [ObservableProperty] private WindowsProxyMode _selectedProxyMode = WindowsProxyMode.AutoPac;
    [ObservableProperty] private TlsFragmentationStrategy _selectedFragmentationStrategy = TlsFragmentationStrategy.RecordChunkSplit;
    [ObservableProperty] private string _fragmentSizeText = "40";
    [ObservableProperty] private string _fragmentDelayText = "0";
    [ObservableProperty] private string _proxyPortText = "10808";
    [ObservableProperty] private string _pacPortText = "10809";

    // Tier 2 Split-Tunnel Upstream
    [ObservableProperty] private bool _upstreamEnabled;
    [ObservableProperty] private UpstreamTunnelKind _selectedUpstreamKind = UpstreamTunnelKind.CloudflareWarpLocal;
    [ObservableProperty] private string _upstreamHost = UpstreamTunnelSettings.DefaultHost;
    [ObservableProperty] private string _upstreamPortText = UpstreamTunnelSettings.DefaultWarpPort.ToString(CultureInfo.InvariantCulture);
    [ObservableProperty] private string _upstreamUsername = string.Empty;
    [ObservableProperty] private string _upstreamPassword = string.Empty;
    [ObservableProperty] private string? _upstreamFeedback;

    // New Rule & Direct Exclusion Inputs
    [ObservableProperty] private string _newRuleName = string.Empty;
    [ObservableProperty] private string _newRulePattern = string.Empty;
    [ObservableProperty] private RoutingMatchKind _newRuleMatchKind = RoutingMatchKind.DomainSuffix;
    [ObservableProperty] private BypassMode _newRuleMode = BypassMode.AutoHybrid;
    [ObservableProperty] private string _newExclusionInput = string.Empty;

    public BypassViewModel(
        IBypassEngineService bypassEngine,
        IWindowsProxyManager windowsProxy,
        ISettingsService settings,
        IServiceClient? serviceClient = null)
        : base("Nav_Bypass", "Page_Bypass_Subtitle")
    {
        _bypassEngine = bypassEngine;
        _windowsProxy = windowsProxy;
        _settings = settings;
        _serviceClient = serviceClient;

        LoadFromSettingsAndEngine();
    }

    public bool IsEngineRunning => EngineState is BypassEngineState.Running or BypassEngineState.Degraded;

    public IReadOnlyList<BypassCoverageMode> CoverageModes { get; } = Enum.GetValues<BypassCoverageMode>();

    public IReadOnlyList<WindowsProxyMode> ProxyModes { get; } = Enum.GetValues<WindowsProxyMode>();

    public IReadOnlyList<TlsFragmentationStrategy> FragmentationStrategies { get; } = Enum.GetValues<TlsFragmentationStrategy>();

    public IReadOnlyList<UpstreamTunnelKind> UpstreamKinds { get; } = Enum.GetValues<UpstreamTunnelKind>();

    public IReadOnlyList<BypassMode> BypassModes { get; } = Enum.GetValues<BypassMode>();

    public IReadOnlyList<RoutingMatchKind> MatchKinds { get; } = Enum.GetValues<RoutingMatchKind>();

    public ObservableCollection<BypassRuleItemViewModel> Rules { get; } = [];

    public ObservableCollection<string> DirectExclusions { get; } = [];

    public ObservableCollection<LearnedHostEntry> LearnedHosts { get; } = [];

    public ObservableCollection<BypassConnectionEvent> RecentEvents { get; } = [];

    public override void OnNavigatedTo()
    {
        _bypassEngine.StateChanged += OnBypassStateChanged;
        _bypassEngine.ConnectionProcessed += OnConnectionProcessed;
        if (_serviceClient is not null)
        {
            _serviceClient.StateChanged -= OnServiceClientStateChanged;
            _serviceClient.StateChanged += OnServiceClientStateChanged;
        }

        LoadFromSettingsAndEngine();
        StartServicePolling();
    }

    public override void OnNavigatedFrom()
    {
        StopServicePolling();
        if (_serviceClient is not null)
        {
            _serviceClient.StateChanged -= OnServiceClientStateChanged;
        }

        _bypassEngine.StateChanged -= OnBypassStateChanged;
        _bypassEngine.ConnectionProcessed -= OnConnectionProcessed;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            StopServicePolling();
            if (_serviceClient is not null)
            {
                _serviceClient.StateChanged -= OnServiceClientStateChanged;
            }

            _bypassEngine.StateChanged -= OnBypassStateChanged;
            _bypassEngine.ConnectionProcessed -= OnConnectionProcessed;
        }

        base.Dispose(disposing);
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleBypassEngineAsync()
    {
        ErrorMessage = null;
        StatusMessage = null;
        if (IsEngineRunning)
        {
            await _bypassEngine.StopAsync();
            StatusMessage = LocalizationManager.Instance["Bypass_Msg_Stopped"];
        }
        else
        {
            await PersistSettingsAsync();
            var (ok, warnOrErr) = await _bypassEngine.StartAsync();
            if (!ok)
            {
                ErrorMessage = warnOrErr;
            }
            else if (!string.IsNullOrWhiteSpace(warnOrErr))
            {
                ErrorMessage = warnOrErr;
            }
            else
            {
                StatusMessage = LocalizationManager.Instance["Bypass_Msg_Started"];
            }
        }

        ApplyStats(_bypassEngine.GetStats());
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RestoreWindowsProxyAsync()
    {
        ErrorMessage = null;
        var res = await _windowsProxy.RestoreOriginalProxyAsync();
        if (res.Success)
        {
            StatusMessage = LocalizationManager.Instance["Bypass_Msg_ProxyRestored"];
        }
        else
        {
            ErrorMessage = res.ErrorMessage;
        }

        ApplyStats(_bypassEngine.GetStats());
    }

    [RelayCommand]
    private void SelectPresetTestDomain(string? domain)
    {
        if (!string.IsNullOrWhiteSpace(domain))
        {
            TestDomainInput = domain;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunDomainTestAsync()
    {
        if (string.IsNullOrWhiteSpace(TestDomainInput))
        {
            return;
        }

        IsTesting = true;
        ErrorMessage = null;
        try
        {
            LastTestResult = await _bypassEngine.TestDomainBypassAsync(TestDomainInput);
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsTesting = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RunBatchSiteTestAsync()
    {
        IsTesting = true;
        ErrorMessage = null;
        BatchTestSummary = null;
        try
        {
            string[] sites =
            [
                "store.steampowered.com",
                "steamcommunity.com",
                "discord.com",
                "www.bbc.com",
                "github.com",
                "www.google.com",
            ];
            var results = await _bypassEngine.TestMultipleDomainsAsync(sites);
            var passed = results.Count(r => r.DirectSucceeded || r.DpiBypassSucceeded || r.TunnelSucceeded);
            var parts = results.Select(r =>
            {
                var status = r.DirectSucceeded
                    ? $"Direct {r.DirectLatencyMs:0.#}ms"
                    : r.DpiBypassSucceeded
                        ? $"DPI {r.DpiBypassLatencyMs:0.#}ms"
                        : r.TunnelSucceeded
                            ? $"Tunnel {r.TunnelLatencyMs:0.#}ms"
                            : "ERR";
                return $"{r.Host} ({status})";
            });
            BatchTestSummary = LocalizationManager.Instance.Format("Bypass_Tester_BatchResult", passed, results.Count, string.Join(" · ", parts));
        }
        catch (Exception ex)
        {
            ErrorMessage = ex.Message;
        }
        finally
        {
            IsTesting = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddTestedDomainRuleAsync()
    {
        if (LastTestResult is null || string.IsNullOrWhiteSpace(LastTestResult.Host))
        {
            return;
        }

        var rule = new BypassRule
        {
            Id = string.Empty,
            Name = LastTestResult.Host,
            Pattern = LastTestResult.Host,
            MatchKind = RoutingMatchKind.DomainSuffix,
            Mode = LastTestResult.RecommendedMode == BypassMode.Direct ? BypassMode.AutoHybrid : LastTestResult.RecommendedMode,
            Category = "Custom",
            Enabled = true,
            IsBuiltIn = false,
        };

        var (ok, _, err) = await _bypassEngine.SaveRuleAsync(rule);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_RuleAdded", rule.Pattern);
        RefreshRules();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SaveAndApplySettingsAsync()
    {
        ErrorMessage = null;
        StatusMessage = null;
        await PersistSettingsAsync();

        if (IsEngineRunning)
        {
            var (ok, err) = await _bypassEngine.RestartAsync();
            if (!ok)
            {
                ErrorMessage = err;
                return;
            }
        }
        else
        {
            await _bypassEngine.RefreshSystemPacAsync();
        }

        StatusMessage = LocalizationManager.Instance["Bypass_Msg_SettingsSaved"];
        ApplyStats(_bypassEngine.GetStats());
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task DetectWarpAsync()
    {
        UpstreamFeedback = null;
        var (available, summary) = await _bypassEngine.DetectCloudflareWarpAsync();
        UpstreamFeedback = summary;
        if (available)
        {
            SelectedUpstreamKind = UpstreamTunnelKind.CloudflareWarpLocal;
            UpstreamHost = UpstreamTunnelSettings.DefaultHost;
            UpstreamPortText = UpstreamTunnelSettings.DefaultWarpPort.ToString(CultureInfo.InvariantCulture);
            UpstreamEnabled = true;
            await PersistSettingsAsync();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task TestUpstreamAsync()
    {
        UpstreamFeedback = null;
        await PersistSettingsAsync();
        var (_, _, summary) = await _bypassEngine.TestUpstreamTunnelAsync();
        UpstreamFeedback = summary;
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddCustomRuleAsync()
    {
        ErrorMessage = null;
        var rule = new BypassRule
        {
            Id = string.Empty,
            Name = string.IsNullOrWhiteSpace(NewRuleName) ? NewRulePattern : NewRuleName,
            Pattern = NewRulePattern,
            MatchKind = NewRuleMatchKind,
            Mode = NewRuleMode,
            Category = "Custom",
            Enabled = true,
            IsBuiltIn = false,
        };

        var (ok, saved, err) = await _bypassEngine.SaveRuleAsync(rule);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        NewRuleName = string.Empty;
        NewRulePattern = string.Empty;
        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_RuleAdded", saved!.Pattern);
        RefreshRules();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task DeleteRuleAsync(BypassRuleItemViewModel? item)
    {
        if (item is null || item.IsBuiltIn)
        {
            return;
        }

        await _bypassEngine.DeleteRuleAsync(item.Id);
        RefreshRules();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task EnableCategoryAsync(string? category)
    {
        if (string.IsNullOrWhiteSpace(category))
        {
            return;
        }

        foreach (var rule in _bypassEngine.GetRules().Where(r => string.Equals(r.Category, category, StringComparison.OrdinalIgnoreCase)))
        {
            await _bypassEngine.SetRuleEnabledAsync(rule.Id, true);
        }

        RefreshRules();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ResetBuiltInRulesAsync()
    {
        await _bypassEngine.ResetBuiltInRulesAsync();
        StatusMessage = LocalizationManager.Instance["Bypass_Msg_RulesReset"];
        RefreshRules();
    }

    [RelayCommand]
    private void ClearEvents()
    {
        _bypassEngine.ClearRecentEvents();
        RecentEvents.Clear();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddDirectExclusionAsync()
    {
        ErrorMessage = null;
        var (ok, err) = await _bypassEngine.AddDirectExclusionAsync(NewExclusionInput);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        var added = NewExclusionInput.Trim();
        NewExclusionInput = string.Empty;
        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_ExclusionAdded", added);
        RefreshExclusionsAndLearned();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveDirectExclusionAsync(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return;
        }

        await _bypassEngine.RemoveDirectExclusionAsync(pattern);
        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_ExclusionRemoved", pattern);
        RefreshExclusionsAndLearned();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ExcludeHostFromActivityAsync(BypassConnectionEvent? entry)
    {
        if (entry is null || string.IsNullOrWhiteSpace(entry.Host))
        {
            return;
        }

        var (ok, err) = await _bypassEngine.AddDirectExclusionAsync(entry.Host);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_ExclusionAdded", entry.Host);
        RefreshExclusionsAndLearned();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task PinLearnedHostAsync(LearnedHostEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        var (ok, err) = await _bypassEngine.PromoteLearnedHostAsync(entry.Host, entry.Strategy);
        if (!ok)
        {
            ErrorMessage = err;
            return;
        }

        StatusMessage = LocalizationManager.Instance.Format("Bypass_Msg_Promoted", entry.Host);
        RefreshRules();
        RefreshExclusionsAndLearned();
    }

    [RelayCommand]
    private void ClearLearnedHosts()
    {
        _bypassEngine.ClearLearnedHosts();
        StatusMessage = LocalizationManager.Instance["Bypass_Msg_LearnedCleared"];
        RefreshExclusionsAndLearned();
    }

    private async Task PersistSettingsAsync()
    {
        var fragSize = int.TryParse(FragmentSizeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fs) ? fs : 40;
        var fragDelay = int.TryParse(FragmentDelayText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fd) ? fd : 0;
        var proxyPort = int.TryParse(ProxyPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pp) ? pp : BypassSettings.DefaultProxyPort;
        var pacPort = int.TryParse(PacPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pacP) ? pacP : BypassSettings.DefaultPacPort;
        var upPort = int.TryParse(UpstreamPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var up) ? up : UpstreamTunnelSettings.DefaultWarpPort;

        await _settings.UpdateAsync(s =>
        {
            s.Bypass.CoverageMode = SelectedCoverageMode;
            s.Bypass.EnableSmartSelfHealing = EnableSmartSelfHealing;
            s.Bypass.AutoStartWithDnsEngine = AutoStartWithDnsEngine;
            s.Bypass.ApplyWindowsProxyAutomatically = ApplyWindowsProxyAutomatically;
            s.Bypass.ResolveTargetViaLocalDns = ResolveTargetViaLocalDns;
            s.Bypass.FragmentHttpHostHeader = FragmentHttpHostHeader;
            s.Bypass.AutoFallbackToTunnelOnDpiFailure = AutoFallbackToTunnelOnDpiFailure;
            s.Bypass.WindowsProxyMode = SelectedProxyMode;
            s.Bypass.FragmentationStrategy = SelectedFragmentationStrategy;
            s.Bypass.FragmentSizeBytes = fragSize;
            s.Bypass.FragmentDelayMs = fragDelay;
            s.Bypass.ProxyPort = proxyPort;
            s.Bypass.PacPort = pacPort;

            s.Bypass.Upstream.Enabled = UpstreamEnabled;
            s.Bypass.Upstream.Kind = SelectedUpstreamKind;
            s.Bypass.Upstream.Host = UpstreamHost;
            s.Bypass.Upstream.Port = upPort;
            s.Bypass.Upstream.Username = UpstreamUsername;
            s.Bypass.Upstream.Password = UpstreamPassword;
        });
    }

    private void LoadFromSettingsAndEngine()
    {
        _loading = true;
        try
        {
            var b = _settings.Current.Bypass;
            SelectedCoverageMode = b.CoverageMode;
            EnableSmartSelfHealing = b.EnableSmartSelfHealing;
            AutoStartWithDnsEngine = b.AutoStartWithDnsEngine;
            ApplyWindowsProxyAutomatically = b.ApplyWindowsProxyAutomatically;
            ResolveTargetViaLocalDns = b.ResolveTargetViaLocalDns;
            FragmentHttpHostHeader = b.FragmentHttpHostHeader;
            AutoFallbackToTunnelOnDpiFailure = b.AutoFallbackToTunnelOnDpiFailure;
            SelectedProxyMode = b.WindowsProxyMode;
            SelectedFragmentationStrategy = b.FragmentationStrategy;
            FragmentSizeText = b.FragmentSizeBytes.ToString(CultureInfo.InvariantCulture);
            FragmentDelayText = b.FragmentDelayMs.ToString(CultureInfo.InvariantCulture);
            ProxyPortText = b.ProxyPort.ToString(CultureInfo.InvariantCulture);
            PacPortText = b.PacPort.ToString(CultureInfo.InvariantCulture);

            UpstreamEnabled = b.Upstream.Enabled;
            SelectedUpstreamKind = b.Upstream.Kind;
            UpstreamHost = b.Upstream.Host;
            UpstreamPortText = b.Upstream.Port.ToString(CultureInfo.InvariantCulture);
            UpstreamUsername = b.Upstream.Username ?? string.Empty;
            UpstreamPassword = b.Upstream.Password ?? string.Empty;
        }
        finally
        {
            _loading = false;
        }

        ApplyStats(_bypassEngine.GetStats());
        RefreshRules();
        RefreshExclusionsAndLearned();

        RecentEvents.Clear();
        foreach (var evt in _bypassEngine.GetRecentEvents().Reverse().Take(MaxUiEvents))
        {
            RecentEvents.Add(evt);
        }
    }

    private void RefreshRules()
    {
        Rules.Clear();
        foreach (var rule in _bypassEngine.GetRules())
        {
            Rules.Add(new BypassRuleItemViewModel(
                rule,
                (id, en) => _bypassEngine.SetRuleEnabledAsync(id, en),
                (r, mode) => _bypassEngine.SaveRuleAsync(r with { Mode = mode })));
        }
    }

    private void RefreshExclusionsAndLearned()
    {
        DirectExclusions.Clear();
        foreach (var excl in _bypassEngine.GetDirectExclusions())
        {
            DirectExclusions.Add(excl);
        }

        LearnedHosts.Clear();
        foreach (var entry in _bypassEngine.GetLearnedHosts())
        {
            LearnedHosts.Add(entry);
        }
    }

    private void ApplyStats(BypassRuntimeStats stats)
    {
        EngineState = stats.State;
        ProxyEndpoint = stats.ProxyEndpoint;
        PacUrl = stats.PacUrl;
        WindowsProxyApplied = stats.WindowsProxyApplied;
        HasProxyBackup = stats.HasProxyBackup;
        ActiveCoverageMode = stats.CoverageMode;
        DpiBypassedDisplay = stats.DpiBypassedConnections.ToString("N0", CultureInfo.CurrentCulture);
        TunneledDisplay = stats.TunneledConnections.ToString("N0", CultureInfo.CurrentCulture);
        AutoFallbacksDisplay = stats.AutoFallbackCount.ToString("N0", CultureInfo.CurrentCulture);
        SelfHealedDisplay = $"{stats.SelfHealedDirectCount:N0} / {stats.EscalatedDpiCount:N0}";
        LearnedCountDisplay = stats.LearnedHostCount.ToString("N0", CultureInfo.CurrentCulture);
        ActiveAndDirectDisplay = $"{stats.ActiveTunnels} / {stats.DirectConnections:N0}";
        if (!string.IsNullOrWhiteSpace(stats.LastError))
        {
            if (ErrorMessage is null)
            {
                ErrorMessage = stats.LastError;
            }
        }
        else if (stats.State is BypassEngineState.Running or BypassEngineState.Degraded)
        {
            ErrorMessage = null;
        }
    }

    private void OnBypassStateChanged(object? sender, BypassRuntimeStats stats)
    {
        var now = Environment.TickCount64;
        var isLifecycleBoundary = stats.State != EngineState;
        if (isLifecycleBoundary || now - Interlocked.Read(ref _lastStatsUiTick) >= 250)
        {
            Interlocked.Exchange(ref _lastStatsUiTick, now);
            _pendingStats = null;
            DispatchStatsToUi(stats);
            return;
        }

        _pendingStats = stats;
        if (Interlocked.CompareExchange(ref _statsFlushScheduled, 1, 0) == 0)
        {
            _ = FlushPendingStatsAsync();
        }
    }

    private async Task FlushPendingStatsAsync()
    {
        await Task.Delay(250).ConfigureAwait(false);
        Interlocked.Exchange(ref _statsFlushScheduled, 0);
        if (_pendingStats is { } latest)
        {
            Interlocked.Exchange(ref _lastStatsUiTick, Environment.TickCount64);
            _pendingStats = null;
            DispatchStatsToUi(latest);
        }
    }

    private void DispatchStatsToUi(BypassRuntimeStats stats)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyStats(stats));
        }
        else
        {
            ApplyStats(stats);
        }
    }

    private void OnConnectionProcessed(object? sender, BypassConnectionEvent entry)
    {
        void InsertEntry()
        {
            RecentEvents.Insert(0, entry);
            while (RecentEvents.Count > MaxUiEvents)
            {
                RecentEvents.RemoveAt(RecentEvents.Count - 1);
            }

            if (entry.Action is BypassActionKind.EscalatedDpi16B or BypassActionKind.SelfHealedDirect or BypassActionKind.AutoFallbackTunnel)
            {
                RefreshExclusionsAndLearned();
            }
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(InsertEntry);
        }
        else
        {
            InsertEntry();
        }
    }

    partial void OnSelectedUpstreamKindChanged(UpstreamTunnelKind value)
    {
        if (_loading)
        {
            return;
        }

        if (value == UpstreamTunnelKind.CloudflareWarpLocal)
        {
            UpstreamHost = UpstreamTunnelSettings.DefaultHost;
            UpstreamPortText = UpstreamTunnelSettings.DefaultWarpPort.ToString(CultureInfo.InvariantCulture);
        }
        else if (value == UpstreamTunnelKind.Socks5 && UpstreamPortText == UpstreamTunnelSettings.DefaultWarpPort.ToString(CultureInfo.InvariantCulture))
        {
            UpstreamPortText = "1080";
        }
        else if (value == UpstreamTunnelKind.HttpConnect && UpstreamPortText is "40000" or "1080")
        {
            UpstreamPortText = "8080";
        }
    }

    private void OnServiceClientStateChanged(object? sender, EventArgs e)
    {
        void Sync()
        {
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                StartServicePolling();
            }
            else
            {
                StopServicePolling();
            }
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }

    private void StartServicePolling()
    {
        if (_serviceClient?.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        _ = PollServiceStateAsync();
        if (_servicePollTimer is null && System.Windows.Application.Current?.Dispatcher is { } dispatcher)
        {
            _servicePollTimer = new DispatcherTimer(
                TimeSpan.FromSeconds(2),
                DispatcherPriority.Background,
                OnServicePollTick,
                dispatcher);
        }

        _servicePollTimer?.Start();
    }

    private void StopServicePolling()
    {
        if (_servicePollTimer is not null)
        {
            _servicePollTimer.Stop();
            _servicePollTimer.Tick -= OnServicePollTick;
            _servicePollTimer = null;
        }
    }

    private void OnServicePollTick(object? sender, EventArgs e) => _ = PollServiceStateAsync();

    private async Task PollServiceStateAsync()
    {
        if (_isServicePollInFlight || _serviceClient?.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        _isServicePollInFlight = true;
        try
        {
            if (_bypassEngine is HybridBypassEngineProxy hybridBypass)
            {
                await hybridBypass.RefreshFromServiceAsync().ConfigureAwait(false);
            }

            List<LearnedHostEntry>? serviceLearned = null;
            var learnedRes = await _serviceClient
                .SendAsync(new IpcRequest(IpcRequestKind.GetLearnedHosts))
                .ConfigureAwait(false);
            if (learnedRes is { Success: true, Message: not null })
            {
                try
                {
                    serviceLearned = System.Text.Json.JsonSerializer.Deserialize<List<LearnedHostEntry>>(learnedRes.Message, SettingsJson.Options);
                }
                catch
                {
                }
            }

            void ApplyToUi()
            {
                ApplyStats(_bypassEngine.GetStats());
                RecentEvents.Clear();
                foreach (var evt in _bypassEngine.GetRecentEvents().Reverse().Take(MaxUiEvents))
                {
                    RecentEvents.Add(evt);
                }

                if (serviceLearned is not null)
                {
                    LearnedHosts.Clear();
                    foreach (var h in serviceLearned)
                    {
                        LearnedHosts.Add(h);
                    }
                }
            }

            if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
            {
                await dispatcher.InvokeAsync(ApplyToUi);
            }
            else
            {
                ApplyToUi();
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // Transient IPC / shutdown timing.
        }
        finally
        {
            _isServicePollInFlight = false;
        }
    }
}
