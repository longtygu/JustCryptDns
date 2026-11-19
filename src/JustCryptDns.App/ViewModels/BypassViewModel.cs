using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
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
    private bool _loading;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsEngineRunning))]
    private BypassEngineState _engineState = BypassEngineState.Stopped;

    [ObservableProperty] private string _proxyEndpoint = "127.0.0.1:10808";
    [ObservableProperty] private string _pacUrl = "http://127.0.0.1:10809/proxy.pac";
    [ObservableProperty] private bool _windowsProxyApplied;
    [ObservableProperty] private bool _hasProxyBackup;
    [ObservableProperty] private string _dpiBypassedDisplay = "0";
    [ObservableProperty] private string _tunneledDisplay = "0";
    [ObservableProperty] private string _autoFallbacksDisplay = "0";
    [ObservableProperty] private string _activeAndDirectDisplay = "0 / 0";
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;

    // Live Domain Bypass Tester
    [ObservableProperty] private string _testDomainInput = "store.steampowered.com";
    [ObservableProperty] private bool _isTesting;
    [ObservableProperty] private BypassTestResult? _lastTestResult;

    // DPI Engine & Windows Proxy Settings
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

    // New Rule Form
    [ObservableProperty] private string _newRuleName = string.Empty;
    [ObservableProperty] private string _newRulePattern = string.Empty;
    [ObservableProperty] private RoutingMatchKind _newRuleMatchKind = RoutingMatchKind.DomainSuffix;
    [ObservableProperty] private BypassMode _newRuleMode = BypassMode.AutoHybrid;

    public BypassViewModel(
        IBypassEngineService bypassEngine,
        IWindowsProxyManager windowsProxy,
        ISettingsService settings)
        : base("Nav_Bypass", "Page_Bypass_Subtitle")
    {
        _bypassEngine = bypassEngine;
        _windowsProxy = windowsProxy;
        _settings = settings;

        LoadFromSettingsAndEngine();
    }

    public bool IsEngineRunning => EngineState is BypassEngineState.Running or BypassEngineState.Degraded;

    public IReadOnlyList<WindowsProxyMode> ProxyModes { get; } = Enum.GetValues<WindowsProxyMode>();

    public IReadOnlyList<TlsFragmentationStrategy> FragmentationStrategies { get; } = Enum.GetValues<TlsFragmentationStrategy>();

    public IReadOnlyList<UpstreamTunnelKind> UpstreamKinds { get; } = Enum.GetValues<UpstreamTunnelKind>();

    public IReadOnlyList<BypassMode> BypassModes { get; } = Enum.GetValues<BypassMode>();

    public IReadOnlyList<RoutingMatchKind> MatchKinds { get; } = Enum.GetValues<RoutingMatchKind>();

    public ObservableCollection<BypassRuleItemViewModel> Rules { get; } = [];

    public ObservableCollection<BypassConnectionEvent> RecentEvents { get; } = [];

    public override void OnNavigatedTo()
    {
        _bypassEngine.StateChanged += OnBypassStateChanged;
        _bypassEngine.ConnectionProcessed += OnConnectionProcessed;
        LoadFromSettingsAndEngine();
    }

    public override void OnNavigatedFrom()
    {
        _bypassEngine.StateChanged -= OnBypassStateChanged;
        _bypassEngine.ConnectionProcessed -= OnConnectionProcessed;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
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

    private async Task PersistSettingsAsync()
    {
        var fragSize = int.TryParse(FragmentSizeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fs) ? fs : 40;
        var fragDelay = int.TryParse(FragmentDelayText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fd) ? fd : 0;
        var proxyPort = int.TryParse(ProxyPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pp) ? pp : BypassSettings.DefaultProxyPort;
        var pacPort = int.TryParse(PacPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pacP) ? pacP : BypassSettings.DefaultPacPort;
        var upPort = int.TryParse(UpstreamPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var up) ? up : UpstreamTunnelSettings.DefaultWarpPort;

        await _settings.UpdateAsync(s =>
        {
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

    private void ApplyStats(BypassRuntimeStats stats)
    {
        EngineState = stats.State;
        ProxyEndpoint = stats.ProxyEndpoint;
        PacUrl = stats.PacUrl;
        WindowsProxyApplied = stats.WindowsProxyApplied;
        HasProxyBackup = stats.HasProxyBackup;
        DpiBypassedDisplay = stats.DpiBypassedConnections.ToString("N0", CultureInfo.CurrentCulture);
        TunneledDisplay = stats.TunneledConnections.ToString("N0", CultureInfo.CurrentCulture);
        AutoFallbacksDisplay = stats.AutoFallbackCount.ToString("N0", CultureInfo.CurrentCulture);
        ActiveAndDirectDisplay = $"{stats.ActiveTunnels} / {stats.DirectConnections:N0}";
        if (!string.IsNullOrWhiteSpace(stats.LastError) && ErrorMessage is null)
        {
            ErrorMessage = stats.LastError;
        }
    }

    private void OnBypassStateChanged(object? sender, BypassRuntimeStats stats)
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
}
