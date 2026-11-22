using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public enum WindowCloseAction
{
    HideToTray,
    ExitApplication,
    PromptUser,
}

public sealed record CommandPaletteItem(
    string Id,
    string Glyph,
    string LabelKey,
    string CategoryKey,
    string Keywords,
    string? PageKey = null,
    string? ActionKey = null);

public sealed partial class ShellViewModel : ObservableObject
{
    /// <summary>Sub-pages shown under a sidebar entry without their own sidebar item.</summary>
    private static readonly Dictionary<string, string> SubPageParents = new()
    {
        [PageKeys.Appearance] = PageKeys.Settings,
    };

    private readonly IPageFactory _pageFactory;
    private readonly ISettingsService _settings;
    private readonly IUpdateService? _updateService;
    private readonly IAboutWindowService? _aboutWindow;
    private readonly IDnsEngine? _dnsEngine;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly IGamingEngineService? _gamingEngine;
    private readonly IFirewallBlocklistCoordinator? _firewall;
    private readonly IDnsCacheService? _cache;
    private readonly IConnectionMonitorService? _connectionMonitor;
    private readonly IThreatIntelligenceService? _threatIntel;
    private readonly ILogger<ShellViewModel> _logger;
    private readonly DispatcherTimer? _stripTimer;
    private readonly List<CommandPaletteItem> _allPaletteCommands;

    /// <summary>Selection in the main navigation list.</summary>
    [ObservableProperty]
    private NavItem? _selectedNavItem;

    /// <summary>Selection in the footer list (Settings).</summary>
    [ObservableProperty]
    private NavItem? _selectedFooterItem;

    [ObservableProperty]
    private PageViewModel? _currentPage;

    [ObservableProperty]
    private bool _isSidebarCollapsed;

    [ObservableProperty]
    private bool _isClosePromptOpen;

    [ObservableProperty]
    private bool _rememberCloseChoice;

    [ObservableProperty]
    private bool _hasAvailableUpdate;

    [ObservableProperty]
    private bool _isDnsProtected;

    [ObservableProperty]
    private bool _isDnsVpnDeferred;

    [ObservableProperty]
    private bool _isDnsCaptivePaused;

    [ObservableProperty]
    private string _dnsStripValue = string.Empty;

    [ObservableProperty]
    private bool _isDpiActive;

    [ObservableProperty]
    private string _dpiStripValue = string.Empty;

    [ObservableProperty]
    private bool _isLeakGuardActive;

    [ObservableProperty]
    private bool _isLockdownActive;

    [ObservableProperty]
    private bool _hasConnectionSecurityAlert;

    [ObservableProperty]
    private int _connectionAlertCount;

    [ObservableProperty]
    private bool _isCommandPaletteOpen;

    [ObservableProperty]
    private string _commandPaletteQuery = string.Empty;

    [ObservableProperty]
    private CommandPaletteItem? _selectedPaletteCommand;

    [ObservableProperty]
    private bool _hasPaletteMatches;

    private bool _isRefreshingFirewall;

    public ShellViewModel(
        IPageFactory pageFactory,
        ISettingsService settings,
        INavigationService navigation,
        ILogger<ShellViewModel> logger,
        IUpdateService? updateService = null,
        IAboutWindowService? aboutWindow = null,
        IDnsEngine? dnsEngine = null,
        IBypassEngineService? bypassEngine = null,
        IGamingEngineService? gamingEngine = null,
        IFirewallBlocklistCoordinator? firewall = null,
        IDnsCacheService? cache = null,
        IConnectionMonitorService? connectionMonitor = null,
        IThreatIntelligenceService? threatIntel = null)
    {
        _pageFactory = pageFactory;
        _settings = settings;
        _updateService = updateService;
        _aboutWindow = aboutWindow;
        _dnsEngine = dnsEngine;
        _bypassEngine = bypassEngine;
        _gamingEngine = gamingEngine;
        _firewall = firewall;
        _cache = cache;
        _connectionMonitor = connectionMonitor;
        _threatIntel = threatIntel;
        _logger = logger;

        NavItems =
        [
            new NavItem(PageKeys.Dashboard, "\uE80F", "Nav_Dashboard", "NavGroup_Overview"),
            new NavItem(PageKeys.DnsManager, "\uE774", "Nav_DnsManager", "NavGroup_Protection"),
            new NavItem(PageKeys.Resolvers, "\uE8F1", "Nav_Resolvers", "NavGroup_Protection"),
            new NavItem(PageKeys.Routing, "\uE8AB", "Nav_Routing", "NavGroup_Protection"),
            new NavItem(PageKeys.Gaming, "\uE7FC", "Nav_Gaming", "NavGroup_Protection"),
            new NavItem(PageKeys.Bypass, "\uE705", "Nav_Bypass", "NavGroup_Protection"),
            new NavItem(PageKeys.Filtering, "\uE71C", "Nav_Filtering", "NavGroup_Protection"),
            new NavItem(PageKeys.Diagnostics, "\uE9D9", "Nav_Diagnostics", "NavGroup_Tools"),
            new NavItem(PageKeys.Monitor, "\uE9D2", "Nav_Monitor", "NavGroup_Tools"),
            new NavItem(PageKeys.Connections, "\uE839", "Nav_Connections", "NavGroup_Tools"),
        ];
        FooterItems = [new NavItem(PageKeys.Settings, "\uE713", "Nav_Settings")];

        NavItemsView = CollectionViewSource.GetDefaultView(NavItems);
        NavItemsView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(NavItem.GroupKey)));

        _allPaletteCommands = BuildPaletteCommands();
        RefreshFilteredPaletteCommands();

        _isSidebarCollapsed = settings.Current.Appearance.SidebarCollapsed;
        settings.Changed += OnSettingsChanged;
        if (_updateService is not null)
        {
            HasAvailableUpdate = _updateService.LatestResult?.Status == UpdateCheckStatus.UpdateAvailable;
            _updateService.UpdateCheckCompleted += OnUpdateCheckCompleted;
        }

        if (_dnsEngine is not null)
        {
            _dnsEngine.StateChanged += OnDnsStateChanged;
        }

        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged += OnBypassStateChanged;
        }

        if (_gamingEngine is not null)
        {
            _gamingEngine.GamingStateChanged += OnEngineOrSecurityChanged;
        }

        LocalizationManager.Instance.PropertyChanged += OnLocalizationChanged;

        navigation.NavigationRequested += (_, key) => NavigateTo(key);
        SelectedNavItem = NavItems[0];

        RefreshSecurityStripState(checkFirewallAndAlerts: false);

        if (Application.Current is not null && _firewall is not null)
        {
            _ = RefreshFirewallAndAlertsAsync();
            _stripTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _stripTimer.Tick += (_, _) => _ = RefreshFirewallAndAlertsAsync();
            _stripTimer.Start();
        }
    }

    public event EventHandler? HideToTrayRequested;

    public event EventHandler? ExitRequested;

    public ObservableCollection<NavItem> NavItems { get; }

    public ICollectionView NavItemsView { get; }

    public ObservableCollection<NavItem> FooterItems { get; }

    public ObservableCollection<CommandPaletteItem> FilteredPaletteCommands { get; } = [];

    /// <summary>Key of the page currently shown.</summary>
    public string? CurrentPageKey { get; private set; }

    /// <summary>When true, the next window close exits the application regardless of <see cref="CloseBehavior"/>.</summary>
    public bool IsExplicitExit { get; set; }

    public void StopTimers()
    {
        _stripTimer?.Stop();
        if (_dnsEngine is not null)
        {
            _dnsEngine.StateChanged -= OnDnsStateChanged;
        }

        if (_bypassEngine is not null)
        {
            _bypassEngine.StateChanged -= OnBypassStateChanged;
        }

        if (_gamingEngine is not null)
        {
            _gamingEngine.GamingStateChanged -= OnEngineOrSecurityChanged;
        }

        LocalizationManager.Instance.PropertyChanged -= OnLocalizationChanged;
    }

    public WindowCloseAction HandleWindowClosing()
    {
        if (IsExplicitExit)
        {
            return WindowCloseAction.ExitApplication;
        }

        switch (_settings.Current.General.CloseBehavior)
        {
            case CloseBehavior.ExitApplication:
                return WindowCloseAction.ExitApplication;
            case CloseBehavior.AskEveryTime:
                RememberCloseChoice = false;
                IsClosePromptOpen = true;
                return WindowCloseAction.PromptUser;
            default:
                return WindowCloseAction.HideToTray;
        }
    }

    [RelayCommand]
    private void ConfirmMinimizeToTray()
    {
        IsClosePromptOpen = false;
        if (RememberCloseChoice)
        {
            _settings.UpdateDeferred(s => s.General.CloseBehavior = CloseBehavior.MinimizeToTray);
        }

        HideToTrayRequested?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void ConfirmExitApplication()
    {
        IsClosePromptOpen = false;
        if (RememberCloseChoice)
        {
            _settings.UpdateDeferred(s => s.General.CloseBehavior = CloseBehavior.ExitApplication);
        }

        IsExplicitExit = true;
        ExitRequested?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void CancelClosePrompt() => IsClosePromptOpen = false;

    public void NavigateTo(string pageKey)
    {
        if (SubPageParents.TryGetValue(pageKey, out var parent))
        {
            // Keep the parent highlighted in the sidebar, then show the sub-page.
            NavigateTo(parent);
            Navigate(pageKey);
            return;
        }

        var main = NavItems.FirstOrDefault(i => i.Key == pageKey);
        if (main is not null)
        {
            SelectedNavItem = main;
            Navigate(main.Key);
            return;
        }

        var footer = FooterItems.FirstOrDefault(i => i.Key == pageKey);
        if (footer is not null)
        {
            SelectedFooterItem = footer;
            Navigate(footer.Key);
        }
    }

    [RelayCommand]
    private void NavigateFromStrip(string? pageKey)
    {
        if (!string.IsNullOrWhiteSpace(pageKey))
        {
            NavigateTo(pageKey);
        }
    }

    [RelayCommand]
    private void OpenCommandPalette()
    {
        CommandPaletteQuery = string.Empty;
        RefreshFilteredPaletteCommands();
        IsCommandPaletteOpen = true;
    }

    [RelayCommand]
    private void CloseCommandPalette() => IsCommandPaletteOpen = false;

    [RelayCommand]
    private void ToggleCommandPalette()
    {
        if (IsCommandPaletteOpen)
        {
            CloseCommandPalette();
        }
        else
        {
            OpenCommandPalette();
        }
    }

    public void MovePaletteSelection(int delta)
    {
        if (FilteredPaletteCommands.Count == 0)
        {
            SelectedPaletteCommand = null;
            return;
        }

        var currentIndex = SelectedPaletteCommand is null
            ? -1
            : FilteredPaletteCommands.IndexOf(SelectedPaletteCommand);

        var nextIndex = currentIndex < 0
            ? 0
            : Math.Clamp(currentIndex + delta, 0, FilteredPaletteCommands.Count - 1);

        SelectedPaletteCommand = FilteredPaletteCommands[nextIndex];
    }

    [RelayCommand]
    private async Task ExecuteSelectedPaletteCommandAsync() =>
        await ExecutePaletteCommandAsync(SelectedPaletteCommand ?? FilteredPaletteCommands.FirstOrDefault()).ConfigureAwait(true);

    [RelayCommand]
    private async Task ExecutePaletteCommandAsync(CommandPaletteItem? item)
    {
        if (item is null)
        {
            return;
        }

        IsCommandPaletteOpen = false;

        if (!string.IsNullOrWhiteSpace(item.PageKey))
        {
            NavigateTo(item.PageKey);
            return;
        }

        switch (item.ActionKey)
        {
            case "toggle-dns" when _dnsEngine is not null:
                if (_dnsEngine.GetStats().State is DnsEngineState.Running or DnsEngineState.Degraded or DnsEngineState.Starting)
                {
                    await _dnsEngine.StopAsync().ConfigureAwait(true);
                }
                else
                {
                    await _dnsEngine.StartAsync().ConfigureAwait(true);
                }

                break;

            case "toggle-dpi" when _bypassEngine is not null:
                if (_bypassEngine.GetStats().State is BypassEngineState.Running or BypassEngineState.Starting)
                {
                    await _bypassEngine.StopAsync().ConfigureAwait(true);
                }
                else
                {
                    await _bypassEngine.StartAsync().ConfigureAwait(true);
                }

                break;

            case "flush-cache":
                _cache?.Clear();
                break;

            case "toggle-lockdown":
                if (_firewall is null)
                {
                    NavigateTo(PageKeys.Connections);
                    break;
                }

                var conn = _settings.Current.Connections;
                var targetLockdown = !IsLockdownActive;
                var result = await _firewall.SyncSecurityAsync(new FirewallSyncRequestPayload(
                    conn.BlockedRules.ToList(),
                    conn.BlockedApps.ToList(),
                    conn.EnableDnsLeakGuard,
                    targetLockdown)).ConfigureAwait(true);
                if (result.Success)
                {
                    IsLockdownActive = targetLockdown;
                }

                break;

            case "pause-captive" when _dnsEngine is not null:
                if (_dnsEngine.GetStats().IsCaptivePortalPaused)
                {
                    await _dnsEngine.ResumeFromCaptivePortalAsync().ConfigureAwait(true);
                }
                else
                {
                    await _dnsEngine.PauseForCaptivePortalAsync(TimeSpan.FromMinutes(5)).ConfigureAwait(true);
                }

                break;

            case "about":
                OpenAbout();
                break;
        }

        RefreshSecurityStripState(checkFirewallAndAlerts: false);
    }

    partial void OnCommandPaletteQueryChanged(string value) => RefreshFilteredPaletteCommands();

    partial void OnSelectedNavItemChanged(NavItem? value)
    {
        if (value is null)
        {
            return;
        }

        SelectedFooterItem = null;
        Navigate(value.Key);
    }

    partial void OnSelectedFooterItemChanged(NavItem? value)
    {
        if (value is null)
        {
            return;
        }

        SelectedNavItem = null;
        Navigate(value.Key);
    }

    private void Navigate(string key)
    {
        if (key == CurrentPageKey)
        {
            return;
        }

        var previous = CurrentPage;
        previous?.OnNavigatedFrom();

        var next = _pageFactory.Create(key);
        CurrentPageKey = key;
        CurrentPage = next;
        next.OnNavigatedTo();
        previous?.Dispose();
        _logger.LogDebug("Navigated to {Page}", key);
    }

    [RelayCommand]
    private void ToggleSidebar() => IsSidebarCollapsed = !IsSidebarCollapsed;

    [RelayCommand]
    private void OpenAbout() => _aboutWindow?.Show(AboutWindowTab.Overview);

    partial void OnIsSidebarCollapsedChanged(bool value)
    {
        if (_settings.Current.Appearance.SidebarCollapsed != value)
        {
            _settings.UpdateDeferred(s => s.Appearance.SidebarCollapsed = value);
        }
    }

    private void OnSettingsChanged(object? sender, AppSettings settings)
    {
        // Keep in sync when the sidebar mode or security settings are changed elsewhere.
        void Sync()
        {
            IsSidebarCollapsed = settings.Appearance.SidebarCollapsed;
            RefreshSecurityStripState(checkFirewallAndAlerts: false);
        }

        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }

    private void OnUpdateCheckCompleted(object? sender, UpdateCheckResult result)
    {
        void Sync() => HasAvailableUpdate = result.Status == UpdateCheckStatus.UpdateAvailable;
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }

    private void OnDnsStateChanged(object? sender, DnsEngineRuntimeStats e) => OnEngineOrSecurityChanged(sender, EventArgs.Empty);

    private void OnBypassStateChanged(object? sender, BypassRuntimeStats e) => OnEngineOrSecurityChanged(sender, EventArgs.Empty);

    private void OnEngineOrSecurityChanged(object? sender, EventArgs e)
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => RefreshSecurityStripState(checkFirewallAndAlerts: false));
        }
        else
        {
            RefreshSecurityStripState(checkFirewallAndAlerts: false);
        }
    }

    private void OnLocalizationChanged(object? sender, PropertyChangedEventArgs e)
    {
        RefreshSecurityStripState(checkFirewallAndAlerts: false);
        RefreshFilteredPaletteCommands();
    }

    private void RefreshSecurityStripState(bool checkFirewallAndAlerts)
    {
        var loc = LocalizationManager.Instance;
        if (_dnsEngine is not null)
        {
            var stats = _dnsEngine.GetStats();
            IsDnsProtected = stats.State is DnsEngineState.Running or DnsEngineState.Degraded;
            IsDnsVpnDeferred = stats.TrafficStatus == SystemTrafficStatus.DeferredToVpn;
            IsDnsCaptivePaused = stats.IsCaptivePortalPaused || stats.TrafficStatus == SystemTrafficStatus.CaptivePortalDetected;
            DnsStripValue = IsDnsCaptivePaused
                ? loc.Get("Strip_Paused")
                : IsDnsVpnDeferred
                    ? loc.Get("Strip_VpnDefer")
                    : IsDnsProtected
                        ? $"{loc.Get("Strip_On")} · {stats.ActiveProtocol}"
                        : loc.Get("Strip_Off");
        }
        else
        {
            IsDnsProtected = false;
            IsDnsVpnDeferred = false;
            IsDnsCaptivePaused = false;
            DnsStripValue = loc.Get("Strip_Off");
        }

        if (_bypassEngine is not null)
        {
            var bypass = _bypassEngine.GetStats();
            IsDpiActive = bypass.State == BypassEngineState.Running;
            DpiStripValue = IsDpiActive ? loc.Get("Strip_On") : loc.Get("Strip_Off");
        }
        else
        {
            IsDpiActive = false;
            DpiStripValue = loc.Get("Strip_Off");
        }

        IsLeakGuardActive = _settings.Current.Connections.EnableDnsLeakGuard;

        if (checkFirewallAndAlerts)
        {
            _ = RefreshFirewallAndAlertsAsync();
        }
    }

    private async Task RefreshFirewallAndAlertsAsync()
    {
        if (_isRefreshingFirewall)
        {
            return;
        }

        _isRefreshingFirewall = true;
        try
        {
            if (_firewall is not null)
            {
                var status = await _firewall.GetStatusAsync().ConfigureAwait(false);
                var threatAlerts = CountActiveThreats();
                if (Application.Current?.Dispatcher is { } dispatcher)
                {
                    await dispatcher.InvokeAsync(() =>
                    {
                        IsLeakGuardActive = status.IsDnsLeakGuardActive || _settings.Current.Connections.EnableDnsLeakGuard;
                        IsLockdownActive = status.IsLockdownActive;
                        ConnectionAlertCount = threatAlerts;
                        HasConnectionSecurityAlert = threatAlerts > 0 || status.IsLockdownActive;
                    });
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "Failed to refresh shell security strip status.");
        }
        finally
        {
            _isRefreshingFirewall = false;
        }
    }

    private int CountActiveThreats()
    {
        if (_connectionMonitor is null || _threatIntel is null || !_settings.Current.Connections.EnableThreatIntelligence)
        {
            return 0;
        }

        try
        {
            var count = 0;
            var snapshot = _connectionMonitor.CaptureSnapshot();
            foreach (var conn in snapshot)
            {
                if (!string.IsNullOrWhiteSpace(conn.RemoteIp)
                    && _threatIntel.TryMatch(conn.RemoteIp, null, out _))
                {
                    count++;
                }
            }

            return count;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return 0;
        }
    }

    private List<CommandPaletteItem> BuildPaletteCommands() =>
    [
        new("nav-dashboard", "\uE80F", "Nav_Dashboard", "CmdPalette_Cat_Page", "dashboard home overview tong quan", PageKeys.Dashboard),
        new("nav-dns", "\uE774", "Nav_DnsManager", "CmdPalette_Cat_Page", "dns doh dot dnscrypt vpn captive canary", PageKeys.DnsManager),
        new("nav-resolvers", "\uE8F1", "Nav_Resolvers", "CmdPalette_Cat_Page", "resolvers servers upstream benchmark", PageKeys.Resolvers),
        new("nav-routing", "\uE8AB", "Nav_Routing", "CmdPalette_Cat_Page", "routing split local rewrite cname lan", PageKeys.Routing),
        new("nav-gaming", "\uE7FC", "Nav_Gaming", "CmdPalette_Cat_Page", "gaming latency pin pubg valorant", PageKeys.Gaming),
        new("nav-bypass", "\uE705", "Nav_Bypass", "CmdPalette_Cat_Page", "dpi bypass proxy pac warp", PageKeys.Bypass),
        new("nav-filtering", "\uE71C", "Nav_Filtering", "CmdPalette_Cat_Page", "filter blocklist cache stale prefetch", PageKeys.Filtering),
        new("nav-diagnostics", "\uE9D9", "Nav_Diagnostics", "CmdPalette_Cat_Page", "diagnostics audit browser doh", PageKeys.Diagnostics),
        new("nav-monitor", "\uE9D2", "Nav_Monitor", "CmdPalette_Cat_Page", "live dns monitor queries log", PageKeys.Monitor),
        new("nav-connections", "\uE839", "Nav_Connections", "CmdPalette_Cat_Page", "connections firewall leak lockdown threat", PageKeys.Connections),
        new("nav-settings", "\uE713", "Nav_Settings", "CmdPalette_Cat_Page", "settings startup language export cai dat", PageKeys.Settings),
        new("nav-appearance", "\uE790", "Appearance_Title", "CmdPalette_Cat_Page", "appearance theme dark light accent giao dien", PageKeys.Appearance),
        new("act-dns", "\uE774", "CmdPalette_Action_ToggleDns", "CmdPalette_Cat_Action", "toggle start stop dns engine bat tat", ActionKey: "toggle-dns"),
        new("act-dpi", "\uE705", "CmdPalette_Action_ToggleDpi", "CmdPalette_Cat_Action", "toggle start stop dpi bypass vuot chan", ActionKey: "toggle-dpi"),
        new("act-cache", "\uE74D", "CmdPalette_Action_FlushCache", "CmdPalette_Cat_Action", "flush clear dns cache xoa bo nho dem", ActionKey: "flush-cache"),
        new("act-lockdown", "\uE72E", "CmdPalette_Action_ToggleLockdown", "CmdPalette_Cat_Action", "emergency lockdown kill switch khoa mang", ActionKey: "toggle-lockdown"),
        new("act-captive", "\uE701", "CmdPalette_Action_PauseCaptive", "CmdPalette_Cat_Action", "captive portal pause resume wifi cong cong", ActionKey: "pause-captive"),
        new("act-diag", "\uE9D9", "CmdPalette_Action_RunDiagnostics", "CmdPalette_Cat_Action", "run diagnostics chan doan", PageKeys.Diagnostics),
        new("act-about", "\uE946", "Nav_About", "CmdPalette_Cat_Action", "about version update diagnostics bundle", ActionKey: "about"),
    ];

    private void RefreshFilteredPaletteCommands()
    {
        var query = CommandPaletteQuery?.Trim() ?? string.Empty;
        var loc = LocalizationManager.Instance;

        var matched = _allPaletteCommands
            .Where(item =>
            {
                if (string.IsNullOrEmpty(query))
                {
                    return true;
                }

                var label = loc.Get(item.LabelKey);
                var category = loc.Get(item.CategoryKey);
                return label.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || category.Contains(query, StringComparison.OrdinalIgnoreCase)
                    || item.Keywords.Contains(query, StringComparison.OrdinalIgnoreCase);
            })
            .ToList();

        FilteredPaletteCommands.Clear();
        foreach (var item in matched)
        {
            FilteredPaletteCommands.Add(item);
        }

        HasPaletteMatches = FilteredPaletteCommands.Count > 0;
        if (SelectedPaletteCommand is null || !FilteredPaletteCommands.Contains(SelectedPaletteCommand))
        {
            SelectedPaletteCommand = FilteredPaletteCommands.FirstOrDefault();
        }
    }
}
