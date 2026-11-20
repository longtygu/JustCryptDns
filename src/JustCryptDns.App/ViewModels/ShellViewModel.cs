using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public enum WindowCloseAction
{
    HideToTray,
    ExitApplication,
    PromptUser,
}

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
    private readonly ILogger<ShellViewModel> _logger;

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

    public ShellViewModel(
        IPageFactory pageFactory,
        ISettingsService settings,
        INavigationService navigation,
        ILogger<ShellViewModel> logger,
        IUpdateService? updateService = null,
        IAboutWindowService? aboutWindow = null)
    {
        _pageFactory = pageFactory;
        _settings = settings;
        _updateService = updateService;
        _aboutWindow = aboutWindow;
        _logger = logger;

        NavItems =
        [
            new NavItem(PageKeys.Dashboard, "\uE80F", "Nav_Dashboard"),
            new NavItem(PageKeys.DnsManager, "\uE774", "Nav_DnsManager"),
            new NavItem(PageKeys.Resolvers, "\uE8F1", "Nav_Resolvers"),
            new NavItem(PageKeys.Routing, "\uE8AB", "Nav_Routing"),
            new NavItem(PageKeys.Gaming, "\uE7FC", "Nav_Gaming"),
            new NavItem(PageKeys.Bypass, "\uE705", "Nav_Bypass"),
            new NavItem(PageKeys.Filtering, "\uE71C", "Nav_Filtering"),
            new NavItem(PageKeys.Diagnostics, "\uE9D9", "Nav_Diagnostics"),
            new NavItem(PageKeys.Monitor, "\uE9D2", "Nav_Monitor"),
        ];
        FooterItems = [new NavItem(PageKeys.Settings, "\uE713", "Nav_Settings")];

        _isSidebarCollapsed = settings.Current.Appearance.SidebarCollapsed;
        settings.Changed += OnSettingsChanged;
        if (_updateService is not null)
        {
            HasAvailableUpdate = _updateService.LatestResult?.Status == UpdateCheckStatus.UpdateAvailable;
            _updateService.UpdateCheckCompleted += OnUpdateCheckCompleted;
        }

        navigation.NavigationRequested += (_, key) => NavigateTo(key);
        SelectedNavItem = NavItems[0];
    }

    public event EventHandler? HideToTrayRequested;

    public event EventHandler? ExitRequested;

    public ObservableCollection<NavItem> NavItems { get; }

    public ObservableCollection<NavItem> FooterItems { get; }

    /// <summary>Key of the page currently shown.</summary>
    public string? CurrentPageKey { get; private set; }

    /// <summary>When true, the next window close exits the application regardless of <see cref="CloseBehavior"/>.</summary>
    public bool IsExplicitExit { get; set; }

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
        // Keep in sync when the sidebar mode is changed from the Appearance page.
        void Sync() => IsSidebarCollapsed = settings.Appearance.SidebarCollapsed;
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
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
