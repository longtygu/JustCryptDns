using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.ViewModels;

public sealed partial class ShellViewModel : ObservableObject
{
    private readonly IPageFactory _pageFactory;
    private readonly ISettingsService _settings;
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

    public ShellViewModel(IPageFactory pageFactory, ISettingsService settings, ILogger<ShellViewModel> logger)
    {
        _pageFactory = pageFactory;
        _settings = settings;
        _logger = logger;

        NavItems =
        [
            new NavItem(PageKeys.Dashboard, "\uE80F", "Nav_Dashboard"),
            new NavItem(PageKeys.DnsManager, "\uE774", "Nav_DnsManager"),
            new NavItem(PageKeys.Resolvers, "\uE8F1", "Nav_Resolvers"),
            new NavItem(PageKeys.Routing, "\uE8AB", "Nav_Routing"),
            new NavItem(PageKeys.Gaming, "\uE7FC", "Nav_Gaming"),
            new NavItem(PageKeys.Filtering, "\uE71C", "Nav_Filtering"),
            new NavItem(PageKeys.Diagnostics, "\uE9D9", "Nav_Diagnostics"),
            new NavItem(PageKeys.Monitor, "\uE9D2", "Nav_Monitor"),
        ];
        FooterItems = [new NavItem(PageKeys.Settings, "\uE713", "Nav_Settings")];

        _isSidebarCollapsed = settings.Current.Appearance.SidebarCollapsed;
        SelectedNavItem = NavItems[0];
    }

    public ObservableCollection<NavItem> NavItems { get; }

    public ObservableCollection<NavItem> FooterItems { get; }

    /// <summary>Key of the page currently shown.</summary>
    public string? CurrentPageKey { get; private set; }

    public void NavigateTo(string pageKey)
    {
        var main = NavItems.FirstOrDefault(i => i.Key == pageKey);
        if (main is not null)
        {
            SelectedNavItem = main;
            return;
        }

        var footer = FooterItems.FirstOrDefault(i => i.Key == pageKey);
        if (footer is not null)
        {
            SelectedFooterItem = footer;
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

    partial void OnIsSidebarCollapsedChanged(bool value) => _ = PersistSidebarAsync(value);

    private async Task PersistSidebarAsync(bool collapsed)
    {
        try
        {
            await _settings.UpdateAsync(s => s.Appearance.SidebarCollapsed = collapsed);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Failed to persist sidebar state.");
        }
    }
}
