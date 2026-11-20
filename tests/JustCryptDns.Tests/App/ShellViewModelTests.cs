using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.App;

public sealed class ShellViewModelTests
{
    private sealed class FakePage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
        public List<string> Events { get; } = [];

        public override void OnNavigatedTo() => Events.Add("to");

        public override void OnNavigatedFrom() => Events.Add("from");

        protected override void Dispose(bool disposing)
        {
            Events.Add("disposed");
            base.Dispose(disposing);
        }
    }

    private sealed class FakeFactory : IPageFactory
    {
        public List<FakePage> Created { get; } = [];

        public PageViewModel Create(string pageKey)
        {
            var page = new FakePage(pageKey);
            Created.Add(page);
            return page;
        }
    }

    private sealed class MemoryStore : ISettingsStore
    {
        public AppSettings? Saved { get; private set; }

        public SettingsLoadResult Load() => new(new AppSettings(), SettingsLoadOutcome.Defaults);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            Saved = settings;
            return Task.CompletedTask;
        }
    }

    private static (ShellViewModel Shell, FakeFactory Factory, MemoryStore Store, SettingsService Settings, NavigationService Nav) Create()
    {
        var factory = new FakeFactory();
        var store = new MemoryStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var nav = new NavigationService();
        return (new ShellViewModel(factory, settings, nav, NullLogger<ShellViewModel>.Instance), factory, store, settings, nav);
    }

    [Fact]
    public void StartsOnDashboard()
    {
        var (shell, factory, _, _, _) = Create();

        Assert.Equal(PageKeys.Dashboard, shell.CurrentPageKey);
        Assert.Single(factory.Created);
        Assert.Equal(["to"], factory.Created[0].Events);
    }

    [Fact]
    public void Navigating_DeactivatesAndDisposesPreviousPage()
    {
        var (shell, factory, _, _, _) = Create();
        var dashboard = factory.Created[0];

        shell.NavigateTo(PageKeys.Gaming);

        Assert.Equal(PageKeys.Gaming, shell.CurrentPageKey);
        Assert.Equal(["to", "from", "disposed"], dashboard.Events);
    }

    [Fact]
    public void FooterAndMainSelections_AreMutuallyExclusive()
    {
        var (shell, _, _, _, _) = Create();

        shell.NavigateTo(PageKeys.Settings);
        Assert.Null(shell.SelectedNavItem);
        Assert.Equal(PageKeys.Settings, shell.SelectedFooterItem?.Key);

        shell.NavigateTo(PageKeys.Routing);
        Assert.Null(shell.SelectedFooterItem);
        Assert.Equal(PageKeys.Routing, shell.SelectedNavItem?.Key);
    }

    [Fact]
    public void SubPageNavigation_HighlightsParentSidebarItem_AndCanReturnToParent()
    {
        var (shell, _, _, _, nav) = Create();

        nav.Navigate(PageKeys.Appearance);

        Assert.Equal(PageKeys.Appearance, shell.CurrentPageKey);
        Assert.Null(shell.SelectedNavItem);
        Assert.Equal(PageKeys.Settings, shell.SelectedFooterItem?.Key);

        nav.Navigate(PageKeys.Settings);

        Assert.Equal(PageKeys.Settings, shell.CurrentPageKey);
        Assert.Equal(PageKeys.Settings, shell.SelectedFooterItem?.Key);
    }

    [Fact]
    public void ReselectingSamePage_DoesNotRecreateIt()
    {
        var (shell, factory, _, _, _) = Create();

        shell.NavigateTo(PageKeys.Dashboard);

        Assert.Single(factory.Created);
    }

    [Fact]
    public async Task ToggleSidebar_PersistsState()
    {
        var (shell, _, store, settings, _) = Create();

        shell.ToggleSidebarCommand.Execute(null);
        await settings.FlushAsync();

        Assert.True(shell.IsSidebarCollapsed);
        Assert.True(store.Saved?.Appearance.SidebarCollapsed);
    }

    [Fact]
    public void AllTenSectionsArePresent()
    {
        var (shell, _, _, _, _) = Create();
        var keys = shell.NavItems.Concat(shell.FooterItems).Select(i => i.Key).ToList();

        Assert.Equal(
            [PageKeys.Dashboard, PageKeys.DnsManager, PageKeys.Resolvers, PageKeys.Routing, PageKeys.Gaming,
             PageKeys.Bypass, PageKeys.Filtering, PageKeys.Diagnostics, PageKeys.Monitor, PageKeys.Connections, PageKeys.Settings],
            keys);
    }

    [Fact]
    public async Task CloseBehavior_HandlesMinimizeExitAndPromptRemember()
    {
        var (shell, _, _, settings, _) = Create();

        // Default is MinimizeToTray
        Assert.Equal(WindowCloseAction.HideToTray, shell.HandleWindowClosing());

        // AskEveryTime opens prompt
        await settings.UpdateAsync(s => s.General.CloseBehavior = CloseBehavior.AskEveryTime);
        Assert.Equal(WindowCloseAction.PromptUser, shell.HandleWindowClosing());
        Assert.True(shell.IsClosePromptOpen);

        var hidToTray = false;
        shell.HideToTrayRequested += (_, _) => hidToTray = true;
        shell.RememberCloseChoice = true;
        shell.ConfirmMinimizeToTrayCommand.Execute(null);

        Assert.False(shell.IsClosePromptOpen);
        Assert.True(hidToTray);
        Assert.Equal(CloseBehavior.MinimizeToTray, settings.Current.General.CloseBehavior);

        // Prompt -> Exit with RememberCloseChoice
        await settings.UpdateAsync(s => s.General.CloseBehavior = CloseBehavior.AskEveryTime);
        Assert.Equal(WindowCloseAction.PromptUser, shell.HandleWindowClosing());
        var exited = false;
        shell.ExitRequested += (_, _) => exited = true;
        shell.RememberCloseChoice = true;
        shell.ConfirmExitApplicationCommand.Execute(null);

        Assert.True(exited);
        Assert.True(shell.IsExplicitExit);
        Assert.Equal(CloseBehavior.ExitApplication, settings.Current.General.CloseBehavior);
        Assert.Equal(WindowCloseAction.ExitApplication, shell.HandleWindowClosing());
    }
}
