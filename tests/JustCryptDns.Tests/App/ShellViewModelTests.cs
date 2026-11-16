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

    private static (ShellViewModel Shell, FakeFactory Factory, MemoryStore Store) Create()
    {
        var factory = new FakeFactory();
        var store = new MemoryStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        return (new ShellViewModel(factory, settings, NullLogger<ShellViewModel>.Instance), factory, store);
    }

    [Fact]
    public void StartsOnDashboard()
    {
        var (shell, factory, _) = Create();

        Assert.Equal(PageKeys.Dashboard, shell.CurrentPageKey);
        Assert.Single(factory.Created);
        Assert.Equal(["to"], factory.Created[0].Events);
    }

    [Fact]
    public void Navigating_DeactivatesAndDisposesPreviousPage()
    {
        var (shell, factory, _) = Create();
        var dashboard = factory.Created[0];

        shell.NavigateTo(PageKeys.Gaming);

        Assert.Equal(PageKeys.Gaming, shell.CurrentPageKey);
        Assert.Equal(["to", "from", "disposed"], dashboard.Events);
    }

    [Fact]
    public void FooterAndMainSelections_AreMutuallyExclusive()
    {
        var (shell, _, _) = Create();

        shell.NavigateTo(PageKeys.Settings);
        Assert.Null(shell.SelectedNavItem);
        Assert.Equal(PageKeys.Settings, shell.SelectedFooterItem?.Key);

        shell.NavigateTo(PageKeys.Routing);
        Assert.Null(shell.SelectedFooterItem);
        Assert.Equal(PageKeys.Routing, shell.SelectedNavItem?.Key);
    }

    [Fact]
    public void ReselectingSamePage_DoesNotRecreateIt()
    {
        var (shell, factory, _) = Create();

        shell.NavigateTo(PageKeys.Dashboard);

        Assert.Single(factory.Created);
    }

    [Fact]
    public void ToggleSidebar_PersistsState()
    {
        var (shell, _, store) = Create();

        shell.ToggleSidebarCommand.Execute(null);

        Assert.True(shell.IsSidebarCollapsed);
        Assert.True(store.Saved?.Appearance.SidebarCollapsed);
    }

    [Fact]
    public void AllNineSectionsArePresent()
    {
        var (shell, _, _) = Create();
        var keys = shell.NavItems.Concat(shell.FooterItems).Select(i => i.Key).ToList();

        Assert.Equal(
            [PageKeys.Dashboard, PageKeys.DnsManager, PageKeys.Resolvers, PageKeys.Routing, PageKeys.Gaming,
             PageKeys.Filtering, PageKeys.Diagnostics, PageKeys.Monitor, PageKeys.Settings],
            keys);
    }
}
