using JustCryptDns.App.ViewModels;
using Microsoft.Extensions.DependencyInjection;

namespace JustCryptDns.App.Composition;

/// <summary>
/// Creates page ViewModels on demand so unused pages consume no memory.
/// </summary>
public sealed class PageFactory : IPageFactory
{
    private readonly IServiceProvider _services;

    public PageFactory(IServiceProvider services) => _services = services;

    public PageViewModel Create(string pageKey) => pageKey switch
    {
        PageKeys.Dashboard => _services.GetRequiredService<DashboardViewModel>(),
        PageKeys.Settings => _services.GetRequiredService<SettingsViewModel>(),
        PageKeys.Appearance => _services.GetRequiredService<AppearanceViewModel>(),
        PageKeys.DnsManager => _services.GetRequiredService<DnsManagerViewModel>(),
        PageKeys.Resolvers => _services.GetRequiredService<ResolverLibraryViewModel>(),
        PageKeys.Routing => _services.GetRequiredService<RoutingViewModel>(),
        PageKeys.Filtering => _services.GetRequiredService<FilteringViewModel>(),
        PageKeys.Gaming => _services.GetRequiredService<GamingViewModel>(),
        PageKeys.Bypass => _services.GetRequiredService<BypassViewModel>(),
        PageKeys.Diagnostics => _services.GetRequiredService<DiagnosticsViewModel>(),
        PageKeys.Monitor => _services.GetRequiredService<LiveMonitorViewModel>(),
        _ => throw new ArgumentOutOfRangeException(nameof(pageKey), pageKey, "Unknown page."),
    };
}
