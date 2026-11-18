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
        PageKeys.DnsManager => new PlannedFeatureViewModel(pageKey, phase: 4, featureCount: 4),
        PageKeys.Resolvers => new PlannedFeatureViewModel(pageKey, phase: 5, featureCount: 4),
        PageKeys.Routing => new PlannedFeatureViewModel(pageKey, phase: 6, featureCount: 4),
        PageKeys.Filtering => new PlannedFeatureViewModel(pageKey, phase: 7, featureCount: 4),
        PageKeys.Gaming => new PlannedFeatureViewModel(pageKey, phase: 8, featureCount: 4),
        PageKeys.Diagnostics => new PlannedFeatureViewModel(pageKey, phase: 10, featureCount: 4),
        PageKeys.Monitor => new PlannedFeatureViewModel(pageKey, phase: 10, featureCount: 4),
        _ => throw new ArgumentOutOfRangeException(nameof(pageKey), pageKey, "Unknown page."),
    };
}
