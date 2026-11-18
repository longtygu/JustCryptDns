using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Filtering;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Gaming;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Composition;

public static class ServiceRegistration
{
    public static ServiceProvider Build(IAppPaths paths, ILoggerFactory loggerFactory, ISettingsStore store, SettingsLoadResult initialSettings)
    {
        var services = new ServiceCollection();

        // Infrastructure
        services.AddSingleton(paths);
        services.AddSingleton(loggerFactory);
        services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));
        services.AddSingleton(store);
        services.AddSingleton<ISettingsService>(sp =>
            new SettingsService(store, sp.GetRequiredService<ILogger<SettingsService>>(), initialSettings));
        services.AddSingleton<IStartupService>(sp =>
            new RegistryStartupService(sp.GetRequiredService<ILogger<RegistryStartupService>>()));
        services.AddSingleton<IServiceClient>(sp =>
            new NamedPipeServiceClient(sp.GetRequiredService<ILogger<NamedPipeServiceClient>>()));

        // Network & DNS Engine
        services.AddSingleton<INetworkInfoService, NetworkInfoService>();
        services.AddSingleton<IWindowsDnsManager, WindowsNetworkDnsService>();
        services.AddSingleton<IDnsCryptProxyManager, DnsCryptProxyManager>();
        services.AddSingleton<IResolverLibraryService, ResolverLibraryService>();
        services.AddSingleton<IDnsRoutingService, DnsRoutingService>();
        services.AddSingleton<IDnsFilteringService, DnsFilteringService>();
        services.AddSingleton<IDnsCacheService, DnsCacheService>();
        services.AddSingleton<IDnsEngine, DnsEngineService>();
        services.AddSingleton<IGamingEngineService, GamingEngineService>();

        // UI services
        services.AddSingleton<IThemeService, ThemeService>();
        services.AddSingleton<IAppearanceService, AppearanceService>();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<ITrayIconService, TrayIconService>();
        services.AddSingleton<IPageFactory, PageFactory>();

        // Shell
        services.AddSingleton<ShellViewModel>();
        services.AddSingleton<MainWindow>();

        // Pages: transient, created on navigation and disposed when left.
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<DnsManagerViewModel>();
        services.AddTransient<ResolverLibraryViewModel>();
        services.AddTransient<RoutingViewModel>();
        services.AddTransient<FilteringViewModel>();
        services.AddTransient<GamingViewModel>();
        services.AddTransient<SettingsViewModel>();
        services.AddTransient<AppearanceViewModel>();

        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }
}
