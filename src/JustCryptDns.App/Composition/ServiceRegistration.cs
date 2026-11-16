using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Services;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Services;
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

        // Network
        services.AddSingleton<INetworkInfoService, NetworkInfoService>();

        // UI services
        services.AddSingleton<IThemeService, ThemeService>();
        services.AddSingleton<IPageFactory, PageFactory>();

        // Shell
        services.AddSingleton<ShellViewModel>();
        services.AddSingleton<MainWindow>();

        // Pages: transient, created on navigation and disposed when left.
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<SettingsViewModel>();

        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }
}
