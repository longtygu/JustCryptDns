using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Infrastructure.Logging;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Service;

public static class Program
{
    public const string WindowsServiceName = "JustCryptDnsService";

    public static async Task<int> Main(string[] args)
    {
        var paths = new AppPaths(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_DATA_DIR"));
        paths.EnsureCreated();

        var bootstrapStore = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var initial = bootstrapStore.Load();
        using var loggerFactory = LoggingSetup.CreateLoggerFactory(
            paths,
            "service",
            initial.Settings.Performance.LogLevel,
            initial.Settings.Performance.LogRetentionDays);

        var logger = loggerFactory.CreateLogger("JustCryptDns.Service");
        try
        {
            var builder = Host.CreateApplicationBuilder(args);
            builder.Services.AddWindowsService(options => options.ServiceName = WindowsServiceName);

            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<ILoggerFactory>(loggerFactory);
            builder.Services.AddSingleton<IAppPaths>(paths);
            builder.Services.AddSingleton<ISettingsStore, JsonSettingsStore>();
            builder.Services.AddSingleton<ISettingsService>(sp =>
                new SettingsService(sp.GetRequiredService<ISettingsStore>(), sp.GetRequiredService<ILogger<SettingsService>>(), initial));
            builder.Services.AddSingleton<INetworkInfoService, NetworkInfoService>();
            builder.Services.AddSingleton<IWindowsDnsManager, WindowsNetworkDnsService>();
            builder.Services.AddSingleton<IDnsCryptProxyManager, DnsCryptProxyManager>();
            builder.Services.AddSingleton<IDnsEngine, DnsEngineService>();
            builder.Services.AddSingleton<ServiceStateManager>();
            builder.Services.AddSingleton<IServiceIpcHandler>(sp => sp.GetRequiredService<ServiceStateManager>());
            builder.Services.AddSingleton<NamedPipeIpcServer>();
            builder.Services.AddHostedService<DnsBackgroundWorker>();

            using var host = builder.Build();
            await host.RunAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "JustCryptDns background service terminated unexpectedly.");
            return 1;
        }
        finally
        {
            LoggingSetup.Shutdown();
        }
    }
}
