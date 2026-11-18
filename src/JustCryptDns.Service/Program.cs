using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Infrastructure.Logging;
using JustCryptDns.Infrastructure.Storage;
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
