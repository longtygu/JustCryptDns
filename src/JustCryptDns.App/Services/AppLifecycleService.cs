using System.IO;
using System.Windows;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

public interface IAppLifecycleService
{
    Task<(bool Launched, string? Error)> ApplyUpdateAndRestartAsync(Func<(bool Ok, string? Error)> launchUpdater);
}

public sealed class AppLifecycleService : IAppLifecycleService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<AppLifecycleService> _logger;

    public AppLifecycleService(IServiceProvider services, ILogger<AppLifecycleService> logger)
    {
        _services = services;
        _logger = logger;
    }

    public async Task<(bool Launched, string? Error)> ApplyUpdateAndRestartAsync(
        Func<(bool Ok, string? Error)> launchUpdater)
    {
        ArgumentNullException.ThrowIfNull(launchUpdater);

        try
        {
            using var stopCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));

            if (_services.GetService<IBypassEngineService>() is { } bypassEngine)
            {
                await bypassEngine.StopAsync(stopCts.Token).ConfigureAwait(false);
            }

            if (_services.GetService<IDnsEngine>() is { } dnsEngine)
            {
                await dnsEngine.StopAsync(stopCts.Token).ConfigureAwait(false);
            }

            if (_services.GetService<ISettingsService>() is { } settings)
            {
                await settings.FlushAsync(stopCts.Token).ConfigureAwait(false);
            }

            var hasDnsBackup = _services.GetService<IWindowsDnsManager>()?.HasActiveBackup() == true;
            var hasProxyBackup = _services.GetService<IWindowsProxyManager>()?.HasActiveBackup() == true;
            if (!hasDnsBackup && !hasProxyBackup)
            {
                _services.GetService<IBootRecoveryRegistrar>()?.ClearAll();
            }

            var (ok, err) = launchUpdater();
            if (!ok)
            {
                return (false, err ?? "Failed to launch the updater.");
            }

            _logger.LogInformation("Updater launched; shutting down UI for in-place update.");
            if (Application.Current is { } app)
            {
                await app.Dispatcher.InvokeAsync(() =>
                {
                    if (_services.GetService<ShellViewModel>() is { } shell)
                    {
                        shell.IsExplicitExit = true;
                    }

                    app.Shutdown(0);
                });
            }

            return (true, null);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _logger.LogError(ex, "Applying update and restarting failed.");
            return (false, ex.Message);
        }
    }
}
