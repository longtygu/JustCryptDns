using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using JustCryptDns.App.Composition;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.Infrastructure.Ipc;
using JustCryptDns.Infrastructure.Logging;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.App;

public partial class App : Application
{
    private SingleInstanceGuard? _instanceGuard;
    private ServiceProvider? _services;
    private ILoggerFactory? _recoveryLoggerFactory;
    private ILogger<App> _logger = NullLogger<App>.Instance;
    private readonly object _shutdownSync = new();
    private bool _shutdownCleanupCompleted;
    private bool _servicesDisposed;
    private string? _lastAppearanceJson;
    private string? _lastLanguage;
    private LogLevelSetting? _lastLogLevel;

    public static bool ShouldStartMinimized(IReadOnlyList<string> args, GeneralSettings general)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(general);

        if (args.Any(a => string.Equals(a, "--show", StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return args.Any(a => string.Equals(a, "--minimized", StringComparison.OrdinalIgnoreCase))
            || general.StartMinimized;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var isRecoveryMode = e.Args.Any(a =>
            string.Equals(a, RegistryBootRecoveryRegistrar.RecoveryArgument, StringComparison.OrdinalIgnoreCase));
        var clearFirewallOnRecovery = e.Args.Any(a =>
            string.Equals(a, "--clear-firewall", StringComparison.OrdinalIgnoreCase));

        _instanceGuard = SingleInstanceGuard.Acquire("JustCryptDns");
        if (!_instanceGuard.IsPrimary)
        {
            if (!isRecoveryMode)
            {
                _instanceGuard.SignalPrimary();
            }

            Shutdown(0);
            return;
        }

        var paths = new AppPaths(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_DATA_DIR"));
        paths.EnsureCreated();

        // Load settings before logging is configured so the configured level/retention apply from the first line.
        var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var initial = store.Load();
        var loggerFactory = LoggingSetup.CreateLoggerFactory(
            paths, "ui", initial.Settings.Performance.LogLevel, initial.Settings.Performance.LogRetentionDays);
        _logger = loggerFactory.CreateLogger<App>();

        if (isRecoveryMode)
        {
            _recoveryLoggerFactory = loggerFactory;
            var exitCode = RunHeadlessBootRecovery(paths, loggerFactory, clearFirewallOnRecovery);
            Shutdown(exitCode);
            return;
        }

        _logger.LogInformation("JustCryptDns UI starting. Version {Version}", typeof(App).Assembly.GetName().Version);

        RegisterExceptionHandlers();

        // Software rendering fallback for unsupported GPUs / remote or virtual sessions.
        if (Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SOFTWARE_RENDER") == "1")
        {
            System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
            _logger.LogInformation("Software rendering enabled.");
        }

        var runtimeStore = new JsonSettingsStore(paths, loggerFactory.CreateLogger<JsonSettingsStore>());
        _services = ServiceRegistration.Build(paths, loggerFactory, runtimeStore, initial);

        var settings = _services.GetRequiredService<ISettingsService>();
        ApplyPresentation(settings.Current);
        settings.Changed += (_, current) =>
        {
            if (Dispatcher.CheckAccess())
            {
                ApplyPresentation(current);
            }
            else
            {
                Dispatcher.BeginInvoke(() => ApplyPresentation(current));
            }
        };

        // Initialize system tray icon.
        var shell = _services.GetRequiredService<ShellViewModel>();
        var tray = _services.GetRequiredService<ITrayIconService>();
        tray.OpenRequested += (_, _) => Dispatcher.BeginInvoke(ActivateMainWindow);
        tray.ExitRequested += (_, _) => Dispatcher.BeginInvoke(() =>
        {
            shell.IsExplicitExit = true;
            Shutdown(0);
        });
        tray.Initialize();

        // Probe background service, recover orphaned backups, and auto-start local engines in standalone mode.
        _ = InitializeStandaloneEnginesAsync(_services, _logger);
        _ = CheckForUpdatesInBackgroundAsync(_services, _logger);

        var window = _services.GetRequiredService<MainWindow>();
        _logger.LogDebug("Main window constructed.");
        MainWindow = window;
        window.Closed += (_, _) => Shutdown(0);
        window.ContentRendered += (_, _) => _logger.LogInformation(
            "First frame rendered {Elapsed} ms after process start.",
            (int)(DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalMilliseconds);
        var dnsEngine = _services.GetRequiredService<Core.Interfaces.IDnsEngine>();
        Diagnostics.DevSnapshot.TryAttach(window, shell, dnsEngine, _logger);

        var startMinimized = ShouldStartMinimized(e.Args, settings.Current.General)
            && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_DIR"));
        if (startMinimized)
        {
            _logger.LogInformation("Started minimized to system tray.");
        }
        else
        {
            window.Show();
            _logger.LogInformation(
                "Main window shown {Width}x{Height} in {Elapsed} ms since process start.",
                window.ActualWidth,
                window.ActualHeight,
                (int)(DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalMilliseconds);
        }

        _instanceGuard.ListenForActivation(() => Dispatcher.BeginInvoke(ActivateMainWindow));
    }

    protected override void OnSessionEnding(SessionEndingCancelEventArgs e)
    {
        e.Cancel = false;
        _logger.LogWarning("Windows session ending ({Reason}); restoring original DNS and proxy settings.", e.ReasonSessionEnding);

        nint hwnd = 0;
        if (MainWindow is { } mainWindow)
        {
            try
            {
                hwnd = new WindowInteropHelper(mainWindow).Handle;
            }
            catch (InvalidOperationException)
            {
                hwnd = 0;
            }
        }

        _ = RegistryBootRecoveryRegistrar.TryCreateShutdownBlockReason(
            hwnd,
            "Restoring original Windows DNS and proxy settings...");
        try
        {
            RunSafeShutdownCleanupSync(timeoutMs: 4500, source: $"SessionEnding:{e.ReasonSessionEnding}");
        }
        finally
        {
            RegistryBootRecoveryRegistrar.TryDestroyShutdownBlockReason(hwnd);
        }

        base.OnSessionEnding(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _logger.LogInformation("JustCryptDns UI exiting with code {Code}.", e.ApplicationExitCode);
        RunSafeShutdownCleanupSync(timeoutMs: 6000, source: "OnExit");

        Volatile.Write(ref _servicesDisposed, true);
        if (_services is { } services)
        {
            try
            {
                // TrayIconService wraps an HwndSource tied to the UI Dispatcher thread; dispose it here before offloading async container teardown.
                services.GetService<ITrayIconService>()?.Dispose();

                if (services.GetService<IBypassEngineService>() is { } bypassEngine)
                {
                    Task.Run(() => bypassEngine.DisposeAsync().AsTask()).Wait(1500);
                }

                if (services.GetService<IDnsEngine>() is { } dnsEngine)
                {
                    Task.Run(() => dnsEngine.DisposeAsync().AsTask()).Wait(1500);
                }

                Task.Run(() => services.DisposeAsync().AsTask()).Wait(2000);
            }
            catch (Exception ex) when (ex is AggregateException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
                _logger.LogWarning(ex, "Engine async disposal during exit did not finish cleanly.");
            }

            _services = null;
        }

        _instanceGuard?.Dispose();
        _instanceGuard = null;
        _recoveryLoggerFactory?.Dispose();
        _recoveryLoggerFactory = null;
        LoggingSetup.Shutdown();
        base.OnExit(e);
    }

    private int RunHeadlessBootRecovery(AppPaths paths, ILoggerFactory loggerFactory, bool clearFirewall = false)
    {
        _logger.LogInformation("Running headless boot recovery ({Arg}, clearFirewall={ClearFirewall}).", RegistryBootRecoveryRegistrar.RecoveryArgument, clearFirewall);
        try
        {
            return Task.Run(async () =>
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                var bootRecovery = new RegistryBootRecoveryRegistrar(
                    loggerFactory.CreateLogger<RegistryBootRecoveryRegistrar>());
                using var windowsDns = new WindowsNetworkDnsService(
                    paths,
                    new NetworkInfoService(loggerFactory.CreateLogger<NetworkInfoService>()),
                    loggerFactory.CreateLogger<WindowsNetworkDnsService>(),
                    bootRecovery: bootRecovery);
                using var windowsProxy = new WindowsSystemProxyService(
                    paths,
                    loggerFactory.CreateLogger<WindowsSystemProxyService>(),
                    bootRecovery: bootRecovery);
                var serviceClient = new NamedPipeServiceClient(
                    loggerFactory.CreateLogger<NamedPipeServiceClient>());

                using (var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token))
                {
                    probeCts.CancelAfter(TimeSpan.FromMilliseconds(1200));
                    await serviceClient.RefreshStatusAsync(probeCts.Token).ConfigureAwait(false);
                }

                await windowsProxy.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false, cts.Token).ConfigureAwait(false);

                if (serviceClient.ConnectionState != ServiceConnectionState.Connected)
                {
                    await windowsDns.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false, cts.Token).ConfigureAwait(false);
                }

                using (var fw = new WindowsFirewallService(loggerFactory.CreateLogger<WindowsFirewallService>()))
                {
                    var fwRes = clearFirewall
                        ? await fw.ClearAllManagedRulesAsync(cts.Token).ConfigureAwait(false)
                        : await fw.ClearLockdownAndLeakGuardAsync(cts.Token).ConfigureAwait(false);
                    _logger.LogInformation(
                        "Boot recovery firewall cleanup (clearAll={ClearAll}): success={Success}, removed={Removed}, msg={Message}",
                        clearFirewall, fwRes.Success, fwRes.RemovedRuleCount, fwRes.Message);
                }

                var dnsRemaining = windowsDns.HasActiveBackup();
                var proxyRemaining = windowsProxy.HasActiveBackup();
                if (dnsRemaining)
                {
                    bootRecovery.Arm("dns");
                }

                if (proxyRemaining)
                {
                    bootRecovery.Arm("proxy");
                }

                if (!dnsRemaining && !proxyRemaining)
                {
                    bootRecovery.ClearAll();
                }

                return dnsRemaining || proxyRemaining ? 1 : 0;
            }).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Headless boot recovery encountered an error.");
            return 1;
        }
    }

    private void RunSafeShutdownCleanupSync(int timeoutMs, string source)
    {
        var services = _services;
        if (services is null || Volatile.Read(ref _servicesDisposed))
        {
            return;
        }

        if (!Monitor.TryEnter(_shutdownSync, Math.Min(timeoutMs, 500)))
        {
            return;
        }

        try
        {
            if (_shutdownCleanupCompleted || Volatile.Read(ref _servicesDisposed))
            {
                return;
            }

            using var cts = new CancellationTokenSource(timeoutMs);
            var cleanupTask = Task.Run(async () =>
            {
                if (services.GetService<IBypassEngineService>() is { } bypassEngine)
                {
                    await bypassEngine.StopAsync(cts.Token).ConfigureAwait(false);
                }

                if (services.GetService<IDnsEngine>() is { } dnsEngine)
                {
                    await dnsEngine.StopAsync(cts.Token).ConfigureAwait(false);
                }

                if (services.GetService<ISettingsService>() is { } settings)
                {
                    await settings.FlushAsync(cts.Token).ConfigureAwait(false);
                }

                // Always lift transient Emergency Lockdown (and standalone DNS Leak Guard when service is not keeping DNS alive).
                var svcState = services.GetService<IServiceClient>()?.ConnectionState;
                if (svcState != ServiceConnectionState.Connected)
                {
                    if (services.GetService<IWindowsFirewallManager>() is { } fw)
                    {
                        await fw.ClearLockdownAndLeakGuardAsync(cts.Token).ConfigureAwait(false);
                    }
                }
                else if (services.GetService<IFirewallBlocklistCoordinator>() is { } coordinator
                    && services.GetService<ISettingsService>() is { } appSettings)
                {
                    var conn = appSettings.Current.Connections;
                    var fwStatus = await coordinator.GetStatusAsync(cts.Token).ConfigureAwait(false);
                    if (fwStatus.IsLockdownActive)
                    {
                        await coordinator.SyncSecurityAsync(
                            new Core.Models.FirewallSyncRequestPayload(
                                conn.BlockedRules,
                                conn.BlockedApps,
                                conn.EnableDnsLeakGuard,
                                EnableEmergencyLockdown: false),
                            cts.Token).ConfigureAwait(false);
                    }
                }

                var hasDnsBackup = services.GetService<IWindowsDnsManager>()?.HasActiveBackup() == true;
                var hasProxyBackup = services.GetService<IWindowsProxyManager>()?.HasActiveBackup() == true;
                if (!hasDnsBackup && !hasProxyBackup)
                {
                    services.GetService<IBootRecoveryRegistrar>()?.ClearAll();
                }
            });

            if (cleanupTask.Wait(timeoutMs))
            {
                _shutdownCleanupCompleted = true;
                _logger.LogInformation("Shutdown cleanup ({Source}) completed cleanly.", source);
            }
            else
            {
                cts.Cancel();
                _logger.LogWarning(
                    "Shutdown cleanup ({Source}) timed out after {TimeoutMs} ms; RunOnce recovery remains armed if backups remain active.",
                    source,
                    timeoutMs);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or AggregateException or ObjectDisposedException or IOException)
        {
            _logger.LogWarning(ex, "Shutdown cleanup ({Source}) did not complete cleanly.", source);
        }
        finally
        {
            Monitor.Exit(_shutdownSync);
        }
    }

    private static async Task InitializeStandaloneEnginesAsync(ServiceProvider services, ILogger<App> logger)
    {
        try
        {
            var serviceClient = services.GetRequiredService<IServiceClient>();
            var windowsDns = services.GetRequiredService<IWindowsDnsManager>();
            var windowsProxy = services.GetRequiredService<IWindowsProxyManager>();
            var settings = services.GetRequiredService<ISettingsService>();
            var dnsEngine = services.GetRequiredService<IDnsEngine>();
            var bypassEngine = services.GetRequiredService<IBypassEngineService>();

            await serviceClient.RefreshStatusAsync().ConfigureAwait(false);
            await windowsProxy.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false).ConfigureAwait(false);

            if (serviceClient.ConnectionState == ServiceConnectionState.Connected)
            {
                return;
            }

            await windowsDns.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_DIR"))
                || !settings.Current.General.AutoStartDnsEngine)
            {
                return;
            }

            var dns = settings.Current.Dns;
            if (string.Equals(dns.ListenAddress, DnsSettings.DefaultListenAddress, StringComparison.OrdinalIgnoreCase)
                && dns.ListenPort == DnsSettings.DefaultListenPort
                && PortConflictDetector.CheckConflict(IPAddress.Loopback, 53) is not null
                && PortConflictDetector.FindAvailableLoopbackForPort53(IPAddress.Loopback) is { } altIp)
            {
                logger.LogInformation("Port 53 on 127.0.0.1 is busy; auto-selecting alternate loopback {AltIp}:53.", altIp);
                await settings.UpdateAsync(s =>
                {
                    s.Dns.ListenAddress = altIp;
                    s.Dns.EnableIpv6 = false;
                    s.Dns.ConfigureWindowsAdapter = true;
                }).ConfigureAwait(false);
            }

            var (ok, err) = await dnsEngine.StartAsync().ConfigureAwait(false);
            if (!ok)
            {
                logger.LogWarning("Standalone DNS auto-start did not succeed: {Error}", err);
                return;
            }

            _ = dnsEngine.ProbeActiveResolverAsync();

            if (settings.Current.Bypass.IsBypassEnabled && settings.Current.Bypass.AutoStartWithDnsEngine)
            {
                var (bypassOk, bypassErr) = await bypassEngine.StartAsync().ConfigureAwait(false);
                if (!bypassOk)
                {
                    logger.LogWarning("Standalone DPI bypass auto-start did not succeed: {Error}", bypassErr);
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Standalone startup initialization encountered an error.");
        }
    }

    private static async Task CheckForUpdatesInBackgroundAsync(ServiceProvider services, ILogger<App> logger)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_DIR")))
            {
                return;
            }

            var settings = services.GetRequiredService<ISettingsService>();
            if (!settings.Current.Updates.AutoCheckOnStartup)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(4)).ConfigureAwait(false);
            var updateService = services.GetRequiredService<IUpdateService>();
            await updateService.CheckForUpdatesAsync(settings.Current.Updates.IncludePrereleases).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Startup background update check failed safely.");
        }
    }

    private void ApplyPresentation(AppSettings settings)
    {
        var appearanceJson = System.Text.Json.JsonSerializer.Serialize(settings.Appearance, SettingsJson.Options);
        if (!string.Equals(appearanceJson, _lastAppearanceJson, StringComparison.Ordinal))
        {
            _lastAppearanceJson = appearanceJson;
            _services!.GetRequiredService<IAppearanceService>().Apply(settings.Appearance);
        }

        if (!string.Equals(settings.General.Language, _lastLanguage, StringComparison.OrdinalIgnoreCase))
        {
            _lastLanguage = settings.General.Language;
            LocalizationManager.Instance.SetLanguage(settings.General.Language);
        }

        if (_lastLogLevel != settings.Performance.LogLevel)
        {
            _lastLogLevel = settings.Performance.LogLevel;
            LoggingSetup.SetLevel(settings.Performance.LogLevel);
        }
    }

    private void ActivateMainWindow()
    {
        if (MainWindow is null)
        {
            return;
        }

        if (!MainWindow.IsVisible)
        {
            MainWindow.Show();
        }

        if (MainWindow.WindowState == WindowState.Minimized)
        {
            MainWindow.WindowState = WindowState.Normal;
        }

        MainWindow.Activate();
        MainWindow.Topmost = true;
        MainWindow.Topmost = false;
        MainWindow.Focus();
    }

    private void RegisterExceptionHandlers()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            RunSafeShutdownCleanupSync(timeoutMs: 2000, source: "ProcessExit");
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            _logger.LogCritical(args.ExceptionObject as Exception, "Unhandled domain exception (terminating={Terminating}).", args.IsTerminating);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            _logger.LogError(args.Exception, "Unobserved task exception.");
            args.SetObserved();
        };
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _logger.LogCritical(e.Exception, "Unhandled UI exception.");
        LoggingSetup.Shutdown();
    }
}
