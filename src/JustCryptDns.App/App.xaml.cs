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
    private static readonly long StartupTimestamp = System.Diagnostics.Stopwatch.GetTimestamp();

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
    private string? _lastServiceSyncFingerprint;
    private int _serviceReloadGeneration;

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

        var paths = new AppPaths(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_DATA_DIR"));
        paths.EnsureCreated();
        if (OperatingSystem.IsWindows())
        {
            SharedDataAclHelper.EnsureSharedDirectoryWritable(paths);
        }

        var migratedLegacySettings = paths.TryMigrateLegacyUserDataToShared();

        // Load settings before logging is configured so the configured level/retention apply from the first line.
        var store = new JsonSettingsStore(paths, NullLogger<JsonSettingsStore>.Instance);
        var initial = store.Load();
        var loggerFactory = LoggingSetup.CreateLoggerFactory(
            paths, isRecoveryMode ? "recovery" : "ui", initial.Settings.Performance.LogLevel, initial.Settings.Performance.LogRetentionDays);
        _logger = loggerFactory.CreateLogger<App>();

        if (isRecoveryMode)
        {
            _recoveryLoggerFactory = loggerFactory;
            var exitCode = RunHeadlessBootRecovery(paths, loggerFactory, clearFirewallOnRecovery);
            Shutdown(exitCode);
            return;
        }

        try
        {
            _instanceGuard = SingleInstanceGuard.Acquire("JustCryptDns");
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "SingleInstanceGuard named kernel objects were inaccessible; continuing startup.");
        }

        if (_instanceGuard is { IsPrimary: false })
        {
            _instanceGuard.SignalPrimary();
            Shutdown(0);
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
        _lastServiceSyncFingerprint = ComputeServiceSyncFingerprint(settings.Current);
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

            var fingerprint = ComputeServiceSyncFingerprint(current);
            if (!string.Equals(fingerprint, _lastServiceSyncFingerprint, StringComparison.Ordinal))
            {
                _lastServiceSyncFingerprint = fingerprint;
                ScheduleServiceConfigSync();
            }
        };

        // Initialize system tray icon before creating MainWindow so --minimized launches have near-zero UI/memory footprint.
        var tray = _services.GetRequiredService<ITrayIconService>();
        tray.OpenRequested += (_, _) => Dispatcher.BeginInvoke(ActivateMainWindow);
        tray.ExitRequested += (_, _) => Dispatcher.BeginInvoke(() =>
        {
            if (MainWindow?.DataContext is ShellViewModel shell)
            {
                shell.IsExplicitExit = true;
            }

            Shutdown(0);
        });
        tray.Initialize();

        // Probe background service, recover orphaned backups, and auto-start local engines in standalone mode.
        _ = InitializeStandaloneEnginesAsync(_services, _logger, migratedLegacySettings);
        _services.GetRequiredService<IOperationModeService>().Start();
        _ = CheckForUpdatesInBackgroundAsync(_services, _logger);

        var startMinimized = ShouldStartMinimized(e.Args, settings.Current.General)
            && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JUSTCRYPTDNS_SNAPSHOT_DIR"));
        if (startMinimized)
        {
            _logger.LogInformation("Started minimized to system tray (MainWindow deferred for zero-idle overhead).");
        }
        else
        {
            var window = EnsureMainWindowCreated();
            window.Show();
            _logger.LogInformation(
                "Main window shown {Width}x{Height} in {Elapsed:0} ms since process start.",
                window.ActualWidth,
                window.ActualHeight,
                System.Diagnostics.Stopwatch.GetElapsedTime(StartupTimestamp).TotalMilliseconds);
        }

        _instanceGuard?.ListenForActivation(() => Dispatcher.BeginInvoke(ActivateMainWindow));
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
        Interlocked.Increment(ref _serviceReloadGeneration);
        if (_services is { } services)
        {
            try
            {
                // TrayIconService wraps an HwndSource tied to the UI Dispatcher thread; dispose it here before offloading async container teardown.
                services.GetService<ITrayIconService>()?.Dispose();

                Task.Run(async () => await services.DisposeAsync().ConfigureAwait(false)).Wait(3500);
            }
            catch (Exception ex) when (ex is AggregateException or OperationCanceledException or ObjectDisposedException or InvalidOperationException)
            {
                _logger.LogDebug(ex, "Service container async disposal completed with expected cancellation.");
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

                var serviceBypassRunning = serviceClient.ConnectionState == ServiceConnectionState.Connected
                    && serviceClient.LastStatus?.IsBypassRunning == true;
                await windowsProxy.RecoverAfterCrashIfNeededAsync(proxyIsRunning: serviceBypassRunning, cts.Token).ConfigureAwait(false);

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
                var svcState = services.GetService<IServiceClient>()?.ConnectionState;
                if (svcState == ServiceConnectionState.Connected)
                {
                    if (services.GetService<IBypassEngineService>() is HybridBypassEngineProxy hybridBypass)
                    {
                        try
                        {
                            await hybridBypass.StopLocalFallbackOnlyAsync(cts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                        {
                            _logger.LogDebug(ex, "Hybrid bypass fallback stop skipped during shutdown.");
                        }
                    }

                    if (services.GetService<IDnsEngine>() is HybridDnsEngineProxy hybridDns)
                    {
                        try
                        {
                            await hybridDns.StopLocalFallbackOnlyAsync(cts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                        {
                            _logger.LogDebug(ex, "Hybrid DNS fallback stop skipped during shutdown.");
                        }
                    }
                }
                else
                {
                    if (services.GetService<IBypassEngineService>() is { } bypassEngine)
                    {
                        try
                        {
                            await bypassEngine.StopAsync(cts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                        {
                            _logger.LogDebug(ex, "Standalone bypass stop skipped during shutdown.");
                        }
                    }

                    if (services.GetService<IDnsEngine>() is { } dnsEngine
                        && (dnsEngine.GetStats().State != DnsEngineState.Stopped || !IsWindowsServiceInstalledAndAutoStart()))
                    {
                        try
                        {
                            await dnsEngine.StopAsync(cts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                        {
                            _logger.LogDebug(ex, "Standalone DNS stop skipped during shutdown.");
                        }
                    }
                }

                if (services.GetService<ISettingsService>() is { } settings)
                {
                    try
                    {
                        await settings.FlushAsync(cts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                    {
                        _logger.LogDebug(ex, "Settings flush skipped during shutdown.");
                    }
                }

                // Always lift transient Emergency Lockdown (and standalone DNS Leak Guard when service is not keeping DNS alive).
                if (svcState != ServiceConnectionState.Connected)
                {
                    if (services.GetService<IWindowsFirewallManager>() is { } fw)
                    {
                        try
                        {
                            await fw.ClearLockdownAndLeakGuardAsync(cts.Token).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                        {
                            _logger.LogDebug(ex, "Firewall cleanup skipped during shutdown.");
                        }
                    }
                }
                else if (services.GetService<IFirewallBlocklistCoordinator>() is { } coordinator
                    && services.GetService<ISettingsService>() is { } appSettings)
                {
                    try
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
                    catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or OperationCanceledException or ObjectDisposedException)
                    {
                        _logger.LogDebug(ex, "Lockdown release skipped during shutdown.");
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

    private static async Task InitializeStandaloneEnginesAsync(
        ServiceProvider services,
        ILogger<App> logger,
        bool migratedLegacySettings)
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
            var isServiceProcessPresent = IsWindowsServiceRunningOrStarting();
            var isBootWindowAutoStart = IsWindowsServiceInstalledAndAutoStart() && Environment.TickCount64 < 180_000;
            if (serviceClient.ConnectionState != ServiceConnectionState.Connected
                && (isServiceProcessPresent || isBootWindowAutoStart))
            {
                for (var retry = 0; retry < 24 && serviceClient.ConnectionState != ServiceConnectionState.Connected; retry++)
                {
                    await Task.Delay(500).ConfigureAwait(false);
                    await serviceClient.RefreshStatusAsync().ConfigureAwait(false);
                }
            }

            if (serviceClient.ConnectionState != ServiceConnectionState.Connected && isBootWindowAutoStart)
            {
                logger.LogWarning("JustCryptDnsService is configured for Automatic startup but did not respond during boot window; deferring standalone engine startup to avoid port conflicts.");
                return;
            }

            var serviceConnected = serviceClient.ConnectionState == ServiceConnectionState.Connected;
            var serviceBypassRunning = serviceConnected && serviceClient.LastStatus?.IsBypassRunning == true;
            await windowsProxy.RecoverAfterCrashIfNeededAsync(proxyIsRunning: serviceBypassRunning).ConfigureAwait(false);

            if (serviceConnected)
            {
                if (migratedLegacySettings)
                {
                    _ = await serviceClient
                        .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration))
                        .ConfigureAwait(false);
                }

                if (dnsEngine is HybridDnsEngineProxy hybridDns)
                {
                    await hybridDns.RefreshFromServiceAsync().ConfigureAwait(false);
                }

                if (bypassEngine is HybridBypassEngineProxy hybridBypass)
                {
                    await hybridBypass.RefreshFromServiceAsync().ConfigureAwait(false);
                    await hybridBypass.EnsureUserProxySynchronizedAsync().ConfigureAwait(false);
                }

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

            if (settings.Current.Connections.EnableDnsLeakGuard
                && services.GetService<IFirewallBlocklistCoordinator>() is { } fwCoordinator)
            {
                try
                {
                    var conn = settings.Current.Connections;
                    var fwRes = await fwCoordinator.SyncSecurityAsync(new Core.Models.FirewallSyncRequestPayload(
                        conn.BlockedRules,
                        conn.BlockedApps,
                        EnableDnsLeakGuard: true,
                        EnableEmergencyLockdown: false)).ConfigureAwait(false);
                    logger.LogInformation("Standalone DNS Leak Guard auto-sync: success={Success}, msg={Msg}", fwRes.Success, fwRes.Message);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogWarning(ex, "Standalone DNS Leak Guard auto-sync skipped.");
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Standalone startup initialization encountered an error.");
        }
    }

    private static bool IsWindowsServiceRunningOrStarting()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            var procs = System.Diagnostics.Process.GetProcessesByName("JustCryptDns.Service");
            var running = procs.Length > 0;
            foreach (var p in procs)
            {
                p.Dispose();
            }

            return running;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsWindowsServiceInstalledAndAutoStart()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\JustCryptDnsService",
                writable: false);
            return key?.GetValue("Start") is int startMode && startMode == 2;
        }
        catch
        {
            return false;
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

    private void ScheduleServiceConfigSync()
    {
        if (Volatile.Read(ref _servicesDisposed))
        {
            return;
        }

        var generation = Interlocked.Increment(ref _serviceReloadGeneration);
        _ = DebounceServiceConfigSyncAsync(generation);
    }

    private async Task DebounceServiceConfigSyncAsync(int generation)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(400)).ConfigureAwait(false);
            if (Volatile.Read(ref _serviceReloadGeneration) == generation && !Volatile.Read(ref _servicesDisposed))
            {
                await SyncUiSettingsToServiceAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
            // Ignore shutdown timing.
        }
    }

    private async Task SyncUiSettingsToServiceAsync()
    {
        if (Volatile.Read(ref _servicesDisposed) || _services is not { } services)
        {
            return;
        }

        try
        {
            var serviceClient = services.GetService<IServiceClient>();
            if (serviceClient?.ConnectionState != ServiceConnectionState.Connected)
            {
                return;
            }

            var settings = services.GetService<ISettingsService>();
            if (settings is not null)
            {
                await settings.FlushAsync().ConfigureAwait(false);
            }

            _ = await serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration)).ConfigureAwait(false);

            if (services.GetService<IBypassEngineService>() is HybridBypassEngineProxy hybridBypass)
            {
                await hybridBypass.RefreshFromServiceAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "Debounced UI-to-service settings sync skipped during shutdown.");
        }
    }

    private static string ComputeServiceSyncFingerprint(AppSettings settings) =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            settings.Dns,
            settings.Cache,
            settings.Filtering,
            settings.Routing,
            settings.Resilience,
            settings.Gaming,
            settings.Bypass,
            settings.Performance.LogLevel,
            settings.General.AutoStartDnsEngine,
            settings.Connections.EnableDnsLeakGuard,
        }, SettingsJson.Options);

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

    private MainWindow EnsureMainWindowCreated()
    {
        if (MainWindow is MainWindow existing)
        {
            return existing;
        }

        var services = _services ?? throw new InvalidOperationException("Services are not initialized.");
        var shell = services.GetRequiredService<ShellViewModel>();
        var window = services.GetRequiredService<MainWindow>();
        _logger.LogDebug("Main window constructed.");
        MainWindow = window;
        window.Closed += (_, _) => Shutdown(0);
        window.ContentRendered += (_, _) => _logger.LogInformation(
            "First frame rendered {Elapsed:0} ms after process start.",
            System.Diagnostics.Stopwatch.GetElapsedTime(StartupTimestamp).TotalMilliseconds);
        var dnsEngine = services.GetRequiredService<Core.Interfaces.IDnsEngine>();
        Diagnostics.DevSnapshot.TryAttach(window, shell, dnsEngine, _logger);
        return window;
    }

    private void ActivateMainWindow()
    {
        if (Volatile.Read(ref _servicesDisposed) || _services is null)
        {
            return;
        }

        var mainWindow = MainWindow ?? EnsureMainWindowCreated();
        if (!mainWindow.IsVisible)
        {
            mainWindow.Show();
        }

        if (mainWindow.WindowState == WindowState.Minimized)
        {
            mainWindow.WindowState = WindowState.Normal;
        }

        mainWindow.Activate();
        mainWindow.Topmost = true;
        mainWindow.Topmost = false;
        mainWindow.Focus();
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
