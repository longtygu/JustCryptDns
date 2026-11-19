using System.Net;
using System.Windows;
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
using JustCryptDns.Infrastructure.Logging;
using JustCryptDns.Infrastructure.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.App;

public partial class App : Application
{
    private SingleInstanceGuard? _instanceGuard;
    private ServiceProvider? _services;
    private ILogger<App> _logger = NullLogger<App>.Instance;
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

        _instanceGuard = SingleInstanceGuard.Acquire("JustCryptDns");
        if (!_instanceGuard.IsPrimary)
        {
            _instanceGuard.SignalPrimary();
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

    protected override void OnExit(ExitEventArgs e)
    {
        _logger.LogInformation("JustCryptDns UI exiting with code {Code}.", e.ApplicationExitCode);
        if (_services?.GetService<IBypassEngineService>() is { } bypassEngine)
        {
            bypassEngine.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        if (_services?.GetService<IDnsEngine>() is { } dnsEngine)
        {
            dnsEngine.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        if (_services?.GetService<ISettingsService>() is { } settings)
        {
            settings.FlushAsync().GetAwaiter().GetResult();
        }

        _services?.Dispose();
        _instanceGuard?.Dispose();
        LoggingSetup.Shutdown();
        base.OnExit(e);
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
