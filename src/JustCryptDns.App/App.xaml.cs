using System.Windows;
using System.Windows.Threading;
using JustCryptDns.App.Composition;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
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
        settings.Changed += (_, current) => ApplyPresentation(current);

        var window = _services.GetRequiredService<MainWindow>();
        _logger.LogDebug("Main window constructed.");
        MainWindow = window;
        window.Closed += (_, _) => Shutdown(0);
        window.ContentRendered += (_, _) => _logger.LogInformation(
            "First frame rendered {Elapsed} ms after process start.",
            (int)(DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalMilliseconds);
        Diagnostics.DevSnapshot.TryAttach(window, _services.GetRequiredService<ViewModels.ShellViewModel>(), _logger);
        window.Show();
        _logger.LogInformation(
            "Main window shown {Width}x{Height} in {Elapsed} ms since process start.",
            window.ActualWidth,
            window.ActualHeight,
            (int)(DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalMilliseconds);

        _instanceGuard.ListenForActivation(() => Dispatcher.BeginInvoke(ActivateMainWindow));
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _logger.LogInformation("JustCryptDns UI exiting with code {Code}.", e.ApplicationExitCode);
        if (_services?.GetService<ISettingsService>() is { } settings)
        {
            settings.FlushAsync().GetAwaiter().GetResult();
        }

        _services?.Dispose();
        _instanceGuard?.Dispose();
        LoggingSetup.Shutdown();
        base.OnExit(e);
    }

    private void ApplyPresentation(AppSettings settings)
    {
        _services!.GetRequiredService<IAppearanceService>().Apply(settings.Appearance);
        LocalizationManager.Instance.SetLanguage(settings.General.Language);
        LoggingSetup.SetLevel(settings.Performance.LogLevel);
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
