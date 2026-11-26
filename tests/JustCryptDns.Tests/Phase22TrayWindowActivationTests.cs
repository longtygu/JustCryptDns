using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using JustCryptDns.App.Converters;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Updates;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests;

public sealed class Phase22TrayWindowActivationTests
{
    private sealed class StubPage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
    }

    private sealed class StubPageFactory : IPageFactory
    {
        public List<string> CreatedKeys { get; } = [];

        public PageViewModel Create(string pageKey)
        {
            CreatedKeys.Add(pageKey);
            return new StubPage(pageKey);
        }
    }

    private sealed class MemoryStore : ISettingsStore
    {
        public SettingsLoadResult Load() => new(new AppSettings(), SettingsLoadOutcome.Defaults);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    [Fact]
    public void NavigationService_BuffersNavigateBeforeShellSubscribes()
    {
        var pageFactory = new StubPageFactory();
        using var settings = new SettingsService(new MemoryStore(), NullLogger<SettingsService>.Instance);
        var nav = new NavigationService();

        nav.Navigate(PageKeys.DnsManager);

        var shell = new ShellViewModel(pageFactory, settings, nav, NullLogger<ShellViewModel>.Instance);
        try
        {
            Assert.Equal(PageKeys.DnsManager, shell.CurrentPageKey);
            Assert.Equal([PageKeys.DnsManager], pageFactory.CreatedKeys);

            nav.Navigate(PageKeys.Routing);
            Assert.Equal(PageKeys.Routing, shell.CurrentPageKey);
        }
        finally
        {
            shell.StopTimers();
        }
    }

    [Fact]
    public void GitHubUpdateService_RelaunchScriptPassesShowArgument()
    {
        var script = GitHubUpdateService.BuildPortableUpdateScript(
            waitPid: 1234,
            sourceDir: @"C:\temp\src",
            targetDir: @"C:\Program Files\JustCryptDns",
            cleanupDir: @"C:\temp\cleanup",
            isPortableMode: false);

        Assert.Contains("Start-Process -FilePath $targetExe -ArgumentList '--show' -WorkingDirectory $TargetDir", script, StringComparison.Ordinal);
    }
}

[Collection("WpfViewSmoke")]
public sealed class Phase22TrayWpfActivationTests
{
    private sealed class StubPage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
    }

    private sealed class StubPageFactory : IPageFactory
    {
        public PageViewModel Create(string pageKey) => new StubPage(pageKey);
    }

    private sealed class MemoryStore : ISettingsStore
    {
        public SettingsLoadResult Load() => new(new AppSettings(), SettingsLoadOutcome.Defaults);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class StubAppearance : IAppearanceService
    {
        public BackdropSupport Support => new(false, false, false);
        public bool SupportsCornerStyle => false;
        public AppearanceState State => new(BackdropKind.None, BackdropStatus.Disabled, 0, "#4F8CFF");
        public event EventHandler<AppearanceState>? Applied { add { } remove { } }
        public void AttachWindow(Window window) { }
        public void Apply(AppearanceSettings settings) { }
    }

    private sealed class StubPerf : IProcessPerformanceService
    {
        private static readonly ProcessPerformanceSnapshot Snapshot = new()
        {
            WorkingSetMb = 24,
            PrivateMemoryMb = 18,
            ManagedHeapMb = 6,
            ThreadCount = 4,
            HandleCount = 120,
            GcGen0Collections = 1,
            GcGen1Collections = 0,
            GcGen2Collections = 0,
            Uptime = TimeSpan.FromSeconds(5),
            ActiveMonitoringMode = MonitoringMode.Balanced,
        };

        public ProcessPerformanceSnapshot CaptureSnapshot() => Snapshot;
        public ProcessPerformanceSnapshot TrimWorkingSet() => Snapshot;
        public void TrimWorkingSetOnly() { }
    }

    [Fact]
    public void ResolveOrCreateMainWindow_CreatesRealMainWindow_EvenWhenTrayPopupOccupiedAppMainWindow()
    {
        RunOnStaThread(() =>
        {
            EnsureApplicationResources();
            var openClicks = 0;
            var popup = new TrayControlCenterWindow(
                null, null, null, null, null, null, null,
                openRequested: () => openClicks++,
                exitRequested: null);

            MainWindow? trackedMainWindow = null;
            Window? simulatedAppMainWindow = popup; // Simulate WPF's auto-assignment before guard.
            var factoryCalls = 0;

            using var settings = new SettingsService(new MemoryStore(), NullLogger<SettingsService>.Instance);
            var nav = new NavigationService();
            var shell = new ShellViewModel(new StubPageFactory(), settings, nav, NullLogger<ShellViewModel>.Instance);

            MainWindow CreateRealMainWindow()
            {
                factoryCalls++;
                return new MainWindow(shell, new StubAppearance(), new StubPerf());
            }

            try
            {
                var headerButton = Assert.IsType<Button>(popup.FindName("OpenHeaderButton"));
                var footerButton = Assert.IsType<Button>(popup.FindName("OpenFooterButton"));
                headerButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
                footerButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
                Assert.Equal(2, openClicks);

                if (Application.Current is { } app && app.CheckAccess())
                {
                    Assert.Null(app.MainWindow);
                }

                var first = JustCryptDns.App.App.ResolveOrCreateMainWindow(
                    ref trackedMainWindow,
                    simulatedAppMainWindow,
                    w => simulatedAppMainWindow = w,
                    CreateRealMainWindow);

                Assert.Equal(1, factoryCalls);
                Assert.Same(first, trackedMainWindow);
                Assert.Same(first, simulatedAppMainWindow);

                // Even if an auxiliary window somehow overwrites Application.MainWindow later, the tracked MainWindow wins.
                simulatedAppMainWindow = popup;
                var second = JustCryptDns.App.App.ResolveOrCreateMainWindow(
                    ref trackedMainWindow,
                    simulatedAppMainWindow,
                    w => simulatedAppMainWindow = w,
                    CreateRealMainWindow);

                Assert.Equal(1, factoryCalls);
                Assert.Same(first, second);
                Assert.Same(first, simulatedAppMainWindow);

                first.Close();
            }
            finally
            {
                shell.StopTimers();
                popup.Close();
            }
        });
    }

    private static void RunOnStaThread(Action action)
    {
        Exception? captured = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                captured = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (captured is not null)
        {
            throw new Xunit.Sdk.XunitException($"STA test failed: {captured}");
        }
    }

    private static void EnsureApplicationResources()
    {
        Application.ResourceAssembly ??= typeof(JustCryptDns.App.App).Assembly;
        var app = Application.Current ?? new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        if (app.Resources.MergedDictionaries.Count == 0)
        {
            app.Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri("pack://application:,,,/JustCryptDns;component/Themes/Dark.xaml", UriKind.Absolute),
            });
            app.Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri("pack://application:,,,/JustCryptDns;component/Styles/Controls.xaml", UriKind.Absolute),
            });

            app.Resources["BoolToVisibility"] = new BoolToVisibilityConverter();
            app.Resources["InverseBoolToVisibility"] = new BoolToVisibilityConverter { Invert = true };
            app.Resources["NullToVisibility"] = new NullToVisibilityConverter();
            app.Resources["NullToCollapsed"] = new NullToVisibilityConverter { Invert = true };
            app.Resources["EnumEquals"] = new EnumEqualsConverter();
            app.Resources["InverseBool"] = new InverseBoolConverter();
            app.Resources["BoolEquals"] = new BoolEqualsConverter();
            app.Resources["AddressList"] = new AddressListConverter();
            app.Resources["LinkSpeed"] = new LinkSpeedConverter();
            app.Resources["WidthToColumns"] = new WidthToColumnsConverter();
            app.Resources["WidthToFiveColumns"] = new WidthToColumnsConverter { TwoColumnMin = 400, ThreeColumnMin = 640, FourColumnMin = 860, MaxColumns = 5 };
            app.Resources["NoAdapterVisibility"] = new NoAdapterVisibilityConverter();
            app.Resources["LocKey"] = new LocKeyConverter();
            app.Resources["LocFormat"] = new LocFormatConverter();
        }
    }
}
