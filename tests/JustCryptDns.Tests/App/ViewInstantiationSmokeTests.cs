using System.Windows;
using System.Windows.Controls;
using JustCryptDns.App.Controls;
using JustCryptDns.App.Converters;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.App;

[Collection("WpfApplication")]
public sealed class ViewInstantiationSmokeTests
{
    [Fact]
    public void CopyTextBehavior_AndAllViews_InitializeCleanlyOnStaThread()
    {
        Exception? captured = null;
        var thread = new Thread(() =>
        {
            try
            {
                EnsureApplicationResources();

                // Exercise attached property registration & setter cleanly (guards against invalid PropertyMetadata defaults).
                var btn = new Button();
                CopyTextBehavior.SetCopyText(btn, "smoke-test-copy");
                Assert.Equal("smoke-test-copy", CopyTextBehavior.GetCopyText(btn));

                // Instantiate every XAML view to catch BAML/XAML runtime parse errors, static cctor failures,
                // invalid properties on controls, or broken Style/Storyboard references.
                UserControl[] views =
                [
                    new DashboardView(),
                    new DnsManagerView(),
                    new ResolverLibraryView(),
                    new RoutingView(),
                    new FilteringView(),
                    new GamingView(),
                    new BypassView(),
                    new DiagnosticsView(),
                    new LiveMonitorView(),
                    new SettingsView(),
                    new AppearanceView(),
                ];

                Assert.Equal(11, views.Length);
                foreach (var view in views)
                {
                    view.Measure(new Size(1000, 900));
                }

                // Also verify AboutWindow XAML parses and initializes cleanly.
                using var aboutVm = new AboutViewModel(
                    new AppPaths(Path.Combine(Path.GetTempPath(), "justcryptdns-smoke")),
                    new StubBugCollector(),
                    new NavigationService(),
                    NullLogger<AboutViewModel>.Instance);
                var aboutWindow = new AboutWindow(aboutVm, new StubAppearance());
                Assert.NotNull(aboutWindow.Content);
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
            throw new Xunit.Sdk.XunitException($"WPF view initialization failed: {captured}");
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

    private sealed class StubBugCollector : IBugDiagnosticsCollector
    {
        public BugDiagnosticsSnapshot Capture() => new("1.4.0", "Windows", "Stopped", "Cloudflare", "Stopped", "AllWebsitesSmart", "Ethernet", []);
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
}
