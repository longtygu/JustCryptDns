using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using JustCryptDns.App.Localization;
using JustCryptDns.App.ViewModels;

namespace JustCryptDns.App.Views;

public partial class MainWindow : Window
{
    private const int SmCxFrame = 32;
    private const int SmCyFrame = 33;
    private const int SmCxPaddedBorder = 92;

    public MainWindow(ShellViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        StateChanged += (_, _) => UpdateMaximizedState();
        LocalizationManager.Instance.PropertyChanged += (_, _) => UpdateMaximizedState();
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        UpdateMaximizedState();
    }

    /// <summary>
    /// With <c>WindowChrome</c>, a maximized window extends past the monitor by the frame thickness; compensate with a margin.
    /// </summary>
    private void UpdateMaximizedState()
    {
        var maximized = WindowState == WindowState.Maximized;
        if (maximized)
        {
            var dpi = VisualTreeHelper.GetDpi(this);
            var padded = GetSystemMetrics(SmCxPaddedBorder);
            var x = (GetSystemMetrics(SmCxFrame) + padded) / dpi.DpiScaleX;
            var y = (GetSystemMetrics(SmCyFrame) + padded) / dpi.DpiScaleY;
            RootGrid.Margin = new Thickness(x, y, x, y);
        }
        else
        {
            RootGrid.Margin = new Thickness(0);
        }

        MaximizeButton.Content = maximized ? "\uE923" : "\uE922";
        var key = maximized ? "Window_Restore" : "Window_Maximize";
        MaximizeButton.ToolTip = LocalizationManager.Instance[key];
        System.Windows.Automation.AutomationProperties.SetName(MaximizeButton, LocalizationManager.Instance[key]);
    }

    private void OnMinimize(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);

    private void OnMaximizeRestore(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            SystemCommands.RestoreWindow(this);
        }
        else
        {
            SystemCommands.MaximizeWindow(this);
        }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);
}
