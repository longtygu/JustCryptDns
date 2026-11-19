using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Infrastructure.Windows;

namespace JustCryptDns.App.Views;

public partial class MainWindow : Window
{
    private const int SmCxFrame = 32;
    private const int SmCyFrame = 33;
    private const int SmCxPaddedBorder = 92;

    private readonly IAppearanceService _appearance;
    private readonly IProcessPerformanceService _performance;

    public MainWindow(ShellViewModel viewModel, IAppearanceService appearance, IProcessPerformanceService performance)
    {
        _appearance = appearance;
        _performance = performance;
        InitializeComponent();
        DataContext = viewModel;
        StateChanged += (_, _) => UpdateMaximizedState();
        IsVisibleChanged += (_, _) =>
        {
            if (IsVisible)
            {
                HideNativeCaptionButtons();
            }
        };
        PreviewKeyDown += OnWindowPreviewKeyDown;
        Closing += OnWindowClosing;
        viewModel.HideToTrayRequested += (_, _) => HideToTray();
        viewModel.ExitRequested += (_, _) => Close();
        LocalizationManager.Instance.PropertyChanged += (_, _) => UpdateMaximizedState();
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        _appearance.AttachWindow(this);
        HideNativeCaptionButtons();
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
        HideNativeCaptionButtons();
    }

    private void HideNativeCaptionButtons()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd != IntPtr.Zero)
        {
            DwmInterop.TryHideNativeCaptionButtons(hwnd);
        }
    }

    private void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.System
            && e.SystemKey == Key.F4
            && (Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt)
        {
            e.Handled = true;
            Close();
        }
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

    private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (DataContext is not ShellViewModel vm)
        {
            return;
        }

        switch (vm.HandleWindowClosing())
        {
            case WindowCloseAction.HideToTray:
                e.Cancel = true;
                HideToTray();
                break;
            case WindowCloseAction.PromptUser:
                e.Cancel = true;
                break;
            case WindowCloseAction.ExitApplication:
                break;
        }
    }

    private void HideToTray()
    {
        Hide();
        _ = Task.Run(() => _performance.TrimWorkingSet());
    }

    private void OnNavListMouseUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (sender is System.Windows.Controls.ListBox { SelectedItem: NavItem item }
            && DataContext is ShellViewModel vm
            && vm.CurrentPageKey != item.Key)
        {
            vm.NavigateTo(item.Key);
        }
    }

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);
}
