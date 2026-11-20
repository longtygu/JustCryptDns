using System.Windows;
using System.Windows.Interop;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Infrastructure.Windows;

namespace JustCryptDns.App.Views;

public partial class AboutWindow : Window
{
    private readonly IAppearanceService _appearance;

    public AboutWindow(AboutViewModel viewModel, IAppearanceService appearance)
    {
        _appearance = appearance;
        InitializeComponent();
        DataContext = viewModel;
        IsVisibleChanged += (_, _) =>
        {
            if (IsVisible)
            {
                HideNativeCaptionButtons();
            }
        };
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        _appearance.AttachSecondaryWindow(this);
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

    private void OnMinimize(object sender, RoutedEventArgs e) => SystemCommands.MinimizeWindow(this);

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
