using System.Windows;
using System.Windows.Interop;
using System.Windows.Shell;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

/// <summary>
/// Applies composition effects to one WPF window without using a layered window (<c>AllowsTransparency</c>),
/// so rendering stays hardware accelerated and the effect can be toggled at runtime.
/// Glass is enabled by extending the DWM frame over the whole client area (<c>WindowChrome.GlassFrameThickness = -1</c>,
/// which also makes the WPF composition target transparent); the material comes from
/// <c>DWMWA_SYSTEMBACKDROP_TYPE</c> (Windows 11 22H2+) or the blur-behind accent (Windows 10).
/// </summary>
public sealed class WindowBackdropController
{
    private readonly Window _window;
    private readonly ILogger _logger;
    private BackdropKind _applied = BackdropKind.None;
    private bool _initialized;

    public WindowBackdropController(Window window, ILogger logger)
    {
        _window = window;
        _logger = logger;
    }

    public static BackdropSupport DetectSupport()
    {
        if (!DwmInterop.IsCompositionEnabled())
        {
            return new BackdropSupport(false, false, false);
        }

        var systemBackdrop = DwmInterop.SupportsSystemBackdrop;
        return new BackdropSupport(Mica: systemBackdrop, Acrylic: systemBackdrop, Blur: DwmInterop.SupportsBlurBehind);
    }

    public IntPtr Handle => new WindowInteropHelper(_window).Handle;

    public bool IsReady => Handle != IntPtr.Zero;

    /// <summary>Applies the backdrop. Returns false (and leaves the window opaque) if the OS call fails.</summary>
    public bool Apply(BackdropKind kind, bool darkTheme, WindowCornerStyle corners)
    {
        var hwnd = Handle;
        if (hwnd == IntPtr.Zero)
        {
            return false;
        }

        DwmInterop.TrySetImmersiveDarkMode(hwnd, darkTheme);
        DwmInterop.TrySetCornerPreference(hwnd, corners switch
        {
            WindowCornerStyle.Rounded => CornerPreference.Round,
            WindowCornerStyle.RoundedSmall => CornerPreference.RoundSmall,
            WindowCornerStyle.Square => CornerPreference.DoNotRound,
            _ => CornerPreference.Default,
        });

        if (_initialized && kind == _applied)
        {
            return true;
        }

        // Tear down the previous material first.
        if (_applied == BackdropKind.Blur || !_initialized)
        {
            DwmInterop.TrySetBlurBehind(hwnd, false);
        }

        if (_applied is BackdropKind.Mica or BackdropKind.Acrylic || !_initialized)
        {
            DwmInterop.TrySetSystemBackdrop(hwnd, SystemBackdropType.None);
        }

        var ok = true;
        SetGlass(kind != BackdropKind.None);
        switch (kind)
        {
            case BackdropKind.Mica:
                ok = DwmInterop.TrySetSystemBackdrop(hwnd, SystemBackdropType.Mica);
                break;
            case BackdropKind.Acrylic:
                ok = DwmInterop.TrySetSystemBackdrop(hwnd, SystemBackdropType.Acrylic);
                break;
            case BackdropKind.Blur:
                ok = DwmInterop.TrySetBlurBehind(hwnd, true);
                break;
        }

        if (!ok)
        {
            _logger.LogWarning("Backdrop {Kind} could not be applied; falling back to an opaque window.", kind);
            SetGlass(false);
            _applied = BackdropKind.None;
            _initialized = true;
            return false;
        }

        _applied = kind;
        _initialized = true;
        _logger.LogInformation("Backdrop applied: {Kind} (dark={Dark}, corners={Corners})", kind, darkTheme, corners);
        return true;
    }

    private void SetGlass(bool enabled)
    {
        var current = WindowChrome.GetWindowChrome(_window);
        var glass = enabled ? new Thickness(-1) : new Thickness(0);
        if (current is not null && current.GlassFrameThickness == glass)
        {
            return;
        }

        WindowChrome.SetWindowChrome(_window, new WindowChrome
        {
            CaptionHeight = current?.CaptionHeight ?? 44,
            ResizeBorderThickness = current?.ResizeBorderThickness ?? new Thickness(6),
            CornerRadius = new CornerRadius(0),
            UseAeroCaptionButtons = false,
            GlassFrameThickness = glass,
        });
    }
}
