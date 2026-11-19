using System.Runtime.InteropServices;

namespace JustCryptDns.Infrastructure.Windows;

public enum SystemBackdropType
{
    Auto = 0,
    None = 1,
    Mica = 2,
    Acrylic = 3,
    Tabbed = 4,
}

public enum CornerPreference
{
    Default = 0,
    DoNotRound = 1,
    Round = 2,
    RoundSmall = 3,
}

/// <summary>
/// Thin wrappers over DWM window attributes. Every method returns false instead of throwing when unsupported.
/// </summary>
public static partial class DwmInterop
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwaSystemBackdropType = 38;

    private const int GwlStyle = -16;
    private const long WsSysMenu = 0x00080000L;
    private const uint SwpNoSize = 0x0001;
    private const uint SwpNoMove = 0x0002;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;
    private const uint SwpFrameChanged = 0x0020;

    private const int WcaAccentPolicy = 19;

    private enum AccentState
    {
        Disabled = 0,
        EnableBlurBehind = 3,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AccentPolicy
    {
        public AccentState State;
        public int Flags;
        public uint GradientColor;
        public int AnimationId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowCompositionAttributeData
    {
        public int Attribute;
        public IntPtr Data;
        public int SizeOfData;
    }

    /// <summary>Dark mode attribute: documented for Windows 11, available on Windows 10 20H1+ (build 19041).</summary>
    public static bool SupportsImmersiveDarkMode => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041);

    public static bool SupportsCornerPreference => WindowsVersion.IsWindows11;

    public static bool SupportsSystemBackdrop => WindowsVersion.SupportsSystemBackdrop;

    /// <summary>The blur-behind accent policy is available on Windows 10 and 11.</summary>
    public static bool SupportsBlurBehind => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10240);

    public static bool TrySetImmersiveDarkMode(IntPtr hwnd, bool dark)
    {
        if (!SupportsImmersiveDarkMode || hwnd == IntPtr.Zero)
        {
            return false;
        }

        var value = dark ? 1 : 0;
        return DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref value, sizeof(int)) == 0;
    }

    public static bool TrySetCornerPreference(IntPtr hwnd, CornerPreference preference)
    {
        if (!SupportsCornerPreference || hwnd == IntPtr.Zero)
        {
            return false;
        }

        var value = (int)preference;
        return DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference, ref value, sizeof(int)) == 0;
    }

    public static bool TrySetSystemBackdrop(IntPtr hwnd, SystemBackdropType type)
    {
        if (!SupportsSystemBackdrop || hwnd == IntPtr.Zero)
        {
            return false;
        }

        var value = (int)type;
        return DwmSetWindowAttribute(hwnd, DwmwaSystemBackdropType, ref value, sizeof(int)) == 0;
    }

    /// <summary>
    /// Enables or disables the blur-behind accent (Windows 10 fallback material).
    /// Uses the long-standing but undocumented <c>SetWindowCompositionAttribute</c>; failures are reported, never thrown.
    /// </summary>
    public static bool TrySetBlurBehind(IntPtr hwnd, bool enable)
    {
        if (!SupportsBlurBehind || hwnd == IntPtr.Zero)
        {
            return false;
        }

        var policy = new AccentPolicy { State = enable ? AccentState.EnableBlurBehind : AccentState.Disabled };
        var size = Marshal.SizeOf<AccentPolicy>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(policy, ptr, false);
            var data = new WindowCompositionAttributeData { Attribute = WcaAccentPolicy, Data = ptr, SizeOfData = size };
            return SetWindowCompositionAttribute(hwnd, ref data);
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    internal static IntPtr StripSystemMenuFlag(IntPtr style) => new(style.ToInt64() & ~WsSysMenu);

    /// <summary>
    /// Removes <c>WS_SYSMENU</c> so DWM never paints native caption icons behind translucent custom buttons,
    /// while keeping minimize, maximize, aero snap, and resize frame behaviors intact.
    /// </summary>
    public static bool TryHideNativeCaptionButtons(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero)
        {
            return false;
        }

        var current = GetWindowLongPtrW(hwnd, GwlStyle);
        if (current == IntPtr.Zero)
        {
            return false;
        }

        var updated = StripSystemMenuFlag(current);
        if (updated != current)
        {
            _ = SetWindowLongPtrW(hwnd, GwlStyle, updated);
            _ = SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0, SwpNoMove | SwpNoSize | SwpNoZOrder | SwpNoActivate | SwpFrameChanged);
        }

        return true;
    }

    public static bool IsCompositionEnabled()
    {
        try
        {
            return DwmIsCompositionEnabled(out var enabled) == 0 && enabled;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmIsCompositionEnabled([MarshalAs(UnmanagedType.Bool)] out bool enabled);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowCompositionAttribute(IntPtr hwnd, ref WindowCompositionAttributeData data);

    [LibraryImport("user32.dll")]
    private static partial IntPtr GetWindowLongPtrW(IntPtr hwnd, int nIndex);

    [LibraryImport("user32.dll")]
    private static partial IntPtr SetWindowLongPtrW(IntPtr hwnd, int nIndex, IntPtr dwNewLong);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetWindowPos(IntPtr hwnd, IntPtr hwndInsertAfter, int x, int y, int cx, int cy, uint flags);
}
