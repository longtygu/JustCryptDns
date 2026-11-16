namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Windows build detection used to select composition features (Mica/Acrylic, rounded corners).
/// </summary>
public static class WindowsVersion
{
    public static int Build => Environment.OSVersion.Version.Build;

    /// <summary>Windows 11 (build 22000+).</summary>
    public static bool IsWindows11 => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000);

    /// <summary>Windows 11 22H2+ supports <c>DWMWA_SYSTEMBACKDROP_TYPE</c>.</summary>
    public static bool SupportsSystemBackdrop => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621);

    public static string DisplayName => IsWindows11 ? $"Windows 11 (build {Build})" : $"Windows 10 (build {Build})";
}
