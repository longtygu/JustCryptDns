using System.Globalization;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>Reads the user's Windows accent color.</summary>
public static class SystemAccent
{
    /// <summary>Returns the accent as <c>#RRGGBB</c>, or null if unavailable.</summary>
    public static string? TryRead()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\DWM");
            if (key?.GetValue("AccentColor") is int abgr)
            {
                return FromAbgr(unchecked((uint)abgr));
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            // Fall through.
        }

        return null;
    }

    /// <summary>Converts the registry's 0xAABBGGRR value to <c>#RRGGBB</c>.</summary>
    public static string FromAbgr(uint abgr)
    {
        var r = abgr & 0xFF;
        var g = (abgr >> 8) & 0xFF;
        var b = (abgr >> 16) & 0xFF;
        return string.Create(CultureInfo.InvariantCulture, $"#{r:X2}{g:X2}{b:X2}");
    }
}
