using System.Runtime.Versioning;
using JustCryptDns.Core.Interfaces;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Reads Windows policy registry hives to detect enterprise/manual Chrome, Edge, or Firefox
/// built-in DNS-over-HTTPS policies that could bypass local proxy interception.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsBrowserPolicyInspector : IBrowserPolicyInspector
{
    public IReadOnlyList<string> InspectConfiguredBrowserDohPolicies()
    {
        var findings = new List<string>();
        InspectChromiumPolicy(Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "Microsoft Edge", findings);
        InspectChromiumPolicy(Registry.CurrentUser, "HKCU", @"SOFTWARE\Policies\Microsoft\Edge", "Microsoft Edge", findings);
        InspectChromiumPolicy(Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\Google\Chrome", "Google Chrome", findings);
        InspectChromiumPolicy(Registry.CurrentUser, "HKCU", @"SOFTWARE\Policies\Google\Chrome", "Google Chrome", findings);
        InspectFirefoxPolicy(Registry.LocalMachine, "HKLM", findings);
        InspectFirefoxPolicy(Registry.CurrentUser, "HKCU", findings);
        return findings;
    }

    private static void InspectChromiumPolicy(
        RegistryKey hive,
        string hiveName,
        string subKeyPath,
        string browserName,
        List<string> findings)
    {
        try
        {
            using var key = hive.OpenSubKey(subKeyPath, writable: false);
            if (key?.GetValue("DnsOverHttpsMode") is string mode
                && !string.IsNullOrWhiteSpace(mode)
                && !string.Equals(mode.Trim(), "off", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add($"{browserName} ({hiveName}): DnsOverHttpsMode={mode}");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Ignore unreadable restricted policy keys.
        }
    }

    private static void InspectFirefoxPolicy(RegistryKey hive, string hiveName, List<string> findings)
    {
        try
        {
            using var key = hive.OpenSubKey(@"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", writable: false);
            if (key?.GetValue("Enabled") is int enabled && enabled != 0)
            {
                findings.Add($"Mozilla Firefox ({hiveName}): DNSOverHTTPS.Enabled={enabled}");
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            // Ignore unreadable restricted policy keys.
        }
    }
}
