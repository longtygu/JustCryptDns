using JustCryptDns.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Manages the single <c>JustCryptDns</c> entry under <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</c>.
/// Idempotent: enabling overwrites the existing value in place; disabling removes it.
/// </summary>
public sealed class RegistryStartupService : IStartupService
{
    public const string DefaultRunSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public const string ValueName = "JustCryptDns";

    private readonly ILogger<RegistryStartupService> _logger;
    private readonly string _runSubKey;
    private readonly string _executablePath;

    public RegistryStartupService(
        ILogger<RegistryStartupService> logger,
        string? runSubKeyOverride = null,
        string? executablePathOverride = null)
    {
        _logger = logger;
        _runSubKey = string.IsNullOrWhiteSpace(runSubKeyOverride) ? DefaultRunSubKey : runSubKeyOverride;
        _executablePath = string.IsNullOrWhiteSpace(executablePathOverride)
            ? Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "JustCryptDns.exe")
            : executablePathOverride;
    }

    public static string BuildCommandLine(string executablePath, bool startMinimized)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        return startMinimized
            ? $"\"{executablePath}\" --autostart --minimized"
            : $"\"{executablePath}\" --autostart";
    }

    public bool IsRegistered()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(_runSubKey, writable: false);
            return key?.GetValue(ValueName) is string value && !string.IsNullOrWhiteSpace(value);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            _logger.LogWarning(ex, "Failed to read Windows startup registration.");
            return false;
        }
    }

    public void SetRegistration(bool enabled, bool startMinimized)
    {
        using var key = Registry.CurrentUser.CreateSubKey(_runSubKey, writable: true)
            ?? throw new IOException($"Unable to open registry key HKCU\\{_runSubKey}.");

        if (enabled)
        {
            var command = BuildCommandLine(_executablePath, startMinimized);
            key.SetValue(ValueName, command, RegistryValueKind.String);
            _logger.LogInformation("Registered Windows startup entry: {Command}", command);
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
            _logger.LogInformation("Removed Windows startup entry.");
        }
    }
}
