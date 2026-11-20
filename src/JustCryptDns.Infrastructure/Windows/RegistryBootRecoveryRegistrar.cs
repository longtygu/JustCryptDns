using System.Runtime.InteropServices;
using System.Security;
using JustCryptDns.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Registers a one-shot per-user Windows <c>RunOnce</c> command (<c>--recover-and-exit</c>) while
/// DNS or WinINet proxy overrides are active, removing it automatically once everything is restored.
/// </summary>
public sealed partial class RegistryBootRecoveryRegistrar : IBootRecoveryRegistrar
{
    public const string DefaultRunOnceSubKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
    public const string RecoveryValueName = "JustCryptDnsRecovery";
    public const string RecoveryArgument = "--recover-and-exit";

    private readonly ILogger<RegistryBootRecoveryRegistrar> _logger;
    private readonly string _runOnceSubKey;
    private readonly string? _executablePathOverride;
    private readonly object _sync = new();
    private readonly HashSet<string> _armedComponents = new(StringComparer.OrdinalIgnoreCase);

    public RegistryBootRecoveryRegistrar(
        ILogger<RegistryBootRecoveryRegistrar> logger,
        string? runOnceSubKeyOverride = null,
        string? executablePathOverride = null)
    {
        _logger = logger;
        _runOnceSubKey = string.IsNullOrWhiteSpace(runOnceSubKeyOverride)
            ? DefaultRunOnceSubKey
            : runOnceSubKeyOverride;
        _executablePathOverride = executablePathOverride;
    }

    public bool IsArmed
    {
        get
        {
            lock (_sync)
            {
                return !string.IsNullOrWhiteSpace(ReadRegisteredCommandUnsafe());
            }
        }
    }

    public string? ReadRegisteredCommand()
    {
        lock (_sync)
        {
            return ReadRegisteredCommandUnsafe();
        }
    }

    public void Arm(string component)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(component);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        lock (_sync)
        {
            _armedComponents.Add(component.Trim());

            var executablePath = string.IsNullOrWhiteSpace(_executablePathOverride)
                ? Environment.ProcessPath
                : _executablePathOverride;
            if (string.IsNullOrWhiteSpace(executablePath))
            {
                _logger.LogWarning("Cannot arm RunOnce recovery for {Component}: executable path unavailable.", component);
                return;
            }

            var command = $"\"{executablePath}\" {RecoveryArgument}";
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(_runOnceSubKey, writable: true);
                key?.SetValue(RecoveryValueName, command, RegistryValueKind.String);
                _logger.LogDebug("Armed RunOnce recovery ({Component}): {Command}", component, command);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
            {
                _logger.LogWarning(ex, "Failed to arm RunOnce recovery for {Component}.", component);
            }
        }
    }

    public void Disarm(string component)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(component);
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        lock (_sync)
        {
            _armedComponents.Remove(component.Trim());
            if (_armedComponents.Count > 0)
            {
                _logger.LogDebug(
                    "Disarmed {Component}, keeping RunOnce recovery active for remaining components ({Remaining}).",
                    component,
                    string.Join(", ", _armedComponents));
                return;
            }

            DeleteRunOnceValueUnsafe();
        }
    }

    public void ClearAll()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        lock (_sync)
        {
            _armedComponents.Clear();
            DeleteRunOnceValueUnsafe();
        }
    }

    private string? ReadRegisteredCommandUnsafe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(_runOnceSubKey, writable: false);
            return key?.GetValue(RecoveryValueName) as string;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
        {
            return null;
        }
    }

    private void DeleteRunOnceValueUnsafe()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(_runOnceSubKey, writable: true);
            key?.DeleteValue(RecoveryValueName, throwOnMissingValue: false);
            _logger.LogDebug("Cleared RunOnce recovery entry {ValueName}.", RecoveryValueName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
        {
            _logger.LogWarning(ex, "Failed to delete RunOnce recovery entry {ValueName}.", RecoveryValueName);
        }
    }

    public static bool TryCreateShutdownBlockReason(nint windowHandle, string reason)
    {
        if (!OperatingSystem.IsWindows() || windowHandle == 0 || string.IsNullOrWhiteSpace(reason))
        {
            return false;
        }

        try
        {
            return ShutdownBlockReasonCreate(windowHandle, reason);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    public static void TryDestroyShutdownBlockReason(nint windowHandle)
    {
        if (!OperatingSystem.IsWindows() || windowHandle == 0)
        {
            return;
        }

        try
        {
            _ = ShutdownBlockReasonDestroy(windowHandle);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShutdownBlockReasonCreate(nint hWnd, string pwszReason);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShutdownBlockReasonDestroy(nint hWnd);
}
