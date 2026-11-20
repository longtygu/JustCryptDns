using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

public sealed record ProxyRegistryState(
    int? ProxyEnable,
    string? ProxyServer,
    string? ProxyOverride,
    string? AutoConfigUrl,
    int? AutoDetect);

public interface ISystemProxyConfigurator
{
    bool CanModifyCurrentUserProxy { get; }

    ProxyRegistryState ReadCurrent();

    (bool Success, string? Error) Write(ProxyRegistryState state);
}

public sealed partial class WinInetSystemProxyConfigurator : ISystemProxyConfigurator
{
    private const string InternetSettingsSubKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionRefresh = 37;
    private const int InternetOptionSettingsChanged = 39;

    public bool CanModifyCurrentUserProxy
    {
        get
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return !identity.IsSystem;
            }
            catch
            {
                return Environment.UserInteractive;
            }
        }
    }

    public ProxyRegistryState ReadCurrent()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new ProxyRegistryState(null, null, null, null, null);
        }

        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: false);
        if (key is null)
        {
            return new ProxyRegistryState(null, null, null, null, null);
        }

        var proxyEnable = key.GetValue("ProxyEnable") as int?;
        var proxyServer = key.GetValue("ProxyServer") as string;
        var proxyOverride = key.GetValue("ProxyOverride") as string;
        var autoConfigUrl = key.GetValue("AutoConfigURL") as string;
        var autoDetect = key.GetValue("AutoDetect") as int?;
        return new ProxyRegistryState(proxyEnable, proxyServer, proxyOverride, autoConfigUrl, autoDetect);
    }

    public (bool Success, string? Error) Write(ProxyRegistryState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!CanModifyCurrentUserProxy)
        {
            return (false, "Per-user Windows proxy settings cannot be modified from a non-interactive LocalSystem service.");
        }

        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(InternetSettingsSubKey, writable: true);
            if (key is null)
            {
                return (false, "Could not open Windows Internet Settings registry key.");
            }

            if (state.ProxyEnable.HasValue)
            {
                key.SetValue("ProxyEnable", state.ProxyEnable.Value, RegistryValueKind.DWord);
            }
            else
            {
                key.DeleteValue("ProxyEnable", throwOnMissingValue: false);
            }

            SetOrDeleteString(key, "ProxyServer", state.ProxyServer);
            SetOrDeleteString(key, "ProxyOverride", state.ProxyOverride);
            SetOrDeleteString(key, "AutoConfigURL", state.AutoConfigUrl);

            if (state.AutoDetect.HasValue)
            {
                key.SetValue("AutoDetect", state.AutoDetect.Value, RegistryValueKind.DWord);
            }
            else
            {
                key.DeleteValue("AutoDetect", throwOnMissingValue: false);
            }

            key.Flush();
            NotifyWinInetChanged();
            return (true, null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return (false, ex.Message);
        }
    }

    private static void SetOrDeleteString(RegistryKey key, string valueName, string? value)
    {
        if (value is null)
        {
            key.DeleteValue(valueName, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(valueName, value, RegistryValueKind.String);
        }
    }

    private static void NotifyWinInetChanged()
    {
        try
        {
            _ = InternetSetOptionW(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            _ = InternetSetOptionW(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        }
        catch (DllNotFoundException)
        {
            // Ignored on unsupported hosts.
        }
    }

    [LibraryImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InternetSetOptionW(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}

/// <summary>
/// Implements crash-safe Windows WinINet proxy configuration (Auto-PAC or manual proxy)
/// with SHA-256 verified disk backup and automatic rollback/recovery.
/// </summary>
public sealed class WindowsSystemProxyService : IWindowsProxyManager, IDisposable
{
    private readonly IAppPaths _paths;
    private readonly ISystemProxyConfigurator _configurator;
    private readonly ILogger<WindowsSystemProxyService> _logger;
    private readonly IBootRecoveryRegistrar? _bootRecovery;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsSystemProxyService(
        IAppPaths paths,
        ILogger<WindowsSystemProxyService> logger,
        ISystemProxyConfigurator? configurator = null,
        IBootRecoveryRegistrar? bootRecovery = null)
    {
        _paths = paths;
        _logger = logger;
        _configurator = configurator ?? new WinInetSystemProxyConfigurator();
        _bootRecovery = bootRecovery;
    }

    public bool HasActiveBackup()
    {
        var doc = ReadBackup();
        return doc is { IsActive: true } && doc.VerifyIntegrity();
    }

    public WindowsProxyBackup? ReadBackup()
    {
        if (!File.Exists(_paths.ProxyBackupFile))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(_paths.ProxyBackupFile, Encoding.UTF8);
            var doc = JsonSerializer.Deserialize<WindowsProxyBackup>(json, SettingsJson.Options);
            return doc is not null && doc.VerifyIntegrity() ? doc : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not read Windows proxy backup file.");
            return null;
        }
    }

    public Task<WindowsProxyOperationResult> ApplyPacProxyAsync(
        string pacUrl,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pacUrl);
        return ApplyCoreAsync(
            current => new ProxyRegistryState(
                ProxyEnable: 0,
                ProxyServer: current.ProxyServer,
                ProxyOverride: current.ProxyOverride,
                AutoConfigUrl: pacUrl.Trim(),
                AutoDetect: current.AutoDetect),
            $"PAC ({pacUrl})",
            cancellationToken);
    }

    public Task<WindowsProxyOperationResult> ApplyManualProxyAsync(
        string proxyServer,
        string? bypassList,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(proxyServer);
        return ApplyCoreAsync(
            current => new ProxyRegistryState(
                ProxyEnable: 1,
                ProxyServer: proxyServer.Trim(),
                ProxyOverride: string.IsNullOrWhiteSpace(bypassList) ? "<local>" : bypassList.Trim(),
                AutoConfigUrl: null,
                AutoDetect: current.AutoDetect),
            $"Manual ({proxyServer})",
            cancellationToken);
    }

    private async Task<WindowsProxyOperationResult> ApplyCoreAsync(
        Func<ProxyRegistryState, ProxyRegistryState> buildTargetState,
        string description,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_configurator.CanModifyCurrentUserProxy)
            {
                return new WindowsProxyOperationResult(
                    Success: false,
                    ErrorMessage: "Windows per-user proxy cannot be applied from a non-interactive service account.");
            }

            var current = _configurator.ReadCurrent();
            var existing = ReadBackup();
            if (existing is not { IsActive: true } || !existing.VerifyIntegrity())
            {
                var created = new WindowsProxyBackup
                {
                    ProxyEnable = current.ProxyEnable,
                    ProxyServer = current.ProxyServer,
                    ProxyOverride = current.ProxyOverride,
                    AutoConfigUrl = current.AutoConfigUrl,
                    AutoDetect = current.AutoDetect,
                    IsActive = true,
                    CreatedAtUtc = DateTimeOffset.UtcNow,
                    Sha256 = string.Empty,
                };
                var sealedBackup = created with { Sha256 = created.ComputePayloadHash() };
                await WriteBackupAtomicallyAsync(sealedBackup, cancellationToken).ConfigureAwait(false);

                var verified = ReadBackup();
                if (verified is null || !verified.VerifyIntegrity())
                {
                    TryDeleteBackupFile();
                    return new WindowsProxyOperationResult(false, "Aborted Windows proxy update: backup SHA-256 verification failed.");
                }

                existing = verified;
            }

            _bootRecovery?.Arm("proxy");

            var targetState = buildTargetState(current);
            var (ok, err) = _configurator.Write(targetState);
            if (!ok)
            {
                await RollbackFromBackupAsync(existing).ConfigureAwait(false);
                return new WindowsProxyOperationResult(false, err ?? "Failed to update Windows proxy settings.", RolledBack: true);
            }

            _logger.LogInformation("Applied Windows system proxy: {Description}", description);
            return new WindowsProxyOperationResult(true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<WindowsProxyOperationResult> RestoreOriginalProxyAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_configurator.CanModifyCurrentUserProxy)
            {
                return new WindowsProxyOperationResult(
                    Success: false,
                    ErrorMessage: "Windows per-user proxy cannot be restored from a non-interactive service account.");
            }

            var backup = ReadBackup();
            if (backup is not null && backup.VerifyIntegrity())
            {
                var err = await RollbackFromBackupAsync(backup).ConfigureAwait(false);
                return err is null
                    ? new WindowsProxyOperationResult(true)
                    : new WindowsProxyOperationResult(false, err);
            }

            // No valid backup: conservatively clear only obvious JustCryptDns loopback PAC/proxy pointers.
            var current = _configurator.ReadCurrent();
            var isOurPac = current.AutoConfigUrl is not null
                && current.AutoConfigUrl.StartsWith("http://127.0.0.1:", StringComparison.OrdinalIgnoreCase)
                && current.AutoConfigUrl.Contains("/proxy.pac", StringComparison.OrdinalIgnoreCase);
            var isOurManual = current.ProxyEnable == 1
                && current.ProxyServer is not null
                && current.ProxyServer.StartsWith("127.0.0.1:", StringComparison.OrdinalIgnoreCase);

            if (isOurPac || isOurManual)
            {
                var cleaned = new ProxyRegistryState(
                    ProxyEnable: isOurManual ? 0 : current.ProxyEnable,
                    ProxyServer: isOurManual ? null : current.ProxyServer,
                    ProxyOverride: current.ProxyOverride,
                    AutoConfigUrl: isOurPac ? null : current.AutoConfigUrl,
                    AutoDetect: current.AutoDetect);
                var (ok, err) = _configurator.Write(cleaned);
                if (ok)
                {
                    TryDeleteBackupFile();
                    _bootRecovery?.Disarm("proxy");
                }
                else
                {
                    _bootRecovery?.Arm("proxy");
                }

                return new WindowsProxyOperationResult(ok, err);
            }

            TryDeleteBackupFile();
            _bootRecovery?.Disarm("proxy");
            return new WindowsProxyOperationResult(true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default)
    {
        if (proxyIsRunning || !HasActiveBackup())
        {
            return;
        }

        _logger.LogWarning("Detected active Windows proxy backup from an unexpected shutdown; restoring original proxy settings.");
        await RestoreOriginalProxyAsync(cancellationToken).ConfigureAwait(false);
    }

    private Task<string?> RollbackFromBackupAsync(WindowsProxyBackup backup)
    {
        var originalState = new ProxyRegistryState(
            backup.ProxyEnable,
            backup.ProxyServer,
            backup.ProxyOverride,
            backup.AutoConfigUrl,
            backup.AutoDetect);
        var (ok, err) = _configurator.Write(originalState);
        if (ok)
        {
            TryDeleteBackupFile();
            _bootRecovery?.Disarm("proxy");
            _logger.LogInformation("Restored original Windows system proxy settings from verified backup.");
            return Task.FromResult<string?>(null);
        }

        _bootRecovery?.Arm("proxy");
        return Task.FromResult<string?>(err ?? "Failed to restore original Windows proxy settings.");
    }

    private async Task WriteBackupAtomicallyAsync(WindowsProxyBackup doc, CancellationToken ct)
    {
        Directory.CreateDirectory(_paths.DataDirectory);
        var json = JsonSerializer.Serialize(doc, SettingsJson.Options);
        var temp = Path.Combine(_paths.DataDirectory, $".{Path.GetFileName(_paths.ProxyBackupFile)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temp, json, Encoding.UTF8, ct).ConfigureAwait(false);
            File.Move(temp, _paths.ProxyBackupFile, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                try { File.Delete(temp); } catch { }
            }
        }
    }

    private void TryDeleteBackupFile()
    {
        try
        {
            if (File.Exists(_paths.ProxyBackupFile))
            {
                File.Delete(_paths.ProxyBackupFile);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not delete Windows proxy backup file.");
        }
    }

    public void Dispose() => _gate.Dispose();
}
