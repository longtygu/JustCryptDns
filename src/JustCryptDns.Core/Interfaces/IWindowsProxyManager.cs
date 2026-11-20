using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

public sealed record WindowsProxyOperationResult(bool Success, string? ErrorMessage = null, bool RolledBack = false);

/// <summary>
/// Manages Windows WinINet per-user system proxy settings (Auto-PAC or manual HTTP/SOCKS proxy)
/// with SHA-256 verified backup, live browser/desktop notification, and crash recovery.
/// </summary>
public interface IWindowsProxyManager
{
    bool CanModifyCurrentUserProxy { get; }

    bool HasActiveBackup();

    WindowsProxyBackup? ReadBackup();

    Task<WindowsProxyOperationResult> ApplyPacProxyAsync(
        string pacUrl,
        CancellationToken cancellationToken = default);

    Task<WindowsProxyOperationResult> ApplyManualProxyAsync(
        string proxyServer,
        string? bypassList,
        CancellationToken cancellationToken = default);

    Task<WindowsProxyOperationResult> RestoreOriginalProxyAsync(
        CancellationToken cancellationToken = default);

    Task RecoverAfterCrashIfNeededAsync(
        bool proxyIsRunning,
        CancellationToken cancellationToken = default);
}
