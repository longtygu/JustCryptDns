using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

public sealed record WindowsDnsOperationResult(bool Success, string? ErrorMessage = null, bool RolledBack = false);

/// <summary>
/// Manages Windows network adapter DNS settings with mandatory backup, SHA-256 verification,
/// connectivity probe, automatic rollback on failure, and emergency restore (Part 2.3 &amp; Part 14).
/// </summary>
public interface IWindowsDnsManager
{
    bool HasActiveBackup();

    AdapterDnsBackupDocument? ReadBackup();

    /// <summary>
    /// Backs up current adapter DNS settings, verifies backup integrity, applies the local proxy DNS,
    /// verifies DNS resolution via <paramref name="connectivityProbe"/>, and rolls back automatically on failure.
    /// </summary>
    Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
        string? targetAdapterId,
        string ipv4Dns,
        string? ipv6Dns,
        Func<CancellationToken, Task<bool>> connectivityProbe,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Restores adapter DNS configuration from the verified backup or resets to DHCP when no backup exists.
    /// </summary>
    Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(
        string? targetAdapterId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Called on service/app startup: if an active backup exists from an unexpected shutdown, restores it safely.
    /// </summary>
    Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default);
}
