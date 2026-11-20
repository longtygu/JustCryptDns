using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Checks GitHub Releases for application updates, streams and verifies packages with SHA-256,
/// and launches an elevated or unprivileged in-place updater without wiping user settings.
/// </summary>
public interface IUpdateService
{
    string CurrentVersion { get; }

    UpdateCheckResult? LatestResult { get; }

    event EventHandler<UpdateCheckResult>? UpdateCheckCompleted;

    Task<UpdateCheckResult> CheckForUpdatesAsync(
        bool includePrereleases = false,
        CancellationToken cancellationToken = default);

    Task<PreparedUpdatePackage> DownloadAndPrepareAsync(
        UpdateReleaseInfo release,
        IProgress<UpdateDownloadProgress>? progress = null,
        CancellationToken cancellationToken = default);

    bool LaunchPreparedUpdate(PreparedUpdatePackage package, out string? errorMessage);
}
