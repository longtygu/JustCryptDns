using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<UpdateCheckStatus>))]
public enum UpdateCheckStatus
{
    Idle,
    Checking,
    UpToDate,
    UpdateAvailable,
    NoReleasesPublished,
    RateLimited,
    Error,
}

[JsonConverter(typeof(JsonStringEnumConverter<UpdatePackageKind>))]
public enum UpdatePackageKind
{
    PortableZip,
    InstallerExe,
}

public sealed record UpdateAssetInfo(
    string FileName,
    string DownloadUrl,
    long SizeBytes,
    UpdatePackageKind Kind,
    string? ChecksumsUrl);

public sealed record UpdateReleaseInfo(
    string TagName,
    string Version,
    string Name,
    string ReleaseNotes,
    DateTimeOffset PublishedAtUtc,
    string HtmlUrl,
    bool IsPrerelease,
    UpdateAssetInfo? PreferredAsset);

public sealed record UpdateCheckResult(
    UpdateCheckStatus Status,
    string CurrentVersion,
    UpdateReleaseInfo? Release,
    DateTimeOffset CheckedAtUtc,
    string? ErrorMessage = null);

public sealed record UpdateDownloadProgress(
    long BytesDownloaded,
    long TotalBytes,
    double ProgressPercent,
    double InstantBytesPerSecond,
    double AverageBytesPerSecond,
    TimeSpan? EstimatedRemaining);

public sealed record PreparedUpdatePackage(
    string Version,
    string PackagePath,
    UpdatePackageKind Kind,
    string? StagingDirectory,
    bool ChecksumVerified,
    string? ExpectedSha256,
    string? ActualSha256);

[JsonConverter(typeof(JsonStringEnumConverter<BugReportCategory>))]
public enum BugReportCategory
{
    DnsEngine,
    DpiBypass,
    Gaming,
    UiAppearance,
    AutoUpdate,
    Other,
}

public sealed record BugReportDraft(
    BugReportCategory Category,
    string Title,
    string Description,
    bool IncludeDiagnostics);

public sealed record BugDiagnosticsSnapshot(
    string AppVersion,
    string OsVersion,
    string DnsEngineState,
    string ActiveResolver,
    string BypassState,
    string BypassCoverage,
    string PrimaryAdapter,
    IReadOnlyList<string> RecentLogLines);
