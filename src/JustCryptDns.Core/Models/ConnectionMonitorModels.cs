using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<ConnectionDisplayStatus>))]
public enum ConnectionDisplayStatus
{
    Active,
    Closed,
    BlockedIp,
    BlockedRange,
}

[JsonConverter(typeof(JsonStringEnumConverter<ConnectionProtocol>))]
public enum ConnectionProtocol
{
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

public sealed record RawSocketConnection(
    ConnectionProtocol Protocol,
    string LocalIp,
    int LocalPort,
    string RemoteIp,
    int RemotePort,
    string TcpState,
    int ProcessId,
    string ProcessName,
    string? ExecutablePath = null);

[JsonConverter(typeof(JsonStringEnumConverter<ProcessTrustLevel>))]
public enum ProcessTrustLevel
{
    Unknown,
    TrustedSystem,
    Signed,
    Unsigned,
    Suspicious,
}

public sealed record ProcessTrustInfo(
    string ExecutablePath,
    ProcessTrustLevel Level,
    string? Publisher,
    bool IsRiskyPath,
    bool IsMasqueradingSystemBinary,
    string? RiskReason);

public sealed record BlockedAppRule
{
    public required string ExecutablePath { get; init; }

    public required string ProcessName { get; init; }

    public string? Note { get; init; }

    public DateTimeOffset AddedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool IsEnabled { get; init; } = true;
}

public sealed record ThreatIntelMatch(
    string Indicator,
    string Source,
    string Category);

public sealed record ThreatIntelStatus(
    int IndicatorCount,
    int IpCount,
    int CidrCount,
    DateTimeOffset? LastUpdatedUtc,
    string? LastError = null);

public sealed record BlockedIpRule
{
    public required string Target { get; init; }

    public string? Note { get; init; }

    public DateTimeOffset AddedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool IsEnabled { get; init; } = true;

    [JsonIgnore]
    public bool IsCidr => Target.Contains('/', StringComparison.Ordinal);
}

public sealed record IpEnrichmentInfo(
    string Ip,
    string? ReverseDns,
    string? Organization,
    string? Country,
    DateTimeOffset CachedAtUtc);

public sealed record FirewallSyncRequestPayload(
    IReadOnlyList<BlockedIpRule> Rules,
    IReadOnlyList<BlockedAppRule>? BlockedApps = null,
    bool EnableDnsLeakGuard = false,
    bool EnableEmergencyLockdown = false,
    IReadOnlyList<string>? AllowedDnsResolverIps = null);

public sealed record FirewallSyncResult(
    bool Success,
    int AppliedRuleCount,
    int RemovedRuleCount,
    int RejectedProtectedCount,
    bool IsWindowsFirewallEnabled,
    bool RequiresElevation,
    string? Message,
    IReadOnlyList<string>? RejectedTargets = null);

public sealed record FirewallStatusSnapshot(
    int ManagedRuleCount,
    bool IsWindowsFirewallEnabled,
    bool RequiresElevation,
    IReadOnlyList<string> ActiveTargets,
    string? Message = null,
    bool IsDnsLeakGuardActive = false,
    bool IsLockdownActive = false,
    int ManagedAppRuleCount = 0);

public sealed record ReverseDnsMapping(
    string Ip,
    string Domain,
    DateTimeOffset ExpiresAtUtc);
