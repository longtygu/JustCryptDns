namespace JustCryptDns.Core.Models;

public sealed record DnsLookupRecordItem(
    string Name,
    string RecordType,
    uint Ttl,
    string Value);

public sealed record DnsLookupReport
{
    public required string Domain { get; init; }

    public required string RecordType { get; init; }

    public required string ResolverName { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public required bool Success { get; init; }

    public required string ResponseCode { get; init; }

    public required double LatencyMs { get; init; }

    public required bool AuthenticDataBit { get; init; }

    public required IReadOnlyList<DnsLookupRecordItem> Records { get; init; }

    public string? ErrorMessage { get; init; }
}

public sealed record DnssecTestReport
{
    public required string ResolverName { get; init; }

    public required bool SupportsDnssecValidation { get; init; }

    public required bool SignedDomainVerified { get; init; }

    public required double LatencyMs { get; init; }

    public required string Summary { get; init; }
}

public sealed record ResolverComparisonEntry(
    string ResolverName,
    string Provider,
    DnsProtocol Protocol,
    bool Success,
    double LatencyMs,
    string ResponseCode,
    string PrimaryAnswerSummary);

public sealed record DnsLeakTestReport
{
    public required bool IsLeakDetected { get; init; }

    public required bool IsAdapterUsingLocalProxy { get; init; }

    public required IReadOnlyList<string> AdapterDnsServers { get; init; }

    public required string ActiveEncryptedResolver { get; init; }

    public required DnsProtocol ActiveProtocol { get; init; }

    public required string Summary { get; init; }
}

public sealed record LiveQueryMonitorEntry
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Domain { get; init; }

    public required string RecordType { get; init; }

    /// <summary>Allowed, Blocked, Cached, Routed, Failed.</summary>
    public required string Outcome { get; init; }

    public required string ResolverName { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public double? LatencyMs { get; init; }
}
