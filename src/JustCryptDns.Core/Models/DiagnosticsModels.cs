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

public enum DiagnosticTestCategory
{
    None,
    Lookup,
    Dnssec,
    Doh,
    DnsCrypt,
    Leak,
    Restrictions,
    Compare,
    Propagation,
    BrowserDoh,
}

public enum DiagnosticStepOutcome
{
    Running,
    Pass,
    Warning,
    Fail,
    Info,
}

public sealed record DiagnosticStepProgress(
    DiagnosticTestCategory Category,
    string StepTitle,
    string Target,
    DiagnosticStepOutcome Outcome,
    double? LatencyMs,
    string Detail,
    int CompletedSteps,
    int TotalSteps,
    DateTimeOffset Timestamp);

public sealed record LiveQueryMonitorEntry
{
    public long SequenceId { get; init; }

    public required DateTimeOffset Timestamp { get; init; }

    public required string Domain { get; init; }

    public required string RecordType { get; init; }

    /// <summary>Allowed, Blocked, Cached, Routed, Rewritten, Stale, Canary, Failed.</summary>
    public required string Outcome { get; init; }

    public required string ResolverName { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public double? LatencyMs { get; init; }

    public string? ResponseCode { get; init; }

    public string? AnswerSummary { get; init; }

    public string? MatchedRule { get; init; }
}

public sealed record DomainQueryAggregate
{
    public required string Domain { get; init; }

    public long TotalCount { get; init; }

    public long BlockedCount { get; init; }

    public long CachedCount { get; init; }

    public long FailedCount { get; init; }

    public long RoutedCount { get; init; }

    public long RewrittenCount { get; init; }

    public double AverageLatencyMs { get; init; }

    public double QueriesPerMinute { get; init; }

    public bool IsHighFrequency { get; init; }

    public required string LastOutcome { get; init; }

    public required string LastResolverName { get; init; }

    public string? LastAnswerSummary { get; init; }

    public DateTimeOffset LastSeenUtc { get; init; }
}

public sealed record QueryAnalyticsSnapshot
{
    public DateTimeOffset SessionStartedUtc { get; init; }

    public long TotalObservedQueries { get; init; }

    public long TotalBlockedQueries { get; init; }

    public long TotalCachedQueries { get; init; }

    public long TotalFailedQueries { get; init; }

    public int UniqueDomainCount { get; init; }

    public double CurrentQueriesPerMinute { get; init; }

    public double BlockedQueriesPerMinute { get; init; }

    public required IReadOnlyList<DomainQueryAggregate> TopQueried { get; init; }

    public required IReadOnlyList<DomainQueryAggregate> TopBlocked { get; init; }

    public required IReadOnlyList<DomainQueryAggregate> TopFailed { get; init; }
}

public sealed record BrowserDohCheckReport
{
    public required bool FirefoxCanaryBlocked { get; init; }

    public required bool AdapterPointsToLocalProxy { get; init; }

    public required bool BrowserPolicyDetected { get; init; }

    public string? BrowserPolicyDetail { get; init; }

    public required IReadOnlyList<string> Findings { get; init; }

    public required string Summary { get; init; }
}
