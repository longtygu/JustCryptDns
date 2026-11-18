using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<FailoverPolicy>))]
public enum FailoverPolicy
{
    /// <summary>Try primary, then secondary, then any enabled encrypted resolver (DoH/DoT/DNSCrypt).</summary>
    EncryptedOnly,

    /// <summary>Try primary, then secondary, then any enabled encrypted resolver, and finally plain UDP/TCP if all encrypted fail.</summary>
    EncryptedThenPlainFallback,

    /// <summary>Only switch between the configured Primary and Secondary resolvers.</summary>
    PrimaryAndSecondaryOnly,
}

[JsonConverter(typeof(JsonStringEnumConverter<DnsFailureCategory>))]
public enum DnsFailureCategory
{
    None,
    ResolverTimeout,
    Udp53BlockedOrUnreachable,
    Tcp53BlockedOrUnreachable,
    DohEndpointFailure,
    DotTlsHandshakeFailure,
    DnsCryptHandshakeFailure,
    Ipv4ConnectivityProblem,
    Ipv6ConnectivityProblem,
}

public sealed record FailoverEventEntry
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string FailedResolverId { get; init; }

    public required string FailedResolverName { get; init; }

    public required DnsProtocol FailedProtocol { get; init; }

    public required string ActivatedResolverId { get; init; }

    public required string ActivatedResolverName { get; init; }

    public required DnsProtocol ActivatedProtocol { get; init; }

    public required DnsFailureCategory FailureCategory { get; init; }

    public required string Reason { get; init; }
}

public sealed record NetworkRestrictionReport
{
    public required DateTimeOffset TestedAt { get; init; }

    public required bool Udp53Reachable { get; init; }

    public required bool Tcp53Reachable { get; init; }

    public required bool Doh443Reachable { get; init; }

    public required bool Dot853Reachable { get; init; }

    public required bool DnsCryptReachable { get; init; }

    public required bool Ipv4Available { get; init; }

    public required bool Ipv6Available { get; init; }

    public required IReadOnlyList<DnsFailureCategory> DetectedIssues { get; init; }

    public required string Summary { get; init; }
}
