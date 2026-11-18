using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Intelligent encrypted DNS failover, configurable retry policy, and network restriction diagnostics (Part 6).
/// </summary>
public interface IDnsFailoverService
{
    event EventHandler<FailoverEventEntry>? FailoverOccurred;

    bool IsAutoFailoverEnabled { get; }

    FailoverPolicy CurrentPolicy { get; }

    IReadOnlyList<DnsResolverEndpoint> GetFailoverChain(DnsResolverEndpoint startingResolver);

    IReadOnlyList<FailoverEventEntry> GetFailoverHistory();

    NetworkRestrictionReport? LastRestrictionReport { get; }

    DnsFailureCategory ClassifyFailure(DnsResolverEndpoint resolver, string? errorMessage);

    Task<DnsQueryResult> QueryWithResilienceAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint preferredResolver,
        Func<DnsResolverEndpoint, CancellationToken, Task<DnsQueryResult>> queryExecutor,
        CancellationToken cancellationToken = default);

    Task<NetworkRestrictionReport> DiagnoseNetworkRestrictionsAsync(
        CancellationToken cancellationToken = default);

    void ClearHistory();
}
