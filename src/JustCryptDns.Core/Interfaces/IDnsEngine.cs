using System.Net;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

public sealed record DnsQueryResult(
    bool Success,
    byte[] ResponseBytes,
    double LatencyMs,
    string ResolverId,
    DnsProtocol Protocol,
    string? Error = null);

public interface IDnsUpstreamClient
{
    DnsProtocol Protocol { get; }

    Task<DnsQueryResult> QueryAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint resolver,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public interface IDnsEngine : IAsyncDisposable
{
    DnsEngineRuntimeStats GetStats();

    event EventHandler<DnsEngineRuntimeStats>? StateChanged;

    Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default);

    Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default);

    Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends real UDP DNS queries directly through the local proxy listener to verify end-to-end
    /// resolution, routing, filtering, caching, and live monitoring.
    /// </summary>
    Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a hostname using JustCryptDns's active encrypted resolver (and TTL cache)
    /// without relying on poisoned or unconfigured OS DNS.
    /// </summary>
    Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        bool includeIpv6 = false,
        CancellationToken cancellationToken = default);
}
