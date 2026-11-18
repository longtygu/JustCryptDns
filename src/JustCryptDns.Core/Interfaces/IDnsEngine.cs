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
}
