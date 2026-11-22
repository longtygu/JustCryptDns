using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Lightweight TTL-aware positive and negative DNS response cache (Part 8).
/// Never serves expired or malformed DNS records.
/// </summary>
public interface IDnsCacheService
{
    event EventHandler<DnsCacheStats>? StatsChanged;

    bool IsEnabled { get; }

    DnsCacheStats GetStats();

    Task SetEnabledAsync(bool enabled, CancellationToken cancellationToken = default);

    /// <summary>
    /// Attempts to retrieve a valid, non-expired DNS wire response for the given query packet,
    /// rewriting the transaction ID to match the request.
    /// </summary>
    bool TryGetResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes);

    bool TryGetResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes, out bool shouldPrefetch)
    {
        shouldPrefetch = false;
        return TryGetResponse(queryWire, out responseBytes);
    }

    bool TryGetStaleResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes)
    {
        responseBytes = [];
        return false;
    }

    /// <summary>
    /// Stores a positive (NOERROR with answers) or negative (NXDOMAIN) DNS wire response using its TTL.
    /// </summary>
    void StoreResponse(ReadOnlySpan<byte> queryWire, ReadOnlySpan<byte> responseWire);

    void Clear();

    int EvictExpired();
}
