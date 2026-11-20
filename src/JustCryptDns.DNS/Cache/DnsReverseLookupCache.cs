using System.Collections.Concurrent;
using System.Net;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.DNS.Cache;

/// <summary>
/// Thread-safe, bounded, TTL-aware in-memory cache mapping resolved IPv4/IPv6 addresses back to their queried domains.
/// </summary>
public sealed class DnsReverseLookupCache : IDnsReverseLookupCache
{
    private sealed class Entry
    {
        public required string Ip { get; init; }

        public required string Domain { get; set; }

        public required DateTimeOffset ExpiresAtUtc { get; set; }

        public long LastAccessTick { get; set; }
    }

    private readonly int _maxEntries;
    private readonly TimeProvider _timeProvider;
    private readonly int _minTtlSeconds;
    private readonly int _maxTtlSeconds;
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _evictLock = new();
    private long _accessTick;

    public DnsReverseLookupCache(
        TimeProvider? timeProvider = null,
        int maxEntries = 4096,
        int minTtlSeconds = 60,
        int maxTtlSeconds = 3600)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _maxEntries = Math.Max(1, maxEntries);
        _minTtlSeconds = Math.Max(1, minTtlSeconds);
        _maxTtlSeconds = Math.Max(_minTtlSeconds, maxTtlSeconds);
    }

    public int Count
    {
        get
        {
            PurgeExpired(_timeProvider.GetUtcNow());
            return _entries.Count;
        }
    }

    public void Record(IPAddress ip, string domain, uint ttlSeconds)
    {
        ArgumentNullException.ThrowIfNull(ip);
        var normalizedDomain = NormalizeDomain(domain);
        if (string.IsNullOrEmpty(normalizedDomain))
        {
            return;
        }

        var ipKey = NormalizeIpString(ip);
        if (string.IsNullOrEmpty(ipKey))
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();
        var effectiveTtl = Math.Clamp((long)ttlSeconds, _minTtlSeconds, _maxTtlSeconds);
        var expiresAt = now.AddSeconds(effectiveTtl);
        var tick = Interlocked.Increment(ref _accessTick);

        if (_entries.TryGetValue(ipKey, out var existing))
        {
            existing.Domain = normalizedDomain;
            existing.ExpiresAtUtc = expiresAt;
            existing.LastAccessTick = tick;
            return;
        }

        var newEntry = new Entry
        {
            Ip = ipKey,
            Domain = normalizedDomain,
            ExpiresAtUtc = expiresAt,
            LastAccessTick = tick,
        };

        if (_entries.Count >= _maxEntries)
        {
            lock (_evictLock)
            {
                _entries[ipKey] = newEntry;
                TrimToCapacityUnsafe(now);
                return;
            }
        }

        _entries[ipKey] = newEntry;
        if (_entries.Count > _maxEntries)
        {
            lock (_evictLock)
            {
                TrimToCapacityUnsafe(now);
            }
        }
    }

    public void RecordFromDnsPacket(string queryDomain, IReadOnlyList<(IPAddress Ip, uint TtlSeconds)> answers)
    {
        ArgumentNullException.ThrowIfNull(answers);
        if (string.IsNullOrWhiteSpace(queryDomain) || answers.Count == 0)
        {
            return;
        }

        foreach (var (ip, ttl) in answers)
        {
            Record(ip, queryDomain, ttl);
        }
    }

    public bool TryResolve(string? ip, out string domain)
    {
        domain = string.Empty;
        if (string.IsNullOrWhiteSpace(ip))
        {
            return false;
        }

        var key = IPAddress.TryParse(ip.Trim(), out var parsed)
            ? NormalizeIpString(parsed)
            : ip.Trim();

        if (!_entries.TryGetValue(key, out var entry))
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow();
        if (entry.ExpiresAtUtc <= now)
        {
            _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
            return false;
        }

        entry.LastAccessTick = Interlocked.Increment(ref _accessTick);
        domain = entry.Domain;
        return true;
    }

    public IReadOnlyList<string> GetIpsForDomain(string? domain)
    {
        var normalized = NormalizeDomain(domain);
        if (string.IsNullOrEmpty(normalized))
        {
            return [];
        }

        var now = _timeProvider.GetUtcNow();
        var suffix = "." + normalized;
        var results = new List<string>();

        foreach (var pair in _entries)
        {
            var entry = pair.Value;
            if (entry.ExpiresAtUtc <= now)
            {
                _entries.TryRemove(pair);
                continue;
            }

            if (string.Equals(entry.Domain, normalized, StringComparison.OrdinalIgnoreCase)
                || entry.Domain.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                results.Add(entry.Ip);
            }
        }

        return results;
    }

    public IReadOnlyList<ReverseDnsMapping> GetSnapshot(int maxItems = 800)
    {
        var cap = Math.Clamp(maxItems, 1, _maxEntries);
        var now = _timeProvider.GetUtcNow();
        PurgeExpired(now);

        return _entries.Values
            .Where(e => e.ExpiresAtUtc > now)
            .OrderByDescending(e => e.LastAccessTick)
            .Take(cap)
            .Select(e => new ReverseDnsMapping(e.Ip, e.Domain, e.ExpiresAtUtc))
            .ToList();
    }

    public void ImportSnapshot(IEnumerable<ReverseDnsMapping> mappings)
    {
        ArgumentNullException.ThrowIfNull(mappings);
        var now = _timeProvider.GetUtcNow();
        foreach (var mapping in mappings)
        {
            if (mapping is null || mapping.ExpiresAtUtc <= now)
            {
                continue;
            }

            if (!IPAddress.TryParse(mapping.Ip, out var ip))
            {
                continue;
            }

            var remainingSeconds = (uint)Math.Clamp((long)(mapping.ExpiresAtUtc - now).TotalSeconds, 1, _maxTtlSeconds);
            Record(ip, mapping.Domain, remainingSeconds);
        }
    }

    public void Clear() => _entries.Clear();

    private void PurgeExpired(DateTimeOffset now)
    {
        foreach (var pair in _entries)
        {
            if (pair.Value.ExpiresAtUtc <= now)
            {
                _entries.TryRemove(pair);
            }
        }
    }

    private void TrimToCapacityUnsafe(DateTimeOffset now)
    {
        PurgeExpired(now);
        if (_entries.Count <= _maxEntries)
        {
            return;
        }

        var excess = _entries.Count - _maxEntries;
        // Evict excess plus up to 10% headroom for larger caches while preserving exact maxEntries ceiling on small caches.
        var batchExtra = _maxEntries >= 20 ? Math.Max(0, _maxEntries / 10) : 0;
        var toRemove = Math.Min(_entries.Count, excess + batchExtra);

        var victims = _entries
            .OrderBy(p => p.Value.LastAccessTick)
            .Take(toRemove)
            .Select(p => p.Key)
            .ToList();

        foreach (var key in victims)
        {
            _entries.TryRemove(key, out _);
        }
    }

    private static string NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return string.Empty;
        }

        var normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
        return string.Equals(normalized, "unknown", StringComparison.Ordinal) ? string.Empty : normalized;
    }

    private static string NormalizeIpString(IPAddress ip)
    {
        var normalized = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        if (normalized.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && normalized.ScopeId != 0)
        {
            Span<byte> bytes = stackalloc byte[16];
            normalized.TryWriteBytes(bytes, out _);
            normalized = new IPAddress(bytes);
        }

        return normalized.ToString();
    }
}
