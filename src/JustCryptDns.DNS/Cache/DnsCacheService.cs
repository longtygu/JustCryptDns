using System.Collections.Concurrent;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.DNS.Cache;

public sealed class DnsCacheService : IDnsCacheService
{
    private sealed record CacheEntry(
        string Key,
        byte[] WireBytes,
        DateTimeOffset ExpiresAt,
        bool IsNegative);

    private readonly ISettingsService _settings;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _evictLock = new();
    private long _hits;
    private long _misses;
    private long _expiredEvictions;

    public DnsCacheService(ISettingsService settings, Func<DateTimeOffset>? clock = null)
    {
        _settings = settings;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    public event EventHandler<DnsCacheStats>? StatsChanged;

    public bool IsEnabled => _settings.Current.Cache.IsCacheEnabled;

    public DnsCacheStats GetStats()
    {
        EvictExpiredInternal(_clock());
        var snapshot = _entries.Values.ToArray();
        var positive = snapshot.LongCount(e => !e.IsNegative);
        var negative = snapshot.Length - positive;
        return new DnsCacheStats
        {
            IsEnabled = IsEnabled,
            CurrentEntries = snapshot.Length,
            MaxEntries = _settings.Current.Cache.MaxEntries,
            CacheHits = Interlocked.Read(ref _hits),
            CacheMisses = Interlocked.Read(ref _misses),
            PositiveEntries = positive,
            NegativeEntries = negative,
            ExpiredEvictions = Interlocked.Read(ref _expiredEvictions),
        };
    }

    public async Task SetEnabledAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s => s.Cache.IsCacheEnabled = enabled, cancellationToken).ConfigureAwait(false);
        if (!enabled)
        {
            Clear();
        }
        else
        {
            RaiseStatsChanged();
        }
    }

    public bool TryGetResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes)
    {
        responseBytes = [];
        if (!IsEnabled)
        {
            return false;
        }

        if (!DnsPacket.TryParse(queryWire, out var query)
            || query is null
            || string.IsNullOrWhiteSpace(query.PrimaryQuestionName))
        {
            return false;
        }

        var key = BuildCacheKey(query.PrimaryQuestionName, query.PrimaryQuestionType);
        var now = _clock();

        if (_entries.TryGetValue(key, out var entry))
        {
            if (now < entry.ExpiresAt && entry.WireBytes.Length >= DnsPacket.HeaderSize)
            {
                var clone = (byte[])entry.WireBytes.Clone();
                DnsPacket.WriteTransactionId(clone, query.Header.Id);
                responseBytes = clone;
                Interlocked.Increment(ref _hits);
                RaiseStatsChanged();
                return true;
            }

            // Expired entry: never serve it, evict immediately.
            if (_entries.TryRemove(key, out _))
            {
                Interlocked.Increment(ref _expiredEvictions);
            }
        }

        Interlocked.Increment(ref _misses);
        return false;
    }

    public void StoreResponse(ReadOnlySpan<byte> queryWire, ReadOnlySpan<byte> responseWire)
    {
        if (!IsEnabled || responseWire.Length < DnsPacket.HeaderSize)
        {
            return;
        }

        if (!DnsPacket.TryParse(responseWire, out var response)
            || response is null
            || !response.Header.IsResponse
            || response.Header.IsTruncated
            || string.IsNullOrWhiteSpace(response.PrimaryQuestionName))
        {
            return;
        }

        var rcode = response.Header.ResponseCode;
        var cacheCfg = _settings.Current.Cache;
        var now = _clock();
        TimeSpan ttl;
        bool isNegative;

        if (rcode == DnsResponseCode.NoError && response.Answers.Count > 0)
        {
            var rawTtl = response.MinAnswerTtl ?? 0;
            if (rawTtl == 0)
            {
                // RFC 1035: TTL 0 means do not cache.
                return;
            }

            var clampedSeconds = Math.Clamp((int)Math.Min(rawTtl, int.MaxValue), cacheCfg.MinPositiveTtlSeconds, cacheCfg.MaxPositiveTtlSeconds);
            ttl = TimeSpan.FromSeconds(clampedSeconds);
            isNegative = false;
        }
        else if (rcode == DnsResponseCode.NxDomain || (rcode == DnsResponseCode.NoError && response.Answers.Count == 0))
        {
            ttl = TimeSpan.FromSeconds(cacheCfg.NegativeTtlSeconds);
            isNegative = true;
        }
        else
        {
            // Never cache SERVFAIL, REFUSED, FORMERR, etc.
            return;
        }

        EnforceCapacity(now, cacheCfg.MaxEntries);

        var key = BuildCacheKey(response.PrimaryQuestionName, response.PrimaryQuestionType);
        var entry = new CacheEntry(key, responseWire.ToArray(), now.Add(ttl), isNegative);
        _entries[key] = entry;
        RaiseStatsChanged();
    }

    public void Clear()
    {
        _entries.Clear();
        RaiseStatsChanged();
    }

    public int EvictExpired()
    {
        var count = EvictExpiredInternal(_clock());
        if (count > 0)
        {
            RaiseStatsChanged();
        }

        return count;
    }

    private static string BuildCacheKey(string domain, DnsRecordType type) =>
        $"{RoutingMatcher.NormalizeDomain(domain)}|{(ushort)type}";

    private int EvictExpiredInternal(DateTimeOffset now)
    {
        var evicted = 0;
        foreach (var (key, entry) in _entries)
        {
            if (now >= entry.ExpiresAt && _entries.TryRemove(key, out _))
            {
                evicted++;
                Interlocked.Increment(ref _expiredEvictions);
            }
        }

        return evicted;
    }

    private void EnforceCapacity(DateTimeOffset now, int maxEntries)
    {
        if (_entries.Count < maxEntries)
        {
            return;
        }

        lock (_evictLock)
        {
            EvictExpiredInternal(now);
            if (_entries.Count < maxEntries)
            {
                return;
            }

            var toRemove = _entries.Values
                .OrderBy(e => e.ExpiresAt)
                .Take(Math.Max(1, _entries.Count - maxEntries + 1))
                .Select(e => e.Key)
                .ToList();

            foreach (var key in toRemove)
            {
                _entries.TryRemove(key, out _);
            }
        }
    }

    private void RaiseStatsChanged() => StatsChanged?.Invoke(this, GetStats());
}
