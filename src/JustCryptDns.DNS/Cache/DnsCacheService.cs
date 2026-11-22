using System.Collections.Concurrent;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.DNS.Cache;

public sealed class DnsCacheService : IDnsCacheService
{
    private sealed class CacheEntry(
        string key,
        byte[] wireBytes,
        DateTimeOffset storedAt,
        DateTimeOffset expiresAt,
        bool isNegative)
    {
        public string Key { get; } = key;
        public byte[] WireBytes { get; } = wireBytes;
        public DateTimeOffset StoredAt { get; } = storedAt;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
        public bool IsNegative { get; } = isNegative;
        public int HitCount;
        public int PrefetchTriggered;
    }

    private sealed record StaleEntry(
        string Key,
        byte[] WireBytes,
        DateTimeOffset StaleUntil);

    private const uint ServeStaleResponseTtlSeconds = 30;

    private readonly ISettingsService _settings;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<string, CacheEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, StaleEntry> _staleEntries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _evictLock = new();
    private long _hits;
    private long _misses;
    private long _expiredEvictions;
    private long _staleHits;
    private long _prefetches;

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
            StaleHits = Interlocked.Read(ref _staleHits),
            PrefetchCount = Interlocked.Read(ref _prefetches),
            StaleEntries = _staleEntries.Count,
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

    public bool TryGetResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes) =>
        TryGetResponse(queryWire, out responseBytes, out _);

    public bool TryGetResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes, out bool shouldPrefetch)
    {
        responseBytes = [];
        shouldPrefetch = false;
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

                var entryHits = Interlocked.Increment(ref entry.HitCount);
                Interlocked.Increment(ref _hits);

                var cacheCfg = _settings.Current.Cache;
                var totalLifetime = (entry.ExpiresAt - entry.StoredAt).TotalSeconds;
                var remaining = (entry.ExpiresAt - now).TotalSeconds;
                var threshold = Math.Max(3.0, totalLifetime * 0.15);
                if (cacheCfg.EnablePrefetch
                    && !entry.IsNegative
                    && entryHits >= 2
                    && totalLifetime >= 10.0
                    && remaining <= threshold
                    && Interlocked.CompareExchange(ref entry.PrefetchTriggered, 1, 0) == 0)
                {
                    shouldPrefetch = true;
                    Interlocked.Increment(ref _prefetches);
                }

                RaiseStatsChanged();
                return true;
            }

            if (_entries.TryRemove(key, out var removed))
            {
                Interlocked.Increment(ref _expiredEvictions);
                MoveToStaleIfEligible(removed, now);
            }
        }

        Interlocked.Increment(ref _misses);
        return false;
    }

    public bool TryGetStaleResponse(ReadOnlySpan<byte> queryWire, out byte[] responseBytes)
    {
        responseBytes = [];
        var cacheCfg = _settings.Current.Cache;
        if (!cacheCfg.IsCacheEnabled || !cacheCfg.EnableServeStale || cacheCfg.ServeStaleGraceSeconds <= 0)
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

        if (_staleEntries.TryGetValue(key, out var stale))
        {
            if (now < stale.StaleUntil && stale.WireBytes.Length >= DnsPacket.HeaderSize)
            {
                var clone = (byte[])stale.WireBytes.Clone();
                DnsPacket.WriteTransactionId(clone, query.Header.Id);
                DnsPacket.RewriteAnswerTtls(clone, ServeStaleResponseTtlSeconds);
                responseBytes = clone;
                Interlocked.Increment(ref _staleHits);
                RaiseStatsChanged();
                return true;
            }

            _staleEntries.TryRemove(key, out _);
        }

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
            return;
        }

        EnforceCapacity(now, cacheCfg.MaxEntries);

        var key = BuildCacheKey(response.PrimaryQuestionName, response.PrimaryQuestionType);
        var entry = new CacheEntry(key, responseWire.ToArray(), now, now.Add(ttl), isNegative);
        _entries[key] = entry;
        _staleEntries.TryRemove(key, out _);
        RaiseStatsChanged();
    }

    public void Clear()
    {
        _entries.Clear();
        _staleEntries.Clear();
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

    private void MoveToStaleIfEligible(CacheEntry entry, DateTimeOffset now)
    {
        var cacheCfg = _settings.Current.Cache;
        if (entry.IsNegative
            || !cacheCfg.EnableServeStale
            || cacheCfg.ServeStaleGraceSeconds <= 0
            || entry.WireBytes.Length < DnsPacket.HeaderSize)
        {
            return;
        }

        var staleUntil = entry.ExpiresAt.AddSeconds(cacheCfg.ServeStaleGraceSeconds);
        if (now < staleUntil)
        {
            _staleEntries[entry.Key] = new StaleEntry(entry.Key, entry.WireBytes, staleUntil);
        }
    }

    private int EvictExpiredInternal(DateTimeOffset now)
    {
        var evicted = 0;
        foreach (var (key, entry) in _entries)
        {
            if (now >= entry.ExpiresAt && _entries.TryRemove(key, out var removed))
            {
                evicted++;
                Interlocked.Increment(ref _expiredEvictions);
                MoveToStaleIfEligible(removed, now);
            }
        }

        foreach (var (key, stale) in _staleEntries)
        {
            if (now >= stale.StaleUntil)
            {
                _staleEntries.TryRemove(key, out _);
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

            if (_staleEntries.Count > maxEntries)
            {
                foreach (var oldStale in _staleEntries.Values
                    .OrderBy(s => s.StaleUntil)
                    .Take(_staleEntries.Count - maxEntries)
                    .ToList())
                {
                    _staleEntries.TryRemove(oldStale.Key, out _);
                }
            }
        }
    }

    private void RaiseStatsChanged() => StatsChanged?.Invoke(this, GetStats());
}
