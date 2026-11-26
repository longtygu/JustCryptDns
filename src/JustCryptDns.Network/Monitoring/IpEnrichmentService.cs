using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Channels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Monitoring;

/// <summary>
/// Optional, user-toggled asynchronous IP enrichment (<c>rDNS</c> + multi-provider HTTPS failover:
/// <c>ipinfo.io</c> → <c>ipwho.is</c> → <c>ipapi.co</c>) with strict rate limiting and persistent disk cache.
/// Disabled by default so zero extra network traffic is emitted unless explicitly turned on.
/// </summary>
public sealed class IpEnrichmentService : IIpEnrichmentService
{
    private const int MaxCachedEntries = 4096;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan MinHttpInterval = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan DiskSaveInterval = TimeSpan.FromSeconds(10);

    private readonly ILogger<IpEnrichmentService> _logger;
    private readonly string? _cacheFilePath;
    private readonly HttpClient _http;
    private readonly Channel<string> _queue;

    private readonly ConcurrentDictionary<string, IpEnrichmentInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly object _diskLock = new();
    private Task? _workerTask;
    private DateTimeOffset _lastSavedAt = DateTimeOffset.MinValue;
    private volatile bool _dirty;
    private volatile bool _isEnabled;
    private int _disposed;

    public IpEnrichmentService(ILogger<IpEnrichmentService> logger, IAppPaths? paths = null)
    {
        _logger = logger;
        _cacheFilePath = paths is not null ? Path.Combine(paths.DataDirectory, "ip-org-cache.json") : null;
        _queue = Channel.CreateBounded<string>(
            new BoundedChannelOptions(128)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
            },
            droppedIp => _inFlight.TryRemove(droppedIp, out _));
        _http = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        })
        {
            Timeout = TimeSpan.FromSeconds(3),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("JustCryptDns/1.8.5");
        LoadDiskCache();
    }

    public event EventHandler<IpEnrichmentInfo>? EnrichmentReady;

    public bool TryGetCached(string ip, out IpEnrichmentInfo info)
    {
        info = null!;
        if (string.IsNullOrWhiteSpace(ip) || !_cache.TryGetValue(ip.Trim(), out var cached))
        {
            return false;
        }

        if ((DateTimeOffset.UtcNow - cached.CachedAtUtc) > CacheTtl)
        {
            _cache.TryRemove(ip.Trim(), out _);
            return false;
        }

        info = cached;
        return true;
    }

    public void EnqueueLookup(string ip)
    {
        if (!_isEnabled || Volatile.Read(ref _disposed) != 0 || string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        var normalized = ip.Trim();
        if (CidrNetwork.IsLanOrLocalString(normalized)
            || !IPAddress.TryParse(normalized, out _))
        {
            return;
        }

        if (TryGetCached(normalized, out _))
        {
            return;
        }

        if (_inFlight.TryAdd(normalized, 0))
        {
            if (!_queue.Writer.TryWrite(normalized))
            {
                _inFlight.TryRemove(normalized, out _);
            }
        }
    }

    public void Pause() => _isEnabled = false;

    public void Resume()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _isEnabled = true;
        EnsureWorkerStarted();
    }

    private void EnsureWorkerStarted()
    {
        if (_workerTask is not null)
        {
            return;
        }

        lock (_queue)
        {
            _workerTask ??= Task.Run(() => ProcessQueueAsync(_disposeCts.Token));
        }
    }

    private async Task ProcessQueueAsync(CancellationToken cancellationToken)
    {
        var lastHttpAt = DateTimeOffset.MinValue;
        try
        {
            await foreach (var ip in _queue.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    if (!_isEnabled)
                    {
                        continue;
                    }

                    var elapsed = DateTimeOffset.UtcNow - lastHttpAt;
                    if (elapsed < MinHttpInterval)
                    {
                        await Task.Delay(MinHttpInterval - elapsed, cancellationToken).ConfigureAwait(false);
                    }

                    lastHttpAt = DateTimeOffset.UtcNow;
                    var info = await FetchEnrichmentAsync(ip, cancellationToken).ConfigureAwait(false);
                    if (_cache.Count >= MaxCachedEntries)
                    {
                        PruneOldest();
                    }

                    _cache[ip] = info;
                    _dirty = true;
                    MaybeFlushDiskCache(force: false);
                    EnrichmentReady?.Invoke(this, info);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "IP enrichment lookup failed cleanly for {Ip}.", ip);
                }
                finally
                {
                    _inFlight.TryRemove(ip, out _);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (ObjectDisposedException)
        {
            // Normal shutdown race.
        }
    }

    private async Task<IpEnrichmentInfo> FetchEnrichmentAsync(string ip, CancellationToken cancellationToken)
    {
        string? rdns = null;
        string? org = null;
        string? country = null;

        try
        {
            using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            dnsCts.CancelAfter(TimeSpan.FromMilliseconds(1500));
            if (IPAddress.TryParse(ip, out var addr))
            {
                var entry = await Dns.GetHostEntryAsync(addr.ToString(), dnsCts.Token).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(entry.HostName)
                    && !string.Equals(entry.HostName, addr.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    rdns = entry.HostName;
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException or ObjectDisposedException)
        {
            // Reverse DNS is best-effort only.
        }

        // Provider 1: ipinfo.io
        (org, country, rdns) = await TryQueryIpInfoAsync(ip, org, country, rdns, cancellationToken).ConfigureAwait(false);

        // Provider 2 fallback: ipwho.is
        if (string.IsNullOrWhiteSpace(org))
        {
            (org, country) = await TryQueryIpWhoIsAsync(ip, org, country, cancellationToken).ConfigureAwait(false);
        }

        // Provider 3 fallback: ipapi.co
        if (string.IsNullOrWhiteSpace(org))
        {
            (org, country) = await TryQueryIpApiCoAsync(ip, org, country, cancellationToken).ConfigureAwait(false);
        }

        return new IpEnrichmentInfo(ip, rdns, org, country, DateTimeOffset.UtcNow);
    }

    private async Task<(string? Org, string? Country, string? Rdns)> TryQueryIpInfoAsync(
        string ip, string? org, string? country, string? rdns, CancellationToken ct)
    {
        try
        {
            using var response = await _http.GetAsync($"https://ipinfo.io/{Uri.EscapeDataString(ip)}/json", ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return (org, country, rdns);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (doc.RootElement.TryGetProperty("org", out var orgProp) && orgProp.ValueKind == JsonValueKind.String)
            {
                org = orgProp.GetString();
            }

            if (doc.RootElement.TryGetProperty("country", out var countryProp) && countryProp.ValueKind == JsonValueKind.String)
            {
                country = countryProp.GetString();
            }

            if (string.IsNullOrWhiteSpace(rdns)
                && doc.RootElement.TryGetProperty("hostname", out var hostProp)
                && hostProp.ValueKind == JsonValueKind.String)
            {
                rdns = hostProp.GetString();
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or ObjectDisposedException)
        {
            // Fall through to secondary provider.
        }

        return (org, country, rdns);
    }

    private async Task<(string? Org, string? Country)> TryQueryIpWhoIsAsync(
        string ip, string? org, string? country, CancellationToken ct)
    {
        try
        {
            using var response = await _http.GetAsync($"https://ipwho.is/{Uri.EscapeDataString(ip)}", ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return (org, country);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (doc.RootElement.TryGetProperty("success", out var okProp) && okProp.ValueKind == JsonValueKind.False)
            {
                return (org, country);
            }

            if (string.IsNullOrWhiteSpace(country)
                && doc.RootElement.TryGetProperty("country_code", out var ccProp)
                && ccProp.ValueKind == JsonValueKind.String)
            {
                country = ccProp.GetString();
            }

            if (doc.RootElement.TryGetProperty("connection", out var connProp) && connProp.ValueKind == JsonValueKind.Object)
            {
                string? isp = connProp.TryGetProperty("org", out var o) && o.ValueKind == JsonValueKind.String ? o.GetString() : null;
                if (string.IsNullOrWhiteSpace(isp) && connProp.TryGetProperty("isp", out var i) && i.ValueKind == JsonValueKind.String)
                {
                    isp = i.GetString();
                }

                if (!string.IsNullOrWhiteSpace(isp))
                {
                    if (connProp.TryGetProperty("asn", out var asn) && asn.TryGetInt64(out var asnNum) && asnNum > 0)
                    {
                        org = $"AS{asnNum} {isp}";
                    }
                    else
                    {
                        org = isp;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or ObjectDisposedException)
        {
            // Fall through to tertiary provider.
        }

        return (org, country);
    }

    private async Task<(string? Org, string? Country)> TryQueryIpApiCoAsync(
        string ip, string? org, string? country, CancellationToken ct)
    {
        try
        {
            using var response = await _http.GetAsync($"https://ipapi.co/{Uri.EscapeDataString(ip)}/json/", ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return (org, country);
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(country)
                && doc.RootElement.TryGetProperty("country_code", out var ccProp)
                && ccProp.ValueKind == JsonValueKind.String)
            {
                country = ccProp.GetString();
            }

            var orgName = doc.RootElement.TryGetProperty("org", out var orgProp) && orgProp.ValueKind == JsonValueKind.String
                ? orgProp.GetString()
                : null;
            var asn = doc.RootElement.TryGetProperty("asn", out var asnProp) && asnProp.ValueKind == JsonValueKind.String
                ? asnProp.GetString()
                : null;

            if (!string.IsNullOrWhiteSpace(orgName))
            {
                org = !string.IsNullOrWhiteSpace(asn) && !orgName.StartsWith(asn, StringComparison.OrdinalIgnoreCase)
                    ? $"{asn} {orgName}"
                    : orgName;
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or ObjectDisposedException)
        {
            // Keep partial rDNS if available.
        }

        return (org, country);
    }

    private void LoadDiskCache()
    {
        if (string.IsNullOrWhiteSpace(_cacheFilePath) || !File.Exists(_cacheFilePath))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(_cacheFilePath);
            var list = JsonSerializer.Deserialize<List<IpEnrichmentInfo>>(json, SettingsJson.Options);
            if (list is null)
            {
                return;
            }

            var now = DateTimeOffset.UtcNow;
            foreach (var item in list.Take(MaxCachedEntries))
            {
                if (item is null || string.IsNullOrWhiteSpace(item.Ip) || (now - item.CachedAtUtc) > CacheTtl)
                {
                    continue;
                }

                _cache[item.Ip] = item;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not load persisted IP enrichment cache.");
        }
    }

    private void MaybeFlushDiskCache(bool force)
    {
        if (string.IsNullOrWhiteSpace(_cacheFilePath) || !_dirty)
        {
            return;
        }

        if (!force && (DateTimeOffset.UtcNow - _lastSavedAt) < DiskSaveInterval)
        {
            return;
        }

        lock (_diskLock)
        {
            if (!_dirty || (!force && (DateTimeOffset.UtcNow - _lastSavedAt) < DiskSaveInterval))
            {
                return;
            }

            try
            {
                var dir = Path.GetDirectoryName(_cacheFilePath);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                var now = DateTimeOffset.UtcNow;
                var items = _cache.Values
                    .Where(e => !string.IsNullOrWhiteSpace(e.Organization) || !string.IsNullOrWhiteSpace(e.ReverseDns))
                    .Where(e => (now - e.CachedAtUtc) <= CacheTtl)
                    .OrderByDescending(e => e.CachedAtUtc)
                    .Take(MaxCachedEntries)
                    .ToList();

                var tmp = _cacheFilePath + ".tmp";
                var json = JsonSerializer.Serialize(items, SettingsJson.Options);
                File.WriteAllText(tmp, json);
                File.Move(tmp, _cacheFilePath, overwrite: true);
                _lastSavedAt = now;
                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug(ex, "Could not flush IP enrichment cache to disk.");
            }
        }
    }

    private void PruneOldest()
    {
        var oldest = _cache
            .OrderBy(kv => kv.Value.CachedAtUtc)
            .Take(MaxCachedEntries / 5)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in oldest)
        {
            _cache.TryRemove(key, out _);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _isEnabled = false;
        _queue.Writer.TryComplete();
        try { _disposeCts.Cancel(); } catch { }
        MaybeFlushDiskCache(force: true);
        _disposeCts.Dispose();
        _http.Dispose();
    }
}
