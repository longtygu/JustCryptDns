using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Channels;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Monitoring;

/// <summary>
/// Optional, user-toggled asynchronous IP enrichment (<c>rDNS</c> + <c>ipinfo.io</c>) with strict rate limiting
/// and bounded local caching. Disabled by default so zero extra network traffic is emitted unless explicitly turned on.
/// </summary>
public sealed class IpEnrichmentService : IIpEnrichmentService
{
    private const int MaxCachedEntries = 2048;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan MinHttpInterval = TimeSpan.FromMilliseconds(400);

    private readonly ILogger<IpEnrichmentService> _logger;
    private readonly HttpClient _http;
    private readonly Channel<string> _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(128)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
    });

    private readonly ConcurrentDictionary<string, IpEnrichmentInfo> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _disposeCts = new();
    private Task? _workerTask;
    private volatile bool _isEnabled;
    private bool _disposed;

    public IpEnrichmentService(ILogger<IpEnrichmentService> logger)
    {
        _logger = logger;
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(3),
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("JustCryptDns/1.5");
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
        if (!_isEnabled || _disposed || string.IsNullOrWhiteSpace(ip))
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
        if (_disposed)
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
                var entry = await Dns.GetHostEntryAsync(addr).WaitAsync(dnsCts.Token).ConfigureAwait(false);
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

        try
        {
            using var response = await _http.GetAsync($"https://ipinfo.io/{Uri.EscapeDataString(ip)}/json", cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException or ObjectDisposedException)
        {
            // Rate-limited or offline; keep partial rDNS if available.
        }

        return new IpEnrichmentInfo(ip, rdns, org, country, DateTimeOffset.UtcNow);
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
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _isEnabled = false;
        _queue.Writer.TryComplete();
        _disposeCts.Cancel();
        _disposeCts.Dispose();
        _http.Dispose();
    }
}
