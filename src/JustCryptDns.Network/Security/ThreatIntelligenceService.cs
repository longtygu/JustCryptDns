using System.Net;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Security;

/// <summary>
/// Local/cached Threat Intelligence IP &amp; CIDR matcher backed by user-triggered HTTPS updates from
/// Abuse.ch Feodo Tracker and Spamhaus DROP. Never flags LAN/loopback or protected DNS/gateway targets.
/// </summary>
public sealed class ThreatIntelligenceService : IThreatIntelligenceService, IDisposable
{
    public const string FeodoFeedUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
    public const string SpamhausDropFeedUrl = "https://www.spamhaus.org/drop/drop.txt";

    private sealed record PersistedThreatDocument(
        DateTimeOffset LastUpdatedUtc,
        List<PersistedThreatEntry> Entries);

    private sealed record PersistedThreatEntry(string Target, string Source, string Category);

    private sealed class ThreatIndex
    {
        public Dictionary<string, ThreatIntelMatch> SingleIps { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        public List<(CidrNetwork Network, ThreatIntelMatch Match)> Cidrs { get; init; } = [];

        public DateTimeOffset? LastUpdatedUtc { get; init; }

        public string? LastError { get; init; }
    }

    private readonly string _cacheFilePath;
    private readonly ILogger<ThreatIntelligenceService> _logger;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private volatile ThreatIndex _index = new();
    private bool _disposed;

    public ThreatIntelligenceService(
        IAppPaths paths,
        ILogger<ThreatIntelligenceService> logger,
        HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        _cacheFilePath = Path.Combine(paths.DataDirectory, "threat-intel-cache.json");
        _logger = logger;
        if (httpClient is not null)
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }
        else
        {
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("JustCryptDns/1.6.0");
            _ownsHttpClient = true;
        }

        LoadFromDisk();
    }

    public ThreatIntelStatus GetStatus()
    {
        var idx = _index;
        return new ThreatIntelStatus(
            idx.SingleIps.Count + idx.Cidrs.Count,
            idx.SingleIps.Count,
            idx.Cidrs.Count,
            idx.LastUpdatedUtc,
            idx.LastError);
    }

    public bool TryMatch(string? ipText, ProtectedIpContext? protectedContext, out ThreatIntelMatch match)
    {
        match = null!;
        if (string.IsNullOrWhiteSpace(ipText) || ipText == "*")
        {
            return false;
        }

        if (!IPAddress.TryParse(ipText.Trim(), out var parsed))
        {
            return false;
        }

        var normalizedIp = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        if (CidrNetwork.IsLanOrLocal(normalizedIp))
        {
            return false;
        }

        if (protectedContext is not null)
        {
            foreach (var entry in protectedContext.Entries)
            {
                if (entry.Network.Contains(normalizedIp))
                {
                    return false;
                }
            }
        }

        var idx = _index;
        if (idx.SingleIps.TryGetValue(normalizedIp.ToString(), out var directMatch))
        {
            match = directMatch;
            return true;
        }

        foreach (var (cidr, cidrMatch) in idx.Cidrs)
        {
            if (cidr.Contains(normalizedIp))
            {
                match = cidrMatch;
                return true;
            }
        }

        return false;
    }

    public async Task<ThreatIntelStatus> RefreshFeedsAsync(CancellationToken cancellationToken = default)
    {
        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = new List<(CidrNetwork Network, ThreatIntelMatch Match)>();
            var errors = new List<string>();

            try
            {
                var feodoText = await _http.GetStringAsync(FeodoFeedUrl, cancellationToken).ConfigureAwait(false);
                entries.AddRange(ParseFeodoLines(feodoText));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                errors.Add($"Feodo: {ex.Message}");
            }

            try
            {
                var dropText = await _http.GetStringAsync(SpamhausDropFeedUrl, cancellationToken).ConfigureAwait(false);
                entries.AddRange(ParseSpamhausDropLines(dropText));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                errors.Add($"Spamhaus: {ex.Message}");
            }

            if (entries.Count == 0 && errors.Count > 0)
            {
                var current = _index;
                _index = new ThreatIndex
                {
                    SingleIps = current.SingleIps,
                    Cidrs = current.Cidrs,
                    LastUpdatedUtc = current.LastUpdatedUtc,
                    LastError = string.Join(" | ", errors),
                };
                return GetStatus();
            }

            var now = DateTimeOffset.UtcNow;
            ApplyEntries(entries, now, errors.Count > 0 ? string.Join(" | ", errors) : null);
            SaveToDisk(entries, now);
            return GetStatus();
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    internal static IReadOnlyList<(CidrNetwork Network, ThreatIntelMatch Match)> ParseFeodoLines(string content)
    {
        var list = new List<(CidrNetwork, ThreatIntelMatch)>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return list;
        }

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith('#') || trimmed.StartsWith(';'))
            {
                continue;
            }

            if (CidrNetwork.TryParse(trimmed, out var net, out _))
            {
                list.Add((net, new ThreatIntelMatch(net.CanonicalText, "Abuse.ch Feodo C2", "Botnet C2")));
            }
        }

        return list;
    }

    internal static IReadOnlyList<(CidrNetwork Network, ThreatIntelMatch Match)> ParseSpamhausDropLines(string content)
    {
        var list = new List<(CidrNetwork, ThreatIntelMatch)>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return list;
        }

        using var reader = new StringReader(content);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            var commentIdx = line.IndexOf(';', StringComparison.Ordinal);
            var targetPart = (commentIdx >= 0 ? line[..commentIdx] : line).Trim();
            if (targetPart.Length == 0 || targetPart.StartsWith('#'))
            {
                continue;
            }

            if (CidrNetwork.TryParse(targetPart, out var net, out _))
            {
                list.Add((net, new ThreatIntelMatch(net.CanonicalText, "Spamhaus DROP", "Hijacked / Malicious Netblock")));
            }
        }

        return list;
    }

    internal void LoadTestIndicators(IEnumerable<(string Target, string Source, string Category)> indicators)
    {
        var list = new List<(CidrNetwork, ThreatIntelMatch)>();
        foreach (var (target, source, category) in indicators)
        {
            if (CidrNetwork.TryParse(target, out var net, out _))
            {
                list.Add((net, new ThreatIntelMatch(net.CanonicalText, source, category)));
            }
        }

        ApplyEntries(list, DateTimeOffset.UtcNow, null);
    }

    private void ApplyEntries(
        IEnumerable<(CidrNetwork Network, ThreatIntelMatch Match)> entries,
        DateTimeOffset updatedAt,
        string? error)
    {
        var ips = new Dictionary<string, ThreatIntelMatch>(StringComparer.OrdinalIgnoreCase);
        var cidrs = new List<(CidrNetwork Network, ThreatIntelMatch Match)>();
        var seenCidrs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (net, match) in entries)
        {
            if (net.IsSingleHost)
            {
                ips.TryAdd(net.CanonicalText, match);
            }
            else if (seenCidrs.Add(net.CanonicalText))
            {
                cidrs.Add((net, match));
            }
        }

        _index = new ThreatIndex
        {
            SingleIps = ips,
            Cidrs = cidrs,
            LastUpdatedUtc = updatedAt,
            LastError = error,
        };
    }

    private void LoadFromDisk()
    {
        if (!File.Exists(_cacheFilePath))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(_cacheFilePath);
            var doc = JsonSerializer.Deserialize<PersistedThreatDocument>(json, SettingsJson.Options);
            if (doc?.Entries is null)
            {
                return;
            }

            var list = new List<(CidrNetwork, ThreatIntelMatch)>(doc.Entries.Count);
            foreach (var entry in doc.Entries)
            {
                if (CidrNetwork.TryParse(entry.Target, out var net, out _))
                {
                    list.Add((net, new ThreatIntelMatch(net.CanonicalText, entry.Source, entry.Category)));
                }
            }

            ApplyEntries(list, doc.LastUpdatedUtc, null);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not load threat intel cache.");
        }
    }

    private void SaveToDisk(IReadOnlyList<(CidrNetwork Network, ThreatIntelMatch Match)> entries, DateTimeOffset updatedAt)
    {
        try
        {
            var dir = Path.GetDirectoryName(_cacheFilePath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var persisted = entries
                .Select(e => new PersistedThreatEntry(e.Network.CanonicalText, e.Match.Source, e.Match.Category))
                .ToList();

            var doc = new PersistedThreatDocument(updatedAt, persisted);
            var tmp = _cacheFilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(doc, SettingsJson.Options));
            File.Move(tmp, _cacheFilePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not persist threat intel cache.");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _refreshGate.Dispose();
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
