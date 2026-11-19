using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Thread-safe rule matcher for DPI Bypass and Split-Tunnel routing, with a 30-minute
/// self-healing learned strategy cache per hostname.
/// </summary>
public sealed class BypassRuleMatcher
{
    private static readonly TimeSpan AdaptiveHintTtl = TimeSpan.FromMinutes(30);
    private readonly ConcurrentDictionary<string, LearnedHostEntry> _learnedHosts = new(StringComparer.OrdinalIgnoreCase);

    public BypassMode Evaluate(string host, BypassSettings settings) =>
        EvaluateDecision(host, settings).Mode;

    public (BypassMode Mode, LearnedHostStrategy? LearnedStrategy) EvaluateDecision(string host, BypassSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalized = NormalizeHost(host);
        if (string.IsNullOrEmpty(normalized) || IsDirectExcluded(normalized, settings.DirectExclusionDomains))
        {
            return (BypassMode.Direct, null);
        }

        var upstreamAvailable = settings.Upstream.Enabled && settings.Upstream.Kind != UpstreamTunnelKind.None;
        var hasLearned = TryGetActiveLearnedEntry(normalized, out var learned);

        var rules = settings.Rules;
        if (rules is not null)
        {
            foreach (var rule in rules)
            {
                if (!rule.Enabled)
                {
                    continue;
                }

                if (RoutingMatcher.IsMatch(normalized, rule.Pattern, rule.MatchKind))
                {
                    if (rule.Mode == BypassMode.AutoHybrid && hasLearned && learned is not null && settings.EnableSmartSelfHealing)
                    {
                        var mapped = MapLearnedMode(learned.Strategy, upstreamAvailable);
                        if (mapped.HasValue)
                        {
                            return (mapped.Value, learned.Strategy);
                        }
                    }

                    return (rule.Mode, null);
                }
            }
        }

        if (hasLearned && learned is not null && settings.EnableSmartSelfHealing)
        {
            var mapped = MapLearnedMode(learned.Strategy, upstreamAvailable);
            if (mapped.HasValue)
            {
                return (mapped.Value, learned.Strategy);
            }
        }

        return settings.CoverageMode == BypassCoverageMode.AllWebsitesSmart
            ? (settings.DefaultUnmatchedMode, null)
            : (BypassMode.Direct, null);
    }

    public void RecordAutoFallbackHint(string host) =>
        RecordLearnedHost(host, LearnedHostStrategy.UpstreamTunnel, "Auto-fallback after DPI failure");

    public void RecordLearnedHost(string host, LearnedHostStrategy strategy, string reason)
    {
        var normalized = NormalizeHost(host);
        if (string.IsNullOrEmpty(normalized))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        _learnedHosts[normalized] = new LearnedHostEntry(
            normalized,
            strategy,
            reason,
            now,
            now.Add(AdaptiveHintTtl));
    }

    public IReadOnlyList<LearnedHostEntry> GetLearnedHosts()
    {
        var now = DateTimeOffset.UtcNow;
        var active = new List<LearnedHostEntry>();
        foreach (var kvp in _learnedHosts)
        {
            if (kvp.Value.ExpiresAt <= now)
            {
                _learnedHosts.TryRemove(kvp.Key, out _);
            }
            else
            {
                active.Add(kvp.Value);
            }
        }

        active.Sort(static (a, b) => b.LearnedAt.CompareTo(a.LearnedAt));
        return active;
    }

    public int ActiveLearnedHostCount => GetLearnedHosts().Count;

    public void ClearHints() => _learnedHosts.Clear();

    private bool TryGetActiveLearnedEntry(string normalizedHost, out LearnedHostEntry? entry)
    {
        if (_learnedHosts.TryGetValue(normalizedHost, out var found))
        {
            if (found.ExpiresAt > DateTimeOffset.UtcNow)
            {
                entry = found;
                return true;
            }

            _learnedHosts.TryRemove(normalizedHost, out _);
        }

        entry = null;
        return false;
    }

    private static BypassMode? MapLearnedMode(LearnedHostStrategy strategy, bool upstreamAvailable) => strategy switch
    {
        LearnedHostStrategy.Direct => BypassMode.Direct,
        LearnedHostStrategy.EscalatedDpi16B => BypassMode.DpiFragment,
        LearnedHostStrategy.UpstreamTunnel => upstreamAvailable ? BypassMode.UpstreamTunnel : null,
        _ => null,
    };

    public static bool IsDirectExcluded(string normalizedHost, IEnumerable<string>? customExclusions)
    {
        if (string.Equals(normalizedHost, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IPAddress.TryParse(normalizedHost, out var ip))
        {
            if (IPAddress.IsLoopback(ip) || IsPrivateOrLinkLocal(ip))
            {
                return true;
            }
        }

        foreach (var pattern in BuiltInBypassRules.DefaultDirectExclusions)
        {
            if (MatchesExclusion(normalizedHost, pattern))
            {
                return true;
            }
        }

        if (customExclusions is not null)
        {
            foreach (var pattern in customExclusions)
            {
                if (!string.IsNullOrWhiteSpace(pattern) && MatchesExclusion(normalizedHost, pattern))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public static string NormalizeHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return string.Empty;
        }

        var trimmed = host.Trim();
        if (trimmed.StartsWith('[') && trimmed.EndsWith(']') && trimmed.Length > 2)
        {
            trimmed = trimmed[1..^1];
        }

        return trimmed.TrimEnd('.').ToLowerInvariant();
    }

    private static bool MatchesExclusion(string normalizedHost, string pattern)
    {
        var p = RoutingMatcher.NormalizeDomain(pattern);
        if (string.IsNullOrEmpty(p))
        {
            return false;
        }

        if (p.Contains('*') || p.Contains('?'))
        {
            return RoutingMatcher.IsMatch(normalizedHost, p, RoutingMatchKind.Wildcard);
        }

        return RoutingMatcher.IsMatch(normalizedHost, p, RoutingMatchKind.DomainSuffix);
    }

    private static bool IsPrivateOrLinkLocal(IPAddress ip)
    {
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;
        }

        if (ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();
        return bytes[0] switch
        {
            10 => true,
            127 => true,
            169 when bytes[1] == 254 => true,
            172 when bytes[1] is >= 16 and <= 31 => true,
            192 when bytes[1] == 168 => true,
            _ => false,
        };
    }
}
