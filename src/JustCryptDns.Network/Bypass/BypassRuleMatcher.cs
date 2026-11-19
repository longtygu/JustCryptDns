using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Thread-safe rule matcher for DPI Bypass and Split-Tunnel routing, with a 15-minute
/// adaptive fallback hint cache so repeated connections skip dead direct paths immediately.
/// </summary>
public sealed class BypassRuleMatcher
{
    private static readonly TimeSpan AdaptiveHintTtl = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _tunnelHints = new(StringComparer.OrdinalIgnoreCase);

    public BypassMode Evaluate(string host, BypassSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalized = NormalizeHost(host);
        if (string.IsNullOrEmpty(normalized))
        {
            return BypassMode.Direct;
        }

        if (IsDirectExcluded(normalized, settings.DirectExclusionDomains))
        {
            return BypassMode.Direct;
        }

        if (settings.Upstream.Enabled
            && settings.AutoFallbackToTunnelOnDpiFailure
            && _tunnelHints.TryGetValue(normalized, out var expiresAt))
        {
            if (expiresAt > DateTimeOffset.UtcNow)
            {
                return BypassMode.UpstreamTunnel;
            }

            _tunnelHints.TryRemove(normalized, out _);
        }

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
                    return rule.Mode;
                }
            }
        }

        return BypassMode.Direct;
    }

    public void RecordAutoFallbackHint(string host)
    {
        var normalized = NormalizeHost(host);
        if (!string.IsNullOrEmpty(normalized))
        {
            _tunnelHints[normalized] = DateTimeOffset.UtcNow.Add(AdaptiveHintTtl);
        }
    }

    public void ClearHints() => _tunnelHints.Clear();

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
