using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<RoutingMatchKind>))]
public enum RoutingMatchKind
{
    DomainSuffix,
    Exact,
    Wildcard,
}

public sealed record DnsRoutingRule
{
    public required string Id { get; init; }

    public required string ProfileId { get; init; }

    public required string Name { get; init; }

    /// <summary>Domain pattern (e.g. <c>steampowered.com</c>, <c>*.riotgames.com</c>).</summary>
    public required string Pattern { get; init; }

    public RoutingMatchKind MatchKind { get; init; } = RoutingMatchKind.DomainSuffix;

    public required string ResolverId { get; init; }

    /// <summary>Lower value means higher precedence (evaluated first).</summary>
    public int Priority { get; init; } = 100;

    public bool IsEnabled { get; init; } = true;
}

public sealed record DnsRoutingProfile
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public string Description { get; init; } = string.Empty;

    public required string FallbackResolverId { get; init; }

    public bool IsBuiltIn { get; init; }
}

public sealed record RoutingDecision
{
    public required string Domain { get; init; }

    public required string ProfileId { get; init; }

    public string? MatchedRuleId { get; init; }

    public string? MatchedRuleName { get; init; }

    public string? MatchedPattern { get; init; }

    public RoutingMatchKind? MatchKind { get; init; }

    public required string ResolverId { get; init; }

    public required string ResolverName { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public required bool IsFallback { get; init; }
}

public sealed record RoutingLogEntry
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Domain { get; init; }

    public required string QueryType { get; init; }

    public required string MatchedRuleName { get; init; }

    public required string ResolverName { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public double? LatencyMs { get; init; }

    public required bool IsFallback { get; init; }
}

public static class RoutingMatcher
{
    public static string NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return string.Empty;
        }

        return domain.Trim().TrimEnd('.').ToLowerInvariant();
    }

    public static bool IsValidPattern(string? pattern, RoutingMatchKind matchKind, out string? errorMessage)
    {
        var norm = NormalizeDomain(pattern);
        if (string.IsNullOrEmpty(norm))
        {
            errorMessage = "Domain pattern is required.";
            return false;
        }

        if (norm.Contains(' ') || norm.Contains('/') || norm.Contains(':'))
        {
            errorMessage = "Domain pattern must not contain spaces, slashes, or ports.";
            return false;
        }

        if (matchKind != RoutingMatchKind.Wildcard && norm.Contains('*'))
        {
            errorMessage = "Wildcard '*' is only allowed when match type is Wildcard.";
            return false;
        }

        errorMessage = null;
        return true;
    }

    public static bool IsMatch(string normalizedDomain, string rulePattern, RoutingMatchKind matchKind)
    {
        if (string.IsNullOrEmpty(normalizedDomain) || string.IsNullOrWhiteSpace(rulePattern))
        {
            return false;
        }

        var pattern = NormalizeDomain(rulePattern);
        if (string.IsNullOrEmpty(pattern))
        {
            return false;
        }

        switch (matchKind)
        {
            case RoutingMatchKind.Exact:
                return string.Equals(normalizedDomain, pattern, StringComparison.OrdinalIgnoreCase);

            case RoutingMatchKind.DomainSuffix:
                if (pattern.StartsWith("*.", StringComparison.Ordinal))
                {
                    pattern = pattern[2..];
                }
                else if (pattern.StartsWith('.'))
                {
                    pattern = pattern[1..];
                }

                return string.Equals(normalizedDomain, pattern, StringComparison.OrdinalIgnoreCase)
                    || normalizedDomain.EndsWith("." + pattern, StringComparison.OrdinalIgnoreCase);

            case RoutingMatchKind.Wildcard:
                // Support *.example.com as matching both example.com and sub.example.com, plus general * and ? globs.
                if (pattern.StartsWith("*.", StringComparison.Ordinal) && !pattern[2..].Contains('*') && !pattern[2..].Contains('?'))
                {
                    var suffix = pattern[2..];
                    return string.Equals(normalizedDomain, suffix, StringComparison.OrdinalIgnoreCase)
                        || normalizedDomain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
                }

                var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
                return Regex.IsMatch(normalizedDomain, regexPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            default:
                return false;
        }
    }
}

public static class BuiltInRoutingProfiles
{
    public const string GamingProfileId = "gaming";
    public const string PrivacyProfileId = "privacy";
    public const string SecurityProfileId = "security";
    public const string CustomProfileId = "custom";

    public static IReadOnlyList<DnsRoutingProfile> All { get; } =
    [
        new DnsRoutingProfile
        {
            Id = GamingProfileId,
            Name = "Gaming",
            Description = "Routes Steam, Riot Games, Epic Games, Battle.net, EA and Ubisoft domains to low-latency resolvers.",
            FallbackResolverId = "cloudflare-doh",
            IsBuiltIn = true,
        },
        new DnsRoutingProfile
        {
            Id = PrivacyProfileId,
            Name = "Privacy",
            Description = "Routes browsing and search domains through no-log encrypted resolvers.",
            FallbackResolverId = "mullvad-doh",
            IsBuiltIn = true,
        },
        new DnsRoutingProfile
        {
            Id = SecurityProfileId,
            Name = "Security",
            Description = "Routes traffic through malware and phishing filtering resolvers.",
            FallbackResolverId = "quad9-doh",
            IsBuiltIn = true,
        },
        new DnsRoutingProfile
        {
            Id = CustomProfileId,
            Name = "Custom",
            Description = "User-defined domain routing rules and fallback resolver.",
            FallbackResolverId = "cloudflare-doh",
            IsBuiltIn = true,
        },
    ];

    public static IReadOnlyList<DnsRoutingRule> CreateDefaultRules() =>
    [
        // Gaming profile rules
        new DnsRoutingRule
        {
            Id = "rule-gaming-steam-1",
            ProfileId = GamingProfileId,
            Name = "Steam Community",
            Pattern = "steamcommunity.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 10,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-steam-2",
            ProfileId = GamingProfileId,
            Name = "Steam Store & CDN",
            Pattern = "steampowered.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 10,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-riot",
            ProfileId = GamingProfileId,
            Name = "Riot Games",
            Pattern = "*.riotgames.com",
            MatchKind = RoutingMatchKind.Wildcard,
            ResolverId = "cloudflare-doh",
            Priority = 20,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-epic",
            ProfileId = GamingProfileId,
            Name = "Epic Games",
            Pattern = "epicgames.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 20,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-battlenet",
            ProfileId = GamingProfileId,
            Name = "Battle.net & Blizzard",
            Pattern = "battle.net",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "google-doh",
            Priority = 30,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-pubg",
            ProfileId = GamingProfileId,
            Name = "PUBG Lobby",
            Pattern = "playbattlegrounds.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 25,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-pubg-core",
            ProfileId = GamingProfileId,
            Name = "PUBG Core",
            Pattern = "pubg.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 25,
        },
        new DnsRoutingRule
        {
            Id = "rule-gaming-ads",
            ProfileId = GamingProfileId,
            Name = "Telemetry & Ads Filter",
            Pattern = "*.doubleclick.net",
            MatchKind = RoutingMatchKind.Wildcard,
            ResolverId = "adguard-doh",
            Priority = 50,
        },

        // Privacy profile rules
        new DnsRoutingRule
        {
            Id = "rule-privacy-search",
            ProfileId = PrivacyProfileId,
            Name = "Search & Knowledge",
            Pattern = "*.wikipedia.org",
            MatchKind = RoutingMatchKind.Wildcard,
            ResolverId = "mullvad-doh",
            Priority = 10,
        },
        new DnsRoutingRule
        {
            Id = "rule-privacy-ads",
            ProfileId = PrivacyProfileId,
            Name = "Ad-Blocked Browsing",
            Pattern = "ads.*",
            MatchKind = RoutingMatchKind.Wildcard,
            ResolverId = "mullvad-adblock-doh",
            Priority = 20,
        },
        new DnsRoutingRule
        {
            Id = "rule-privacy-gaming-bypass",
            ProfileId = PrivacyProfileId,
            Name = "Steam Direct CDN",
            Pattern = "steampowered.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 30,
        },

        // Security profile rules
        new DnsRoutingRule
        {
            Id = "rule-security-zero",
            ProfileId = SecurityProfileId,
            Name = "High-Security Zero Trust",
            Pattern = "*.login.live.com",
            MatchKind = RoutingMatchKind.Wildcard,
            ResolverId = "dns0-zero-doh",
            Priority = 10,
        },
        new DnsRoutingRule
        {
            Id = "rule-security-quad9",
            ProfileId = SecurityProfileId,
            Name = "Microsoft Identity",
            Pattern = "microsoftonline.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "quad9-doh",
            Priority = 20,
        },

        // Custom profile starter rule
        new DnsRoutingRule
        {
            Id = "rule-custom-example",
            ProfileId = CustomProfileId,
            Name = "Example Custom Rule",
            Pattern = "steamcommunity.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 10,
        },
    ];
}

[JsonConverter(typeof(JsonStringEnumConverter<LocalDnsRewriteRecordType>))]
public enum LocalDnsRewriteRecordType
{
    A,
    AAAA,
    CNAME,
}

public sealed record LocalDnsRewriteRule
{
    public required string Id { get; init; }

    public required string Pattern { get; init; }

    public RoutingMatchKind MatchKind { get; init; } = RoutingMatchKind.Exact;

    public LocalDnsRewriteRecordType RecordType { get; init; } = LocalDnsRewriteRecordType.A;

    public required string TargetValue { get; init; }

    public int TtlSeconds { get; init; } = 60;

    public bool IsEnabled { get; init; } = true;

    public string Note { get; init; } = string.Empty;
}

public static class LocalDnsRewriteValidator
{
    public static (bool IsValid, string? ErrorMessage) Validate(LocalDnsRewriteRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (!RoutingMatcher.IsValidPattern(rule.Pattern, rule.MatchKind, out var patternError))
        {
            return (false, patternError ?? "Invalid domain pattern.");
        }

        if (rule.TtlSeconds is < 1 or > 86400)
        {
            return (false, "TTL must be between 1 and 86400 seconds.");
        }

        var target = rule.TargetValue?.Trim() ?? string.Empty;
        switch (rule.RecordType)
        {
            case LocalDnsRewriteRecordType.A:
                if (!IPAddress.TryParse(target, out var ipv4) || ipv4.AddressFamily != AddressFamily.InterNetwork)
                {
                    return (false, "Target value for A record must be a valid IPv4 address.");
                }

                break;

            case LocalDnsRewriteRecordType.AAAA:
                if (!IPAddress.TryParse(target, out var ipv6) || ipv6.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    return (false, "Target value for AAAA record must be a valid IPv6 address.");
                }

                break;

            case LocalDnsRewriteRecordType.CNAME:
                var cname = RoutingMatcher.NormalizeDomain(target);
                if (!IsValidHostName(cname))
                {
                    return (false, "Target value for CNAME record must be a valid domain name.");
                }

                break;

            default:
                return (false, "Unsupported local rewrite record type.");
        }

        return (true, null);
    }

    private static bool IsValidHostName(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253 || domain.Contains('*', StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var label in domain.Split('.'))
        {
            if (label.Length is 0 or > 63 || label.StartsWith('-') || label.EndsWith('-'))
            {
                return false;
            }

            foreach (var ch in label)
            {
                if (!(char.IsAsciiLetterOrDigit(ch) || ch == '-' || ch == '_'))
                {
                    return false;
                }
            }
        }

        return true;
    }
}
