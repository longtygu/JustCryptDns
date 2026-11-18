using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<BlocklistCategory>))]
public enum BlocklistCategory
{
    Advertising,
    Tracking,
    Malware,
    Phishing,
    Telemetry,
    Custom,
}

public sealed record DnsBlocklistSource
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required BlocklistCategory Category { get; init; }

    public required string SourceUrl { get; init; }

    public bool IsEnabled { get; init; } = true;

    public bool IsBuiltIn { get; init; } = true;

    public DateTimeOffset? LastUpdatedAt { get; init; }

    public int DomainCount { get; init; }

    /// <summary>Built-in seed domains so offline/fresh installations still enforce core protections immediately.</summary>
    [JsonIgnore]
    public IReadOnlyList<string> SeedDomains { get; init; } = [];
}

public sealed record DnsAllowlistEntry
{
    public required string Domain { get; init; }

    public string Note { get; init; } = string.Empty;

    /// <summary>When non-null, this exception is temporary and expires at the given UTC time.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    [JsonIgnore]
    public bool IsTemporary => ExpiresAt.HasValue;

    public bool IsExpired(DateTimeOffset now) => ExpiresAt.HasValue && now >= ExpiresAt.Value;
}

[JsonConverter(typeof(JsonStringEnumConverter<FilterAction>))]
public enum FilterAction
{
    Allowed,
    AllowedByEssentialWindowsGuard,
    AllowedByUserAllowlist,
    AllowedByTemporaryException,
    BlockedByCustomRule,
    BlockedByBlocklist,
}

public sealed record FilterDecision
{
    public required string Domain { get; init; }

    public required bool IsBlocked { get; init; }

    public required FilterAction Action { get; init; }

    public string? MatchedRuleOrListId { get; init; }

    public string? MatchedRuleOrListName { get; init; }

    public BlocklistCategory? Category { get; init; }

    public required string Reason { get; init; }
}

public sealed record FilterLogEntry
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Domain { get; init; }

    public required bool IsBlocked { get; init; }

    public required FilterAction Action { get; init; }

    public required string SourceName { get; init; }
}

public sealed record DnsCacheStats
{
    public required bool IsEnabled { get; init; }

    public required int CurrentEntries { get; init; }

    public required int MaxEntries { get; init; }

    public required long CacheHits { get; init; }

    public required long CacheMisses { get; init; }

    public required long PositiveEntries { get; init; }

    public required long NegativeEntries { get; init; }

    public required long ExpiredEvictions { get; init; }

    public double HitRatioPercent
    {
        get
        {
            var total = CacheHits + CacheMisses;
            return total > 0 ? Math.Round((double)CacheHits * 100.0 / total, 1) : 0.0;
        }
    }
}

public static class EssentialWindowsDomains
{
    /// <summary>
    /// Essential Windows connectivity, time sync, update, and authentication domains that must never be silently blocked.
    /// </summary>
    public static IReadOnlySet<string> ProtectedDomains { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "www.msftconnecttest.com",
        "msftconnecttest.com",
        "dns.msftncsi.com",
        "www.msftncsi.com",
        "windowsupdate.microsoft.com",
        "update.microsoft.com",
        "download.windowsupdate.com",
        "ctldl.windowsupdate.com",
        "settings-win.data.microsoft.com",
        "login.microsoftonline.com",
        "login.live.com",
        "time.windows.com",
    };

    public static bool IsProtected(string normalizedDomain) =>
        ProtectedDomains.Contains(normalizedDomain);
}

public static class BuiltInBlocklists
{
    public static IReadOnlyList<DnsBlocklistSource> All { get; } =
    [
        new DnsBlocklistSource
        {
            Id = "list-ads-stevenblack",
            Name = "StevenBlack Adware & Advertising",
            Category = BlocklistCategory.Advertising,
            SourceUrl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            IsEnabled = true,
            IsBuiltIn = true,
            SeedDomains =
            [
                "pagead2.googlesyndication.com",
                "adservice.google.com",
                "ads.pubmatic.com",
                "ad.doubleclick.net",
                "static.ads-twitter.com",
                "ads.yahoo.com",
            ],
        },
        new DnsBlocklistSource
        {
            Id = "list-tracking-easyprivacy",
            Name = "OISD / EasyPrivacy Trackers",
            Category = BlocklistCategory.Tracking,
            SourceUrl = "https://v.firebog.net/hosts/Easyprivacy.txt",
            IsEnabled = true,
            IsBuiltIn = true,
            SeedDomains =
            [
                "pixel.facebook.com",
                "analytics.tiktok.com",
                "bat.bing.com",
                "scorecardresearch.com",
                "sb.scorecardresearch.com",
                "mouseflow.com",
            ],
        },
        new DnsBlocklistSource
        {
            Id = "list-malware-urlhaus",
            Name = "abuse.ch URLhaus Malware Domains",
            Category = BlocklistCategory.Malware,
            SourceUrl = "https://urlhaus.abuse.ch/downloads/hostfile/",
            IsEnabled = true,
            IsBuiltIn = true,
            SeedDomains =
            [
                "malware-distribution.test.invalid",
                "botnet-c2.test.invalid",
                "trojan-dropper.test.invalid",
            ],
        },
        new DnsBlocklistSource
        {
            Id = "list-phishing-openphish",
            Name = "Phishing Army & Anti-Phishing",
            Category = BlocklistCategory.Phishing,
            SourceUrl = "https://phishing.army/download/phishing_army_blocklist.txt",
            IsEnabled = true,
            IsBuiltIn = true,
            SeedDomains =
            [
                "phishing-login-verify.test.invalid",
                "fake-secure-wallet.test.invalid",
                "credential-harvest.test.invalid",
            ],
        },
        new DnsBlocklistSource
        {
            Id = "list-telemetry-thirdparty",
            Name = "Third-Party App Telemetry",
            Category = BlocklistCategory.Telemetry,
            SourceUrl = "https://v.firebog.net/hosts/Prigent-Ads.txt",
            IsEnabled = false,
            IsBuiltIn = true,
            SeedDomains =
            [
                "telemetry.sdk.test.invalid",
                "crashmetrics.example.invalid",
                "app-measurement.com",
            ],
        },
    ];
}
