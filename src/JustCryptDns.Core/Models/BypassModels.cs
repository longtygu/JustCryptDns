using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<BypassMode>))]
public enum BypassMode
{
    Direct,
    DpiFragment,
    UpstreamTunnel,
    AutoHybrid,
}

[JsonConverter(typeof(JsonStringEnumConverter<BypassCoverageMode>))]
public enum BypassCoverageMode
{
    AllWebsitesSmart,
    RuleListOnly,
}

[JsonConverter(typeof(JsonStringEnumConverter<LearnedHostStrategy>))]
public enum LearnedHostStrategy
{
    Direct,
    EscalatedDpi16B,
    UpstreamTunnel,
}

[JsonConverter(typeof(JsonStringEnumConverter<TlsFragmentationStrategy>))]
public enum TlsFragmentationStrategy
{
    RecordChunkSplit,
    SniMidpointSplit,
    AggressiveSmallRecords,
}

[JsonConverter(typeof(JsonStringEnumConverter<UpstreamTunnelKind>))]
public enum UpstreamTunnelKind
{
    None,
    CloudflareWarpLocal,
    Socks5,
    HttpConnect,
}

[JsonConverter(typeof(JsonStringEnumConverter<WindowsProxyMode>))]
public enum WindowsProxyMode
{
    AutoPac,
    GlobalSystemProxy,
    ManualOnly,
}

[JsonConverter(typeof(JsonStringEnumConverter<BypassEngineState>))]
public enum BypassEngineState
{
    Stopped,
    Starting,
    Running,
    Degraded,
    Stopping,
}

[JsonConverter(typeof(JsonStringEnumConverter<BypassActionKind>))]
public enum BypassActionKind
{
    DpiFragmented,
    EscalatedDpi16B,
    SelfHealedDirect,
    UpstreamTunneled,
    AutoFallbackTunnel,
    DirectPassthrough,
    Failed,
}

public sealed record LearnedHostEntry(
    string Host,
    LearnedHostStrategy Strategy,
    string Reason,
    DateTimeOffset LearnedAt,
    DateTimeOffset ExpiresAt);

public sealed record BypassRule
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Pattern { get; init; }

    public RoutingMatchKind MatchKind { get; init; } = RoutingMatchKind.DomainSuffix;

    public BypassMode Mode { get; init; } = BypassMode.AutoHybrid;

    public string Category { get; init; } = "Custom";

    public bool Enabled { get; init; } = true;

    public bool IsBuiltIn { get; init; }
}

public sealed class UpstreamTunnelSettings
{
    public const string DefaultHost = "127.0.0.1";
    public const int DefaultWarpPort = 40000;

    public bool Enabled { get; set; }

    public UpstreamTunnelKind Kind { get; set; } = UpstreamTunnelKind.CloudflareWarpLocal;

    public string Host { get; set; } = DefaultHost;

    public int Port { get; set; } = DefaultWarpPort;

    public string? Username { get; set; }

    public string? Password { get; set; }

    public void Normalize()
    {
        if (!Enum.IsDefined(Kind))
        {
            Kind = UpstreamTunnelKind.CloudflareWarpLocal;
        }

        if (string.IsNullOrWhiteSpace(Host))
        {
            Host = DefaultHost;
        }
        else
        {
            Host = Host.Trim();
        }

        if (Port <= 0 || Port > 65535)
        {
            Port = DefaultWarpPort;
        }

        Username = string.IsNullOrWhiteSpace(Username) ? null : Username.Trim();
        Password = string.IsNullOrEmpty(Password) ? null : Password;
    }
}

public sealed record BypassRuntimeStats
{
    public BypassEngineState State { get; init; } = BypassEngineState.Stopped;

    public string ProxyEndpoint { get; init; } = "127.0.0.1:10808";

    public string PacUrl { get; init; } = "http://127.0.0.1:10809/proxy.pac";

    public int BoundProxyPort { get; init; }

    public int BoundPacPort { get; init; }

    public bool WindowsProxyApplied { get; init; }

    public WindowsProxyMode ActiveWindowsProxyMode { get; init; } = WindowsProxyMode.AutoPac;

    public long TotalConnections { get; init; }

    public long DpiBypassedConnections { get; init; }

    public long TunneledConnections { get; init; }

    public long DirectConnections { get; init; }

    public long FailedConnections { get; init; }

    public long AutoFallbackCount { get; init; }

    public int ActiveTunnels { get; init; }

    public bool UpstreamConfigured { get; init; }

    public string UpstreamSummary { get; init; } = string.Empty;

    public string? LastError { get; init; }

    public bool HasProxyBackup { get; init; }

    public BypassCoverageMode CoverageMode { get; init; } = BypassCoverageMode.AllWebsitesSmart;

    public int LearnedHostCount { get; init; }

    public long SelfHealedDirectCount { get; init; }

    public long EscalatedDpiCount { get; init; }
}

public sealed record BypassConnectionEvent
{
    public required DateTimeOffset Timestamp { get; init; }

    public required string Host { get; init; }

    public required int Port { get; init; }

    public required string ClientProtocol { get; init; }

    public required BypassActionKind Action { get; init; }

    public required string StrategyUsed { get; init; }

    public double? LatencyMs { get; init; }

    public string? Error { get; init; }
}

public sealed record BypassTestResult
{
    public required string Host { get; init; }

    public string? ResolvedIp { get; init; }

    public bool DirectSucceeded { get; init; }

    public double? DirectLatencyMs { get; init; }

    public string? DirectError { get; init; }

    public bool DpiBypassSucceeded { get; init; }

    public double? DpiBypassLatencyMs { get; init; }

    public int? DpiBypassStatusCode { get; init; }

    public string? DpiBypassError { get; init; }

    public bool TunnelSucceeded { get; init; }

    public double? TunnelLatencyMs { get; init; }

    public string? TunnelError { get; init; }

    public BypassMode RecommendedMode { get; init; } = BypassMode.AutoHybrid;

    public required string Summary { get; init; }
}

public sealed record WindowsProxyBackup
{
    public int? ProxyEnable { get; init; }

    public string? ProxyServer { get; init; }

    public string? ProxyOverride { get; init; }

    public string? AutoConfigUrl { get; init; }

    public int? AutoDetect { get; init; }

    public bool IsActive { get; init; } = true;

    public required DateTimeOffset CreatedAtUtc { get; init; }

    public required string Sha256 { get; init; }

    public string ComputePayloadHash()
    {
        var canonical = string.Create(
            CultureInfo.InvariantCulture,
            $"pe={ProxyEnable?.ToString(CultureInfo.InvariantCulture) ?? "<null>"};ps={ProxyServer ?? "<null>"};po={ProxyOverride ?? "<null>"};ac={AutoConfigUrl ?? "<null>"};ad={AutoDetect?.ToString(CultureInfo.InvariantCulture) ?? "<null>"};at={CreatedAtUtc.ToUnixTimeMilliseconds()}");
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes);
    }

    public bool VerifyIntegrity() =>
        !string.IsNullOrWhiteSpace(Sha256)
        && string.Equals(Sha256, ComputePayloadHash(), StringComparison.OrdinalIgnoreCase);
}

public static class BuiltInBypassRules
{
    public const string CategorySteam = "Steam";
    public const string CategoryGaming = "Gaming";
    public const string CategoryWeb = "BlockedWeb";

    public static IReadOnlyList<string> DefaultDirectExclusions { get; } =
    [
        "localhost",
        "127.0.0.1",
        "*.local",
        "*.lan",
    ];

    public static IReadOnlyList<BypassRule> All { get; } =
    [
        // Steam Store & Community (enabled by default, AutoHybrid)
        Rule("steam-store", "Steam Store", "steampowered.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-community", "Steam Community", "steamcommunity.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-static", "Steam Static CDN", "steamstatic.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-usercontent", "Steam User Content", "steamusercontent.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-chat", "Steam Chat", "steam-chat.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-games", "Steam Games", "steamgames.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-content", "Steam Content", "steamcontent.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategorySteam, enabled: true),
        Rule("steam-akamai", "Steam Akamai CDN", "steamcdn-a.akamaihd.net", RoutingMatchKind.Exact, BypassMode.AutoHybrid, CategorySteam, enabled: true),

        // Gaming Storefronts & Voice (Discord & NexusMods enabled by default; launchers toggleable)
        Rule("gaming-discord", "Discord", "discord.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: true),
        Rule("gaming-discordapp", "Discord Media", "discordapp.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: true),
        Rule("gaming-discordgg", "Discord Invites", "discord.gg", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: true),
        Rule("gaming-nexusmods", "Nexus Mods", "nexusmods.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: true),
        Rule("gaming-epic", "Epic Games", "epicgames.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-riot", "Riot Games", "riotgames.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-ea", "EA Games", "ea.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-ubisoft", "Ubisoft", "ubisoft.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-battlenet", "Battle.net", "battle.net", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-gog", "GOG", "gog.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),
        Rule("gaming-itch", "itch.io", "itch.io", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryGaming, enabled: false),

        // Blocked Web & Media (enabled by default)
        Rule("web-medium", "Medium", "medium.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-reddit", "Reddit", "reddit.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-reddit-short", "Reddit Short", "redd.it", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-imgur", "Imgur", "imgur.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-bbc", "BBC News", "bbc.com", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-bbc-uk", "BBC UK", "bbc.co.uk", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-telegram", "Telegram Web", "telegram.org", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
        Rule("web-telegram-short", "Telegram Short", "t.me", RoutingMatchKind.DomainSuffix, BypassMode.AutoHybrid, CategoryWeb, enabled: true),
    ];

    public static IReadOnlyList<BypassRule> CreateDefaultRules() => [.. All];

    private static BypassRule Rule(
        string id,
        string name,
        string pattern,
        RoutingMatchKind matchKind,
        BypassMode mode,
        string category,
        bool enabled) => new()
        {
            Id = id,
            Name = name,
            Pattern = pattern,
            MatchKind = matchKind,
            Mode = mode,
            Category = category,
            Enabled = enabled,
            IsBuiltIn = true,
        };
}
