using System.Text.Json.Serialization;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<GamingSelectionProfile>))]
public enum GamingSelectionProfile
{
    LowestLatency,
    Balanced,
    MaximumReliability,
}

public enum GamingBenchmarkProgressStage
{
    ResolverStarted,
    DomainProbed,
    ResolverCompleted,
    Cancelled,
}

public sealed record GamingBenchmarkProgress(
    GamingBenchmarkProgressStage Stage,
    string ResolverId,
    string ResolverName,
    DnsProtocol Protocol,
    string Domain,
    int Round,
    int TotalRounds,
    int CompletedResolvers,
    int TotalResolvers,
    int CompletedQueries,
    int TotalQueries,
    bool Success,
    bool TimedOut,
    double LatencyMs,
    double AverageLatencyMs,
    double ReliabilityScore,
    string? Error,
    DateTimeOffset Timestamp);

public sealed record ResolverBenchmarkResult
{
    public required string ResolverId { get; init; }

    public required string ResolverName { get; init; }

    public required string Provider { get; init; }

    public required DnsProtocol Protocol { get; init; }

    public required int TotalQueries { get; init; }

    public required int SuccessfulQueries { get; init; }

    public required int TimeoutQueries { get; init; }

    public required double AverageLatencyMs { get; init; }

    public required double MinLatencyMs { get; init; }

    public required double MaxLatencyMs { get; init; }

    public required double P95LatencyMs { get; init; }

    public required double JitterMs { get; init; }

    public required double SuccessRatePercent { get; init; }

    public required double TimeoutRatePercent { get; init; }

    public required double ReliabilityScore { get; init; }

    public required DateTimeOffset MeasuredAt { get; init; }
}

public sealed record GamingPlatformProfile
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required IReadOnlyList<string> Domains { get; init; }

    public string? PreferredResolverId { get; init; }

    public bool IsBuiltIn { get; init; } = true;
}

public static class BuiltInGamingProfiles
{
    public const string GeneralGamingId = "gaming-general";

    public static IReadOnlyList<string> DefaultBenchmarkDomains { get; } =
    [
        "steamcommunity.com",
        "steampowered.com",
        "riotgames.com",
        "epicgames.com",
        "battle.net",
        "ea.com",
    ];

    public static IReadOnlyList<GamingPlatformProfile> All { get; } =
    [
        new GamingPlatformProfile
        {
            Id = "gaming-steam",
            Name = "Steam",
            Domains = ["steampowered.com", "steamcommunity.com", "steamgames.com", "steamstatic.com", "steamcontent.com"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-riot",
            Name = "Riot Games",
            Domains = ["riotgames.com", "pvp.net", "leagueoflegends.com", "playvalorant.com", "riotcdn.net"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-epic",
            Name = "Epic Games",
            Domains = ["epicgames.com", "unrealengine.com", "fortnite.com", "ol.epicgames.net"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-ea",
            Name = "EA Games",
            Domains = ["ea.com", "origin.com", "tnt-ea.com", "ears.ea.com"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-ubisoft",
            Name = "Ubisoft Connect",
            Domains = ["ubisoft.com", "ubi.com", "uplay.com", "ubiservices.ubi.com"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-battlenet",
            Name = "Battle.net",
            Domains = ["battle.net", "blizzard.com", "bnet.com", "actual.battle.net"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-pubg",
            Name = "PUBG: Battlegrounds",
            Domains = ["pubg.com", "playbattlegrounds.com", "krafton.com", "acs.pubg.com", "battlegrounds.com"],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = GeneralGamingId,
            Name = "General Gaming",
            Domains =
            [
                "steampowered.com",
                "steamcommunity.com",
                "riotgames.com",
                "epicgames.com",
                "ea.com",
                "ubisoft.com",
                "battle.net",
                "playbattlegrounds.com",
                "xboxlive.com",
                "playstation.net",
            ],
            IsBuiltIn = true,
        },
        new GamingPlatformProfile
        {
            Id = "gaming-custom",
            Name = "Custom",
            Domains = ["steamcommunity.com", "riotgames.com", "epicgames.com"],
            IsBuiltIn = true,
        },
    ];
}
