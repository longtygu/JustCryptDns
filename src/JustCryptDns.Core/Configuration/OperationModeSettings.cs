using System.Text.Json.Serialization;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Configuration;

[JsonConverter(typeof(JsonStringEnumConverter<AppOperationMode>))]
public enum AppOperationMode
{
    HighSpeed,
    Gaming,
    Balanced,
    Auto,
    Security,
}

public sealed class OperationModeProfile
{
    public string ResolverId { get; set; } = BuiltInResolvers.DefaultResolverId;

    public string SecondaryResolverId { get; set; } = BuiltInResolvers.DefaultSecondaryResolverId;

    public bool EnableFiltering { get; set; } = true;

    public bool EnableAllBuiltInBlocklists { get; set; }

    public bool EnableGamingEngine { get; set; }

    public bool ForceEncryptedOnly { get; set; }

    public int QueryTimeoutMs { get; set; } = 2500;

    public int CacheMaxEntries { get; set; } = 6144;

    public bool EnableCachePrefetch { get; set; } = true;

    public bool EnableServeStale { get; set; } = true;

    public bool EnableDnsLeakGuard { get; set; }

    public bool EnableThreatIntelligence { get; set; } = true;

    public bool AutoBlockDetectedThreats { get; set; }

    public bool VerifyProcessSignatures { get; set; } = true;

    public bool BlockFirefoxDohCanary { get; set; } = true;

    public MonitoringMode MonitoringMode { get; set; } = MonitoringMode.Balanced;

    public bool MinimizeVisualEffects { get; set; }

    public OperationModeProfile Clone() => new()
    {
        ResolverId = ResolverId,
        SecondaryResolverId = SecondaryResolverId,
        EnableFiltering = EnableFiltering,
        EnableAllBuiltInBlocklists = EnableAllBuiltInBlocklists,
        EnableGamingEngine = EnableGamingEngine,
        ForceEncryptedOnly = ForceEncryptedOnly,
        QueryTimeoutMs = QueryTimeoutMs,
        CacheMaxEntries = CacheMaxEntries,
        EnableCachePrefetch = EnableCachePrefetch,
        EnableServeStale = EnableServeStale,
        EnableDnsLeakGuard = EnableDnsLeakGuard,
        EnableThreatIntelligence = EnableThreatIntelligence,
        AutoBlockDetectedThreats = AutoBlockDetectedThreats,
        VerifyProcessSignatures = VerifyProcessSignatures,
        BlockFirefoxDohCanary = BlockFirefoxDohCanary,
        MonitoringMode = MonitoringMode,
        MinimizeVisualEffects = MinimizeVisualEffects,
    };

    internal void Normalize(OperationModeProfile fallback)
    {
        if (string.IsNullOrWhiteSpace(ResolverId))
        {
            ResolverId = fallback.ResolverId;
        }
        else
        {
            ResolverId = ResolverId.Trim();
        }

        if (string.IsNullOrWhiteSpace(SecondaryResolverId))
        {
            SecondaryResolverId = fallback.SecondaryResolverId;
        }
        else
        {
            SecondaryResolverId = SecondaryResolverId.Trim();
        }

        QueryTimeoutMs = Math.Clamp(QueryTimeoutMs, 500, 15000);
        CacheMaxEntries = Math.Clamp(CacheMaxEntries, 256, 65536);
        if (!Enum.IsDefined(MonitoringMode))
        {
            MonitoringMode = fallback.MonitoringMode;
        }
    }
}

public sealed class AutoModeRulesSettings
{
    public static readonly IReadOnlyList<string> DefaultGameProcesses =
    [
        "valorant",
        "valorant-win64-shipping",
        "league of legends",
        "cs2",
        "csgo",
        "dota2",
        "tslgame",
        "fortniteclient-win64-shipping",
        "r5apex",
        "overwatch",
        "genshinimpact",
        "starrail",
        "gta5",
        "cyberpunk2077",
        "eldenring",
        "minecraft",
        "javaw",
        "robloxplayerbeta",
        "cod",
        "bf2042",
        "pubg",
        "naraka",
    ];

    public bool SwitchToGamingOnFullscreenGame { get; set; } = true;

    public bool SwitchToSecurityOnThreatOrSpike { get; set; } = true;

    public int HighBlockRateThresholdPerMinute { get; set; } = 40;

    public int CooldownSeconds { get; set; } = 20;

    public List<string> CustomGameProcessNames { get; set; } = [];

    public AutoModeRulesSettings Clone() => new()
    {
        SwitchToGamingOnFullscreenGame = SwitchToGamingOnFullscreenGame,
        SwitchToSecurityOnThreatOrSpike = SwitchToSecurityOnThreatOrSpike,
        HighBlockRateThresholdPerMinute = HighBlockRateThresholdPerMinute,
        CooldownSeconds = CooldownSeconds,
        CustomGameProcessNames = [.. CustomGameProcessNames],
    };

    internal void Normalize()
    {
        HighBlockRateThresholdPerMinute = Math.Clamp(HighBlockRateThresholdPerMinute, 10, 500);
        CooldownSeconds = Math.Clamp(CooldownSeconds, 5, 120);
        CustomGameProcessNames ??= [];

        var cleaned = new List<string>(CustomGameProcessNames.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in CustomGameProcessNames)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var normalized = raw.Trim();
            if (normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized[..^4];
            }

            if (normalized.Length > 0 && seen.Add(normalized))
            {
                cleaned.Add(normalized);
            }
        }

        CustomGameProcessNames = cleaned;
    }

    public bool IsKnownGameProcess(string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName))
        {
            return false;
        }

        var trimmed = processName.Trim();
        if (trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^4];
        }

        foreach (var custom in CustomGameProcessNames)
        {
            if (string.Equals(custom, trimmed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        foreach (var builtIn in DefaultGameProcesses)
        {
            if (string.Equals(builtIn, trimmed, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Captures the user's pre-mode baseline preferences so returning to Balanced or disabling
/// aggressive visual/security overrides cleanly restores personal appearance &amp; engine defaults
/// without ever touching custom rules, blocklists, allowlists, rewrites, or firewall rules.
/// </summary>
public sealed class OperationBaselineSnapshot
{
    public AnimationLevel Animations { get; set; } = AnimationLevel.Normal;

    public bool TransparencyEnabled { get; set; } = true;

    public int Transparency { get; set; }

    public StatusPulseStyle StatusPulseStyle { get; set; } = StatusPulseStyle.Breathing;

    public MonitoringMode MonitoringMode { get; set; } = MonitoringMode.Balanced;

    public string ActiveResolverId { get; set; } = BuiltInResolvers.DefaultResolverId;

    public string SecondaryResolverId { get; set; } = BuiltInResolvers.DefaultSecondaryResolverId;

    public int QueryTimeoutMs { get; set; } = 3500;

    public bool BlockFirefoxDohCanary { get; set; } = true;

    public bool IsFilteringEnabled { get; set; } = true;

    public List<string> EnabledBuiltInBlocklistIds { get; set; } = [];

    public int CacheMaxEntries { get; set; } = 4096;

    public bool EnableServeStale { get; set; } = true;

    public bool EnablePrefetch { get; set; } = true;

    public FailoverPolicy ResiliencePolicy { get; set; } = FailoverPolicy.EncryptedOnly;

    public bool EnableDnsLeakGuard { get; set; }

    public bool EnableThreatIntelligence { get; set; } = true;

    public bool AutoBlockDetectedThreats { get; set; }

    public bool VerifyProcessSignatures { get; set; } = true;

    public static OperationBaselineSnapshot CaptureFrom(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return new OperationBaselineSnapshot
        {
            Animations = settings.Appearance.Animations,
            TransparencyEnabled = settings.Appearance.TransparencyEnabled,
            Transparency = settings.Appearance.Transparency,
            StatusPulseStyle = settings.Appearance.StatusPulseStyle,
            MonitoringMode = settings.Performance.MonitoringMode,
            ActiveResolverId = settings.Dns.ActiveResolverId,
            SecondaryResolverId = settings.Dns.SecondaryResolverId,
            QueryTimeoutMs = settings.Dns.QueryTimeoutMs,
            BlockFirefoxDohCanary = settings.Dns.BlockFirefoxDohCanary,
            IsFilteringEnabled = settings.Filtering.IsFilteringEnabled,
            EnabledBuiltInBlocklistIds = (settings.Filtering.Blocklists ?? [])
                .Where(b => b.IsBuiltIn && b.IsEnabled)
                .Select(b => b.Id)
                .ToList(),
            CacheMaxEntries = settings.Cache.MaxEntries,
            EnableServeStale = settings.Cache.EnableServeStale,
            EnablePrefetch = settings.Cache.EnablePrefetch,
            ResiliencePolicy = settings.Resilience.Policy,
            EnableDnsLeakGuard = settings.Connections.EnableDnsLeakGuard,
            EnableThreatIntelligence = settings.Connections.EnableThreatIntelligence,
            AutoBlockDetectedThreats = settings.Connections.AutoBlockDetectedThreats,
            VerifyProcessSignatures = settings.Connections.VerifyProcessSignatures,
        };
    }

    internal void Normalize()
    {
        if (!Enum.IsDefined(Animations)) Animations = AnimationLevel.Normal;
        Transparency = Math.Clamp(Transparency, 0, AppearanceSettings.MaxTransparency);
        if (!Enum.IsDefined(StatusPulseStyle)) StatusPulseStyle = StatusPulseStyle.Breathing;
        if (!Enum.IsDefined(MonitoringMode)) MonitoringMode = MonitoringMode.Balanced;
        if (string.IsNullOrWhiteSpace(ActiveResolverId)) ActiveResolverId = BuiltInResolvers.DefaultResolverId;
        if (string.IsNullOrWhiteSpace(SecondaryResolverId)) SecondaryResolverId = BuiltInResolvers.DefaultSecondaryResolverId;
        QueryTimeoutMs = Math.Clamp(QueryTimeoutMs, 500, 15000);
        CacheMaxEntries = Math.Clamp(CacheMaxEntries, 64, 65536);
        if (!Enum.IsDefined(ResiliencePolicy)) ResiliencePolicy = FailoverPolicy.EncryptedOnly;
        EnabledBuiltInBlocklistIds ??= [];
    }
}

public sealed class OperationModeSettings
{
    public static readonly AppOperationMode[] ConfigurableModes =
    [
        AppOperationMode.HighSpeed,
        AppOperationMode.Gaming,
        AppOperationMode.Balanced,
        AppOperationMode.Security,
    ];

    public AppOperationMode ActiveMode { get; set; } = AppOperationMode.Balanced;

    public Dictionary<AppOperationMode, OperationModeProfile> ModeProfiles { get; set; } = CreateDefaultProfiles();

    public AutoModeRulesSettings AutoRules { get; set; } = new();

    public OperationBaselineSnapshot? BaselineSnapshot { get; set; }

    public static OperationModeProfile CreateDefaultProfile(AppOperationMode mode) => mode switch
    {
        AppOperationMode.HighSpeed => new OperationModeProfile
        {
            ResolverId = "cloudflare-udp",
            SecondaryResolverId = "google-udp",
            EnableFiltering = false,
            EnableAllBuiltInBlocklists = false,
            EnableGamingEngine = false,
            ForceEncryptedOnly = false,
            QueryTimeoutMs = 1500,
            CacheMaxEntries = 8192,
            EnableCachePrefetch = true,
            EnableServeStale = true,
            EnableDnsLeakGuard = false,
            EnableThreatIntelligence = false,
            AutoBlockDetectedThreats = false,
            VerifyProcessSignatures = false,
            BlockFirefoxDohCanary = false,
            MonitoringMode = MonitoringMode.Performance,
            MinimizeVisualEffects = false,
        },
        AppOperationMode.Gaming => new OperationModeProfile
        {
            ResolverId = "cloudflare-doh",
            SecondaryResolverId = "google-doh",
            EnableFiltering = false,
            EnableAllBuiltInBlocklists = false,
            EnableGamingEngine = true,
            ForceEncryptedOnly = false,
            QueryTimeoutMs = 1800,
            CacheMaxEntries = 8192,
            EnableCachePrefetch = true,
            EnableServeStale = true,
            EnableDnsLeakGuard = false,
            EnableThreatIntelligence = false,
            AutoBlockDetectedThreats = false,
            VerifyProcessSignatures = false,
            BlockFirefoxDohCanary = true,
            MonitoringMode = MonitoringMode.PowerSaving,
            MinimizeVisualEffects = true,
        },
        AppOperationMode.Security => new OperationModeProfile
        {
            ResolverId = "quad9-doh",
            SecondaryResolverId = "cloudflare-security-doh",
            EnableFiltering = true,
            EnableAllBuiltInBlocklists = true,
            EnableGamingEngine = false,
            ForceEncryptedOnly = true,
            QueryTimeoutMs = 4000,
            CacheMaxEntries = 4096,
            EnableCachePrefetch = false,
            EnableServeStale = false,
            EnableDnsLeakGuard = true,
            EnableThreatIntelligence = true,
            AutoBlockDetectedThreats = true,
            VerifyProcessSignatures = true,
            BlockFirefoxDohCanary = true,
            MonitoringMode = MonitoringMode.Balanced,
            MinimizeVisualEffects = false,
        },
        _ => new OperationModeProfile
        {
            ResolverId = "cloudflare-doh",
            SecondaryResolverId = "quad9-doh",
            EnableFiltering = true,
            EnableAllBuiltInBlocklists = false,
            EnableGamingEngine = false,
            ForceEncryptedOnly = false,
            QueryTimeoutMs = 2500,
            CacheMaxEntries = 6144,
            EnableCachePrefetch = true,
            EnableServeStale = true,
            EnableDnsLeakGuard = false,
            EnableThreatIntelligence = true,
            AutoBlockDetectedThreats = false,
            VerifyProcessSignatures = true,
            BlockFirefoxDohCanary = true,
            MonitoringMode = MonitoringMode.Balanced,
            MinimizeVisualEffects = false,
        },
    };

    public static Dictionary<AppOperationMode, OperationModeProfile> CreateDefaultProfiles() => new()
    {
        [AppOperationMode.HighSpeed] = CreateDefaultProfile(AppOperationMode.HighSpeed),
        [AppOperationMode.Gaming] = CreateDefaultProfile(AppOperationMode.Gaming),
        [AppOperationMode.Balanced] = CreateDefaultProfile(AppOperationMode.Balanced),
        [AppOperationMode.Security] = CreateDefaultProfile(AppOperationMode.Security),
    };

    public OperationModeProfile GetProfile(AppOperationMode mode)
    {
        var effectiveMode = mode == AppOperationMode.Auto ? AppOperationMode.Balanced : mode;
        if (ModeProfiles.TryGetValue(effectiveMode, out var profile) && profile is not null)
        {
            return profile;
        }

        var created = CreateDefaultProfile(effectiveMode);
        ModeProfiles[effectiveMode] = created;
        return created;
    }

    public void ResetModeToDefault(AppOperationMode mode)
    {
        if (mode == AppOperationMode.Auto)
        {
            AutoRules = new AutoModeRulesSettings();
            return;
        }

        ModeProfiles[mode] = CreateDefaultProfile(mode);
    }

    internal void Normalize()
    {
        if (!Enum.IsDefined(ActiveMode))
        {
            ActiveMode = AppOperationMode.Balanced;
        }

        ModeProfiles ??= CreateDefaultProfiles();
        foreach (var mode in ConfigurableModes)
        {
            var fallback = CreateDefaultProfile(mode);
            if (!ModeProfiles.TryGetValue(mode, out var profile) || profile is null)
            {
                ModeProfiles[mode] = fallback;
            }
            else
            {
                profile.Normalize(fallback);
            }
        }

        ModeProfiles.Remove(AppOperationMode.Auto);

        AutoRules ??= new AutoModeRulesSettings();
        AutoRules.Normalize();
        BaselineSnapshot?.Normalize();
    }
}
