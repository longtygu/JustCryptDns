using System.Net;
using System.Text.Json.Serialization;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;

namespace JustCryptDns.Core.Configuration;

/// <summary>
/// Root of the versioned, persisted user configuration.
/// </summary>
/// <remarks>
/// Every structural change must bump <see cref="CurrentSchemaVersion"/> and add an
/// <see cref="ISettingsMigration"/> so that older files are upgraded safely.
/// Only settings that are actually implemented are added here; future phases extend the schema.
/// </remarks>
public sealed class AppSettings
{
    /// <summary>v1–v12: Phases 1–14. v13: StatusPulseStyle. v14: GitHub auto-update settings. v15: Connection Monitor &amp; IP Blocker.</summary>
    public const int CurrentSchemaVersion = 15;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public GeneralSettings General { get; set; } = new();

    public AppearanceSettings Appearance { get; set; } = new();

    public DnsSettings Dns { get; set; } = new();

    public RoutingSettings Routing { get; set; } = new();

    public FilteringSettings Filtering { get; set; } = new();

    public CacheSettings Cache { get; set; } = new();

    public GamingSettings Gaming { get; set; } = new();

    public ResilienceSettings Resilience { get; set; } = new();

    public PerformanceSettings Performance { get; set; } = new();

    public BypassSettings Bypass { get; set; } = new();

    public UpdateSettings Updates { get; set; } = new();

    public ConnectionMonitorSettings Connections { get; set; } = new();

    /// <summary>Normalizes out-of-range or missing values after deserialization.</summary>
    public AppSettings Normalize()
    {
        General ??= new GeneralSettings();
        Appearance ??= new AppearanceSettings();
        Dns ??= new DnsSettings();
        Routing ??= new RoutingSettings();
        Filtering ??= new FilteringSettings();
        Cache ??= new CacheSettings();
        Gaming ??= new GamingSettings();
        Resilience ??= new ResilienceSettings();
        Performance ??= new PerformanceSettings();
        Bypass ??= new BypassSettings();
        Updates ??= new UpdateSettings();
        Connections ??= new ConnectionMonitorSettings();
        General.Normalize();
        Appearance.Normalize();
        Dns.Normalize();
        Routing.Normalize();
        Filtering.Normalize();
        Cache.Normalize();
        Gaming.Normalize();
        Resilience.Normalize();
        Performance.Normalize();
        Bypass.Normalize();
        Updates.Normalize();
        Connections.Normalize();
        return this;
    }

    public AppSettings Clone()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(this, SettingsJson.Options);
        return System.Text.Json.JsonSerializer.Deserialize<AppSettings>(json, SettingsJson.Options)!.Normalize();
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<CloseBehavior>))]
public enum CloseBehavior
{
    MinimizeToTray,
    ExitApplication,
    AskEveryTime,
}

public sealed class GeneralSettings
{
    /// <summary>UI language: <c>system</c>, <c>en</c> or <c>vi</c>.</summary>
    public string Language { get; set; } = LanguageCodes.System;

    public bool StartWithWindows { get; set; }

    public bool StartMinimized { get; set; }

    public bool AutoStartDnsEngine { get; set; } = true;

    public bool RestorePreviousProfile { get; set; } = true;

    public bool EnableGamingModeOnStartup { get; set; }

    public CloseBehavior CloseBehavior { get; set; } = CloseBehavior.MinimizeToTray;

    internal void Normalize()
    {
        if (!LanguageCodes.IsSupported(Language))
        {
            Language = LanguageCodes.System;
        }

        if (!Enum.IsDefined(CloseBehavior))
        {
            CloseBehavior = CloseBehavior.MinimizeToTray;
        }
    }
}

public static class LanguageCodes
{
    public const string System = "system";
    public const string English = "en";
    public const string Vietnamese = "vi";

    public static IReadOnlyList<string> All { get; } = [System, English, Vietnamese];

    public static bool IsSupported(string? code) =>
        code is not null && All.Contains(code, StringComparer.OrdinalIgnoreCase);
}

[JsonConverter(typeof(JsonStringEnumConverter<AppTheme>))]
public enum AppTheme
{
    Dark,
    Light,
    System,

    /// <summary>A Dark or Light base palette tinted with <see cref="AppearanceSettings.CustomTintColor"/>.</summary>
    Custom,
}

/// <summary>Preferred window material. Unsupported choices fall back automatically.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<BackdropPreference>))]
public enum BackdropPreference
{
    /// <summary>Acrylic on Windows 11 22H2+, blur on Windows 10.</summary>
    Auto,
    Mica,
    Acrylic,
    Blur,
}

[JsonConverter(typeof(JsonStringEnumConverter<BackgroundStyle>))]
public enum BackgroundStyle
{
    Plain,
    AccentTint,
}

[JsonConverter(typeof(JsonStringEnumConverter<CardDensity>))]
public enum CardDensity
{
    Compact,
    Comfortable,
    Spacious,
}

/// <summary>Maps to <c>DWM_WINDOW_CORNER_PREFERENCE</c> (Windows 11 only).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<WindowCornerStyle>))]
public enum WindowCornerStyle
{
    Default,
    Rounded,
    RoundedSmall,
    Square,
}

[JsonConverter(typeof(JsonStringEnumConverter<TextSize>))]
public enum TextSize
{
    Small,
    Default,
    Large,
    ExtraLarge,
}

[JsonConverter(typeof(JsonStringEnumConverter<AnimationLevel>))]
public enum AnimationLevel
{
    Off,
    Reduced,
    Normal,
}

[JsonConverter(typeof(JsonStringEnumConverter<StatusPulseStyle>))]
public enum StatusPulseStyle
{
    Off,
    Breathing,
    GlowHalo,
    Heartbeat,
    Beacon,
}

public sealed class AppearanceSettings
{
    public const string DefaultAccentColor = "#4F8CFF";
    public const int MaxTransparency = 90;
    public const int MinUiScale = 80;
    public const int MaxUiScale = 150;

    public AppTheme Theme { get; set; } = AppTheme.Dark;

    /// <summary>Base palette for <see cref="AppTheme.Custom"/>: Dark or Light.</summary>
    public AppTheme CustomBaseTheme { get; set; } = AppTheme.Dark;

    /// <summary>Surface tint for <see cref="AppTheme.Custom"/> as <c>#RRGGBB</c>.</summary>
    public string CustomTintColor { get; set; } = "#7B5CFF";

    /// <summary>Accent color as <c>#RRGGBB</c>.</summary>
    public string AccentColor { get; set; } = DefaultAccentColor;

    /// <summary>Use the Windows accent color instead of <see cref="AccentColor"/>.</summary>
    public bool UseSystemAccent { get; set; }

    /// <summary>Master switch; when false the window is opaque regardless of <see cref="Transparency"/>.</summary>
    public bool TransparencyEnabled { get; set; } = true;

    /// <summary>Window transparency in percent: 0 (opaque) – 90 (highly transparent).</summary>
    public int Transparency { get; set; }

    public BackdropPreference Backdrop { get; set; } = BackdropPreference.Auto;

    public BackgroundStyle Background { get; set; } = BackgroundStyle.Plain;

    public bool SidebarCollapsed { get; set; }

    public CardDensity Density { get; set; } = CardDensity.Comfortable;

    public WindowCornerStyle CornerStyle { get; set; } = WindowCornerStyle.Default;

    /// <summary>Additional UI scale in percent (80–150) on top of Windows DPI scaling.</summary>
    public int UiScalePercent { get; set; } = 100;

    public TextSize TextSize { get; set; } = TextSize.Default;

    public AnimationLevel Animations { get; set; } = AnimationLevel.Normal;

    public StatusPulseStyle StatusPulseStyle { get; set; } = StatusPulseStyle.Breathing;

    internal void Normalize()
    {
        if (!Enum.IsDefined(Theme))
        {
            Theme = AppTheme.Dark;
        }

        if (CustomBaseTheme is not (AppTheme.Dark or AppTheme.Light))
        {
            CustomBaseTheme = AppTheme.Dark;
        }

        if (!ColorText.IsValidRgb(AccentColor))
        {
            AccentColor = DefaultAccentColor;
        }

        if (!ColorText.IsValidRgb(CustomTintColor))
        {
            CustomTintColor = "#7B5CFF";
        }

        Transparency = Math.Clamp(Transparency, 0, MaxTransparency);
        UiScalePercent = Math.Clamp(UiScalePercent, MinUiScale, MaxUiScale);
        Backdrop = Enum.IsDefined(Backdrop) ? Backdrop : BackdropPreference.Auto;
        Background = Enum.IsDefined(Background) ? Background : BackgroundStyle.Plain;
        Density = Enum.IsDefined(Density) ? Density : CardDensity.Comfortable;
        CornerStyle = Enum.IsDefined(CornerStyle) ? CornerStyle : WindowCornerStyle.Default;
        TextSize = Enum.IsDefined(TextSize) ? TextSize : TextSize.Default;
        Animations = Enum.IsDefined(Animations) ? Animations : AnimationLevel.Normal;
        StatusPulseStyle = Enum.IsDefined(StatusPulseStyle) ? StatusPulseStyle : StatusPulseStyle.Breathing;
    }
}

public sealed class DnsSettings
{
    public const string DefaultListenAddress = "127.0.0.1";
    public const int DefaultListenPort = 53;
    public const int DefaultDnsCryptInternalPort = 5354;

    public string ActiveResolverId { get; set; } = BuiltInResolvers.DefaultResolverId;

    public string SecondaryResolverId { get; set; } = BuiltInResolvers.DefaultSecondaryResolverId;

    public List<DnsResolverEndpoint> CustomResolvers { get; set; } = [];

    public List<string> DisabledResolverIds { get; set; } = [];

    public Dictionary<string, string> ResolverGroupOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> CustomGroups { get; set; } = [];

    public string ListenAddress { get; set; } = DefaultListenAddress;

    public int ListenPort { get; set; } = DefaultListenPort;

    public bool EnableIpv6 { get; set; }

    public bool ConfigureWindowsAdapter { get; set; }

    public string? TargetAdapterId { get; set; }

    public int DnsCryptInternalPort { get; set; } = DefaultDnsCryptInternalPort;

    public int QueryTimeoutMs { get; set; } = 3500;

    internal void Normalize()
    {
        if (string.IsNullOrWhiteSpace(ActiveResolverId))
        {
            ActiveResolverId = BuiltInResolvers.DefaultResolverId;
        }

        if (string.IsNullOrWhiteSpace(SecondaryResolverId))
        {
            SecondaryResolverId = BuiltInResolvers.DefaultSecondaryResolverId;
        }

        CustomResolvers ??= [];
        DisabledResolverIds ??= [];
        ResolverGroupOverrides ??= new(StringComparer.OrdinalIgnoreCase);
        CustomGroups ??= [];

        if (!IPAddress.TryParse(ListenAddress, out var ip) || !IPAddress.IsLoopback(ip))
        {
            ListenAddress = DefaultListenAddress;
        }

        ListenPort = Math.Clamp(ListenPort, 0, 65535);
        DnsCryptInternalPort = Math.Clamp(DnsCryptInternalPort, 1024, 65535);
        if (DnsCryptInternalPort == ListenPort)
        {
            DnsCryptInternalPort = ListenPort == DefaultDnsCryptInternalPort ? 5355 : DefaultDnsCryptInternalPort;
        }

        QueryTimeoutMs = Math.Clamp(QueryTimeoutMs, 500, 15000);
    }
}

public sealed class RoutingSettings
{
    public bool IsRoutingEnabled { get; set; } = true;

    public string ActiveProfileId { get; set; } = BuiltInRoutingProfiles.GamingProfileId;

    public List<DnsRoutingProfile> CustomProfiles { get; set; } = [];

    public Dictionary<string, string> ProfileFallbackOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public List<DnsRoutingRule>? Rules { get; set; }

    internal void Normalize()
    {
        if (string.IsNullOrWhiteSpace(ActiveProfileId))
        {
            ActiveProfileId = BuiltInRoutingProfiles.GamingProfileId;
        }

        CustomProfiles ??= [];
        ProfileFallbackOverrides ??= new(StringComparer.OrdinalIgnoreCase);
        if (Rules is null)
        {
            Rules = BuiltInRoutingProfiles.CreateDefaultRules().ToList();
        }
    }
}

public sealed class FilteringSettings
{
    public bool IsFilteringEnabled { get; set; } = true;

    public bool AutoUpdateBlocklists { get; set; } = true;

    public List<DnsBlocklistSource>? Blocklists { get; set; }

    public List<string> CustomBlockedDomains { get; set; } = [];

    public List<DnsAllowlistEntry> Allowlist { get; set; } = [];

    internal void Normalize()
    {
        if (Blocklists is null || Blocklists.Count == 0)
        {
            Blocklists = BuiltInBlocklists.All.ToList();
        }

        CustomBlockedDomains ??= [];
        Allowlist ??= [];
    }
}

public sealed class CacheSettings
{
    public bool IsCacheEnabled { get; set; } = true;

    public int MaxEntries { get; set; } = 4096;

    public int MinPositiveTtlSeconds { get; set; } = 10;

    public int MaxPositiveTtlSeconds { get; set; } = 3600;

    public int NegativeTtlSeconds { get; set; } = 60;

    internal void Normalize()
    {
        MaxEntries = Math.Clamp(MaxEntries, 64, 65536);
        MinPositiveTtlSeconds = Math.Clamp(MinPositiveTtlSeconds, 1, 3600);
        MaxPositiveTtlSeconds = Math.Clamp(MaxPositiveTtlSeconds, MinPositiveTtlSeconds, 86400);
        NegativeTtlSeconds = Math.Clamp(NegativeTtlSeconds, 5, 3600);
    }
}

public sealed class GamingSettings
{
    public bool IsGamingModeEnabled { get; set; }

    public GamingSelectionProfile SelectionProfile { get; set; } = GamingSelectionProfile.LowestLatency;

    public string? ManualOverrideResolverId { get; set; }

    public string ActiveGamingProfileId { get; set; } = BuiltInGamingProfiles.GeneralGamingId;

    public List<GamingPlatformProfile> CustomGamingProfiles { get; set; } = [];

    internal void Normalize()
    {
        if (!Enum.IsDefined(SelectionProfile))
        {
            SelectionProfile = GamingSelectionProfile.LowestLatency;
        }

        if (string.IsNullOrWhiteSpace(ActiveGamingProfileId))
        {
            ActiveGamingProfileId = BuiltInGamingProfiles.GeneralGamingId;
        }

        CustomGamingProfiles ??= [];
    }
}

public sealed class ResilienceSettings
{
    public bool EnableAutoFailover { get; set; } = true;

    public FailoverPolicy Policy { get; set; } = FailoverPolicy.EncryptedOnly;

    public int MaxRetriesPerQuery { get; set; } = 2;

    public int FailureThresholdBeforeSwitch { get; set; } = 3;

    public int RetryDelayMs { get; set; } = 200;

    internal void Normalize()
    {
        if (!Enum.IsDefined(Policy))
        {
            Policy = FailoverPolicy.EncryptedOnly;
        }

        MaxRetriesPerQuery = Math.Clamp(MaxRetriesPerQuery, 0, 5);
        FailureThresholdBeforeSwitch = Math.Clamp(FailureThresholdBeforeSwitch, 1, 20);
        RetryDelayMs = Math.Clamp(RetryDelayMs, 0, 5000);
    }
}

[JsonConverter(typeof(JsonStringEnumConverter<LogLevelSetting>))]
public enum LogLevelSetting
{
    Debug,
    Information,
    Warning,
    Error,
}

[JsonConverter(typeof(JsonStringEnumConverter<MonitoringMode>))]
public enum MonitoringMode
{
    PowerSaving,
    Balanced,
    Performance,
}

public sealed class PerformanceSettings
{
    public LogLevelSetting LogLevel { get; set; } = LogLevelSetting.Information;

    /// <summary>Number of daily log files to keep (1–90).</summary>
    public int LogRetentionDays { get; set; } = 7;

    public MonitoringMode MonitoringMode { get; set; } = MonitoringMode.Balanced;

    public bool EnablePerformanceDiagnostics { get; set; }

    public int GetMonitorBufferLimit() => MonitoringMode switch
    {
        MonitoringMode.PowerSaving => 100,
        MonitoringMode.Performance => 500,
        _ => 300,
    };

    internal void Normalize()
    {
        if (!Enum.IsDefined(LogLevel))
        {
            LogLevel = LogLevelSetting.Information;
        }

        if (!Enum.IsDefined(MonitoringMode))
        {
            MonitoringMode = MonitoringMode.Balanced;
        }

        LogRetentionDays = Math.Clamp(LogRetentionDays, 1, 90);
    }
}

public sealed class BypassSettings
{
    public const string DefaultListenAddress = "127.0.0.1";
    public const int DefaultProxyPort = 10808;
    public const int DefaultPacPort = 10809;

    public bool IsBypassEnabled { get; set; } = true;

    public bool AutoStartWithDnsEngine { get; set; } = true;

    public BypassCoverageMode CoverageMode { get; set; } = BypassCoverageMode.AllWebsitesSmart;

    public BypassMode DefaultUnmatchedMode { get; set; } = BypassMode.AutoHybrid;

    public bool EnableSmartSelfHealing { get; set; } = true;

    public string ListenAddress { get; set; } = DefaultListenAddress;

    public int ProxyPort { get; set; } = DefaultProxyPort;

    public int PacPort { get; set; } = DefaultPacPort;

    public WindowsProxyMode WindowsProxyMode { get; set; } = WindowsProxyMode.AutoPac;

    public bool ApplyWindowsProxyAutomatically { get; set; } = true;

    public TlsFragmentationStrategy FragmentationStrategy { get; set; } = TlsFragmentationStrategy.RecordChunkSplit;

    public int FragmentSizeBytes { get; set; } = 40;

    public int FragmentDelayMs { get; set; }

    public bool FragmentHttpHostHeader { get; set; } = true;

    public bool AutoFallbackToTunnelOnDpiFailure { get; set; } = true;

    public int ConnectTimeoutMs { get; set; } = 5000;

    public bool ResolveTargetViaLocalDns { get; set; } = true;

    public UpstreamTunnelSettings Upstream { get; set; } = new();

    public List<BypassRule>? Rules { get; set; }

    public List<string> DirectExclusionDomains { get; set; } = [];

    internal void Normalize()
    {
        if (!IPAddress.TryParse(ListenAddress, out var ip) || !IPAddress.IsLoopback(ip))
        {
            ListenAddress = DefaultListenAddress;
        }

        ProxyPort = Math.Clamp(ProxyPort, 0, 65535);
        PacPort = Math.Clamp(PacPort, 0, 65535);
        if (ProxyPort > 0 && PacPort == ProxyPort)
        {
            PacPort = ProxyPort == 65535 ? 65534 : ProxyPort + 1;
        }

        if (!Enum.IsDefined(CoverageMode))
        {
            CoverageMode = BypassCoverageMode.AllWebsitesSmart;
        }

        if (!Enum.IsDefined(DefaultUnmatchedMode))
        {
            DefaultUnmatchedMode = BypassMode.AutoHybrid;
        }

        if (!Enum.IsDefined(WindowsProxyMode))
        {
            WindowsProxyMode = WindowsProxyMode.AutoPac;
        }

        if (!Enum.IsDefined(FragmentationStrategy))
        {
            FragmentationStrategy = TlsFragmentationStrategy.RecordChunkSplit;
        }

        FragmentSizeBytes = Math.Clamp(FragmentSizeBytes, 8, 256);
        FragmentDelayMs = Math.Clamp(FragmentDelayMs, 0, 50);
        ConnectTimeoutMs = Math.Clamp(ConnectTimeoutMs, 1000, 20000);

        Upstream ??= new UpstreamTunnelSettings();
        Upstream.Normalize();

        Rules ??= BuiltInBypassRules.CreateDefaultRules().ToList();
        DirectExclusionDomains ??= [];
    }
}

public sealed class UpdateSettings
{
    public const string DefaultRepositoryOwner = "longtygu";
    public const string DefaultRepositoryName = "JustCryptDns";

    public bool AutoCheckOnStartup { get; set; } = true;

    public bool IncludePrereleases { get; set; }

    public string RepositoryOwner { get; set; } = DefaultRepositoryOwner;

    public string RepositoryName { get; set; } = DefaultRepositoryName;

    public DateTimeOffset? LastCheckedUtc { get; set; }

    internal void Normalize()
    {
        RepositoryOwner = string.IsNullOrWhiteSpace(RepositoryOwner)
            ? DefaultRepositoryOwner
            : RepositoryOwner.Trim();
        RepositoryName = string.IsNullOrWhiteSpace(RepositoryName)
            ? DefaultRepositoryName
            : RepositoryName.Trim();
    }
}

public sealed class ConnectionMonitorSettings
{
    public List<BlockedIpRule> BlockedRules { get; set; } = [];

    public Dictionary<string, string> IpNotes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public bool EnableOnlineLookup { get; set; }

    public bool AlertNewUnknownProcess { get; set; }

    public bool HideLanConnections { get; set; } = true;

    public bool AutoScroll { get; set; } = true;

    public int PollIntervalMs { get; set; } = 1000;

    public bool HasUnsyncedFirewallChanges { get; set; }

    internal void Normalize()
    {
        BlockedRules ??= [];
        var normalizedRules = new List<BlockedIpRule>(BlockedRules.Count);
        var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in BlockedRules)
        {
            if (rule is null || !CidrNetwork.TryParse(rule.Target, out var parsed, out _))
            {
                continue;
            }

            if (!seenTargets.Add(parsed.CanonicalText))
            {
                continue;
            }

            normalizedRules.Add(rule with
            {
                Target = parsed.CanonicalText,
                Note = string.IsNullOrWhiteSpace(rule.Note) ? null : rule.Note.Trim(),
            });
        }

        BlockedRules = normalizedRules;

        var normalizedNotes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (IpNotes is not null)
        {
            foreach (var (key, value) in IpNotes)
            {
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                normalizedNotes[key.Trim()] = value.Trim();
            }
        }

        IpNotes = normalizedNotes;
        PollIntervalMs = Math.Clamp(PollIntervalMs, 500, 5000);
    }
}

public static class ColorText
{
    /// <summary>Returns true for strings of the form <c>#RRGGBB</c>.</summary>
    public static bool IsValidRgb(string? value)
    {
        if (value is null || value.Length != 7 || value[0] != '#')
        {
            return false;
        }

        for (var i = 1; i < 7; i++)
        {
            if (!Uri.IsHexDigit(value[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Accepts <c>RRGGBB</c>, <c>#RRGGBB</c> or <c>#RGB</c> (any case) and returns <c>#RRGGBB</c> upper-case, or null.</summary>
    public static string? NormalizeRgb(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        if (!text.StartsWith('#'))
        {
            text = "#" + text;
        }

        if (text.Length == 4)
        {
            text = string.Concat("#", text[1], text[1], text[2], text[2], text[3], text[3]);
        }

        return IsValidRgb(text) ? text.ToUpperInvariant() : null;
    }
}
