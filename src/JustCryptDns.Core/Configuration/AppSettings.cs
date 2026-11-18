using System.Net;
using System.Text.Json.Serialization;
using JustCryptDns.Core.Models;

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
    /// <summary>v1: Phase 1. v2: Phase 2 appearance. v3: Phase 3 background/startup. v4: Phase 4 DNS engine. v5: Phase 5 resolver library. v6: Phase 6 smart routing. v7: Phase 7 filtering & cache. v8: Phase 8 gaming optimization.</summary>
    public const int CurrentSchemaVersion = 8;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public GeneralSettings General { get; set; } = new();

    public AppearanceSettings Appearance { get; set; } = new();

    public DnsSettings Dns { get; set; } = new();

    public RoutingSettings Routing { get; set; } = new();

    public FilteringSettings Filtering { get; set; } = new();

    public CacheSettings Cache { get; set; } = new();

    public GamingSettings Gaming { get; set; } = new();

    public PerformanceSettings Performance { get; set; } = new();

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
        Performance ??= new PerformanceSettings();
        General.Normalize();
        Appearance.Normalize();
        Dns.Normalize();
        Routing.Normalize();
        Filtering.Normalize();
        Cache.Normalize();
        Gaming.Normalize();
        Performance.Normalize();
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

[JsonConverter(typeof(JsonStringEnumConverter<LogLevelSetting>))]
public enum LogLevelSetting
{
    Debug,
    Information,
    Warning,
    Error,
}

public sealed class PerformanceSettings
{
    public LogLevelSetting LogLevel { get; set; } = LogLevelSetting.Information;

    /// <summary>Number of daily log files to keep (1–90).</summary>
    public int LogRetentionDays { get; set; } = 7;

    internal void Normalize()
    {
        if (!Enum.IsDefined(LogLevel))
        {
            LogLevel = LogLevelSetting.Information;
        }

        LogRetentionDays = Math.Clamp(LogRetentionDays, 1, 90);
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
