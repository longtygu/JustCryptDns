using System.Text.Json.Serialization;

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
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public GeneralSettings General { get; set; } = new();

    public AppearanceSettings Appearance { get; set; } = new();

    public PerformanceSettings Performance { get; set; } = new();

    /// <summary>Normalizes out-of-range or missing values after deserialization.</summary>
    public AppSettings Normalize()
    {
        General ??= new GeneralSettings();
        Appearance ??= new AppearanceSettings();
        Performance ??= new PerformanceSettings();
        General.Normalize();
        Appearance.Normalize();
        Performance.Normalize();
        return this;
    }

    public AppSettings Clone()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(this, SettingsJson.Options);
        return System.Text.Json.JsonSerializer.Deserialize<AppSettings>(json, SettingsJson.Options)!.Normalize();
    }
}

public sealed class GeneralSettings
{
    /// <summary>UI language: <c>system</c>, <c>en</c> or <c>vi</c>.</summary>
    public string Language { get; set; } = LanguageCodes.System;

    internal void Normalize()
    {
        if (!LanguageCodes.IsSupported(Language))
        {
            Language = LanguageCodes.System;
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
}

public sealed class AppearanceSettings
{
    public const string DefaultAccentColor = "#4F8CFF";

    public AppTheme Theme { get; set; } = AppTheme.Dark;

    /// <summary>Accent color as <c>#RRGGBB</c>.</summary>
    public string AccentColor { get; set; } = DefaultAccentColor;

    public bool SidebarCollapsed { get; set; }

    internal void Normalize()
    {
        if (!Enum.IsDefined(Theme))
        {
            Theme = AppTheme.Dark;
        }

        if (!ColorText.IsValidRgb(AccentColor))
        {
            AccentColor = DefaultAccentColor;
        }
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
}
