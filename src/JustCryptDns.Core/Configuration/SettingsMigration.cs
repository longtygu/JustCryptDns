using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace JustCryptDns.Core.Configuration;

public static class SettingsJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}

/// <summary>
/// Upgrades a raw settings document from <see cref="FromVersion"/> to <c>FromVersion + 1</c>.
/// Migrations operate on <see cref="JsonObject"/> so they never depend on current CLR types.
/// </summary>
public interface ISettingsMigration
{
    int FromVersion { get; }

    void Apply(JsonObject document);
}

/// <summary>
/// Version 0 = files written before the schema was versioned (no <c>schemaVersion</c> property).
/// Layout is identical to v1, so only the version marker is added.
/// </summary>
internal sealed class MigrationV0ToV1 : ISettingsMigration
{
    public int FromVersion => 0;

    public void Apply(JsonObject document)
    {
        // No structural change.
    }
}

/// <summary>
/// v2 adds appearance options (transparency, backdrop, density, scaling, text size, animations, corners, custom theme).
/// All new properties have safe defaults, so existing values are kept unchanged.
/// </summary>
internal sealed class MigrationV1ToV2 : ISettingsMigration
{
    public int FromVersion => 1;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by AppearanceSettings.
    }
}

/// <summary>
/// v3 adds startup and system-tray close behavior options to <see cref="GeneralSettings"/>.
/// </summary>
internal sealed class MigrationV2ToV3 : ISettingsMigration
{
    public int FromVersion => 2;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by GeneralSettings.
    }
}

/// <summary>
/// v4 adds <see cref="DnsSettings"/> (active resolver, local proxy endpoint, adapter integration, timeouts).
/// </summary>
internal sealed class MigrationV3ToV4 : ISettingsMigration
{
    public int FromVersion => 3;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by DnsSettings.
    }
}

/// <summary>
/// v5 adds custom resolvers, disabled resolver IDs, secondary resolver, and resolver groups to <see cref="DnsSettings"/>.
/// </summary>
internal sealed class MigrationV4ToV5 : ISettingsMigration
{
    public int FromVersion => 4;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by DnsSettings.
    }
}

/// <summary>
/// v6 adds <see cref="RoutingSettings"/> (domain-based routing profiles, rules, and fallback resolvers).
/// </summary>
internal sealed class MigrationV5ToV6 : ISettingsMigration
{
    public int FromVersion => 5;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by RoutingSettings.
    }
}

/// <summary>
/// v7 adds <see cref="FilteringSettings"/> and <see cref="CacheSettings"/>.
/// </summary>
internal sealed class MigrationV6ToV7 : ISettingsMigration
{
    public int FromVersion => 6;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by FilteringSettings and CacheSettings.
    }
}

/// <summary>
/// v8 adds <see cref="GamingSettings"/> (gaming optimization profiles, resolver selection criteria, and Gaming Mode).
/// </summary>
internal sealed class MigrationV7ToV8 : ISettingsMigration
{
    public int FromVersion => 7;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by GamingSettings.
    }
}

/// <summary>
/// v9 adds <see cref="ResilienceSettings"/> (failover policy, retry policy, and failure thresholds).
/// </summary>
internal sealed class MigrationV8ToV9 : ISettingsMigration
{
    public int FromVersion => 8;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by ResilienceSettings.
    }
}

/// <summary>
/// v10 adds <see cref="MonitoringMode"/> and <see cref="PerformanceSettings.EnablePerformanceDiagnostics"/>.
/// </summary>
internal sealed class MigrationV9ToV10 : ISettingsMigration
{
    public int FromVersion => 9;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by PerformanceSettings.
    }
}

public sealed class SettingsMigrator
{
    private readonly Dictionary<int, ISettingsMigration> _migrations;

    public SettingsMigrator(IEnumerable<ISettingsMigration>? migrations = null, int targetVersion = AppSettings.CurrentSchemaVersion)
    {
        TargetVersion = targetVersion;
        _migrations = (migrations ?? DefaultMigrations()).ToDictionary(m => m.FromVersion);
    }

    public int TargetVersion { get; }

    public static IEnumerable<ISettingsMigration> DefaultMigrations() =>
        [new MigrationV0ToV1(), new MigrationV1ToV2(), new MigrationV2ToV3(), new MigrationV3ToV4(), new MigrationV4ToV5(), new MigrationV5ToV6(), new MigrationV6ToV7(), new MigrationV7ToV8(), new MigrationV8ToV9(), new MigrationV9ToV10()];

    public static int ReadVersion(JsonObject document)
    {
        foreach (var (key, value) in document)
        {
            if (string.Equals(key, "schemaVersion", StringComparison.OrdinalIgnoreCase)
                && value is JsonValue v && v.TryGetValue<int>(out var version))
            {
                return version;
            }
        }

        return 0;
    }

    /// <summary>
    /// Applies migrations in sequence until <see cref="TargetVersion"/> is reached.
    /// </summary>
    /// <returns>True when the document was modified.</returns>
    /// <exception cref="InvalidOperationException">A migration step is missing.</exception>
    public bool Migrate(JsonObject document)
    {
        var version = ReadVersion(document);
        if (version >= TargetVersion)
        {
            return false;
        }

        while (version < TargetVersion)
        {
            if (!_migrations.TryGetValue(version, out var migration))
            {
                throw new InvalidOperationException($"No settings migration registered from schema version {version}.");
            }

            migration.Apply(document);
            version++;
            SetVersion(document, version);
        }

        return true;
    }

    private static void SetVersion(JsonObject document, int version)
    {
        foreach (var key in document.Select(p => p.Key).ToList())
        {
            if (string.Equals(key, "schemaVersion", StringComparison.OrdinalIgnoreCase))
            {
                document.Remove(key);
            }
        }

        document["schemaVersion"] = version;
    }
}
