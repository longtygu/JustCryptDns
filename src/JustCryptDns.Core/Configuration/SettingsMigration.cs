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

/// <summary>
/// v11 adds <see cref="BypassSettings"/> (DPI fragmentation, local Auto-PAC smart proxy, and Split-Tunnel upstream).
/// </summary>
internal sealed class MigrationV10ToV11 : ISettingsMigration
{
    public int FromVersion => 10;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by BypassSettings.
    }
}

/// <summary>
/// v12 upgrades <see cref="BypassSettings"/> to All-Website Smart DPI coverage with 4-stage self-healing.
/// </summary>
internal sealed class MigrationV11ToV12 : ISettingsMigration
{
    public int FromVersion => 11;

    public void Apply(JsonObject document)
    {
        if (document["bypass"] is JsonObject bypass)
        {
            bypass["coverageMode"] ??= nameof(Models.BypassCoverageMode.AllWebsitesSmart);
            bypass["defaultUnmatchedMode"] ??= nameof(Models.BypassMode.AutoHybrid);
            bypass["enableSmartSelfHealing"] ??= true;
        }
    }
}

/// <summary>
/// v13 adds customizable <see cref="StatusPulseStyle"/> to <see cref="AppearanceSettings"/>.
/// </summary>
internal sealed class MigrationV12ToV13 : ISettingsMigration
{
    public int FromVersion => 12;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by AppearanceSettings.
    }
}

/// <summary>
/// v14 adds GitHub auto-update preferences (<see cref="UpdateSettings"/>).
/// </summary>
internal sealed class MigrationV13ToV14 : ISettingsMigration
{
    public int FromVersion => 13;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by UpdateSettings.
    }
}

/// <summary>
/// v15 adds Connection Monitor &amp; IP Blocker preferences, blocklist, and IP notes (<see cref="ConnectionMonitorSettings"/>).
/// </summary>
internal sealed class MigrationV14ToV15 : ISettingsMigration
{
    public int FromVersion => 14;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by ConnectionMonitorSettings.
    }
}

/// <summary>
/// v16 adds Security Shield preferences (Per-App blocklist, DNS Leak Guard, Threat Intel, Process Trust).
/// </summary>
internal sealed class MigrationV15ToV16 : ISettingsMigration
{
    public int FromVersion => 15;

    public void Apply(JsonObject document)
    {
        // Additive change only; defaults are supplied by ConnectionMonitorSettings.
    }
}

/// <summary>
/// v17 appends built-in PUBG / Krafton smart bypass rules to existing user bypass rule lists.
/// </summary>
internal sealed class MigrationV16ToV17 : ISettingsMigration
{
    private static readonly string[] PubgRuleIds = ["gaming-pubg", "gaming-playbattlegrounds", "gaming-krafton"];

    public int FromVersion => 16;

    public void Apply(JsonObject document)
    {
        if (document["bypass"] is not JsonObject bypass || bypass["rules"] is not JsonArray rules)
        {
            return;
        }

        var existingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in rules)
        {
            if (node is JsonObject obj && obj["id"] is JsonValue idVal && idVal.TryGetValue<string>(out var id))
            {
                existingIds.Add(id);
            }
        }

        foreach (var targetId in PubgRuleIds)
        {
            if (existingIds.Contains(targetId))
            {
                continue;
            }

            var rule = Models.BuiltInBypassRules.All.FirstOrDefault(r => string.Equals(r.Id, targetId, StringComparison.OrdinalIgnoreCase));
            if (rule is null)
            {
                continue;
            }

            var serialized = JsonSerializer.SerializeToNode(rule, SettingsJson.Options);
            if (serialized is not null)
            {
                rules.Add(serialized);
            }
        }
    }
}

/// <summary>
/// v18 adds adaptive network/VPN/captive-portal toggles, Serve-Stale/Prefetch cache options, and Local DNS Rewrite rules.
/// </summary>
internal sealed class MigrationV17ToV18 : ISettingsMigration
{
    public int FromVersion => 17;

    public void Apply(JsonObject document)
    {
        // Additive change only; safe defaults are supplied by DnsSettings, CacheSettings, and RoutingSettings.
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
        [new MigrationV0ToV1(), new MigrationV1ToV2(), new MigrationV2ToV3(), new MigrationV3ToV4(), new MigrationV4ToV5(), new MigrationV5ToV6(), new MigrationV6ToV7(), new MigrationV7ToV8(), new MigrationV8ToV9(), new MigrationV9ToV10(), new MigrationV10ToV11(), new MigrationV11ToV12(), new MigrationV12ToV13(), new MigrationV13ToV14(), new MigrationV14ToV15(), new MigrationV15ToV16(), new MigrationV16ToV17(), new MigrationV17ToV18()];

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
