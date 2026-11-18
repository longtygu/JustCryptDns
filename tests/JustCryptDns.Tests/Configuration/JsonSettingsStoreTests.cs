using System.Text.Json.Nodes;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Configuration;

public sealed class JsonSettingsStoreTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public JsonSettingsStoreTests()
    {
        _paths = new AppPaths(_root);
        _paths.EnsureCreated();
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private JsonSettingsStore CreateStore(SettingsMigrator? migrator = null) =>
        new(_paths, NullLogger<JsonSettingsStore>.Instance, migrator);

    [Fact]
    public void Load_MissingFile_ReturnsDefaults()
    {
        var result = CreateStore().Load();

        Assert.Equal(SettingsLoadOutcome.Defaults, result.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, result.Settings.SchemaVersion);
        Assert.Equal(AppTheme.Dark, result.Settings.Appearance.Theme);
    }

    [Fact]
    public async Task SaveThenLoad_RoundTripsValues()
    {
        var store = CreateStore();
        var settings = new AppSettings();
        settings.General.Language = LanguageCodes.Vietnamese;
        settings.Appearance.Theme = AppTheme.Light;
        settings.Appearance.AccentColor = "#10B981";
        settings.Appearance.SidebarCollapsed = true;

        await store.SaveAsync(settings);
        var result = store.Load();

        Assert.Equal(SettingsLoadOutcome.Loaded, result.Outcome);
        Assert.Equal(LanguageCodes.Vietnamese, result.Settings.General.Language);
        Assert.Equal(AppTheme.Light, result.Settings.Appearance.Theme);
        Assert.Equal("#10B981", result.Settings.Appearance.AccentColor);
        Assert.True(result.Settings.Appearance.SidebarCollapsed);
    }

    [Fact]
    public async Task Save_KeepsPreviousValidFileAsBackup()
    {
        var store = CreateStore();
        await store.SaveAsync(new AppSettings { Appearance = { Theme = AppTheme.Light } });
        await store.SaveAsync(new AppSettings { Appearance = { Theme = AppTheme.System } });

        Assert.True(File.Exists(_paths.SettingsFile + ".bak"));
        Assert.Contains("\"light\"", File.ReadAllText(_paths.SettingsFile + ".bak"), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public async Task Load_CorruptFile_RecoversFromBackup()
    {
        var store = CreateStore();
        await store.SaveAsync(new AppSettings { Appearance = { Theme = AppTheme.Light } });
        await store.SaveAsync(new AppSettings { Appearance = { Theme = AppTheme.Light } });
        await File.WriteAllTextAsync(_paths.SettingsFile, "{ this is not json");

        var result = store.Load();

        Assert.Equal(SettingsLoadOutcome.RecoveredFromBackup, result.Outcome);
        Assert.Equal(AppTheme.Light, result.Settings.Appearance.Theme);
        Assert.Single(Directory.GetFiles(_root, "settings.corrupt-*.json"));
    }

    [Fact]
    public async Task Load_CorruptFileWithoutBackup_ResetsAndPreservesCorruptFile()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, "[1,2,3]");

        var result = CreateStore().Load();

        Assert.Equal(SettingsLoadOutcome.ResetAfterCorruption, result.Outcome);
        Assert.False(File.Exists(_paths.SettingsFile));
        Assert.Single(Directory.GetFiles(_root, "settings.corrupt-*.json"));
    }

    [Fact]
    public async Task Load_InvalidValues_AreNormalized()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile,
            """{ "schemaVersion": 1, "general": { "language": "xx" }, "appearance": { "accentColor": "red" }, "performance": { "logRetentionDays": 5000 } }""");

        var result = CreateStore().Load();

        Assert.Equal(LanguageCodes.System, result.Settings.General.Language);
        Assert.Equal(AppearanceSettings.DefaultAccentColor, result.Settings.Appearance.AccentColor);
        Assert.Equal(90, result.Settings.Performance.LogRetentionDays);
    }

    [Fact]
    public async Task Load_V1File_IsMigratedToV2()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 1, "appearance": { "theme": "Light", "accentColor": "#22C55E" } }""");

        var result = CreateStore().Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, result.Outcome);
        Assert.Equal(AppTheme.Light, result.Settings.Appearance.Theme);
        Assert.Equal("#22C55E", result.Settings.Appearance.AccentColor);
        Assert.Equal(AppSettings.CurrentSchemaVersion, result.Settings.SchemaVersion);
    }

    [Fact]
    public async Task Load_UnversionedFile_IsMigrated()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "appearance": { "theme": "Light" } }""");

        var result = CreateStore().Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, result.Outcome);
        Assert.Equal(AppTheme.Light, result.Settings.Appearance.Theme);
        Assert.Equal(AppSettings.CurrentSchemaVersion, result.Settings.SchemaVersion);
    }

    [Fact]
    public async Task Load_NewerSchema_IsFlaggedReadOnly()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 999, "appearance": { "theme": "Light" }, "futureThing": 1 }""");

        var result = CreateStore().Load();

        Assert.Equal(SettingsLoadOutcome.NewerSchemaReadOnly, result.Outcome);
        Assert.Equal(AppTheme.Light, result.Settings.Appearance.Theme);
    }

    [Fact]
    public void Migrator_AppliesStepsInOrder()
    {
        var calls = new List<int>();
        var migrator = new SettingsMigrator(
            [new RecordingMigration(0, calls), new RecordingMigration(1, calls), new RecordingMigration(2, calls)],
            targetVersion: 3);
        var doc = new JsonObject();

        Assert.True(migrator.Migrate(doc));
        Assert.Equal([0, 1, 2], calls);
        Assert.Equal(3, SettingsMigrator.ReadVersion(doc));
    }

    [Fact]
    public void Migrator_MissingStep_Throws()
    {
        var migrator = new SettingsMigrator([new RecordingMigration(0, [])], targetVersion: 3);
        Assert.Throws<InvalidOperationException>(() => migrator.Migrate(new JsonObject()));
    }

    private sealed class RecordingMigration(int from, List<int> calls) : ISettingsMigration
    {
        public int FromVersion => from;

        public void Apply(JsonObject document) => calls.Add(from);
    }
}
