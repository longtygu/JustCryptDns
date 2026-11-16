using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Storage;

/// <summary>
/// JSON file store with atomic replacement, a rolling <c>.bak</c> copy, schema migration and corruption recovery.
/// </summary>
public sealed class JsonSettingsStore : ISettingsStore
{
    private readonly string _path;
    private readonly string _backupPath;
    private readonly SettingsMigrator _migrator;
    private readonly ILogger<JsonSettingsStore> _logger;

    public JsonSettingsStore(IAppPaths paths, ILogger<JsonSettingsStore> logger, SettingsMigrator? migrator = null)
    {
        _path = paths.SettingsFile;
        _backupPath = _path + ".bak";
        _migrator = migrator ?? new SettingsMigrator();
        _logger = logger;
    }

    public SettingsLoadResult Load()
    {
        if (!File.Exists(_path))
        {
            return new SettingsLoadResult(new AppSettings(), SettingsLoadOutcome.Defaults);
        }

        if (TryRead(_path, out var settings, out var outcome, out var error))
        {
            return new SettingsLoadResult(settings!, outcome);
        }

        _logger.LogWarning("Settings file unreadable ({Error}); trying backup.", error);

        if (File.Exists(_backupPath) && TryRead(_backupPath, out settings, out _, out var backupError))
        {
            PreserveCorrupt();
            return new SettingsLoadResult(settings!, SettingsLoadOutcome.RecoveredFromBackup, error);
        }

        var preserved = PreserveCorrupt();
        return new SettingsLoadResult(new AppSettings(), SettingsLoadOutcome.ResetAfterCorruption, $"{error}; preserved as {preserved}");
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);

        var json = JsonSerializer.Serialize(settings, SettingsJson.Options);

        // Validate that what we are about to write can be read back.
        _ = JsonSerializer.Deserialize<AppSettings>(json, SettingsJson.Options)
            ?? throw new InvalidOperationException("Serialized settings failed round-trip validation.");

        var temp = Path.Combine(directory, $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                var bytes = Encoding.UTF8.GetBytes(json);
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (File.Exists(_path))
            {
                // Only keep the current file as backup if it is valid, so a corrupt file never overwrites a good backup.
                if (TryRead(_path, out _, out _, out _))
                {
                    File.Replace(temp, _path, _backupPath, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(temp, _path, overwrite: true);
                }
            }
            else
            {
                File.Move(temp, _path);
            }
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }

    private bool TryRead(string path, out AppSettings? settings, out SettingsLoadOutcome outcome, out string? error)
    {
        settings = null;
        outcome = SettingsLoadOutcome.Loaded;
        error = null;
        try
        {
            var text = File.ReadAllText(path, Encoding.UTF8);
            var node = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

            if (node is not JsonObject document)
            {
                error = "Root element is not a JSON object.";
                return false;
            }

            var version = SettingsMigrator.ReadVersion(document);
            if (version > _migrator.TargetVersion)
            {
                outcome = SettingsLoadOutcome.NewerSchemaReadOnly;
            }
            else if (_migrator.Migrate(document))
            {
                outcome = SettingsLoadOutcome.Migrated;
            }

            settings = document.Deserialize<AppSettings>(SettingsJson.Options);
            if (settings is null)
            {
                error = "Document deserialized to null.";
                return false;
            }

            settings.Normalize();
            return true;
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidOperationException or UnauthorizedAccessException or NotSupportedException)
        {
            error = ex.Message;
            return false;
        }
    }

    private string? PreserveCorrupt()
    {
        try
        {
            var target = Path.Combine(
                Path.GetDirectoryName(_path)!,
                $"{Path.GetFileNameWithoutExtension(_path)}.corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}.json");
            File.Move(_path, target, overwrite: true);
            return target;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "Could not preserve corrupt settings file.");
            return null;
        }
    }
}
