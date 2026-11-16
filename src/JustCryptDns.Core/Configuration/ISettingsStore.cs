namespace JustCryptDns.Core.Configuration;

public enum SettingsLoadOutcome
{
    /// <summary>File did not exist; defaults were used.</summary>
    Defaults,

    /// <summary>File loaded successfully at the current schema version.</summary>
    Loaded,

    /// <summary>File loaded and was upgraded from an older schema version.</summary>
    Migrated,

    /// <summary>Primary file was unreadable; the backup copy was used.</summary>
    RecoveredFromBackup,

    /// <summary>Primary and backup were unreadable; defaults were used and the corrupt file was preserved.</summary>
    ResetAfterCorruption,

    /// <summary>File was written by a newer application version; it is loaded but will not be overwritten.</summary>
    NewerSchemaReadOnly,
}

public sealed record SettingsLoadResult(AppSettings Settings, SettingsLoadOutcome Outcome, string? Detail = null);

/// <summary>Low-level persistence of <see cref="AppSettings"/>.</summary>
public interface ISettingsStore
{
    SettingsLoadResult Load();

    /// <summary>Atomically persists settings, keeping the previous file as a backup.</summary>
    Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default);
}

/// <summary>
/// Application-wide access to the current settings with change notification.
/// </summary>
public interface ISettingsService
{
    /// <summary>The live settings instance. Treat as read-only; mutate via <see cref="UpdateAsync"/>.</summary>
    AppSettings Current { get; }

    SettingsLoadOutcome LoadOutcome { get; }

    /// <summary>Raised on the calling thread after settings were changed and persisted.</summary>
    event EventHandler<AppSettings>? Changed;

    /// <summary>Applies <paramref name="mutate"/>, normalizes, persists and raises <see cref="Changed"/>.</summary>
    Task UpdateAsync(Action<AppSettings> mutate, CancellationToken cancellationToken = default);
}
