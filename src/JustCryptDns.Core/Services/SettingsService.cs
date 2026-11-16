using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Core.Services;

/// <summary>
/// Holds the live <see cref="AppSettings"/> and serializes updates/persistence.
/// </summary>
public sealed class SettingsService : ISettingsService, IDisposable
{
    private readonly ISettingsStore _store;
    private readonly ILogger<SettingsService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SettingsService(ISettingsStore store, ILogger<SettingsService> logger)
        : this(store, logger, store.Load())
    {
    }

    /// <summary>Creates the service from an already performed load (used when settings are needed before DI is built).</summary>
    public SettingsService(ISettingsStore store, ILogger<SettingsService> logger, SettingsLoadResult initial)
    {
        ArgumentNullException.ThrowIfNull(initial);
        _store = store;
        _logger = logger;
        Current = initial.Settings;
        LoadOutcome = initial.Outcome;
        _logger.LogInformation("Settings loaded: {Outcome} {Detail}", initial.Outcome, initial.Detail);
    }

    public AppSettings Current { get; private set; }

    public SettingsLoadOutcome LoadOutcome { get; }

    public event EventHandler<AppSettings>? Changed;

    public async Task UpdateAsync(Action<AppSettings> mutate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(true);
        try
        {
            // Mutate a copy so a failed save never leaves the live instance half-updated.
            var copy = Current.Clone();
            mutate(copy);
            copy.Normalize();
            copy.SchemaVersion = AppSettings.CurrentSchemaVersion;

            if (LoadOutcome == SettingsLoadOutcome.NewerSchemaReadOnly)
            {
                _logger.LogWarning("Settings file has a newer schema; changes are applied in memory only.");
            }
            else
            {
                await _store.SaveAsync(copy, cancellationToken).ConfigureAwait(true);
            }

            Current = copy;
        }
        finally
        {
            _gate.Release();
        }

        Changed?.Invoke(this, Current);
    }

    public void Dispose() => _gate.Dispose();
}
