using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Core.Services;

/// <summary>
/// Holds the live <see cref="AppSettings"/> and serializes updates/persistence.
/// </summary>
public sealed class SettingsService : ISettingsService, IDisposable
{
    /// <summary>Delay used by <see cref="UpdateDeferred"/> to coalesce rapid changes (e.g. slider drags) into one write.</summary>
    public static readonly TimeSpan DeferredSaveDelay = TimeSpan.FromMilliseconds(600);

    private readonly ISettingsStore _store;
    private readonly ILogger<SettingsService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Timer _deferredTimer;
    private int _pendingDeferred;

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
        _deferredTimer = new Timer(_ => _ = SaveDeferredAsync(), null, Timeout.Infinite, Timeout.Infinite);
        _logger.LogInformation("Settings loaded: {Outcome} {Detail}", initial.Outcome, initial.Detail);
    }

    public AppSettings Current { get; private set; }

    public SettingsLoadOutcome LoadOutcome { get; }

    public event EventHandler<AppSettings>? Changed;

    public event EventHandler<Exception>? SaveFailed;

    public async Task UpdateAsync(Action<AppSettings> mutate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(true);
        try
        {
            // Mutate a copy so a failed save never leaves the live instance half-updated.
            var copy = Mutate(mutate);
            if (CanPersist)
            {
                await _store.SaveAsync(copy, cancellationToken).ConfigureAwait(true);
            }

            Current = copy;
            Interlocked.Exchange(ref _pendingDeferred, 0);
        }
        finally
        {
            _gate.Release();
        }

        Changed?.Invoke(this, Current);
    }

    public void UpdateDeferred(Action<AppSettings> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        Current = Mutate(mutate);
        Interlocked.Exchange(ref _pendingDeferred, 1);
        _deferredTimer.Change(DeferredSaveDelay, Timeout.InfiniteTimeSpan);
        Changed?.Invoke(this, Current);
    }

    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        _deferredTimer.Change(Timeout.Infinite, Timeout.Infinite);
        await SaveDeferredAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _deferredTimer.Dispose();
        _gate.Dispose();
    }

    private bool CanPersist
    {
        get
        {
            if (LoadOutcome != SettingsLoadOutcome.NewerSchemaReadOnly)
            {
                return true;
            }

            _logger.LogWarning("Settings file has a newer schema; changes are applied in memory only.");
            return false;
        }
    }

    private AppSettings Mutate(Action<AppSettings> mutate)
    {
        var copy = Current.Clone();
        mutate(copy);
        copy.Normalize();
        copy.SchemaVersion = AppSettings.CurrentSchemaVersion;
        return copy;
    }

    private async Task SaveDeferredAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _pendingDeferred, 0) == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (CanPersist)
            {
                await _store.SaveAsync(Current, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _logger.LogError(ex, "Deferred settings save failed.");
            SaveFailed?.Invoke(this, ex);
        }
        finally
        {
            _gate.Release();
        }
    }
}
