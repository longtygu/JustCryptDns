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
    private int _disposed;

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
        Current = initial.Settings.Normalize();
        LoadOutcome = initial.Outcome;
        _deferredTimer = new Timer(_ => _ = SaveDeferredAsync(), null, Timeout.Infinite, Timeout.Infinite);
        _logger.LogInformation("Settings loaded: {Outcome} {Detail}", initial.Outcome, initial.Detail);
    }

    public AppSettings Current { get; private set; }

    public SettingsLoadOutcome LoadOutcome { get; private set; }

    public event EventHandler<AppSettings>? Changed;

    public event EventHandler<Exception>? SaveFailed;

    public async Task UpdateAsync(Action<AppSettings> mutate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        AppSettings copy;
        try
        {
            // Mutate a copy so a failed save never leaves the live instance half-updated.
            copy = Mutate(mutate);
            if (CanPersist)
            {
                await _store.SaveAsync(copy, cancellationToken).ConfigureAwait(false);
            }

            Current = copy;
            Interlocked.Exchange(ref _pendingDeferred, 0);
        }
        finally
        {
            ReleaseGateSafe();
        }

        Changed?.Invoke(this, copy);
    }

    public void UpdateDeferred(Action<AppSettings> mutate)
    {
        ArgumentNullException.ThrowIfNull(mutate);
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        AppSettings updated;
        var acquired = false;
        try
        {
            _gate.Wait();
            acquired = true;
            updated = Mutate(mutate);
            Current = updated;
            Interlocked.Exchange(ref _pendingDeferred, 1);
            if (Volatile.Read(ref _disposed) == 0)
            {
                _deferredTimer.Change(DeferredSaveDelay, Timeout.InfiniteTimeSpan);
            }
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        finally
        {
            if (acquired)
            {
                ReleaseGateSafe();
            }
        }

        Changed?.Invoke(this, updated);
    }

    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            _deferredTimer.Change(Timeout.Infinite, Timeout.Infinite);
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        await SaveDeferredAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> ReloadFromDiskAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return false;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        AppSettings reloaded;
        try
        {
            try
            {
                _deferredTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            catch (ObjectDisposedException)
            {
            }

            Interlocked.Exchange(ref _pendingDeferred, 0);

            var result = _store.Load();
            if (result.Outcome == SettingsLoadOutcome.ResetAfterCorruption)
            {
                _logger.LogWarning("Skipping disk settings reload because primary and backup settings files were unreadable.");
                return false;
            }

            LoadOutcome = result.Outcome;
            result.Settings.Normalize();
            Current = result.Settings;
            reloaded = result.Settings;
        }
        finally
        {
            ReleaseGateSafe();
        }

        Changed?.Invoke(this, reloaded);
        return true;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _deferredTimer.Dispose();
        _gate.Dispose();
    }

    private void ReleaseGateSafe()
    {
        try
        {
            _gate.Release();
        }
        catch (ObjectDisposedException)
        {
        }
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
        if (Volatile.Read(ref _disposed) != 0 || Interlocked.Exchange(ref _pendingDeferred, 0) == 0)
        {
            return;
        }

        var acquired = false;
        try
        {
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            acquired = true;
            if (CanPersist)
            {
                await _store.SaveAsync(Current, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (ObjectDisposedException)
        {
            // Ignored on shutdown.
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _logger.LogError(ex, "Deferred settings save failed.");
            SaveFailed?.Invoke(this, ex);
        }
        finally
        {
            if (acquired)
            {
                ReleaseGateSafe();
            }
        }
    }
}
