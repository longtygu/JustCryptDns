using System.IO;
using System.Threading;

namespace JustCryptDns.App.Services;

/// <summary>
/// Ensures a single UI instance per user session. A second launch signals the first one to show its window and exits.
/// </summary>
public sealed class SingleInstanceGuard : IDisposable
{
    private readonly Mutex _mutex;
    private readonly EventWaitHandle _activateSignal;
    private RegisteredWaitHandle? _registration;

    private SingleInstanceGuard(Mutex mutex, EventWaitHandle activateSignal, bool isPrimary)
    {
        _mutex = mutex;
        _activateSignal = activateSignal;
        IsPrimary = isPrimary;
    }

    public bool IsPrimary { get; }

    public static SingleInstanceGuard Acquire(string name)
    {
        // "Local\" scopes to the current logon session.
        var mutex = new Mutex(initiallyOwned: true, $@"Local\{name}.Instance", out var createdNew);
        var signal = new EventWaitHandle(false, EventResetMode.AutoReset, $@"Local\{name}.Activate");
        return new SingleInstanceGuard(mutex, signal, createdNew);
    }

    /// <summary>Asks the primary instance to activate its window.</summary>
    public void SignalPrimary() => _activateSignal.Set();

    /// <summary>Invokes <paramref name="onActivate"/> (on a pool thread) whenever another instance signals.</summary>
    public void ListenForActivation(Action onActivate)
    {
        _registration = ThreadPool.RegisterWaitForSingleObject(_activateSignal, (_, _) => onActivate(), null, Timeout.Infinite, executeOnlyOnce: false);
    }

    public void Dispose()
    {
        _registration?.Unregister(null);
        if (IsPrimary)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Not owned by this thread; the OS releases it on exit.
            }
        }

        _mutex.Dispose();
        _activateSignal.Dispose();
    }
}
