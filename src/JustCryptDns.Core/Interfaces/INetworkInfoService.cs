using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Read-only, event-driven view of local network adapters.
/// </summary>
public interface INetworkInfoService
{
    /// <summary>
    /// Raised (debounced, on a thread-pool thread) when adapter addresses or availability change.
    /// The OS notification hooks are only installed while at least one handler is attached.
    /// </summary>
    event EventHandler? NetworkChanged;

    /// <summary>Captures a snapshot of all adapters. May block briefly; call off the UI thread.</summary>
    NetworkSnapshot GetSnapshot();
}
