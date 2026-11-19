using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Samples real-time ICMP ping and active adapter throughput while the dashboard is visible,
/// and pauses all polling whenever the window is minimized, hidden, or in background mode.
/// </summary>
public interface INetworkTelemetryService : IDisposable
{
    event EventHandler<NetworkTelemetrySample>? SampleReceived;

    bool IsActive { get; }

    void ConfigureTargets(string? primaryAdapterId, string? preferredPingHost);

    void Resume();

    void Pause();

    IReadOnlyList<NetworkTelemetrySample> GetRecentSamples();
}
