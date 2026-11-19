using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Network.Monitoring;

/// <summary>
/// Samples real-time ICMP ping and active network adapter throughput while the Dashboard is visible.
/// Stops all background timers and ICMP probes when <see cref="Pause"/> is called (window minimized, hidden, or inactive page).
/// </summary>
public sealed class NetworkTelemetryService : INetworkTelemetryService
{
    public const int MaxHistorySamples = 60;
    private const string DefaultPingTarget = "1.1.1.1";
    private const string FallbackPingTarget = "8.8.8.8";
    private const int PingTimeoutMs = 1000;

    private readonly ILogger<NetworkTelemetryService> _logger;
    private readonly object _sync = new();
    private readonly Queue<NetworkTelemetrySample> _history = new(MaxHistorySamples);

    private CancellationTokenSource? _loopCts;
    private string? _primaryAdapterId;
    private string? _preferredPingHost;
    private bool _hasPreviousCounters;
    private long _prevReceivedBytes;
    private long _prevSentBytes;
    private long _prevTimestamp;
    private bool _disposed;

    public NetworkTelemetryService(ILogger<NetworkTelemetryService>? logger = null)
    {
        _logger = logger ?? NullLogger<NetworkTelemetryService>.Instance;
    }

    public event EventHandler<NetworkTelemetrySample>? SampleReceived;

    public bool IsActive { get; private set; }

    public void ConfigureTargets(string? primaryAdapterId, string? preferredPingHost)
    {
        lock (_sync)
        {
            if (!string.Equals(_primaryAdapterId, primaryAdapterId, StringComparison.OrdinalIgnoreCase))
            {
                _primaryAdapterId = primaryAdapterId;
                // Discard the baseline when switching adapters to prevent artificial rate spikes.
                _hasPreviousCounters = false;
            }

            _preferredPingHost = preferredPingHost;
        }
    }

    public void Resume()
    {
        CancellationTokenSource? ctsToStart = null;
        lock (_sync)
        {
            if (_disposed || IsActive)
            {
                return;
            }

            IsActive = true;
            _hasPreviousCounters = false;
            ctsToStart = new CancellationTokenSource();
            _loopCts = ctsToStart;
        }

        _ = Task.Run(() => SamplingLoopAsync(ctsToStart.Token));
    }

    public void Pause()
    {
        lock (_sync)
        {
            if (!IsActive && _loopCts is null)
            {
                return;
            }

            IsActive = false;
            _hasPreviousCounters = false;
            StopLoopLocked();
        }
    }

    public IReadOnlyList<NetworkTelemetrySample> GetRecentSamples()
    {
        lock (_sync)
        {
            return _history.ToList();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            IsActive = false;
            _hasPreviousCounters = false;
            StopLoopLocked();
        }
    }

    internal static (double DownloadBytesPerSecond, double UploadBytesPerSecond) CalculateRates(
        long previousReceived,
        long previousSent,
        long currentReceived,
        long currentSent,
        double elapsedSeconds)
    {
        if (elapsedSeconds <= 0.05 || elapsedSeconds > 10.0)
        {
            return (0, 0);
        }

        var rxDelta = Math.Max(0L, currentReceived - previousReceived);
        var txDelta = Math.Max(0L, currentSent - previousSent);
        return (rxDelta / elapsedSeconds, txDelta / elapsedSeconds);
    }

    public static string FormatThroughput(double bytesPerSecond)
    {
        if (bytesPerSecond <= 0 || double.IsNaN(bytesPerSecond) || double.IsInfinity(bytesPerSecond))
        {
            return "0 Kbps";
        }

        var bps = bytesPerSecond * 8.0;
        if (bps < 1_000_000.0)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{bps / 1_000.0:0.#} Kbps");
        }

        if (bps < 1_000_000_000.0)
        {
            return string.Create(CultureInfo.InvariantCulture, $"{bps / 1_000_000.0:0.##} Mbps");
        }

        return string.Create(CultureInfo.InvariantCulture, $"{bps / 1_000_000_000.0:0.##} Gbps");
    }

    internal static string ResolvePingTarget(string? preferredHost)
    {
        if (!string.IsNullOrWhiteSpace(preferredHost)
            && IPAddress.TryParse(preferredHost.Trim(), out var ip)
            && !IPAddress.IsLoopback(ip)
            && !ip.Equals(IPAddress.Any)
            && !ip.Equals(IPAddress.IPv6Any))
        {
            return ip.ToString();
        }

        return DefaultPingTarget;
    }

    private void StopLoopLocked()
    {
        if (_loopCts is null)
        {
            return;
        }

        try
        {
            _loopCts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed.
        }
        finally
        {
            _loopCts.Dispose();
            _loopCts = null;
        }
    }

    private async Task SamplingLoopAsync(CancellationToken ct)
    {
        using var ping = new Ping();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));

        double? lastPingMs = null;
        var lastPingAt = DateTimeOffset.MinValue;
        long tickIndex = 0;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var sample = await CaptureSampleAsync(
                    ping,
                    tickIndex,
                    lastPingMs,
                    lastPingAt,
                    ct).ConfigureAwait(false);

                if (ct.IsCancellationRequested)
                {
                    break;
                }

                if (sample.UpdatedPingMs is { } measuredPing)
                {
                    lastPingMs = measuredPing;
                    lastPingAt = sample.Sample.Timestamp;
                }

                lock (_sync)
                {
                    if (_history.Count >= MaxHistorySamples)
                    {
                        _history.Dequeue();
                    }

                    _history.Enqueue(sample.Sample);
                }

                SampleReceived?.Invoke(this, sample.Sample);
                tickIndex++;

                if (!await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal pause / shutdown.
        }
        catch (ObjectDisposedException)
        {
            // Normal pause / shutdown race.
        }
        catch (Exception ex) when (ex is NetworkInformationException or SocketException or InvalidOperationException)
        {
            _logger.LogDebug(ex, "Live telemetry sampling loop stopped due to network/state error.");
        }
    }

    private async Task<(NetworkTelemetrySample Sample, double? UpdatedPingMs)> CaptureSampleAsync(
        Ping ping,
        long tickIndex,
        double? lastPingMs,
        DateTimeOffset lastPingAt,
        CancellationToken ct)
    {
        string? adapterId;
        string? pingHost;
        lock (_sync)
        {
            adapterId = _primaryAdapterId;
            pingHost = _preferredPingHost;
        }

        var nowTick = Stopwatch.GetTimestamp();
        var (rxBytes, txBytes, hasCounters) = ReadAdapterBytes(adapterId);
        double downRate = 0;
        double upRate = 0;

        if (hasCounters)
        {
            lock (_sync)
            {
                if (_hasPreviousCounters)
                {
                    var elapsed = Stopwatch.GetElapsedTime(_prevTimestamp, nowTick).TotalSeconds;
                    (downRate, upRate) = CalculateRates(_prevReceivedBytes, _prevSentBytes, rxBytes, txBytes, elapsed);
                }

                _prevReceivedBytes = rxBytes;
                _prevSentBytes = txBytes;
                _prevTimestamp = nowTick;
                _hasPreviousCounters = true;
            }
        }

        double? updatedPing = null;
        double? displayPing = lastPingMs;
        var now = DateTimeOffset.UtcNow;

        if (tickIndex % 2 == 0)
        {
            updatedPing = await ProbePingAsync(ping, ResolvePingTarget(pingHost), ct).ConfigureAwait(false);
            displayPing = updatedPing ?? (now - lastPingAt <= TimeSpan.FromSeconds(6) ? lastPingMs : null);
        }
        else if (now - lastPingAt > TimeSpan.FromSeconds(6))
        {
            displayPing = null;
        }

        return (new NetworkTelemetrySample(now, displayPing, downRate, upRate), updatedPing);
    }

    private static async Task<double?> ProbePingAsync(Ping ping, string primaryTarget, CancellationToken ct)
    {
        var first = await SendSinglePingAsync(ping, primaryTarget, ct).ConfigureAwait(false);
        if (first is not null)
        {
            return first;
        }

        if (!ct.IsCancellationRequested && !string.Equals(primaryTarget, FallbackPingTarget, StringComparison.OrdinalIgnoreCase))
        {
            return await SendSinglePingAsync(ping, FallbackPingTarget, ct).ConfigureAwait(false);
        }

        return null;
    }

    private static async Task<double?> SendSinglePingAsync(Ping ping, string host, CancellationToken ct)
    {
        try
        {
            var sw = Stopwatch.StartNew();
            var reply = await ping.SendPingAsync(host, PingTimeoutMs).WaitAsync(ct).ConfigureAwait(false);
            sw.Stop();
            if (reply.Status == IPStatus.Success)
            {
                return reply.RoundtripTime > 0
                    ? reply.RoundtripTime
                    : Math.Max(0.5, Math.Round(sw.Elapsed.TotalMilliseconds, 1));
            }
        }
        catch (Exception ex) when (ex is PingException or SocketException or TimeoutException or InvalidOperationException)
        {
            // Ignore transient ICMP failures and let the caller decide fallback/null.
        }

        return null;
    }

    private (long Received, long Sent, bool Valid) ReadAdapterBytes(string? adapterId)
    {
        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            if (!string.IsNullOrWhiteSpace(adapterId))
            {
                foreach (var nic in nics)
                {
                    if (nic.OperationalStatus == OperationalStatus.Up
                        && string.Equals(nic.Id, adapterId, StringComparison.OrdinalIgnoreCase))
                    {
                        var stats = nic.GetIPStatistics();
                        return (stats.BytesReceived, stats.BytesSent, true);
                    }
                }
            }

            long totalRx = 0;
            long totalTx = 0;
            var found = false;
            foreach (var nic in nics)
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                var stats = nic.GetIPStatistics();
                totalRx += stats.BytesReceived;
                totalTx += stats.BytesSent;
                found = true;
            }

            return (totalRx, totalTx, found);
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            _logger.LogDebug(ex, "Unable to read NIC byte counters.");
            return (0, 0, false);
        }
    }
}
