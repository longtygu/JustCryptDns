namespace JustCryptDns.Core.Models;

/// <summary>
/// Single point-in-time live telemetry sample containing gateway/resolver ping and network interface throughput.
/// </summary>
public readonly record struct NetworkTelemetrySample(
    DateTimeOffset Timestamp,
    double? PingMs,
    double DownloadBytesPerSecond,
    double UploadBytesPerSecond)
{
    public double DownloadMbps => DownloadBytesPerSecond * 8.0 / 1_000_000.0;

    public double UploadMbps => UploadBytesPerSecond * 8.0 / 1_000_000.0;
}
