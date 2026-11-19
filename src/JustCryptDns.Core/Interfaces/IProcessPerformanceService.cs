using JustCryptDns.Core.Configuration;

namespace JustCryptDns.Core.Interfaces;

public sealed record ProcessPerformanceSnapshot
{
    public required double WorkingSetMb { get; init; }

    public required double PrivateMemoryMb { get; init; }

    public required double ManagedHeapMb { get; init; }

    public required int ThreadCount { get; init; }

    public required int HandleCount { get; init; }

    public required int GcGen0Collections { get; init; }

    public required int GcGen1Collections { get; init; }

    public required int GcGen2Collections { get; init; }

    public required TimeSpan Uptime { get; init; }

    public required MonitoringMode ActiveMonitoringMode { get; init; }
}

/// <summary>
/// Real-time process memory, thread, handle, and GC diagnostics plus working-set trimming (Part 12).
/// </summary>
public interface IProcessPerformanceService
{
    ProcessPerformanceSnapshot CaptureSnapshot();

    ProcessPerformanceSnapshot TrimWorkingSet();
}
