using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;

namespace JustCryptDns.Infrastructure.Diagnostics;

public sealed class ProcessPerformanceService : IProcessPerformanceService
{
    private readonly ISettingsService _settings;

    public ProcessPerformanceService(ISettingsService settings)
    {
        _settings = settings;
    }

    public ProcessPerformanceSnapshot CaptureSnapshot()
    {
        using var proc = System.Diagnostics.Process.GetCurrentProcess();
        proc.Refresh();

        var workingSetMb = Math.Round(proc.WorkingSet64 / (1024.0 * 1024.0), 1);
        var privateMb = Math.Round(proc.PrivateMemorySize64 / (1024.0 * 1024.0), 1);
        var managedMb = Math.Round(GC.GetTotalMemory(forceFullCollection: false) / (1024.0 * 1024.0), 1);
        var uptime = DateTime.Now - proc.StartTime;
        if (uptime < TimeSpan.Zero)
        {
            uptime = TimeSpan.Zero;
        }

        var threads = proc.Threads;
        var threadCount = threads.Count;
        foreach (ProcessThread t in threads)
        {
            t.Dispose();
        }

        return new ProcessPerformanceSnapshot
        {
            WorkingSetMb = workingSetMb,
            PrivateMemoryMb = privateMb,
            ManagedHeapMb = managedMb,
            ThreadCount = threadCount,
            HandleCount = proc.HandleCount,
            GcGen0Collections = GC.CollectionCount(0),
            GcGen1Collections = GC.CollectionCount(1),
            GcGen2Collections = GC.CollectionCount(2),
            Uptime = uptime,
            ActiveMonitoringMode = _settings.Current.Performance.MonitoringMode,
        };
    }

    public ProcessPerformanceSnapshot TrimWorkingSet()
    {
        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();

        if (OperatingSystem.IsWindows())
        {
            using var proc = System.Diagnostics.Process.GetCurrentProcess();
            _ = SetProcessWorkingSetSize(proc.Handle, -1, -1);
        }

        return CaptureSnapshot();
    }

    public void TrimWorkingSetOnly()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, blocking: false, compacting: false);
        if (OperatingSystem.IsWindows())
        {
            using var proc = System.Diagnostics.Process.GetCurrentProcess();
            _ = SetProcessWorkingSetSize(proc.Handle, -1, -1);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessWorkingSetSize(nint hProcess, nint dwMinimumWorkingSetSize, nint dwMaximumWorkingSetSize);
}
