using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Infrastructure;

public sealed class PerformanceOptimizationPhase11Tests
{
    private sealed class MemorySettingsStore : ISettingsStore
    {
        private AppSettings _current = new();

        public SettingsLoadResult Load() => new(_current.Clone().Normalize(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            _current = settings.Clone().Normalize();
            return Task.CompletedTask;
        }
    }

    [Fact]
    public void MonitoringMode_MapsToExpectedBoundedBufferLimits()
    {
        var perf = new PerformanceSettings();
        perf.MonitoringMode = MonitoringMode.PowerSaving;
        Assert.Equal(100, perf.GetMonitorBufferLimit());

        perf.MonitoringMode = MonitoringMode.Balanced;
        Assert.Equal(300, perf.GetMonitorBufferLimit());

        perf.MonitoringMode = MonitoringMode.Performance;
        Assert.Equal(500, perf.GetMonitorBufferLimit());
    }

    [Fact]
    public void ProcessPerformanceService_CapturesRealMetricsAndTrimsWorkingSet()
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var svc = new ProcessPerformanceService(settings);

        var snap = svc.CaptureSnapshot();
        Assert.True(snap.WorkingSetMb > 0);
        Assert.True(snap.PrivateMemoryMb > 0);
        Assert.True(snap.ManagedHeapMb > 0);
        Assert.True(snap.ThreadCount > 0);
        Assert.Equal(MonitoringMode.Balanced, snap.ActiveMonitoringMode);

        var trimmed = svc.TrimWorkingSet();
        Assert.True(trimmed.WorkingSetMb > 0);
    }
}
