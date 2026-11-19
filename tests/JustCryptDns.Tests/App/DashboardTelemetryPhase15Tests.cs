using System.Net;
using JustCryptDns.App.Controls;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Network.Monitoring;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.App;

public sealed class DashboardTelemetryPhase15Tests
{
    private sealed class StubNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot() => new([], null, LocalConnectivity.Offline, DateTimeOffset.UtcNow);
    }

    private sealed class StubNavigationService : INavigationService
    {
        public event EventHandler<string>? NavigationRequested
        {
            add { }
            remove { }
        }

        public void Navigate(string pageKey)
        {
        }
    }

    private sealed class StubDnsEngine : IDnsEngine
    {
        public event EventHandler<DnsEngineRuntimeStats>? StateChanged
        {
            add { }
            remove { }
        }

        public DnsEngineRuntimeStats GetStats() => new()
        {
            State = DnsEngineState.Stopped,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        };

        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 15.0, "cloudflare-doh", DnsProtocol.DnsOverHttps));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 15.0, "OK"));

        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeTelemetryService : INetworkTelemetryService
    {
        private readonly List<NetworkTelemetrySample> _samples = [];

        public event EventHandler<NetworkTelemetrySample>? SampleReceived;

        public bool IsActive { get; private set; }

        public int ResumeCalls { get; private set; }

        public int PauseCalls { get; private set; }

        public string? LastAdapterId { get; private set; }

        public string? LastPingHost { get; private set; }

        public void ConfigureTargets(string? primaryAdapterId, string? preferredPingHost)
        {
            LastAdapterId = primaryAdapterId;
            LastPingHost = preferredPingHost;
        }

        public void Resume()
        {
            IsActive = true;
            ResumeCalls++;
        }

        public void Pause()
        {
            IsActive = false;
            PauseCalls++;
        }

        public void Emit(NetworkTelemetrySample sample)
        {
            _samples.Add(sample);
            SampleReceived?.Invoke(this, sample);
        }

        public IReadOnlyList<NetworkTelemetrySample> GetRecentSamples() => _samples.ToList();

        public void Dispose() => Pause();
    }

    [Theory]
    [InlineData(0, 100, 100)]
    [InlineData(50, 100, 100)]
    [InlineData(100, 100, 250)]
    [InlineData(450, 100, 1000)]
    [InlineData(12000, 100, 25000)]
    public void GaugeMath_AutoScaleMax_ScalesCleanlyAcrossQueryVolumes(double currentValue, double baseCeiling, double expected)
    {
        Assert.Equal(expected, GaugeMath.ComputeAutoScaleMax(currentValue, baseCeiling));
    }

    [Theory]
    [InlineData(50, "50")]
    [InlineData(1000, "1k")]
    [InlineData(2500, "2.5k")]
    [InlineData(1000000, "1M")]
    public void GaugeMath_FormatCompactScaleLabel_FormatsThresholds(double value, string expected)
    {
        Assert.Equal(expected, GaugeMath.FormatCompactScaleLabel(value));
    }

    [Fact]
    public void GaugeMath_StepNeedle_ConvergesMonotonicallyAndClampsDt()
    {
        var current = 0.0;
        for (var i = 0; i < 60; i++)
        {
            var next = GaugeMath.StepNeedle(current, 0.8, 0.033);
            Assert.True(next >= current);
            Assert.InRange(next, 0.0, 0.8);
            current = next;
        }

        Assert.True(current > 0.78);

        var clampedBigDt = GaugeMath.StepNeedle(0.0, 1.0, 50.0);
        Assert.InRange(clampedBigDt, 0.5, 1.0);
    }

    [Fact]
    public void GaugeMath_LiveIdleJitter_ZeroWhenInactive_BoundedWhenActive()
    {
        Assert.Equal(0.0, GaugeMath.ComputeLiveIdleJitter(1.23, 0.4, isActive: false, phaseOffset: 0.5, pulseBoost: 0.02));

        for (var i = 0; i < 20; i++)
        {
            var norm = 0.02 + (i * 0.045);
            var delta = GaugeMath.ComputeLiveIdleJitter(i * 0.37, norm, isActive: true, phaseOffset: 1.1, pulseBoost: 0.02);
            Assert.InRange(norm + delta, 0.0, 1.0);
        }
    }

    [Fact]
    public void GaugeMath_EvaluatesSeverityLevelsForLatencyAndCacheHit()
    {
        Assert.Equal(GaugeSeverity.Neutral, GaugeMath.EvaluateLatencySeverity(null));
        Assert.Equal(GaugeSeverity.Good, GaugeMath.EvaluateLatencySeverity(18.5));
        Assert.Equal(GaugeSeverity.Warning, GaugeMath.EvaluateLatencySeverity(75.0));
        Assert.Equal(GaugeSeverity.Danger, GaugeMath.EvaluateLatencySeverity(145.0));

        Assert.Equal(GaugeSeverity.Neutral, GaugeMath.EvaluateCacheHitSeverity(95.0, 0));
        Assert.Equal(GaugeSeverity.Good, GaugeMath.EvaluateCacheHitSeverity(72.0, 20));
        Assert.Equal(GaugeSeverity.Neutral, GaugeMath.EvaluateCacheHitSeverity(45.0, 20));
        Assert.Equal(GaugeSeverity.Warning, GaugeMath.EvaluateCacheHitSeverity(12.0, 20));
    }

    [Fact]
    public void GaugeMath_WaveCeilings_ScaleAboveMaxSampleWithHeadroom()
    {
        Assert.Equal(50.0, GaugeMath.ComputePingWaveCeiling([]));
        Assert.Equal(50.0, GaugeMath.ComputePingWaveCeiling([18.0, 32.0]));
        Assert.Equal(150.0, GaugeMath.ComputePingWaveCeiling([22.0, 110.0]));

        Assert.Equal(1.0, GaugeMath.ComputeSpeedWaveCeiling([]));
        Assert.Equal(1.0, GaugeMath.ComputeSpeedWaveCeiling([0.4, 0.8]));
        Assert.Equal(25.0, GaugeMath.ComputeSpeedWaveCeiling([4.2, 18.0]));
    }

    [Fact]
    public void NetworkTelemetryService_CalculateRates_ComputesBpsAndSuppressesResetOrPauseSpikes()
    {
        var (down, up) = NetworkTelemetryService.CalculateRates(1_000, 500, 126_000, 25_500, 1.0);
        Assert.Equal(125_000.0, down);
        Assert.Equal(25_000.0, up);

        // Counter wrap/reset should clamp negative deltas cleanly to 0.
        var (resetDown, resetUp) = NetworkTelemetryService.CalculateRates(50_000, 40_000, 1_200, 800, 1.0);
        Assert.Equal(0.0, resetDown);
        Assert.Equal(0.0, resetUp);

        // Resuming after long pause (> 10s elapsed) must discard accumulated bytes to avoid fake spikes.
        var (resumeDown, resumeUp) = NetworkTelemetryService.CalculateRates(1_000, 500, 50_000_000, 10_000_000, 35.0);
        Assert.Equal(0.0, resumeDown);
        Assert.Equal(0.0, resumeUp);
    }

    [Theory]
    [InlineData(0, "0 Kbps")]
    [InlineData(50_000, "400 Kbps")]
    [InlineData(1_500_000, "12 Mbps")]
    [InlineData(250_000_000, "2 Gbps")]
    public void NetworkTelemetryService_FormatThroughput_FormatsCorrectly(double bytesPerSec, string expected)
    {
        Assert.Equal(expected, NetworkTelemetryService.FormatThroughput(bytesPerSec));
    }

    [Fact]
    public void NetworkTelemetryService_ResolvePingTarget_PrefersNonLoopbackIp()
    {
        Assert.Equal("8.8.8.8", NetworkTelemetryService.ResolvePingTarget("8.8.8.8"));
        Assert.Equal("1.1.1.1", NetworkTelemetryService.ResolvePingTarget("127.0.0.1"));
        Assert.Equal("1.1.1.1", NetworkTelemetryService.ResolvePingTarget("not-an-ip"));
        Assert.Equal("1.1.1.1", NetworkTelemetryService.ResolvePingTarget(null));
    }

    [Fact]
    public void NetworkTelemetryService_Lifecycle_ResumePauseAndDisposeToggleIsActive()
    {
        using var service = new NetworkTelemetryService(NullLogger<NetworkTelemetryService>.Instance);
        Assert.False(service.IsActive);

        service.Resume();
        Assert.True(service.IsActive);

        // Duplicate resume is idempotent.
        service.Resume();
        Assert.True(service.IsActive);

        service.Pause();
        Assert.False(service.IsActive);

        service.Dispose();
        service.Resume();
        Assert.False(service.IsActive);
    }

    [Fact]
    public void HoverDelayPolicy_ValidatesThreeSecondDefaultAndVisibilityRules()
    {
        Assert.Equal(3.0, HoverDelayPolicy.DefaultDelaySeconds);
        Assert.Equal(0.5, HoverDelayPolicy.ClampDelaySeconds(0.1));
        Assert.Equal(30.0, HoverDelayPolicy.ClampDelaySeconds(60.0));
        Assert.Equal(3.0, HoverDelayPolicy.ClampDelaySeconds(double.NaN));

        Assert.True(HoverDelayPolicy.ShouldTrigger(isMouseOver: true, isElementVisible: true, isHostVisible: true, isHostMinimized: false));
        Assert.False(HoverDelayPolicy.ShouldTrigger(isMouseOver: true, isElementVisible: true, isHostVisible: true, isHostMinimized: true));
        Assert.False(HoverDelayPolicy.ShouldTrigger(isMouseOver: true, isElementVisible: true, isHostVisible: false, isHostMinimized: false));
        Assert.False(HoverDelayPolicy.ShouldTrigger(isMouseOver: false, isElementVisible: true, isHostVisible: true, isHostMinimized: false));
    }

    [Fact]
    public void DashboardViewModel_UpdatesGaugeMetricsAndPausesOrResumesTelemetry()
    {
        using var telemetry = new FakeTelemetryService();
        using var vm = new DashboardViewModel(
            new StubNetworkInfoService(),
            new StubDnsEngine(),
            new StubNavigationService(),
            NullLogger<DashboardViewModel>.Instance,
            telemetry: telemetry);

        vm.ApplyEngineStats(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Running,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
            LastLatencyMs = 24.5,
            TotalQueries = 420,
            BlockedQueries = 75,
            CacheHitRatioPercent = 68.4,
        });

        Assert.Equal(24.5, vm.LatencyMsValue);
        Assert.Equal(200.0, vm.LatencyMaxScale);
        Assert.Equal("200ms", vm.LatencyScaleLabel);
        Assert.Equal(GaugeSeverity.Good, vm.LatencySeverity);

        Assert.Equal(420.0, vm.TotalQueriesValue);
        Assert.Equal(1000.0, vm.TotalQueriesMaxScale);
        Assert.Equal("1k", vm.TotalQueriesScaleLabel);

        Assert.Equal(75.0, vm.BlockedQueriesValue);
        Assert.Equal(100.0, vm.BlockedQueriesMaxScale);
        Assert.Equal("100", vm.BlockedQueriesScaleLabel);

        Assert.Equal(68.4, vm.CacheHitPercentValue);
        Assert.Equal(GaugeSeverity.Good, vm.CacheHitSeverity);

        vm.SetLiveTelemetryActive(true);
        Assert.True(telemetry.IsActive);
        Assert.False(vm.IsTelemetryPaused);

        vm.ApplyTelemetrySample(new NetworkTelemetrySample(DateTimeOffset.UtcNow, 19.0, 2_500_000, 625_000));
        Assert.Equal("19 ms", vm.PingDisplay);
        Assert.Equal("20 Mbps", vm.DownloadSpeedDisplay);
        Assert.Equal("5 Mbps", vm.UploadSpeedDisplay);

        vm.SetLiveTelemetryActive(false);
        Assert.False(telemetry.IsActive);
        Assert.True(vm.IsTelemetryPaused);
        Assert.True(telemetry.PauseCalls >= 1);
    }

    [Fact]
    public void GaugeMath_IgnitionSweep_ClimbsToPeakAndReturnsToTarget()
    {
        var (atZero, doneZero) = GaugeMath.ComputeIgnitionSweepValue(0.0, startNormalized: 0.1, targetNormalized: 0.35);
        Assert.Equal(0.1, atZero, 3);
        Assert.False(doneZero);

        var (atPeak, donePeak) = GaugeMath.ComputeIgnitionSweepValue(0.48, startNormalized: 0.1, targetNormalized: 0.35);
        Assert.InRange(atPeak, 0.99, 1.0);
        Assert.False(donePeak);

        var (midReturn, doneMid) = GaugeMath.ComputeIgnitionSweepValue(0.85, startNormalized: 0.1, targetNormalized: 0.35);
        Assert.InRange(midReturn, 0.35, 1.0);
        Assert.False(doneMid);

        var (atEnd, doneEnd) = GaugeMath.ComputeIgnitionSweepValue(GaugeMath.IgnitionSweepDurationSeconds, startNormalized: 0.1, targetNormalized: 0.35);
        Assert.Equal(0.35, atEnd, 4);
        Assert.True(doneEnd);
    }

    [Fact]
    public void StatusPulseMath_EvaluatesAllStylesAndBounds()
    {
        for (var i = 0; i < 6; i++)
        {
            var off = StatusPulseMath.Evaluate(StatusPulseStyle.Off, i * 0.31);
            Assert.Equal(0.0, off.Intensity);
            Assert.Equal(0.0, off.HaloOpacity);
            Assert.Equal(1.0, off.HaloScale);
            Assert.Equal(1.0, off.SurfaceOpacity);
        }

        foreach (var style in new[] { StatusPulseStyle.Breathing, StatusPulseStyle.GlowHalo, StatusPulseStyle.Heartbeat, StatusPulseStyle.Beacon })
        {
            var intensities = new HashSet<double>();
            for (var i = 0; i < 8; i++)
            {
                var frame = StatusPulseMath.Evaluate(style, i * 0.23);
                Assert.InRange(frame.Intensity, 0.0, 1.0);
                Assert.InRange(frame.HaloOpacity, 0.0, 1.0);
                Assert.True(frame.HaloScale >= 1.0);
                Assert.InRange(frame.SurfaceOpacity, 0.0, 1.0);
                intensities.Add(Math.Round(frame.Intensity, 4));
            }

            Assert.True(intensities.Count > 1, $"Expected animated intensity variation for {style}");
        }

        var nanSafe = StatusPulseMath.Evaluate(StatusPulseStyle.Breathing, double.NaN);
        Assert.InRange(nanSafe.HaloOpacity, 0.0, 1.0);
    }

    [Fact]
    public void DashboardViewModel_ProtectionStatusLocKey_ReflectsDnsAndBypassStates()
    {
        using var vm = new DashboardViewModel(
            new StubNetworkInfoService(),
            new StubDnsEngine(),
            new StubNavigationService(),
            NullLogger<DashboardViewModel>.Instance);

        vm.ApplyEngineStats(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Stopped,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        });
        vm.ApplyBypassStats(new BypassRuntimeStats { State = BypassEngineState.Stopped });
        Assert.Equal("Dash_Status_Stopped", vm.ProtectionStatusLocKey);

        vm.ApplyEngineStats(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Running,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        });
        Assert.Equal("Dash_Status_RunningBypassOff", vm.ProtectionStatusLocKey);

        vm.ApplyBypassStats(new BypassRuntimeStats { State = BypassEngineState.Running });
        Assert.Equal("Dash_Status_RunningBypassOn", vm.ProtectionStatusLocKey);

        vm.ApplyEngineStats(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Degraded,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        });
        Assert.Equal("Dash_Status_DegradedBypassOn", vm.ProtectionStatusLocKey);

        vm.ApplyBypassStats(new BypassRuntimeStats { State = BypassEngineState.Stopped });
        Assert.Equal("Dash_Status_DegradedBypassOff", vm.ProtectionStatusLocKey);
    }
}
