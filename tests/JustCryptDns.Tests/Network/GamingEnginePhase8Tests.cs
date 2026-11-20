using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Network.Gaming;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class GamingEnginePhase8Tests
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

    private sealed class SimulatedBenchmarkUpstream : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

        public Dictionary<string, int> QueryCountsByResolver { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            lock (QueryCountsByResolver)
            {
                QueryCountsByResolver.TryGetValue(resolver.Id, out var c);
                QueryCountsByResolver[resolver.Id] = c + 1;
            }

            // Simulate different latency & reliability profiles per resolver ID
            (bool succeed, double latency, string? err) = resolver.Id switch
            {
                "cloudflare-doh" => (true, 9.5, (string?)null),
                "quad9-doh" => (true, 16.0, (string?)null),
                "google-doh" => (true, 12.0, (string?)null),
                _ => (true, 24.0, (string?)null),
            };

            var bytes = succeed ? DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError) : [];
            return Task.FromResult(new DnsQueryResult(succeed, bytes, latency, resolver.Id, Protocol, err));
        }
    }

    private sealed class ControllableDnsEngine : IDnsEngine
    {
        public string ActiveId { get; private set; } = BuiltInResolvers.DefaultResolverId;

        public event EventHandler<DnsEngineRuntimeStats>? StateChanged;

        public DnsEngineRuntimeStats GetStats() => new()
        {
            State = DnsEngineState.Running,
            ActiveResolverId = ActiveId,
            ActiveResolverName = ActiveId,
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        };

        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<(bool, string?)>((true, null));

        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default)
        {
            ActiveId = resolverId;
            return Task.FromResult<(bool, string?)>((true, null));
        }

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 10.0, ActiveId, DnsProtocol.DnsOverHttps));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 10.0, "OK"));

        public Task<IReadOnlyList<System.Net.IPAddress>> ResolveHostAsync(
            string host,
            bool includeIpv6 = false,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<System.Net.IPAddress>>([System.Net.IPAddress.Loopback]);

        public void RaiseDegraded(string currentResolverId)
        {
            StateChanged?.Invoke(this, new DnsEngineRuntimeStats
            {
                State = DnsEngineState.Degraded,
                ActiveResolverId = currentResolverId,
                ActiveResolverName = currentResolverId,
                ActiveProtocol = DnsProtocol.DnsOverHttps,
                ListenEndpoint = "127.0.0.1:53",
                LastError = "Simulated resolver timeout",
            });
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static (GamingEngineService Gaming, ResolverLibraryService Resolvers, DnsRoutingService Routing, DnsCacheService Cache, ControllableDnsEngine Engine, SimulatedBenchmarkUpstream Upstream) CreateGamingStack()
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var upstream = new SimulatedBenchmarkUpstream();
        var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance, [upstream]);
        var routing = new DnsRoutingService(settings, NullLogger<DnsRoutingService>.Instance, resolvers);
        var cache = new DnsCacheService(settings);
        var engine = new ControllableDnsEngine();
        var gaming = new GamingEngineService(
            settings,
            resolvers,
            routing,
            cache,
            engine,
            NullLogger<GamingEngineService>.Instance,
            [upstream]);
        return (gaming, resolvers, routing, cache, engine, upstream);
    }

    [Fact]
    public void BuiltInGamingProfiles_IncludeAllRequiredPlatforms()
    {
        var names = BuiltInGamingProfiles.All.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] required =
        [
            "Steam",
            "Riot Games",
            "Epic Games",
            "EA Games",
            "Ubisoft Connect",
            "Battle.net",
            "General Gaming",
            "Custom",
        ];

        foreach (var name in required)
        {
            Assert.Contains(name, names);
        }
    }

    [Fact]
    public async Task RunBenchmarkAsync_UsesRepeatedMultiDomainTestsAndComputesMetrics()
    {
        var (gaming, _, _, _, _, upstream) = CreateGamingStack();
        using (gaming)
        {
            var results = await gaming.RunBenchmarkAsync(roundsPerDomain: 2);
            Assert.NotEmpty(results);

            // Every tested resolver must be queried across multiple domains * 2 rounds (>= 6 queries, never 1 response)
            foreach (var r in results)
            {
                Assert.True(r.TotalQueries >= 6, $"Expected >= 6 queries for {r.ResolverId}, got {r.TotalQueries}");
                Assert.Equal(r.TotalQueries, upstream.QueryCountsByResolver[r.ResolverId]);
                Assert.Equal(100.0, r.SuccessRatePercent);
                Assert.Equal(0.0, r.TimeoutRatePercent);
                Assert.True(r.ReliabilityScore > 90.0);
            }

            Assert.Equal("cloudflare-doh", results[0].ResolverId);
        }
    }

    [Fact]
    public void SelectBestBenchmarkResult_DifferentiatesLowestLatencyBalancedAndMaxReliability()
    {
        var (gaming, _, _, _, _, _) = CreateGamingStack();
        using (gaming)
        {
            ResolverBenchmarkResult[] sample =
            [
                // Fast but 15% timeout rate (85% success)
                new ResolverBenchmarkResult
                {
                    ResolverId = "fast-flaky",
                    ResolverName = "Fast Flaky",
                    Provider = "Test",
                    Protocol = DnsProtocol.DnsOverHttps,
                    TotalQueries = 20,
                    SuccessfulQueries = 17,
                    TimeoutQueries = 3,
                    AverageLatencyMs = 8.0,
                    MinLatencyMs = 6.0,
                    MaxLatencyMs = 15.0,
                    P95LatencyMs = 12.0,
                    JitterMs = 2.0,
                    SuccessRatePercent = 85.0,
                    TimeoutRatePercent = 15.0,
                    ReliabilityScore = 82.0,
                    MeasuredAt = DateTimeOffset.UtcNow,
                },
                // Slightly higher latency (14 ms) but 100% reliable, 0% timeout
                new ResolverBenchmarkResult
                {
                    ResolverId = "rock-solid",
                    ResolverName = "Rock Solid",
                    Provider = "Test",
                    Protocol = DnsProtocol.DnsOverHttps,
                    TotalQueries = 20,
                    SuccessfulQueries = 20,
                    TimeoutQueries = 0,
                    AverageLatencyMs = 14.0,
                    MinLatencyMs = 12.0,
                    MaxLatencyMs = 17.0,
                    P95LatencyMs = 16.0,
                    JitterMs = 1.1,
                    SuccessRatePercent = 100.0,
                    TimeoutRatePercent = 0.0,
                    ReliabilityScore = 98.5,
                    MeasuredAt = DateTimeOffset.UtcNow,
                },
            ];

            var lowest = gaming.SelectBestBenchmarkResult(sample, GamingSelectionProfile.LowestLatency);
            var balanced = gaming.SelectBestBenchmarkResult(sample, GamingSelectionProfile.Balanced);
            var maxRel = gaming.SelectBestBenchmarkResult(sample, GamingSelectionProfile.MaximumReliability);

            Assert.Equal("fast-flaky", lowest!.ResolverId);
            Assert.Equal("rock-solid", balanced!.ResolverId);
            Assert.Equal("rock-solid", maxRel!.ResolverId);
        }
    }

    [Fact]
    public async Task GamingMode_ActivatesRoutingPinsResolverKeepsCacheAndRecoversOnFailure()
    {
        var (gaming, resolvers, routing, cache, engine, _) = CreateGamingStack();
        using (gaming)
        {
            await cache.SetEnabledAsync(false);
            await gaming.SetActiveGamingProfileAsync("gaming-riot");
            await gaming.SetManualOverrideResolverAsync("google-doh");

            var (ok, err) = await gaming.SetGamingModeAsync(true);
            Assert.True(ok, err);
            Assert.True(gaming.IsGamingModeEnabled);
            Assert.True(gaming.IsSessionPinned);
            Assert.True(cache.IsEnabled);
            Assert.Equal("google-doh", engine.ActiveId);

            // Riot Games domain should route to google-doh
            var riotDecision = routing.ResolveForDomain("auth.riotgames.com");
            Assert.False(riotDecision.IsFallback);
            Assert.Equal("google-doh", riotDecision.ResolverId);

            // Simulate degraded active resolver during session -> automatically recovers to secondary resolver (quad9-doh)
            await resolvers.SetSecondaryResolverAsync("quad9-doh");
            engine.RaiseDegraded("google-doh");
            Assert.Equal("quad9-doh", engine.ActiveId);
        }
    }

    [Fact]
    public async Task RunBenchmarkAsync_WithDetailedProgress_StreamsStagesAndSupportsCancellation()
    {
        var (gaming, _, _, _, _, _) = CreateGamingStack();
        using (gaming)
        {
            var events = new List<GamingBenchmarkProgress>();
            var progress = new SyncGamingProgress(events);

            var results = await gaming.RunBenchmarkAsync(roundsPerDomain: 2, detailedProgress: progress);
            Assert.NotEmpty(results);
            Assert.Contains(events, e => e.Stage == GamingBenchmarkProgressStage.ResolverStarted);
            Assert.Contains(events, e => e.Stage == GamingBenchmarkProgressStage.DomainProbed);
            Assert.Contains(events, e => e.Stage == GamingBenchmarkProgressStage.ResolverCompleted);

            var cancelEvents = new List<GamingBenchmarkProgress>();
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var cancelledResults = await gaming.RunBenchmarkAsync(
                roundsPerDomain: 2,
                detailedProgress: new SyncGamingProgress(cancelEvents),
                cancellationToken: cts.Token);
            Assert.Empty(cancelledResults);
            Assert.Contains(cancelEvents, e => e.Stage == GamingBenchmarkProgressStage.Cancelled);
        }
    }

    private sealed class SyncGamingProgress(List<GamingBenchmarkProgress> target) : IProgress<GamingBenchmarkProgress>
    {
        public void Report(GamingBenchmarkProgress value)
        {
            lock (target)
            {
                target.Add(value);
            }
        }
    }
}
