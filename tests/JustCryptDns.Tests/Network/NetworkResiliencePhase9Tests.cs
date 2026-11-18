using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Network.Failover;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class NetworkResiliencePhase9Tests
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

    private sealed class ConfigurableUpstreamClient(DnsProtocol protocol, Func<DnsResolverEndpoint, DnsQueryResult> handler) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => protocol;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(handler(resolver));
    }

    private static (DnsFailoverService Failover, ResolverLibraryService Resolvers, SettingsService Settings) CreateFailover(
        IEnumerable<IDnsUpstreamClient>? upstreams = null)
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance, upstreams);
        var failover = new DnsFailoverService(settings, resolvers, NullLogger<DnsFailoverService>.Instance, null, upstreams);
        return (failover, resolvers, settings);
    }

    [Fact]
    public async Task GetFailoverChain_RespectsEncryptedOnlyPrimarySecondaryAndPlainFallbackPolicies()
    {
        var (failover, resolvers, settings) = CreateFailover();
        using (failover)
        using (resolvers)
        {
            var start = resolvers.GetPrimaryResolver();

            // 1. EncryptedOnly -> no UdpTcp resolvers
            await settings.UpdateAsync(s => s.Resilience.Policy = FailoverPolicy.EncryptedOnly);
            var encChain = failover.GetFailoverChain(start);
            Assert.All(encChain, r => Assert.True(r.IsEncrypted));

            // 2. PrimaryAndSecondaryOnly -> only 2 resolvers
            await settings.UpdateAsync(s => s.Resilience.Policy = FailoverPolicy.PrimaryAndSecondaryOnly);
            var pairChain = failover.GetFailoverChain(start);
            Assert.Equal(2, pairChain.Count);

            // 3. EncryptedThenPlainFallback -> includes UdpTcp at the end
            await settings.UpdateAsync(s => s.Resilience.Policy = FailoverPolicy.EncryptedThenPlainFallback);
            var fullChain = failover.GetFailoverChain(start);
            Assert.Contains(fullChain, r => r.Protocol == DnsProtocol.UdpTcp);
        }
    }

    [Fact]
    public void ClassifyFailure_MapsProtocolsAndTimeoutsToDiagnosticCategories()
    {
        var (failover, resolvers, _) = CreateFailover();
        using (failover)
        using (resolvers)
        {
            var doh = resolvers.GetByIdOrDefault("cloudflare-doh");
            var dot = resolvers.GetByIdOrDefault("cloudflare-dot");
            var crypt = resolvers.GetByIdOrDefault("quad9-dnscrypt");
            var udp = resolvers.GetByIdOrDefault("cloudflare-udp");

            Assert.Equal(DnsFailureCategory.ResolverTimeout, failover.ClassifyFailure(doh, "Operation timed out"));
            Assert.Equal(DnsFailureCategory.DohEndpointFailure, failover.ClassifyFailure(doh, "HTTP 502 Bad Gateway"));
            Assert.Equal(DnsFailureCategory.DotTlsHandshakeFailure, failover.ClassifyFailure(dot, "TLS authentication failed"));
            Assert.Equal(DnsFailureCategory.DnsCryptHandshakeFailure, failover.ClassifyFailure(crypt, "Certificate magic mismatch"));
            Assert.Equal(DnsFailureCategory.Udp53BlockedOrUnreachable, failover.ClassifyFailure(udp, "Socket unreachable"));
            Assert.Equal(DnsFailureCategory.Tcp53BlockedOrUnreachable, failover.ClassifyFailure(udp, "TCP connection reset"));
        }
    }

    [Fact]
    public async Task QueryWithResilienceAsync_RetriesAndFailsOverToSecondaryWhenPrimaryIsDown()
    {
        var (failover, resolvers, settings) = CreateFailover();
        using (failover)
        using (resolvers)
        {
            await settings.UpdateAsync(s =>
            {
                s.Resilience.MaxRetriesPerQuery = 1;
                s.Resilience.RetryDelayMs = 0;
                s.Resilience.FailureThresholdBeforeSwitch = 2;
            });

            var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
            var validResp = DnsPacket.CreateErrorResponse(query, DnsResponseCode.NoError);
            var primary = resolvers.GetPrimaryResolver(); // cloudflare-doh
            var attemptsByResolver = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            var result = await failover.QueryWithResilienceAsync(
                query,
                primary,
                (candidate, _) =>
                {
                    attemptsByResolver.TryGetValue(candidate.Id, out var c);
                    attemptsByResolver[candidate.Id] = c + 1;

                    if (candidate.Id == primary.Id)
                    {
                        return Task.FromResult(new DnsQueryResult(false, [], 50, candidate.Id, candidate.Protocol, "HTTPS endpoint unreachable"));
                    }

                    return Task.FromResult(new DnsQueryResult(true, validResp, 14.0, candidate.Id, candidate.Protocol));
                });

            Assert.True(result.Success);
            Assert.Equal("quad9-doh", result.ResolverId);
            Assert.Equal(2, attemptsByResolver[primary.Id]); // 1 initial + 1 retry
            Assert.Equal(1, attemptsByResolver["quad9-doh"]);

            var history = failover.GetFailoverHistory();
            Assert.Single(history);
            Assert.Equal(primary.Id, history[0].FailedResolverId);
            Assert.Equal("quad9-doh", history[0].ActivatedResolverId);
            Assert.Equal(DnsFailureCategory.DohEndpointFailure, history[0].FailureCategory);
        }
    }

    [Fact]
    public async Task DiagnoseNetworkRestrictionsAsync_IdentifiesBlockedProtocols()
    {
        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
        var okResp = DnsPacket.CreateErrorResponse(query, DnsResponseCode.NoError);

        var upstreams = new IDnsUpstreamClient[]
        {
            // Simulate UDP/53 blocked, DoH/443 reachable, DoT/853 blocked, DNSCrypt reachable
            new ConfigurableUpstreamClient(DnsProtocol.UdpTcp, r => new DnsQueryResult(false, [], 100, r.Id, r.Protocol, "UDP 53 blocked")),
            new ConfigurableUpstreamClient(DnsProtocol.DnsOverHttps, r => new DnsQueryResult(true, okResp, 12, r.Id, r.Protocol)),
            new ConfigurableUpstreamClient(DnsProtocol.DnsOverTls, r => new DnsQueryResult(false, [], 100, r.Id, r.Protocol, "TLS 853 blocked")),
            new ConfigurableUpstreamClient(DnsProtocol.DnsCrypt, r => new DnsQueryResult(true, okResp, 18, r.Id, r.Protocol)),
        };

        var (failover, resolvers, _) = CreateFailover(upstreams);
        using (failover)
        using (resolvers)
        {
            var report = await failover.DiagnoseNetworkRestrictionsAsync();
            Assert.False(report.Udp53Reachable);
            Assert.True(report.Doh443Reachable);
            Assert.False(report.Dot853Reachable);
            Assert.True(report.DnsCryptReachable);
            Assert.Contains(DnsFailureCategory.Udp53BlockedOrUnreachable, report.DetectedIssues);
            Assert.Contains(DnsFailureCategory.DotTlsHandshakeFailure, report.DetectedIssues);
        }
    }
}
