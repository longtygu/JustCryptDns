using System.Buffers.Binary;
using System.Net;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Network.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class DiagnosticsAndMonitorPhase10Tests
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

    private sealed class FakeNetworkInfo(params IPAddress[] dnsServers) : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot()
        {
            var adapter = new NetworkAdapterInfo
            {
                Id = "eth0",
                Name = "Ethernet",
                Description = "Intel Ethernet",
                Kind = AdapterKind.Ethernet,
                Status = System.Net.NetworkInformation.OperationalStatus.Up,
                SpeedBitsPerSecond = 1_000_000_000,
                IPv4Addresses = [IPAddress.Parse("192.168.1.50")],
                IPv6Addresses = [],
                Gateways = [IPAddress.Parse("192.168.1.1")],
                DnsServers = dnsServers.ToList(),
            };
            return new NetworkSnapshot([adapter], adapter, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
        }
    }

    private sealed class FakeDiagnosticUpstream(DnsProtocol protocol, double latencyMs = 11.5) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => protocol;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            var baseResp = DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError);
            // Set AD (Authentic Data) bit 0x0020 and ANCOUNT = 1
            var flags = BinaryPrimitives.ReadUInt16BigEndian(baseResp.AsSpan(2, 2));
            BinaryPrimitives.WriteUInt16BigEndian(baseResp.AsSpan(2, 2), (ushort)(flags | 0x0020));
            BinaryPrimitives.WriteUInt16BigEndian(baseResp.AsSpan(6, 2), 1);

            using var ms = new MemoryStream();
            ms.Write(baseResp);
            Span<byte> rr = stackalloc byte[16];
            rr[0] = 0xC0;
            rr[1] = 0x0C;
            BinaryPrimitives.WriteUInt16BigEndian(rr[2..4], (ushort)DnsRecordType.A);
            BinaryPrimitives.WriteUInt16BigEndian(rr[4..6], 1);
            BinaryPrimitives.WriteUInt32BigEndian(rr[6..10], 300);
            BinaryPrimitives.WriteUInt16BigEndian(rr[10..12], 4);
            IPAddress.Parse("1.1.1.1").GetAddressBytes().CopyTo(rr[12..16]);
            ms.Write(rr);

            return Task.FromResult(new DnsQueryResult(true, ms.ToArray(), latencyMs, resolver.Id, Protocol));
        }
    }

    private static (NetworkDiagnosticsService Diagnostics, ResolverLibraryService Resolvers) CreateDiagnostics(params IPAddress[] adapterDns)
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var upstreams = new IDnsUpstreamClient[]
        {
            new FakeDiagnosticUpstream(DnsProtocol.DnsOverHttps, 10.2),
            new FakeDiagnosticUpstream(DnsProtocol.DnsOverTls, 14.8),
            new FakeDiagnosticUpstream(DnsProtocol.UdpTcp, 7.5),
            new FakeDiagnosticUpstream(DnsProtocol.DnsCrypt, 12.1),
        };
        var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance, upstreams);
        var netInfo = new FakeNetworkInfo(adapterDns);
        var diag = new NetworkDiagnosticsService(settings, resolvers, netInfo, upstreams);
        return (diag, resolvers);
    }

    [Fact]
    public async Task LookupDnssecCompareAndPropagation_ReturnStructuredResultsAndRecordMonitor()
    {
        var (diag, resolvers) = CreateDiagnostics(IPAddress.Loopback);
        using (diag)
        using (resolvers)
        {
            var lookup = await diag.LookupAsync("cloudflare.com", "A");
            Assert.True(lookup.Success);
            Assert.Equal("NoError", lookup.ResponseCode);
            Assert.True(lookup.AuthenticDataBit);
            Assert.Single(lookup.Records);
            Assert.Equal("1.1.1.1", lookup.Records[0].Value);

            var dnssec = await diag.TestDnssecAsync();
            Assert.True(dnssec.SignedDomainVerified);

            var (dohOk, _, _) = await diag.TestDohConnectivityAsync();
            Assert.True(dohOk);

            var (cryptOk, _, _) = await diag.TestDnsCryptConnectivityAsync();
            Assert.True(cryptOk);

            var comparison = await diag.CompareResolversAsync("example.com", "A");
            Assert.NotEmpty(comparison);
            Assert.All(comparison, c => Assert.True(c.Success));

            var propagation = await diag.CheckPropagationAsync("example.com", "A");
            Assert.True(propagation.Count >= 6);
            Assert.All(propagation, p => Assert.Equal("1.1.1.1", p.PrimaryAnswerSummary));

            Assert.NotEmpty(diag.GetMonitorEntries());
        }
    }

    [Fact]
    public async Task DnsLeakTest_DistinguishesLoopbackProxyFromExternalAdapterDns()
    {
        var (cleanDiag, cleanRes) = CreateDiagnostics(IPAddress.Loopback);
        using (cleanDiag)
        using (cleanRes)
        {
            var cleanReport = await cleanDiag.RunDnsLeakTestAsync();
            Assert.False(cleanReport.IsLeakDetected);
            Assert.True(cleanReport.IsAdapterUsingLocalProxy);
        }

        var (leakDiag, leakRes) = CreateDiagnostics(IPAddress.Parse("192.168.1.1"));
        using (leakDiag)
        using (leakRes)
        {
            var leakReport = await leakDiag.RunDnsLeakTestAsync();
            Assert.True(leakReport.IsLeakDetected);
            Assert.False(leakReport.IsAdapterUsingLocalProxy);
        }
    }

    [Fact]
    public void LiveMonitor_RespectsPauseAndBoundedCapacity()
    {
        var (diag, res) = CreateDiagnostics(IPAddress.Loopback);
        using (diag)
        using (res)
        {
            for (var i = 0; i < NetworkDiagnosticsService.MaxMonitorEntries + 25; i++)
            {
                diag.RecordMonitorEntry(new LiveQueryMonitorEntry
                {
                    Timestamp = DateTimeOffset.Now,
                    Domain = $"host{i}.example.com",
                    RecordType = "A",
                    Outcome = "Allowed",
                    ResolverName = "Cloudflare (DoH)",
                    Protocol = DnsProtocol.DnsOverHttps,
                    LatencyMs = 10.0,
                });
            }

            Assert.Equal(NetworkDiagnosticsService.MaxMonitorEntries, diag.GetMonitorEntries().Count);

            diag.ClearMonitorEntries();
            Assert.Empty(diag.GetMonitorEntries());

            diag.IsMonitorPaused = true;
            diag.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = DateTimeOffset.Now,
                Domain = "ignored-while-paused.example.com",
                RecordType = "A",
                Outcome = "Allowed",
                ResolverName = "Cloudflare (DoH)",
                Protocol = DnsProtocol.DnsOverHttps,
                LatencyMs = 10.0,
            });
            Assert.Empty(diag.GetMonitorEntries());
        }
    }
}
