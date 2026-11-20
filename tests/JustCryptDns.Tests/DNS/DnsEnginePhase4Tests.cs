using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.DNS;

public sealed class DnsEnginePhase4Tests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-dns-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public DnsEnginePhase4Tests()
    {
        _paths = new AppPaths(_root);
        _paths.EnsureCreated();
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void DnsPacket_BuildsAndParsesQueryAndErrorResponse()
    {
        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.AAAA, id: 0x4242, dnssecOk: true);
        Assert.True(DnsPacket.TryParse(query, out var parsed));
        Assert.NotNull(parsed);
        Assert.Equal(0x4242, parsed!.Header.Id);
        Assert.False(parsed.Header.IsResponse);
        Assert.Equal("example.com", parsed.PrimaryQuestionName);
        Assert.Equal(DnsRecordType.AAAA, parsed.PrimaryQuestionType);
        Assert.Equal(1, parsed.Header.AdditionalCount);

        var err = DnsPacket.CreateErrorResponse(query, DnsResponseCode.ServFail);
        Assert.True(DnsPacket.TryParse(err, out var parsedErr));
        Assert.NotNull(parsedErr);
        Assert.Equal(0x4242, parsedErr!.Header.Id);
        Assert.True(parsedErr.Header.IsResponse);
        Assert.Equal(DnsResponseCode.ServFail, parsedErr.Header.ResponseCode);
        Assert.Equal("example.com", parsedErr.PrimaryQuestionName);
    }

    [Fact]
    public void DnsPacket_RejectsMaliciousCompressionPointerLoop()
    {
        // Craft a 16-byte packet whose QNAME at offset 12 jumps to offset 12 (0xC0, 0x0C).
        var loopPacket = new byte[16];
        BinaryPrimitives.WriteUInt16BigEndian(loopPacket.AsSpan(4, 2), 1); // QDCOUNT = 1
        loopPacket[12] = 0xC0;
        loopPacket[13] = 0x0C;

        Assert.False(DnsPacket.TryParse(loopPacket, out _));
    }

    [Fact]
    public void DnsLoopGuard_DetectsSelfForwarding()
    {
        var loopbackUdp = new DnsResolverEndpoint
        {
            Id = "self",
            Name = "Self",
            Provider = "Test",
            Protocol = DnsProtocol.UdpTcp,
            Endpoint = "127.0.0.1",
            PrimaryIp = "127.0.0.1",
            Port = 53,
        };
        Assert.True(DnsLoopGuard.WouldLoop(loopbackUdp, IPAddress.Loopback, 53));
        Assert.False(DnsLoopGuard.WouldLoop(loopbackUdp, IPAddress.Loopback, 5353));

        var cloudflare = BuiltInResolvers.GetByIdOrDefault("cloudflare-doh");
        Assert.False(DnsLoopGuard.WouldLoop(cloudflare, IPAddress.Loopback, 53));
    }

    [Fact]
    public async Task LocalDnsProxy_ServesUdpAndTcpAndDetectsPortConflict()
    {
        await using var proxy = new LocalDnsProxy(
            IPAddress.Loopback,
            port: 0,
            enableIpv6: false,
            (query, _) => Task.FromResult(DnsPacket.CreateErrorResponse(query.Span, DnsResponseCode.NoError)),
            NullLogger.Instance);

        proxy.Start();
        Assert.True(proxy.BoundPort > 0);

        // Port conflict detector must spot the active UDP/TCP listener on BoundPort.
        var conflict = PortConflictDetector.CheckConflict(IPAddress.Loopback, proxy.BoundPort);
        Assert.NotNull(conflict);
        Assert.True(conflict!.HasConflict);
        Assert.NotEqual(proxy.BoundPort, conflict.SuggestedPort);

        var endpoint = new IPEndPoint(IPAddress.Loopback, proxy.BoundPort);
        var queryBytes = DnsPacket.CreateQuery("test.example.com", DnsRecordType.A, id: 0x3344);

        // UDP round-trip
        var udpResult = await UdpTcpDnsUpstream.QueryEndpointAsync(
            queryBytes,
            endpoint,
            "local-test",
            DnsProtocol.UdpTcp,
            TimeSpan.FromSeconds(2));
        Assert.True(udpResult.Success);
        Assert.True(DnsPacket.TryReadTransactionId(udpResult.ResponseBytes, out var udpId));
        Assert.Equal(0x3344, udpId);

        // TCP round-trip
        var tcpBytes = await UdpTcpDnsUpstream.QueryTcpAsync(queryBytes, 0x3344, endpoint, CancellationToken.None);
        Assert.True(DnsPacket.TryReadTransactionId(tcpBytes, out var tcpId));
        Assert.Equal(0x3344, tcpId);
    }

    [Fact]
    public async Task DohDnsUpstream_ZeroesWireIdAndRestoresCallerId()
    {
        ushort observedWireId = 0xFFFF;
        using var httpClient = new HttpClient(new FakeDohHandler(wire =>
        {
            DnsPacket.TryReadTransactionId(wire, out observedWireId);
            return DnsPacket.CreateErrorResponse(wire, DnsResponseCode.NoError);
        }));
        using var doh = new DohDnsUpstream(httpClient);

        var resolver = BuiltInResolvers.GetByIdOrDefault("cloudflare-doh");
        var query = DnsPacket.CreateQuery("cloudflare.com", DnsRecordType.A, id: 0x7788);
        var result = await doh.QueryAsync(query, resolver, TimeSpan.FromSeconds(2));

        Assert.True(result.Success);
        Assert.Equal(0, observedWireId); // RFC 8484 §4.1
        Assert.True(DnsPacket.TryReadTransactionId(result.ResponseBytes, out var restoredId));
        Assert.Equal(0x7788, restoredId);
    }

    [Fact]
    public void DnsCryptProxyManager_GeneratesValidSelfContainedToml()
    {
        var resolver = BuiltInResolvers.GetByIdOrDefault("cloudflare-dnscrypt");
        var toml = DnsCryptProxyManager.BuildTomlConfig(resolver, 5354);

        Assert.Contains("listen_addresses = ['127.0.0.1:5354']", toml, StringComparison.Ordinal);
        Assert.Contains("ignore_system_dns = true", toml, StringComparison.Ordinal);
        Assert.Contains("[static.'cloudflare-dnscrypt']", toml, StringComparison.Ordinal);
        Assert.Contains("stamp = 'sdns://", toml, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WindowsNetworkDnsService_BacksUpAppliesRollsBackOnFailureAndRecovers()
    {
        var netInfo = new FakeNetworkInfoService();
        var configurator = new FakeAdapterConfigurator();
        var service = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance, configurator);

        // 1. Apply fails connectivity probe -> automatic rollback to original static DNS (9.9.9.9).
        var failedResult = await service.ApplyLocalProxyDnsAsync(
            targetAdapterId: null,
            ipv4Dns: "127.0.0.1",
            ipv6Dns: null,
            connectivityProbe: _ => Task.FromResult(false));

        Assert.False(failedResult.Success);
        Assert.True(failedResult.RolledBack);
        Assert.Equal(["9.9.9.9"], configurator.CurrentIpv4);
        Assert.False(service.HasActiveBackup());

        // 2. Apply succeeds -> backup is active and verified on disk.
        var okResult = await service.ApplyLocalProxyDnsAsync(
            targetAdapterId: null,
            ipv4Dns: "127.0.0.1",
            ipv6Dns: null,
            connectivityProbe: _ => Task.FromResult(true));

        Assert.True(okResult.Success);
        Assert.Equal(["127.0.0.1"], configurator.CurrentIpv4);
        Assert.True(service.HasActiveBackup());

        // 3. Crash recovery when proxy is not running restores original DNS (9.9.9.9).
        await service.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false);
        Assert.Equal(["9.9.9.9"], configurator.CurrentIpv4);
        Assert.False(service.HasActiveBackup());
    }

    [Fact]
    public async Task DnsEngineService_StartsResolvesThroughLocalProxySwitchesAndStops()
    {
        var freePort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var store = new MemoryStore(new AppSettings
        {
            Dns = { ListenAddress = "127.0.0.1", ListenPort = freePort, ActiveResolverId = "cloudflare-doh" },
        });
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var netInfo = new FakeNetworkInfoService();
        var winDns = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance, new FakeAdapterConfigurator());
        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);

        var fakeDoh = new FakeUpstream(DnsProtocol.DnsOverHttps);
        var fakeDot = new FakeUpstream(DnsProtocol.DnsOverTls);
        await using var engine = new DnsEngineService(
            settings,
            dnsCrypt,
            winDns,
            NullLogger<DnsEngineService>.Instance,
            [fakeDoh, fakeDot]);

        var (started, err) = await engine.StartAsync();
        Assert.True(started, err);
        Assert.Equal(DnsEngineState.Running, engine.GetStats().State);

        var probe = await engine.ProbeActiveResolverAsync();
        Assert.True(probe.Success);
        Assert.Equal(1, engine.GetStats().TotalQueries);

        var (switched, switchErr) = await engine.SwitchResolverAsync("cloudflare-dot");
        Assert.True(switched, switchErr);
        Assert.Equal(DnsProtocol.DnsOverTls, engine.GetStats().ActiveProtocol);

        await engine.StopAsync();
        Assert.Equal(DnsEngineState.Stopped, engine.GetStats().State);
    }

    [Fact]
    public async Task WindowsNetworkDnsService_KeepsActiveBackupWhenRestoreFails()
    {
        var configurator = new FakeAdapterConfigurator();
        var bootRecovery = new FakeBootRecoveryRegistrar();
        using var service = new WindowsNetworkDnsService(
            _paths,
            new FakeNetworkInfoService(),
            NullLogger<WindowsNetworkDnsService>.Instance,
            configurator,
            bootRecovery);

        var applied = await service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", null, _ => Task.FromResult(true));
        Assert.True(applied.Success);
        Assert.True(service.HasActiveBackup());
        Assert.True(bootRecovery.IsArmed);
        Assert.Equal(["127.0.0.2"], configurator.CurrentIpv4);

        configurator.FailSetDns = true;
        var failedRestore = await service.RestoreOriginalDnsAsync();
        Assert.False(failedRestore.Success);
        Assert.True(service.HasActiveBackup());
        Assert.True(bootRecovery.IsArmed);

        configurator.FailSetDns = false;
        var recovered = await service.RestoreOriginalDnsAsync();
        Assert.True(recovered.Success);
        Assert.False(service.HasActiveBackup());
        Assert.False(bootRecovery.IsArmed);
        Assert.Equal(["9.9.9.9"], configurator.CurrentIpv4);
    }

    [Fact]
    public async Task WindowsNetworkDnsService_DeadLoopbackBackupFallsBackToDhcpOnRestore()
    {
        var configurator = new FakeAdapterConfigurator
        {
            CurrentIpv4 = ["127.0.0.1"],
            IsIpv6Dhcp = false,
            CurrentIpv6 = ["::1"],
        };
        using var service = new WindowsNetworkDnsService(
            _paths,
            new FakeNetworkInfoService(),
            NullLogger<WindowsNetworkDnsService>.Instance,
            configurator,
            loopbackDnsAliveProbe: _ => false);

        var applied = await service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", null, _ => Task.FromResult(true));
        Assert.True(applied.Success);
        Assert.Equal(["127.0.0.2"], configurator.CurrentIpv4);

        var restored = await service.RestoreOriginalDnsAsync();
        Assert.True(restored.Success);
        Assert.True(configurator.UsedDhcpIpv4);
        Assert.Empty(configurator.CurrentIpv4);
        Assert.True(configurator.UsedDhcpIpv6);
        Assert.Empty(configurator.CurrentIpv6);
        Assert.False(service.HasActiveBackup());
    }

    [Fact]
    public async Task WindowsNetworkDnsService_PreservesAliveLoopbackOnRestore()
    {
        var configurator = new FakeAdapterConfigurator
        {
            CurrentIpv4 = ["127.0.0.1"],
        };
        using var service = new WindowsNetworkDnsService(
            _paths,
            new FakeNetworkInfoService(),
            NullLogger<WindowsNetworkDnsService>.Instance,
            configurator,
            loopbackDnsAliveProbe: ip => ip.Equals(IPAddress.Loopback));

        var applied = await service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", null, _ => Task.FromResult(true));
        Assert.True(applied.Success);

        var restored = await service.RestoreOriginalDnsAsync();
        Assert.True(restored.Success);
        Assert.False(configurator.UsedDhcpIpv4);
        Assert.Equal(["127.0.0.1"], configurator.CurrentIpv4);
    }

    [Fact]
    public async Task WindowsNetworkDnsService_SanitizesSelfLoopbackWhenCreatingBackup()
    {
        var configurator = new FakeAdapterConfigurator
        {
            CurrentIpv4 = ["127.0.0.2"],
        };
        using var service = new WindowsNetworkDnsService(
            _paths,
            new FakeNetworkInfoService(),
            NullLogger<WindowsNetworkDnsService>.Instance,
            configurator);

        var applied = await service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", null, _ => Task.FromResult(true));
        Assert.True(applied.Success);

        var backup = service.ReadBackup();
        Assert.NotNull(backup);
        var entry = Assert.Single(backup!.Adapters);
        Assert.True(entry.WasIpv4Dhcp);
        Assert.Empty(entry.Ipv4DnsServers);

        var restored = await service.RestoreOriginalDnsAsync();
        Assert.True(restored.Success);
        Assert.True(configurator.UsedDhcpIpv4);
        Assert.Empty(configurator.CurrentIpv4);
    }

    [Fact]
    public async Task DnsEngineService_StopAsyncRestoresOrphanedBackupEvenWhenAlreadyStopped()
    {
        var freePort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var store = new MemoryStore(new AppSettings
        {
            Dns = { ListenAddress = "127.0.0.1", ListenPort = freePort, ActiveResolverId = "cloudflare-doh" },
        });
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var configurator = new FakeAdapterConfigurator { CurrentIpv4 = ["1.1.1.1"] };
        using var winDns = new WindowsNetworkDnsService(
            _paths,
            new FakeNetworkInfoService(),
            NullLogger<WindowsNetworkDnsService>.Instance,
            configurator);

        var applied = await winDns.ApplyLocalProxyDnsAsync(null, "127.0.0.2", null, _ => Task.FromResult(true));
        Assert.True(applied.Success);
        Assert.True(winDns.HasActiveBackup());

        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);
        await using var engine = new DnsEngineService(
            settings,
            dnsCrypt,
            winDns,
            NullLogger<DnsEngineService>.Instance,
            [new FakeUpstream(DnsProtocol.DnsOverHttps)]);

        Assert.Equal(DnsEngineState.Stopped, engine.GetStats().State);
        await engine.StopAsync();

        Assert.False(winDns.HasActiveBackup());
        Assert.Equal(["1.1.1.1"], configurator.CurrentIpv4);
    }

    private sealed class FakeDohHandler(Func<byte[], byte[]> responder) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var query = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            var reply = responder(query);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(reply),
            };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            return response;
        }
    }

    private sealed class FakeUpstream(DnsProtocol protocol) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => protocol;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            var resp = DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError);
            return Task.FromResult(new DnsQueryResult(true, resp, 12.3, resolver.Id, Protocol));
        }
    }

    private sealed class FakeNetworkInfoService : INetworkInfoService
    {
        public event EventHandler? NetworkChanged
        {
            add { }
            remove { }
        }

        public NetworkSnapshot GetSnapshot()
        {
            var primary = new NetworkAdapterInfo
            {
                Id = "{TEST-GUID}",
                Name = "Ethernet",
                Description = "Test Adapter",
                Kind = AdapterKind.Ethernet,
                Status = OperationalStatus.Up,
                IPv4Addresses = [IPAddress.Parse("192.168.1.10")],
                Gateways = [IPAddress.Parse("192.168.1.1")],
                DnsServers = [IPAddress.Parse("9.9.9.9")],
            };
            return new NetworkSnapshot([primary], primary, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
        }
    }

    private sealed class FakeBootRecoveryRegistrar : IBootRecoveryRegistrar
    {
        private readonly HashSet<string> _components = new(StringComparer.OrdinalIgnoreCase);

        public bool IsArmed => _components.Count > 0;

        public void Arm(string component) => _components.Add(component);

        public void Disarm(string component) => _components.Remove(component);

        public void ClearAll() => _components.Clear();
    }

    private sealed class FakeAdapterConfigurator : IAdapterDnsConfigurator
    {
        public bool FailSetDns { get; set; }
        public bool UsedDhcpIpv4 { get; private set; }
        public bool UsedDhcpIpv6 { get; private set; }
        public bool IsIpv6Dhcp { get; set; } = true;
        public List<string> CurrentIpv4 { get; set; } = ["9.9.9.9"];
        public List<string> CurrentIpv6 { get; set; } = [];

        public (bool IsIpv4Dhcp, IReadOnlyList<string> StaticIpv4, bool IsIpv6Dhcp, IReadOnlyList<string> StaticIpv6) ReadStaticConfiguration(NetworkAdapterInfo adapter) =>
            (false, CurrentIpv4.ToList(), IsIpv6Dhcp, CurrentIpv6.ToList());

        public Task<(bool Success, string? Error)> SetDnsAsync(
            string adapterName,
            bool ipv6,
            bool useDhcp,
            IReadOnlyList<string> servers,
            CancellationToken cancellationToken = default)
        {
            if (FailSetDns)
            {
                return Task.FromResult<(bool, string?)>((false, "Simulated netsh failure"));
            }

            if (!ipv6)
            {
                UsedDhcpIpv4 = useDhcp;
                CurrentIpv4 = useDhcp ? [] : servers.ToList();
            }
            else
            {
                UsedDhcpIpv6 = useDhcp;
                IsIpv6Dhcp = useDhcp;
                CurrentIpv6 = useDhcp ? [] : servers.ToList();
            }

            return Task.FromResult<(bool, string?)>((true, null));
        }
    }

    private sealed class MemoryStore(AppSettings initial) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(initial.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
