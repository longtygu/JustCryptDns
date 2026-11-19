using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Network.Gaming;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class BypassAndSplitTunnelPhase13Tests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(Path.GetTempPath(), "jcd-bypass-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public BypassAndSplitTunnelPhase13Tests()
    {
        _paths = new AppPaths(_tempRoot);
        _paths.EnsureCreated();
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup lock in temp dir.
        }
    }

    [Theory]
    [InlineData("store.steampowered.com", 0)]
    [InlineData("steamcommunity.com", 1800)]
    public void TlsClientHelloFragmenter_ParsesSniAndSplitsWithoutIntactHostname(string sni, int paddingLen)
    {
        var hello = BuildSampleClientHello(sni, paddingLen);
        Assert.True(TlsClientHelloFragmenter.IsTlsClientHelloHeader(hello));
        Assert.True(TlsClientHelloFragmenter.TryFindSniHostSpan(hello, out var hostStart, out var hostLen));
        Assert.Equal(sni, Encoding.ASCII.GetString(hello, hostStart, hostLen));

        var sniBytes = Encoding.ASCII.GetBytes(sni);
        foreach (var strategy in Enum.GetValues<TlsFragmentationStrategy>())
        {
            var records = TlsClientHelloFragmenter.BuildFragmentedTlsRecords(hello, strategy, 40);
            Assert.True(records.Count >= 2, $"Expected >=2 fragments for {strategy}.");

            var reassembledPayload = new MemoryStream();
            foreach (var rec in records)
            {
                Assert.True(rec.Length > 5);
                Assert.Equal(0x16, rec[0]);
                Assert.Equal(0x03, rec[1]);
                var recLen = BinaryPrimitives.ReadUInt16BigEndian(rec.AsSpan(3, 2));
                Assert.Equal(rec.Length - 5, recLen);

                // No individual TLS record may contain the full SNI string intact.
                Assert.True(rec.AsSpan(5).IndexOf(sniBytes) < 0, $"SNI '{sni}' appeared intact inside a fragment under {strategy}.");
                reassembledPayload.Write(rec, 5, recLen);
            }

            var rebuilt = reassembledPayload.ToArray();
            Assert.Equal(hello.Length - 5, rebuilt.Length);
            Assert.Equal(hello.AsSpan(5).ToArray(), rebuilt);
        }
    }

    [Fact]
    public void TlsClientHelloFragmenter_SplitsHttpHostHeader()
    {
        var req = "GET / HTTP/1.1\r\nHost: store.steampowered.com\r\nUser-Agent: Test\r\n\r\n"u8.ToArray();
        Assert.True(TlsClientHelloFragmenter.TrySplitHttpHostHeader(req, out var split));
        var part1 = Encoding.ASCII.GetString(req, 0, split);
        var part2 = Encoding.ASCII.GetString(req, split, req.Length - split);
        Assert.DoesNotContain("store.steampowered.com", part1, StringComparison.Ordinal);
        Assert.DoesNotContain("store.steampowered.com", part2, StringComparison.Ordinal);
        Assert.Equal(req.Length, part1.Length + part2.Length);
    }

    [Fact]
    public async Task PacScriptGenerator_And_LocalPacHttpServer_ServeValidPacOverLoopback()
    {
        var settings = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.RuleListOnly,
            ListenAddress = "127.0.0.1",
            ProxyPort = 10808,
            PacPort = 0,
            DirectExclusionDomains = ["corp.internal"],
        };
        settings.Normalize();

        var script = PacScriptGenerator.Generate(settings, 10808);
        Assert.Contains("FindProxyForURL", script, StringComparison.Ordinal);
        Assert.Contains("steampowered.com", script, StringComparison.Ordinal);
        Assert.Contains("corp.internal", script, StringComparison.Ordinal);
        Assert.Contains("PROXY 127.0.0.1:10808; DIRECT", script, StringComparison.Ordinal);

        await using var pacServer = new LocalPacHttpServer(
            IPAddress.Loopback,
            0,
            () => script,
            NullLogger.Instance);
        pacServer.Start();
        Assert.True(pacServer.BoundPort > 0);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, pacServer.BoundPort);
        var stream = tcp.GetStream();
        await stream.WriteAsync("GET /proxy.pac?v=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"u8.ToArray());
        await stream.FlushAsync();

        using var reader = new StreamReader(stream, Encoding.UTF8);
        var responseText = await reader.ReadToEndAsync();
        Assert.Contains("HTTP/1.1 200 OK", responseText, StringComparison.Ordinal);
        Assert.Contains("application/x-ns-proxy-autoconfig", responseText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(script, responseText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LocalSmartBypassProxy_HttpConnectAndSocks5_FragmentTlsAndPreventSelfLoops()
    {
        using var mockTarget = new TcpListener(IPAddress.Loopback, 0);
        mockTarget.Start();
        var targetPort = ((IPEndPoint)mockTarget.LocalEndpoint).Port;

        var receivedPayloads = new ConcurrentBag<List<byte[]>>();
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = Task.Run(async () =>
        {
            for (var c = 0; c < 2; c++)
            {
                using var conn = await mockTarget.AcceptTcpClientAsync(cts.Token);
                var s = conn.GetStream();
                var tlsRecords = new List<byte[]>();
                var header = new byte[5];
                while (true)
                {
                    await s.ReadExactlyAsync(header, cts.Token);
                    var len = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
                    var payload = new byte[len];
                    await s.ReadExactlyAsync(payload, cts.Token);
                    var fullRec = new byte[5 + len];
                    header.CopyTo(fullRec, 0);
                    payload.CopyTo(fullRec, 5);
                    tlsRecords.Add(fullRec);

                    // Signal test once entire ClientHello is assembled (last record sends ACK)
                    if (tlsRecords.Sum(r => r.Length - 5) >= 80)
                    {
                        break;
                    }
                }

                receivedPayloads.Add(tlsRecords);
                await s.WriteAsync("ACK-FROM-SERVER"u8.ToArray(), cts.Token);
                await s.FlushAsync(cts.Token);
            }
        }, cts.Token);

        var settings = new BypassSettings
        {
            FragmentationStrategy = TlsFragmentationStrategy.RecordChunkSplit,
            FragmentSizeBytes = 24,
            ResolveTargetViaLocalDns = true,
        };
        settings.Normalize();

        var dns = new LoopbackResolvingDnsEngine();
        var events = new ConcurrentQueue<BypassActionKind>();
        await using var proxy = new LocalSmartBypassProxy(
            IPAddress.Loopback,
            0,
            () => 0,
            () => settings,
            () => false,
            new BypassRuleMatcher(),
            new UpstreamTunnelConnector(dns),
            (act, _, _, _, _, _, _) => events.Enqueue(act),
            NullLogger.Instance);
        proxy.Start();

        var clientHello = BuildSampleClientHello("store.steampowered.com", 0);

        // 1. HTTP CONNECT test
        using (var httpClient = new TcpClient())
        {
            await httpClient.ConnectAsync(IPAddress.Loopback, proxy.BoundPort, cts.Token);
            var stream = httpClient.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT store.steampowered.com:{targetPort} HTTP/1.1\r\nHost: store.steampowered.com:{targetPort}\r\n\r\n"), cts.Token);
            var respBuf = new byte[256];
            var respLen = await stream.ReadAsync(respBuf, cts.Token);
            Assert.Contains("200", Encoding.ASCII.GetString(respBuf, 0, respLen), StringComparison.Ordinal);

            await stream.WriteAsync(clientHello, cts.Token);
            await stream.FlushAsync(cts.Token);

            var ackBuf = new byte[64];
            var ackLen = await stream.ReadAsync(ackBuf, cts.Token);
            Assert.Equal("ACK-FROM-SERVER", Encoding.ASCII.GetString(ackBuf, 0, ackLen));
        }

        // 2. SOCKS5 test on the exact same proxy port
        using (var socksClient = new TcpClient())
        {
            await socksClient.ConnectAsync(IPAddress.Loopback, proxy.BoundPort, cts.Token);
            var stream = socksClient.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cts.Token);
            var methodResp = new byte[2];
            await stream.ReadExactlyAsync(methodResp, cts.Token);
            Assert.Equal(0x00, methodResp[1]);

            var hostBytes = "store.steampowered.com"u8.ToArray();
            var req = new byte[7 + hostBytes.Length];
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = (byte)hostBytes.Length;
            hostBytes.CopyTo(req, 5);
            BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(5 + hostBytes.Length, 2), (ushort)targetPort);
            await stream.WriteAsync(req, cts.Token);

            var reply = new byte[10];
            await stream.ReadExactlyAsync(reply, cts.Token);
            Assert.Equal(0x00, reply[1]);

            await stream.WriteAsync(clientHello, cts.Token);
            await stream.FlushAsync(cts.Token);

            var ackBuf = new byte[64];
            var ackLen = await stream.ReadAsync(ackBuf, cts.Token);
            Assert.Equal("ACK-FROM-SERVER", Encoding.ASCII.GetString(ackBuf, 0, ackLen));
        }

        // 3. Self-loop prevention test
        using (var loopClient = new TcpClient())
        {
            await loopClient.ConnectAsync(IPAddress.Loopback, proxy.BoundPort, cts.Token);
            var stream = loopClient.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT 127.0.0.1:{proxy.BoundPort} HTTP/1.1\r\nHost: 127.0.0.1:{proxy.BoundPort}\r\n\r\n"), cts.Token);
            var respBuf = new byte[256];
            var respLen = await stream.ReadAsync(respBuf, cts.Token);
            Assert.Contains("403", Encoding.ASCII.GetString(respBuf, 0, respLen), StringComparison.Ordinal);
        }

        await serverTask;
        Assert.Equal(2, receivedPayloads.Count);
        foreach (var recordList in receivedPayloads)
        {
            Assert.True(recordList.Count >= 2);
            var combined = recordList.SelectMany(r => r.Skip(5)).ToArray();
            Assert.Equal(clientHello.AsSpan(5).ToArray(), combined);
        }
    }

    [Fact]
    public async Task LocalSmartBypassProxy_AutoHybrid_FailsOverToMockSocks5Upstream()
    {
        // Direct target accepts TCP then immediately closes without answering (simulates DPI RST / block)
        using var droppingDirect = new TcpListener(IPAddress.Loopback, 0);
        droppingDirect.Start();
        var directPort = ((IPEndPoint)droppingDirect.LocalEndpoint).Port;

        using var mockSocksUpstream = new TcpListener(IPAddress.Loopback, 0);
        mockSocksUpstream.Start();
        var upstreamPort = ((IPEndPoint)mockSocksUpstream.LocalEndpoint).Port;

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dropTask = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    using var conn = await droppingDirect.AcceptTcpClientAsync(cts.Token);
                    conn.Close();
                }
                catch (Exception)
                {
                    break;
                }
            }
        }, cts.Token);

        string? requestedUpstreamHost = null;
        var upstreamTask = Task.Run(async () =>
        {
            for (var round = 0; round < 2; round++)
            {
                using var conn = await mockSocksUpstream.AcceptTcpClientAsync(cts.Token);
                var s = conn.GetStream();

                // Greeting
                var g = new byte[3];
                await s.ReadExactlyAsync(g, cts.Token);
                await s.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

                // CONNECT request (ATYP=0x03 domain)
                var head = new byte[5];
                await s.ReadExactlyAsync(head, cts.Token);
                var domainBytes = new byte[head[4]];
                await s.ReadExactlyAsync(domainBytes, cts.Token);
                requestedUpstreamHost = Encoding.ASCII.GetString(domainBytes);
                var portBytes = new byte[2];
                await s.ReadExactlyAsync(portBytes, cts.Token);

                await s.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, cts.Token);

                // Read ClientHello replay from proxy
                var buf = new byte[512];
                var n = await s.ReadAsync(buf, cts.Token);
                Assert.True(n > 20);
                await s.WriteAsync("FROM-UPSTREAM-TUNNEL"u8.ToArray(), cts.Token);
                await s.FlushAsync(cts.Token);
            }
        }, cts.Token);

        var settings = new BypassSettings
        {
            AutoFallbackToTunnelOnDpiFailure = true,
            ConnectTimeoutMs = 2000,
            Upstream = new UpstreamTunnelSettings
            {
                Enabled = true,
                Kind = UpstreamTunnelKind.Socks5,
                Host = "127.0.0.1",
                Port = upstreamPort,
            },
            Rules =
            [
                new BypassRule
                {
                    Id = "test-blocked",
                    Name = "Blocked Host",
                    Pattern = "blocked-ip.test",
                    MatchKind = RoutingMatchKind.Exact,
                    Mode = BypassMode.AutoHybrid,
                    Enabled = true,
                },
            ],
        };
        settings.Normalize();

        var dns = new LoopbackResolvingDnsEngine();
        var matcher = new BypassRuleMatcher();
        var recordedActions = new ConcurrentQueue<BypassActionKind>();
        await using var proxy = new LocalSmartBypassProxy(
            IPAddress.Loopback,
            0,
            () => 0,
            () => settings,
            () => false,
            matcher,
            new UpstreamTunnelConnector(dns),
            (act, _, _, _, _, _, _) => recordedActions.Enqueue(act),
            NullLogger.Instance);
        proxy.Start();

        var clientHello = BuildSampleClientHello("blocked-ip.test", 0);

        // First connection: triggers AutoHybrid DPI fail -> transparent Socks5 fallback
        using (var c1 = new TcpClient())
        {
            await c1.ConnectAsync(IPAddress.Loopback, proxy.BoundPort, cts.Token);
            var s = c1.GetStream();
            await s.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT blocked-ip.test:{directPort} HTTP/1.1\r\nHost: blocked-ip.test:{directPort}\r\n\r\n"), cts.Token);
            var r = new byte[128];
            _ = await s.ReadAsync(r, cts.Token);
            await s.WriteAsync(clientHello, cts.Token);
            await s.FlushAsync(cts.Token);
            var outBuf = new byte[64];
            var outLen = await s.ReadAsync(outBuf, cts.Token);
            Assert.Equal("FROM-UPSTREAM-TUNNEL", Encoding.ASCII.GetString(outBuf, 0, outLen));
        }

        // Second connection: 15-min adaptive hint routes directly via UpstreamTunnel
        using (var c2 = new TcpClient())
        {
            await c2.ConnectAsync(IPAddress.Loopback, proxy.BoundPort, cts.Token);
            var s = c2.GetStream();
            await s.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT blocked-ip.test:{directPort} HTTP/1.1\r\nHost: blocked-ip.test:{directPort}\r\n\r\n"), cts.Token);
            var r = new byte[128];
            _ = await s.ReadAsync(r, cts.Token);
            await s.WriteAsync(clientHello, cts.Token);
            await s.FlushAsync(cts.Token);
            var outBuf = new byte[64];
            var outLen = await s.ReadAsync(outBuf, cts.Token);
            Assert.Equal("FROM-UPSTREAM-TUNNEL", Encoding.ASCII.GetString(outBuf, 0, outLen));
        }

        await upstreamTask;
        await cts.CancelAsync();
        droppingDirect.Stop();
        await dropTask;
        Assert.Equal("blocked-ip.test", requestedUpstreamHost);
        var list = recordedActions.ToArray();
        Assert.Equal([BypassActionKind.AutoFallbackTunnel, BypassActionKind.UpstreamTunneled], list);
    }

    [Fact]
    public async Task WindowsSystemProxyService_ProtectsOriginalSettingsWithSha256BackupAndCrashRecovery()
    {
        var fake = new FakeSystemProxyConfigurator
        {
            State = new ProxyRegistryState(0, "10.0.0.1:8080", "intranet.local", null, 1),
        };
        using var service = new WindowsSystemProxyService(_paths, NullLogger<WindowsSystemProxyService>.Instance, fake);

        var pacResult = await service.ApplyPacProxyAsync("http://127.0.0.1:10809/proxy.pac");
        Assert.True(pacResult.Success);
        Assert.True(service.HasActiveBackup());
        Assert.Equal("http://127.0.0.1:10809/proxy.pac", fake.State.AutoConfigUrl);
        Assert.Equal(0, fake.State.ProxyEnable);

        // Simulate unclean crash recovery with another service instance
        using var crashedRecovery = new WindowsSystemProxyService(_paths, NullLogger<WindowsSystemProxyService>.Instance, fake);
        await crashedRecovery.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false);

        Assert.False(crashedRecovery.HasActiveBackup());
        Assert.Null(fake.State.AutoConfigUrl);
        Assert.Equal("10.0.0.1:8080", fake.State.ProxyServer);
        Assert.Equal("intranet.local", fake.State.ProxyOverride);
        Assert.Equal(1, fake.State.AutoDetect);
    }

    [Fact]
    public async Task SettingsMigration_V10ToV11_InitializesBypassDefaultsAndSteamRules()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 10, "general": { "language": "vi" } }""");
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var result = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, result.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, result.Settings.SchemaVersion);
        Assert.True(result.Settings.Bypass.IsBypassEnabled);
        Assert.Equal(WindowsProxyMode.AutoPac, result.Settings.Bypass.WindowsProxyMode);
        Assert.NotNull(result.Settings.Bypass.Rules);
        Assert.Contains(result.Settings.Bypass.Rules!, r => r.Pattern == "steampowered.com" && r.Enabled);
    }

    [Fact]
    public async Task ServiceStateManager_Ipc_DelegatesGamingModeAndBypassEngine()
    {
        var freeDnsPort = JustCryptDns.DNS.Proxy.PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var freeProxyPort = JustCryptDns.DNS.Proxy.PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var freePacPort = JustCryptDns.DNS.Proxy.PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);

        var initial = new AppSettings
        {
            General = { AutoStartDnsEngine = false },
            Dns = { ListenPort = freeDnsPort },
            Bypass = { ProxyPort = freeProxyPort, PacPort = freePacPort, ApplyWindowsProxyAutomatically = false },
        };

        var store = new MemorySettingsStore(initial);
        using var settingsService = new SettingsService(store, NullLogger<SettingsService>.Instance);
        using var netInfo = new JustCryptDns.Network.Monitoring.NetworkInfoService(NullLogger<JustCryptDns.Network.Monitoring.NetworkInfoService>.Instance);
        var winDns = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance);
        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);
        var cache = new DnsCacheService(settingsService);
        var resolvers = new ResolverLibraryService(settingsService, NullLogger<ResolverLibraryService>.Instance);
        var routing = new DnsRoutingService(settingsService, NullLogger<DnsRoutingService>.Instance, resolvers);
        await using var dnsEngine = new JustCryptDns.DNS.Proxy.DnsEngineService(settingsService, dnsCrypt, winDns, NullLogger<JustCryptDns.DNS.Proxy.DnsEngineService>.Instance, null, resolvers, routing, null, cache);
        using var gamingEngine = new GamingEngineService(settingsService, resolvers, routing, cache, dnsEngine, NullLogger<GamingEngineService>.Instance);

        var fakeProxyMgr = new WindowsSystemProxyService(_paths, NullLogger<WindowsSystemProxyService>.Instance, new FakeSystemProxyConfigurator());
        await using var bypassEngine = new BypassEngineService(settingsService, fakeProxyMgr, dnsEngine, NullLogger<BypassEngineService>.Instance);

        var stateMgr = new ServiceStateManager(
            settingsService,
            dnsEngine,
            winDns,
            NullLogger<ServiceStateManager>.Instance,
            gamingEngine,
            bypassEngine);
        await stateMgr.InitializeFromSettingsAsync();

        var gResp = await stateMgr.HandleAsync(new IpcRequest(IpcRequestKind.SetGamingMode, BoolValue: true));
        Assert.True(gResp.Success);
        Assert.True(gamingEngine.IsGamingModeEnabled);
        Assert.True(gResp.Status.IsGamingModeEnabled);

        var bStart = await stateMgr.HandleAsync(new IpcRequest(IpcRequestKind.SetBypassEnabled, BoolValue: true));
        Assert.True(bStart.Success);
        Assert.True(bStart.Status.IsBypassRunning);

        var bStop = await stateMgr.HandleAsync(new IpcRequest(IpcRequestKind.SetBypassEnabled, BoolValue: false));
        Assert.True(bStop.Success);
        Assert.False(bStop.Status.IsBypassRunning);
    }

    private static byte[] BuildSampleClientHello(string sni, int paddingLen)
    {
        var sniBytes = Encoding.ASCII.GetBytes(sni);
        using var ext = new MemoryStream();
        // SNI extension 0x0000
        ext.Write([0x00, 0x00]);
        var sniExtLen = (ushort)(sniBytes.Length + 5);
        ext.Write([(byte)(sniExtLen >> 8), (byte)(sniExtLen & 0xFF)]);
        var listLen = (ushort)(sniBytes.Length + 3);
        ext.Write([(byte)(listLen >> 8), (byte)(listLen & 0xFF), 0x00]);
        ext.Write([(byte)(sniBytes.Length >> 8), (byte)(sniBytes.Length & 0xFF)]);
        ext.Write(sniBytes);

        if (paddingLen > 0)
        {
            ext.Write([0x00, 0x15]);
            ext.Write([(byte)(paddingLen >> 8), (byte)(paddingLen & 0xFF)]);
            ext.Write(new byte[paddingLen]);
        }

        var extBytes = ext.ToArray();
        using var body = new MemoryStream();
        body.Write([0x03, 0x03]); // TLS 1.2 legacy version
        body.Write(new byte[32]); // Random
        body.WriteByte(0); // Session ID length
        body.Write([0x00, 0x04, 0xC0, 0x2F, 0x13, 0x01]); // Ciphers
        body.Write([0x01, 0x00]); // Compression
        body.Write([(byte)(extBytes.Length >> 8), (byte)(extBytes.Length & 0xFF)]);
        body.Write(extBytes);
        var bodyBytes = body.ToArray();

        using var handshake = new MemoryStream();
        handshake.WriteByte(0x01); // ClientHello
        handshake.Write([0x00, (byte)(bodyBytes.Length >> 8), (byte)(bodyBytes.Length & 0xFF)]);
        handshake.Write(bodyBytes);
        var hsBytes = handshake.ToArray();

        var record = new byte[5 + hsBytes.Length];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), (ushort)hsBytes.Length);
        hsBytes.CopyTo(record, 5);
        return record;
    }

    private sealed class LoopbackResolvingDnsEngine : IDnsEngine
    {
        public event EventHandler<DnsEngineRuntimeStats>? StateChanged { add { } remove { } }
        public DnsEngineRuntimeStats GetStats() => new()
        {
            State = DnsEngineState.Running,
            ActiveResolverId = "test",
            ActiveResolverName = "Test",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.1:53",
        };
        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) => Task.FromResult(new DnsQueryResult(true, [], 1, "test", DnsProtocol.DnsOverHttps));
        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) => Task.FromResult((true, 1.0, "OK"));
        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeSystemProxyConfigurator : ISystemProxyConfigurator
    {
        public ProxyRegistryState State { get; set; } = new(0, null, null, null, 1);

        public bool CanModifyCurrentUserProxy => true;

        public ProxyRegistryState ReadCurrent() => State;

        public (bool Success, string? Error) Write(ProxyRegistryState state)
        {
            State = state;
            return (true, null);
        }
    }

    private sealed class MemorySettingsStore(AppSettings settings) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(settings.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings value, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
