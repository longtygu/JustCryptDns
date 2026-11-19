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
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class BypassAllWebPhase14Tests : IDisposable
{
    private readonly string _tempRoot = Path.Combine(Path.GetTempPath(), "jcd-allweb-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public BypassAllWebPhase14Tests()
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
            // Ignore cleanup errors.
        }
    }

    [Fact]
    public void PacScriptGenerator_AllWebsitesSmart_ProxiesAllWebButExcludesLanRfc1918AndDirectRules()
    {
        var settings = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.AllWebsitesSmart,
            ListenAddress = "127.0.0.1",
            ProxyPort = 10808,
            DirectExclusionDomains = ["bank.example.vn", "*.corp.internal"],
            Rules =
            [
                new BypassRule
                {
                    Id = "explicit-direct",
                    Name = "Explicit Direct",
                    Pattern = "intranet-app.org",
                    MatchKind = RoutingMatchKind.Exact,
                    Mode = BypassMode.Direct,
                    Enabled = true,
                },
            ],
        };
        settings.Normalize();

        var pac = PacScriptGenerator.Generate(settings, 10808);
        Assert.Contains("/^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(h)", pac, StringComparison.Ordinal);
        Assert.Contains("bank.example.vn", pac, StringComparison.Ordinal);
        Assert.Contains("intranet-app.org", pac, StringComparison.Ordinal);
        Assert.EndsWith("  return proxy;\r\n}\r\n", pac, StringComparison.Ordinal);
    }

    [Fact]
    public void BypassRuleMatcher_AllWebsitesSmart_AppliesDefaultUnmatchedMode_AndRespectsDirectExclusions()
    {
        var matcher = new BypassRuleMatcher();
        var smart = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.AllWebsitesSmart,
            DefaultUnmatchedMode = BypassMode.AutoHybrid,
            DirectExclusionDomains = ["mybank.com.vn"],
        };
        smart.Normalize();

        Assert.Equal(BypassMode.AutoHybrid, matcher.Evaluate("arbitrary-website.org", smart));
        Assert.Equal(BypassMode.Direct, matcher.Evaluate("online.mybank.com.vn", smart));
        Assert.Equal(BypassMode.Direct, matcher.Evaluate("192.168.1.10", smart));

        var ruleOnly = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.RuleListOnly,
            DefaultUnmatchedMode = BypassMode.AutoHybrid,
        };
        ruleOnly.Normalize();

        Assert.Equal(BypassMode.Direct, matcher.Evaluate("arbitrary-website.org", ruleOnly));
        Assert.Equal(BypassMode.AutoHybrid, matcher.Evaluate("store.steampowered.com", ruleOnly));
    }

    [Fact]
    public async Task LocalSmartBypassProxy_SelfHeals_WhenServerRejectsFragmentedTlsWithAlert_AndLearnsDirect()
    {
        var clientHello = BuildSampleClientHello("quirky-bank.test");
        using var mockServer = new TcpListener(IPAddress.Loopback, 0);
        mockServer.Start();
        var serverPort = ((IPEndPoint)mockServer.LocalEndpoint).Port;

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverAttempts = 0;
        var serverTask = Task.Run(async () =>
        {
            // Expect 3 connections: 1) Fragmented -> TLS Alert; 2) Unfragmented self-heal -> OK; 3) Learned Direct -> OK
            for (var round = 0; round < 3; round++)
            {
                using var conn = await mockServer.AcceptTcpClientAsync(cts.Token);
                Interlocked.Increment(ref serverAttempts);
                var s = conn.GetStream();
                var header = new byte[5];
                await s.ReadExactlyAsync(header, cts.Token);
                var recLen = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
                var body = new byte[recLen];
                await s.ReadExactlyAsync(body, cts.Token);

                if (recLen < clientHello.Length - 5)
                {
                    // Legacy server rejects fragmented TLS handshake with TLS Alert (0x15)
                    await s.WriteAsync(new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 }, cts.Token);
                    await s.FlushAsync(cts.Token);
                }
                else
                {
                    await s.WriteAsync("LEGACY-DIRECT-OK"u8.ToArray(), cts.Token);
                    await s.FlushAsync(cts.Token);
                }
            }
        }, cts.Token);

        var settings = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.AllWebsitesSmart,
            EnableSmartSelfHealing = true,
            FragmentationStrategy = TlsFragmentationStrategy.RecordChunkSplit,
            FragmentSizeBytes = 24,
        };
        settings.Normalize();

        var matcher = new BypassRuleMatcher();
        var actions = new ConcurrentQueue<BypassActionKind>();
        await using var proxy = new LocalSmartBypassProxy(
            IPAddress.Loopback,
            0,
            () => 0,
            () => settings,
            () => false,
            matcher,
            new UpstreamTunnelConnector(new LoopbackDns()),
            (act, _, _, _, _, _, _) => actions.Enqueue(act),
            NullLogger.Instance);
        proxy.Start();

        // Request 1: triggers Stage 1 TLS Alert -> skips Stage 2 -> Stage 3 SelfHealedDirect
        Assert.Equal("LEGACY-DIRECT-OK", await SendConnectAndHelloAsync(proxy.BoundPort, "quirky-bank.test", serverPort, clientHello, cts.Token));

        var learned = matcher.GetLearnedHosts();
        Assert.Contains(learned, h => h.Host == "quirky-bank.test" && h.Strategy == LearnedHostStrategy.Direct);

        // Request 2: uses Learned Direct immediately cleanly
        Assert.Equal("LEGACY-DIRECT-OK", await SendConnectAndHelloAsync(proxy.BoundPort, "quirky-bank.test", serverPort, clientHello, cts.Token));

        await serverTask;
        Assert.Equal(3, serverAttempts);
        Assert.Equal([BypassActionKind.SelfHealedDirect, BypassActionKind.DirectPassthrough], actions.ToArray());
    }

    [Fact]
    public async Task LocalSmartBypassProxy_SelfHeals_EscalatesTo16B_WhenPrimary40BDrops_AndLearns16B()
    {
        var clientHello = BuildSampleClientHello("strict-dpi.test");
        using var mockServer = new TcpListener(IPAddress.Loopback, 0);
        mockServer.Start();
        var serverPort = ((IPEndPoint)mockServer.LocalEndpoint).Port;

        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var serverTask = Task.Run(async () =>
        {
            // Round 1: Stage 1 sends >20B record -> drop connection immediately
            // Round 2: Stage 2 sends <=16B records -> assemble all records and reply DPI-16B-OK
            // Round 3: Next request uses Learned 16B directly -> assemble all records and reply DPI-16B-OK
            while (!cts.IsCancellationRequested)
            {
                TcpClient conn;
                try
                {
                    conn = await mockServer.AcceptTcpClientAsync(cts.Token);
                }
                catch
                {
                    break;
                }

                using (conn)
                {
                    var s = conn.GetStream();
                    var firstHead = new byte[5];
                    try
                    {
                        await s.ReadExactlyAsync(firstHead, cts.Token);
                    }
                    catch
                    {
                        continue;
                    }

                    var firstLen = BinaryPrimitives.ReadUInt16BigEndian(firstHead.AsSpan(3, 2));
                    if (firstLen > 20)
                    {
                        // Simulate strict DPI box dropping >20B records
                        conn.Close();
                        continue;
                    }

                    var firstBody = new byte[firstLen];
                    await s.ReadExactlyAsync(firstBody, cts.Token);
                    var assembledLen = firstLen;
                    var header = new byte[5];
                    while (assembledLen < clientHello.Length - 5)
                    {
                        await s.ReadExactlyAsync(header, cts.Token);
                        var len = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
                        var buf = new byte[len];
                        await s.ReadExactlyAsync(buf, cts.Token);
                        assembledLen += len;
                    }

                    await s.WriteAsync("DPI-16B-OK"u8.ToArray(), cts.Token);
                    await s.FlushAsync(cts.Token);
                }
            }
        }, cts.Token);

        var settings = new BypassSettings
        {
            CoverageMode = BypassCoverageMode.AllWebsitesSmart,
            EnableSmartSelfHealing = true,
            FragmentationStrategy = TlsFragmentationStrategy.RecordChunkSplit,
            FragmentSizeBytes = 40,
        };
        settings.Normalize();

        var matcher = new BypassRuleMatcher();
        var actions = new ConcurrentQueue<BypassActionKind>();
        await using var proxy = new LocalSmartBypassProxy(
            IPAddress.Loopback,
            0,
            () => 0,
            () => settings,
            () => false,
            matcher,
            new UpstreamTunnelConnector(new LoopbackDns()),
            (act, _, _, _, _, _, _) => actions.Enqueue(act),
            NullLogger.Instance);
        proxy.Start();

        Assert.Equal("DPI-16B-OK", await SendConnectAndHelloAsync(proxy.BoundPort, "strict-dpi.test", serverPort, clientHello, cts.Token));
        Assert.Contains(matcher.GetLearnedHosts(), h => h.Host == "strict-dpi.test" && h.Strategy == LearnedHostStrategy.EscalatedDpi16B);

        Assert.Equal("DPI-16B-OK", await SendConnectAndHelloAsync(proxy.BoundPort, "strict-dpi.test", serverPort, clientHello, cts.Token));

        await cts.CancelAsync();
        mockServer.Stop();
        await serverTask;
        Assert.Equal([BypassActionKind.EscalatedDpi16B, BypassActionKind.EscalatedDpi16B], actions.ToArray());
    }

    [Fact]
    public async Task BypassEngineService_DirectExclusionsAndLearnedPromotion_UpdateSettingsAndRefreshPac()
    {
        var initial = new AppSettings
        {
            Dns = { ListenPort = 0 },
            Bypass = { ProxyPort = 0, PacPort = 0, ApplyWindowsProxyAutomatically = true, WindowsProxyMode = WindowsProxyMode.AutoPac },
        };
        var store = new MemStore(initial);
        using var settingsService = new SettingsService(store, NullLogger<SettingsService>.Instance);
        using var netInfo = new JustCryptDns.Network.Monitoring.NetworkInfoService(NullLogger<JustCryptDns.Network.Monitoring.NetworkInfoService>.Instance);
        var winDns = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance);
        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);
        var cache = new DnsCacheService(settingsService);
        var resolvers = new ResolverLibraryService(settingsService, NullLogger<ResolverLibraryService>.Instance);
        var routing = new DnsRoutingService(settingsService, NullLogger<DnsRoutingService>.Instance, resolvers);
        await using var dnsEngine = new JustCryptDns.DNS.Proxy.DnsEngineService(settingsService, dnsCrypt, winDns, NullLogger<JustCryptDns.DNS.Proxy.DnsEngineService>.Instance, null, resolvers, routing, null, cache);

        var fakeConfigurator = new RecordingProxyConfigurator();
        using var winProxy = new WindowsSystemProxyService(_paths, NullLogger<WindowsSystemProxyService>.Instance, fakeConfigurator);
        await using var engine = new BypassEngineService(settingsService, winProxy, dnsEngine, NullLogger<BypassEngineService>.Instance);

        var (ok, _) = await engine.StartAsync();
        Assert.True(ok);
        Assert.Contains("/proxy.pac?v=1", fakeConfigurator.LastAutoConfigUrl, StringComparison.Ordinal);

        var (addOk, _) = await engine.AddDirectExclusionAsync("banking.local.vn");
        Assert.True(addOk);
        Assert.Contains("banking.local.vn", engine.GetDirectExclusions());
        Assert.Contains("/proxy.pac?v=2", fakeConfigurator.LastAutoConfigUrl, StringComparison.Ordinal);
        Assert.Contains("banking.local.vn", engine.GeneratePacScript(), StringComparison.Ordinal);

        var (pinOk, _) = await engine.PromoteLearnedHostAsync("need-warp.example", LearnedHostStrategy.UpstreamTunnel);
        Assert.True(pinOk);
        Assert.Contains(engine.GetRules(), r => r.Pattern == "need-warp.example" && r.Mode == BypassMode.UpstreamTunnel);
        Assert.Contains("/proxy.pac?v=3", fakeConfigurator.LastAutoConfigUrl, StringComparison.Ordinal);

        await engine.StopAsync();
    }

    [Fact]
    public async Task SettingsMigration_V11ToV12_EnablesAllWebsitesSmartAndSelfHealing()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 11, "bypass": { "proxyPort": 10808 } }""");
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var result = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, result.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, result.Settings.SchemaVersion);
        Assert.Equal(BypassCoverageMode.AllWebsitesSmart, result.Settings.Bypass.CoverageMode);
        Assert.Equal(BypassMode.AutoHybrid, result.Settings.Bypass.DefaultUnmatchedMode);
        Assert.True(result.Settings.Bypass.EnableSmartSelfHealing);
    }

    private static async Task<string> SendConnectAndHelloAsync(
        int proxyPort,
        string targetHost,
        int targetPort,
        byte[] clientHello,
        CancellationToken ct)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxyPort, ct);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {targetHost}:{targetPort} HTTP/1.1\r\nHost: {targetHost}:{targetPort}\r\n\r\n"), ct);
        var respBuf = new byte[128];
        var respLen = await stream.ReadAsync(respBuf, ct);
        Assert.Contains("200", Encoding.ASCII.GetString(respBuf, 0, respLen), StringComparison.Ordinal);

        await stream.WriteAsync(clientHello, ct);
        await stream.FlushAsync(ct);

        var replyBuf = new byte[128];
        var replyLen = await stream.ReadAsync(replyBuf, ct);
        return Encoding.ASCII.GetString(replyBuf, 0, replyLen);
    }

    private static byte[] BuildSampleClientHello(string sni)
    {
        var sniBytes = Encoding.ASCII.GetBytes(sni);
        using var ext = new MemoryStream();
        ext.Write([0x00, 0x00]);
        var sniExtLen = (ushort)(sniBytes.Length + 5);
        ext.Write([(byte)(sniExtLen >> 8), (byte)(sniExtLen & 0xFF)]);
        var listLen = (ushort)(sniBytes.Length + 3);
        ext.Write([(byte)(listLen >> 8), (byte)(listLen & 0xFF), 0x00]);
        ext.Write([(byte)(sniBytes.Length >> 8), (byte)(sniBytes.Length & 0xFF)]);
        ext.Write(sniBytes);
        var extBytes = ext.ToArray();

        using var body = new MemoryStream();
        body.Write([0x03, 0x03]);
        body.Write(new byte[32]);
        body.WriteByte(0);
        body.Write([0x00, 0x04, 0xC0, 0x2F, 0x13, 0x01]);
        body.Write([0x01, 0x00]);
        body.Write([(byte)(extBytes.Length >> 8), (byte)(extBytes.Length & 0xFF)]);
        body.Write(extBytes);
        var bodyBytes = body.ToArray();

        using var hs = new MemoryStream();
        hs.WriteByte(0x01);
        hs.Write([0x00, (byte)(bodyBytes.Length >> 8), (byte)(bodyBytes.Length & 0xFF)]);
        hs.Write(bodyBytes);
        var hsBytes = hs.ToArray();

        var rec = new byte[5 + hsBytes.Length];
        rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(rec.AsSpan(3, 2), (ushort)hsBytes.Length);
        hsBytes.CopyTo(rec, 5);
        return rec;
    }

    private sealed class LoopbackDns : IDnsEngine
    {
        public event EventHandler<DnsEngineRuntimeStats>? StateChanged { add { } remove { } }
        public DnsEngineRuntimeStats GetStats() => new() { State = DnsEngineState.Running, ActiveResolverId = "r", ActiveResolverName = "r", ActiveProtocol = DnsProtocol.DnsOverHttps, ListenEndpoint = "127.0.0.1:53" };
        public Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) => Task.FromResult(new DnsQueryResult(true, [], 1, "r", DnsProtocol.DnsOverHttps));
        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) => Task.FromResult((true, 1.0, "OK"));
        public Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, bool includeIpv6 = false, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingProxyConfigurator : ISystemProxyConfigurator
    {
        private ProxyRegistryState _state = new(0, null, null, null, 1);

        public string? LastAutoConfigUrl => _state.AutoConfigUrl;

        public bool CanModifyCurrentUserProxy => true;

        public ProxyRegistryState ReadCurrent() => _state;

        public (bool Success, string? Error) Write(ProxyRegistryState state)
        {
            _state = state;
            return (true, null);
        }
    }

    private sealed class MemStore(AppSettings settings) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(settings.Clone(), SettingsLoadOutcome.Loaded);
        public Task SaveAsync(AppSettings value, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
