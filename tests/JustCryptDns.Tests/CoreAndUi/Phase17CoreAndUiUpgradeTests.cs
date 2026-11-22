using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Windows;
using JustCryptDns.App.Composition;
using JustCryptDns.App.Converters;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.App.ViewModels;
using JustCryptDns.App.Views;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Storage;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.CoreAndUi;

public sealed class Phase17CoreAndUiUpgradeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-phase17-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public Phase17CoreAndUiUpgradeTests()
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
    public async Task DotDnsUpstream_ReusesPooledConnectionAndPipelinesConcurrentQueries()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pfx = ephemeral.Export(X509ContentType.Pfx, "test");
        using var serverCert = new X509Certificate2(pfx, "test", X509KeyStorageFlags.Exportable);
        var expectedThumbprint = serverCert.Thumbprint;

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var serverTask = Task.Run(async () =>
        {
            using var tcp = await listener.AcceptTcpClientAsync(cts.Token);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions { ServerCertificate = serverCert },
                cts.Token);

            // Read 3 pipelined DNS queries first, then respond out of order to verify transaction-ID routing.
            var incoming = new List<byte[]>();
            for (var i = 0; i < 3; i++)
            {
                incoming.Add(await ReadDotFrameAsync(ssl, cts.Token));
            }

            incoming.Reverse();
            foreach (var query in incoming)
            {
                var resp = DnsPacket.CreateLocalRewriteResponse(query, LocalDnsRewriteRecordType.A, "93.184.216.34", 120);
                await WriteDotFrameAsync(ssl, resp, cts.Token);
            }
        }, cts.Token);

        try
        {
            using var dot = new DotDnsUpstream((_, cert, _, _) =>
                cert is X509Certificate2 x509 && string.Equals(x509.Thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase));
            var endpoint = new DnsResolverEndpoint
            {
                Id = "local-dot",
                Name = "Local Test DoT",
                Provider = "Test",
                Protocol = DnsProtocol.DnsOverTls,
                Endpoint = "localhost",
                PrimaryIp = "127.0.0.1",
                Port = port,
            };

            var q1 = DnsPacket.CreateQuery("one.example.test", DnsRecordType.A, id: 0x1111);
            var q2 = DnsPacket.CreateQuery("two.example.test", DnsRecordType.A, id: 0x2222);
            var q3 = DnsPacket.CreateQuery("three.example.test", DnsRecordType.A, id: 0x3333);

            var tasks = new[]
            {
                dot.QueryAsync(q1, endpoint, TimeSpan.FromSeconds(5), cts.Token),
                dot.QueryAsync(q2, endpoint, TimeSpan.FromSeconds(5), cts.Token),
                dot.QueryAsync(q3, endpoint, TimeSpan.FromSeconds(5), cts.Token),
            };
            var results = await Task.WhenAll(tasks);

            Assert.All(results, r => Assert.True(r.Success, r.Error));
            Assert.Equal(0x1111, BinaryPrimitives.ReadUInt16BigEndian(results[0].ResponseBytes.AsSpan(0, 2)));
            Assert.Equal(0x2222, BinaryPrimitives.ReadUInt16BigEndian(results[1].ResponseBytes.AsSpan(0, 2)));
            Assert.Equal(0x3333, BinaryPrimitives.ReadUInt16BigEndian(results[2].ResponseBytes.AsSpan(0, 2)));
            Assert.Equal(1, dot.ConnectionsCreated);
            Assert.True(dot.QueriesReusedConnection >= 2);
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task DotDnsUpstream_RetriesOnceWhenPooledConnectionIsClosed()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pfx = ephemeral.Export(X509ContentType.Pfx, "test");
        using var serverCert = new X509Certificate2(pfx, "test", X509KeyStorageFlags.Exportable);
        var expectedThumbprint = serverCert.Thumbprint;

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var serverTask = Task.Run(async () =>
        {
            // First connection: answer 1 query then abruptly close socket.
            using (var tcp1 = await listener.AcceptTcpClientAsync(cts.Token))
            using (var ssl1 = new SslStream(tcp1.GetStream(), leaveInnerStreamOpen: false))
            {
                await ssl1.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = serverCert }, cts.Token);
                var query1 = await ReadDotFrameAsync(ssl1, cts.Token);
                await WriteDotFrameAsync(ssl1, DnsPacket.CreateLocalRewriteResponse(query1, LocalDnsRewriteRecordType.A, "1.1.1.1", 60), cts.Token);
            }

            // Second connection after reconnect retry: answer second query cleanly.
            using (var tcp2 = await listener.AcceptTcpClientAsync(cts.Token))
            using (var ssl2 = new SslStream(tcp2.GetStream(), leaveInnerStreamOpen: false))
            {
                await ssl2.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = serverCert }, cts.Token);
                var query2 = await ReadDotFrameAsync(ssl2, cts.Token);
                await WriteDotFrameAsync(ssl2, DnsPacket.CreateLocalRewriteResponse(query2, LocalDnsRewriteRecordType.A, "1.0.0.1", 60), cts.Token);
            }
        }, cts.Token);

        try
        {
            using var dot = new DotDnsUpstream((_, cert, _, _) =>
                cert is X509Certificate2 x509 && string.Equals(x509.Thumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase));
            var endpoint = new DnsResolverEndpoint
            {
                Id = "local-dot-retry",
                Name = "Local Retry DoT",
                Provider = "Test",
                Protocol = DnsProtocol.DnsOverTls,
                Endpoint = "localhost",
                PrimaryIp = "127.0.0.1",
                Port = port,
            };

            var r1 = await dot.QueryAsync(DnsPacket.CreateQuery("first.test", DnsRecordType.A, 0x0101), endpoint, TimeSpan.FromSeconds(5), cts.Token);
            Assert.True(r1.Success);

            await Task.Delay(120, cts.Token);

            var r2 = await dot.QueryAsync(DnsPacket.CreateQuery("second.test", DnsRecordType.A, 0x0202), endpoint, TimeSpan.FromSeconds(5), cts.Token);
            Assert.True(r2.Success, r2.Error);
            Assert.Equal(2, dot.ConnectionsCreated);
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void DnsCacheService_ServeStaleAndNearExpiryPrefetchWorkCorrectly()
    {
        var now = new DateTimeOffset(2026, 11, 22, 12, 0, 0, TimeSpan.Zero);
        var settings = new SettingsService(new MemoryStore(new AppSettings()), NullLogger<SettingsService>.Instance);
        var cache = new DnsCacheService(settings, () => now);

        var query1 = DnsPacket.CreateQuery("prefetch.example", DnsRecordType.A, id: 0x0010);
        var response = DnsPacket.CreateLocalRewriteResponse(query1, LocalDnsRewriteRecordType.A, "198.51.100.10", ttlSeconds: 100);
        cache.StoreResponse(query1, response);

        // Hit 1 at t+10s: well before 15% remaining threshold -> no prefetch.
        now = now.AddSeconds(10);
        var query2 = DnsPacket.CreateQuery("prefetch.example", DnsRecordType.A, id: 0x0011);
        Assert.True(cache.TryGetResponse(query2, out _, out var shouldPrefetch1));
        Assert.False(shouldPrefetch1);

        // Hit 2 at t+90s (10s remaining <= 15s threshold, hitCount == 2): triggers prefetch once!
        now = now.AddSeconds(80);
        var query3 = DnsPacket.CreateQuery("prefetch.example", DnsRecordType.A, id: 0x0012);
        Assert.True(cache.TryGetResponse(query3, out _, out var shouldPrefetch2));
        Assert.True(shouldPrefetch2);
        Assert.Equal(1, cache.GetStats().PrefetchCount);

        // Advance past expiry (t+105s): fresh lookup misses & preserves CurrentEntries == 0 semantics.
        now = now.AddSeconds(15);
        var query4 = DnsPacket.CreateQuery("prefetch.example", DnsRecordType.A, id: 0x0013);
        Assert.False(cache.TryGetResponse(query4, out _));
        var statsAfterExpiry = cache.GetStats();
        Assert.Equal(0, statsAfterExpiry.CurrentEntries);
        Assert.Equal(1, statsAfterExpiry.ExpiredEvictions);
        Assert.Equal(1, statsAfterExpiry.StaleEntries);

        // RFC 8767 Serve-Stale returns cached entry with capped 30s TTL.
        Assert.True(cache.TryGetStaleResponse(query4, out var staleBytes));
        Assert.True(DnsPacket.TryParse(staleBytes, out var parsedStale));
        Assert.NotNull(parsedStale);
        Assert.Single(parsedStale!.Answers);
        Assert.Equal(30u, parsedStale.Answers[0].Ttl);
        Assert.Equal("198.51.100.10", parsedStale.Answers[0].DataSummary);
        Assert.Equal(1, cache.GetStats().StaleHits);
    }

    [Fact]
    public void NetworkAdaptationEvaluator_DetectsVpnAndCaptivePortals()
    {
        var eth = new NetworkAdapterInfo
        {
            Id = "eth",
            Name = "Ethernet",
            Description = "Intel I225-V",
            Kind = AdapterKind.Ethernet,
            Status = OperationalStatus.Up,
            IPv4Addresses = [IPAddress.Parse("192.168.1.50")],
        };
        var hv = new NetworkAdapterInfo
        {
            Id = "hv",
            Name = "vEthernet (Default Switch)",
            Description = "Hyper-V Virtual Ethernet Adapter",
            Kind = AdapterKind.Virtual,
            Status = OperationalStatus.Up,
            IPv4Addresses = [IPAddress.Parse("172.20.0.1")],
        };
        var warp = new NetworkAdapterInfo
        {
            Id = "warp",
            Name = "CloudflareWARP",
            Description = "Cloudflare WARP Tunnel",
            Kind = AdapterKind.Virtual,
            Status = OperationalStatus.Up,
            IPv4Addresses = [IPAddress.Parse("172.16.0.2")],
        };

        var snapshotWithWarp = new NetworkSnapshot([eth, hv, warp], eth, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
        var vpn = NetworkAdaptationEvaluator.DetectActiveVpnAdapter(snapshotWithWarp);
        Assert.NotNull(vpn);
        Assert.Equal("CloudflareWARP", vpn!.Name);

        Assert.False(NetworkAdaptationEvaluator.IsVpnAdapter(eth));
        Assert.False(NetworkAdaptationEvaluator.IsVpnAdapter(hv));
        Assert.True(NetworkAdaptationEvaluator.IsCaptivePortalHttpResponse(HttpStatusCode.Redirect, null));
        Assert.True(NetworkAdaptationEvaluator.IsCaptivePortalHttpResponse(HttpStatusCode.OK, "<html>Login</html>"));
        Assert.False(NetworkAdaptationEvaluator.IsCaptivePortalHttpResponse(HttpStatusCode.OK, NetworkAdaptationEvaluator.ExpectedConnectTestBody));
    }

    [Fact]
    public async Task LocalDnsRewrite_WirePacketRoutingServiceAndCanaryGuardWorkEndToEnd()
    {
        // 1. Validate wire builders for A, AAAA, CNAME
        var qA = DnsPacket.CreateQuery("dev.local", DnsRecordType.A, 0xA1A1);
        var rA = DnsPacket.CreateLocalRewriteResponse(qA, LocalDnsRewriteRecordType.A, "10.0.0.88", 120);
        Assert.True(DnsPacket.TryParse(rA, out var parsedA) && parsedA is { Answers.Count: 1 });
        Assert.Equal("10.0.0.88", parsedA!.Answers[0].DataSummary);

        var qAaaa = DnsPacket.CreateQuery("dev6.local", DnsRecordType.AAAA, 0xB2B2);
        var rAaaa = DnsPacket.CreateLocalRewriteResponse(qAaaa, LocalDnsRewriteRecordType.AAAA, "fd00::42", 120);
        Assert.True(DnsPacket.TryParse(rAaaa, out var parsedAaaa) && parsedAaaa is { Answers.Count: 1 });
        Assert.Equal("fd00::42", parsedAaaa!.Answers[0].DataSummary);

        var qCname = DnsPacket.CreateQuery("alias.local", DnsRecordType.CNAME, 0xC3C3);
        var rCname = DnsPacket.CreateLocalRewriteResponse(qCname, LocalDnsRewriteRecordType.CNAME, "target.lan", 90);
        Assert.True(DnsPacket.TryParse(rCname, out var parsedCname) && parsedCname is { Answers.Count: 1 });
        Assert.Equal(DnsRecordType.CNAME, parsedCname!.Answers[0].Type);
        Assert.Equal("target.lan", parsedCname.Answers[0].DataSummary);

        // 2. Validate DnsRoutingService CRUD + Engine Local Rewrite & Firefox Canary Guard
        var freePort = PortConflictDetector.FindAvailablePort(IPAddress.Loopback);
        var initial = new AppSettings
        {
            Dns = new DnsSettings
            {
                ListenAddress = "127.0.0.1",
                ListenPort = freePort,
                ConfigureWindowsAdapter = false,
                BlockFirefoxDohCanary = true,
            },
        };
        var settings = new SettingsService(new MemoryStore(initial), NullLogger<SettingsService>.Instance);
        var library = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        var routing = new DnsRoutingService(settings, NullLogger<DnsRoutingService>.Instance, library);

        var addResult = await routing.AddOrUpdateLocalRewriteAsync(new LocalDnsRewriteRule
        {
            Id = string.Empty,
            Pattern = "*.lan.test",
            MatchKind = RoutingMatchKind.Wildcard,
            RecordType = LocalDnsRewriteRecordType.A,
            TargetValue = "192.168.50.10",
            TtlSeconds = 75,
        });
        Assert.True(addResult.Success, addResult.Error);
        Assert.NotNull(routing.FindMatchingRewrite("api.lan.test", "A"));

        await using var engine = new DnsEngineService(
            settings,
            new StubDnsCryptManager(),
            new StubWindowsDnsManager(),
            NullLogger<DnsEngineService>.Instance,
            customUpstreams: [new FailingUpstream()],
            resolverLibrary: library,
            routingService: routing);

        var started = await engine.StartAsync();
        Assert.True(started.Success, started.Error);

        using var udp = new UdpClient();
        var serverEp = new IPEndPoint(IPAddress.Loopback, freePort);

        // Firefox DoH canary MUST return NXDOMAIN cleanly.
        var canaryQuery = DnsPacket.CreateQuery("use-application-dns.net", DnsRecordType.A, 0x5555);
        await udp.SendAsync(canaryQuery, canaryQuery.Length, serverEp);
        var canaryReply = await udp.ReceiveAsync();
        Assert.True(DnsPacket.TryParse(canaryReply.Buffer, out var parsedCanary));
        Assert.Equal(DnsResponseCode.NxDomain, parsedCanary!.Header.ResponseCode);

        // Local Rewrite MUST answer directly without calling upstream.
        var localQuery = DnsPacket.CreateQuery("portal.lan.test", DnsRecordType.A, 0x6666);
        await udp.SendAsync(localQuery, localQuery.Length, serverEp);
        var localReply = await udp.ReceiveAsync();
        Assert.True(DnsPacket.TryParse(localReply.Buffer, out var parsedLocal));
        Assert.Equal(DnsResponseCode.NoError, parsedLocal!.Header.ResponseCode);
        Assert.Single(parsedLocal.Answers);
        Assert.Equal("192.168.50.10", parsedLocal.Answers[0].DataSummary);
        Assert.True(engine.GetStats().RewrittenQueries >= 1);

        // Disable & remove cleanup works
        await routing.SetLocalRewriteEnabledAsync(addResult.Rule!.Id, false);
        Assert.Null(routing.FindMatchingRewrite("api.lan.test", "A"));
        Assert.True(await routing.RemoveLocalRewriteAsync(addResult.Rule.Id));
    }

    [Fact]
    public void SettingsMigration_UpgradesV17ToV18PreservingBatch2Defaults()
    {
        var v17Json = """
            {
              "schemaVersion": 17,
              "dns": { "activeResolverId": "cloudflare-doh", "listenPort": 53 }
            }
            """;

        File.WriteAllText(_paths.SettingsFile, v17Json);
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var loaded = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, loaded.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);
        Assert.True(loaded.Settings.SchemaVersion >= 18);
        Assert.True(loaded.Settings.Dns.AutoAdaptNetworkChanges);
        Assert.True(loaded.Settings.Dns.AutoDeferToVpn);
        Assert.True(loaded.Settings.Dns.BlockFirefoxDohCanary);
        Assert.True(loaded.Settings.Cache.EnableServeStale);
        Assert.True(loaded.Settings.Cache.EnablePrefetch);
        Assert.NotNull(loaded.Settings.Routing.LocalRewrites);

        // Direct migrator check as well
        var doc = JsonNode.Parse(v17Json)!.AsObject();
        var migrator = new SettingsMigrator();
        Assert.True(migrator.Migrate(doc));
        Assert.Equal(AppSettings.CurrentSchemaVersion, SettingsMigrator.ReadVersion(doc));
    }

    [Fact]
    public async Task ShellViewModel_AndConnectionInspectorDrawer_WorkCleanly()
    {
        var store = new MemoryStore(new AppSettings());
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var factory = new DummyPageFactory();
        var nav = new NavigationService();
        var shell = new ShellViewModel(factory, settings, nav, NullLogger<ShellViewModel>.Instance);

        try
        {
            Assert.Equal(3, shell.NavItemsView.Groups.Count);

            shell.OpenCommandPaletteCommand.Execute(null);
            Assert.True(shell.IsCommandPaletteOpen);

            shell.CommandPaletteQuery = "routing";
            var match = Assert.Single(shell.FilteredPaletteCommands, c => c.PageKey == PageKeys.Routing);
            await shell.ExecutePaletteCommandCommand.ExecuteAsync(match);
            Assert.False(shell.IsCommandPaletteOpen);
            Assert.Equal(PageKeys.Routing, shell.CurrentPageKey);
        }
        finally
        {
            shell.StopTimers();
        }

        await using var provider = ServiceRegistration.Build(
            _paths,
            NullLoggerFactory.Instance,
            store,
            new SettingsLoadResult(new AppSettings(), SettingsLoadOutcome.Defaults));
        Assert.NotNull(provider.GetService(typeof(IBrowserPolicyInspector)));
        var connVm = Assert.IsType<ConnectionMonitorViewModel>(provider.GetService(typeof(ConnectionMonitorViewModel)));
        try
        {
            Assert.False(connVm.IsInspectorOpen);
            connVm.SelectedConnection = new ConnectionRowViewModel("tcp4|1234|1.1.1.1:443")
            {
                ProcessId = 1234,
                ProcessName = "test.exe",
                RemoteIp = "1.1.1.1",
                RemotePort = 443,
            };
            Assert.True(connVm.IsInspectorOpen);

            connVm.CloseInspectorCommand.Execute(null);
            Assert.False(connVm.IsInspectorOpen);
        }
        finally
        {
            connVm.Dispose();
        }
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), ct);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }

            offset += read;
        }
    }

    private static async Task<byte[]> ReadDotFrameAsync(Stream stream, CancellationToken ct)
    {
        var lenBuf = new byte[2];
        await ReadExactlyAsync(stream, lenBuf, ct);
        var len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
        var payload = new byte[len];
        await ReadExactlyAsync(stream, payload, ct);
        return payload;
    }

    private static async Task WriteDotFrameAsync(Stream stream, byte[] payload, CancellationToken ct)
    {
        var frame = new byte[2 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), (ushort)payload.Length);
        payload.CopyTo(frame.AsSpan(2));
        await stream.WriteAsync(frame, ct);
        await stream.FlushAsync(ct);
    }

    private sealed class MemoryStore(AppSettings initial) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(initial, SettingsLoadOutcome.Loaded);
        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class DummyPageFactory : IPageFactory
    {
        public PageViewModel Create(string pageKey) => new DummyPage(pageKey);
    }

    private sealed class DummyPage(string key) : PageViewModel("Nav_" + key, "Page_" + key + "_Subtitle")
    {
    }

    private sealed class FailingUpstream : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWireFormat,
            DnsResolverEndpoint endpoint,
            TimeSpan timeout,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(false, [], 0, endpoint.Id, Protocol, "Upstream disabled in offline test."));
    }

    private sealed class StubDnsCryptManager : IDnsCryptProxyManager
    {
        public bool IsInstalled => false;
        public string? InstalledVersion => null;
        public string ExecutablePath => "dnscrypt-proxy.exe";
        public bool IsRunning => false;
        public Task<string?> DetectInstalledVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task<(bool Success, string? Version, string? Error)> InstallOrUpdateAsync(HttpClient? httpClient = null, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?, string?)>((false, null, "Disabled"));
        public Task<(bool Success, string? Error)> EnsureRunningAsync(DnsResolverEndpoint resolver, int internalPort, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class StubWindowsDnsManager : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;
        public AdapterDnsBackupDocument? ReadBackup() => null;
        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(string? targetAdapterId, string ipv4Dns, string? ipv6Dns, Func<CancellationToken, Task<bool>> connectivityProbe, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(string? targetAdapterId = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

[Collection("WpfViewSmoke")]
public sealed class Phase17WpfSmokeTests
{
    [Fact]
    public void TrayControlCenterWindow_InitializesCleanlyOnStaThread()
    {
        Exception? captured = null;
        var thread = new Thread(() =>
        {
            try
            {
                EnsureApplicationResources();
                var popup = new TrayControlCenterWindow();
                popup.RefreshState();
                popup.Measure(new Size(400, 500));
                Assert.NotNull(popup.Content);
                popup.Close();
            }
            catch (Exception ex)
            {
                captured = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        if (captured is not null)
        {
            throw new Xunit.Sdk.XunitException($"TrayControlCenterWindow STA initialization failed: {captured}");
        }
    }

    private static void EnsureApplicationResources()
    {
        Application.ResourceAssembly ??= typeof(JustCryptDns.App.App).Assembly;
        var app = Application.Current ?? new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        if (app.Resources.MergedDictionaries.Count == 0)
        {
            app.Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri("pack://application:,,,/JustCryptDns;component/Themes/Dark.xaml", UriKind.Absolute),
            });
            app.Resources.MergedDictionaries.Add(new ResourceDictionary
            {
                Source = new Uri("pack://application:,,,/JustCryptDns;component/Styles/Controls.xaml", UriKind.Absolute),
            });

            app.Resources["BoolToVisibility"] = new BoolToVisibilityConverter();
            app.Resources["InverseBoolToVisibility"] = new BoolToVisibilityConverter { Invert = true };
            app.Resources["NullToVisibility"] = new NullToVisibilityConverter();
            app.Resources["NullToCollapsed"] = new NullToVisibilityConverter { Invert = true };
            app.Resources["EnumEquals"] = new EnumEqualsConverter();
            app.Resources["InverseBool"] = new InverseBoolConverter();
            app.Resources["BoolEquals"] = new BoolEqualsConverter();
            app.Resources["AddressList"] = new AddressListConverter();
            app.Resources["LinkSpeed"] = new LinkSpeedConverter();
            app.Resources["WidthToColumns"] = new WidthToColumnsConverter();
            app.Resources["WidthToFiveColumns"] = new WidthToColumnsConverter { TwoColumnMin = 400, ThreeColumnMin = 640, FourColumnMin = 860, MaxColumns = 5 };
            app.Resources["NoAdapterVisibility"] = new NoAdapterVisibilityConverter();
            app.Resources["LocKey"] = new LocKeyConverter();
            app.Resources["LocFormat"] = new LocFormatConverter();
        }
    }
}
