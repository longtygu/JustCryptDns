using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using JustCryptDns.App.Composition;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class ConnectionMonitorAndFirewallTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-conn-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public ConnectionMonitorAndFirewallTests()
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
    public void CidrNetwork_ParsesAndNormalizesIpv4Ipv6_AndRejectsInvalid()
    {
        Assert.True(CidrNetwork.TryParse("203.0.113.42", out var singleV4, out _));
        Assert.True(singleV4.IsSingleHost);
        Assert.Equal("203.0.113.42", singleV4.CanonicalText);
        Assert.Equal("203.0.113.42", singleV4.FirewallRemoteAddress);
        Assert.True(singleV4.Contains(IPAddress.Parse("203.0.113.42")));
        Assert.False(singleV4.Contains(IPAddress.Parse("203.0.113.43")));

        Assert.True(CidrNetwork.TryParse("198.51.100.77/24", out var netV4, out _));
        Assert.False(netV4.IsSingleHost);
        Assert.Equal("198.51.100.0/24", netV4.CanonicalText);
        Assert.True(netV4.Contains(IPAddress.Parse("198.51.100.254")));
        Assert.False(netV4.Contains(IPAddress.Parse("198.51.101.1")));

        Assert.True(CidrNetwork.TryParse("2001:db8:0:1::dead:beef/64", out var netV6, out _));
        Assert.Equal("2001:db8:0:1::/64", netV6.CanonicalText);
        Assert.True(netV6.Contains(IPAddress.Parse("2001:db8:0:1::cafe")));
        Assert.False(netV6.Contains(IPAddress.Parse("2001:db8:0:2::1")));

        Assert.True(CidrNetwork.TryParse("198.51.100.128/25", out var halfV4, out _));
        Assert.True(netV4.Overlaps(halfV4));
        Assert.True(halfV4.Overlaps(netV4));

        Assert.False(CidrNetwork.TryParse("0.0.0.0/0", out _, out _));
        Assert.False(CidrNetwork.TryParse("::/0", out _, out _));
        Assert.False(CidrNetwork.TryParse("192.168.1.1/33", out _, out _));
        Assert.False(CidrNetwork.TryParse("2001:db8::/129", out _, out _));
        Assert.False(CidrNetwork.TryParse("not-an-ip", out _, out _));
        Assert.False(CidrNetwork.TryParse("", out _, out _));
    }

    [Fact]
    public void IpBlockerGuard_RejectsSelfLockoutTargets_AndWarnsOnWideOrCdnRanges()
    {
        var adapter = new NetworkAdapterInfo
        {
            Id = "eth0",
            Name = "Ethernet",
            Description = "Intel Adapter",
            Kind = AdapterKind.Ethernet,
            Status = OperationalStatus.Up,
            IPv4Addresses = [IPAddress.Parse("192.168.1.50")],
            Gateways = [IPAddress.Parse("192.168.1.1")],
            DnsServers = [IPAddress.Parse("192.168.1.2")],
        };
        var snapshot = new NetworkSnapshot([adapter], adapter, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
        var reverseCache = new DnsReverseLookupCache();
        reverseCache.Record(IPAddress.Parse("104.16.249.249"), "cloudflare-dns.com", 300);

        var context = ProtectedIpContext.Build(
            snapshot,
            BuiltInResolvers.All,
            new DnsSettings { ListenAddress = "127.0.0.1" },
            new BypassSettings { ListenAddress = "127.0.0.1" },
            reverseCache);

        // Hard-protected targets (must NEVER be blocked)
        foreach (var protectedTarget in new[]
                 {
                     "127.0.0.1",
                     "127.0.0.0/8",
                     "::1",
                     "0.0.0.0",
                     "192.168.1.1",
                     "192.168.1.0/24",
                     "192.168.1.2",
                     "192.168.1.50",
                     "1.1.1.1",
                     "8.8.8.8",
                     "9.9.9.9",
                     "104.16.249.249",
                 })
        {
            var res = IpBlockerGuard.Evaluate(protectedTarget, context);
            Assert.False(res.IsValid, $"Expected {protectedTarget} to be rejected.");
            Assert.True(res.IsProtectedViolation, $"Expected protected violation for {protectedTarget}.");
        }

        // Wide CIDR warning
        var wide = IpBlockerGuard.Evaluate("198.51.0.0/16", context);
        Assert.True(wide.IsValid);
        Assert.False(wide.IsProtectedViolation);
        Assert.True(wide.RequiresConfirmation);
        Assert.Equal("WideCidr", wide.WarningCode);

        // Major CDN prefix warning (outside protected resolver IPs)
        var cdn = IpBlockerGuard.Evaluate("151.101.1.69", context);
        Assert.True(cdn.IsValid);
        Assert.False(cdn.IsProtectedViolation);
        Assert.True(cdn.RequiresConfirmation);
        Assert.Equal("MajorCdnOrCloud", cdn.WarningCode);

        // Clean third-party target
        var clean = IpBlockerGuard.Evaluate("203.0.113.77", context);
        Assert.True(clean.IsValid);
        Assert.False(clean.IsProtectedViolation);
        Assert.False(clean.RequiresConfirmation);
        Assert.Equal("203.0.113.77", clean.NormalizedNetwork?.CanonicalText);
    }

    [Fact]
    public void DnsReverseLookupCache_ExpiresTtlAndEvictsLeastRecentlyUsed()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 11, 20, 12, 0, 0, TimeSpan.Zero));
        var cache = new DnsReverseLookupCache(timeProvider: clock, maxEntries: 3, minTtlSeconds: 10, maxTtlSeconds: 300);

        cache.Record(IPAddress.Parse("203.0.113.1"), "cdn.example.com", 30);
        cache.Record(IPAddress.Parse("203.0.113.2"), "api.example.com", 30);
        cache.Record(IPAddress.Parse("203.0.113.3"), "auth.example.com", 30);

        // Access .1 so .2 becomes least-recently-used.
        Assert.True(cache.TryResolve("203.0.113.1", out var d1));
        Assert.Equal("cdn.example.com", d1);

        // Inserting a 4th item must evict .2 and cap count at maxEntries (3).
        cache.Record(IPAddress.Parse("203.0.113.4"), "static.other.org", 60);
        Assert.Equal(3, cache.Count);
        Assert.False(cache.TryResolve("203.0.113.2", out _));
        Assert.True(cache.TryResolve("203.0.113.1", out _));
        Assert.True(cache.TryResolve("203.0.113.3", out _));
        Assert.True(cache.TryResolve("203.0.113.4", out _));

        // Domain lookup matches domain & subdomains.
        var ips = cache.GetIpsForDomain("example.com");
        Assert.Contains("203.0.113.1", ips);
        Assert.Contains("203.0.113.3", ips);
        Assert.DoesNotContain("203.0.113.4", ips);

        // Advance clock 35s: 30s entries expire, 60s entry remains valid.
        clock.Advance(TimeSpan.FromSeconds(35));
        Assert.False(cache.TryResolve("203.0.113.1", out _));
        Assert.False(cache.TryResolve("203.0.113.3", out _));
        Assert.True(cache.TryResolve("203.0.113.4", out var d4));
        Assert.Equal("static.other.org", d4);
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public async Task DnsEngineService_PopulatesReverseLookupCache_OnResolvedQuery()
    {
        var store = new MemoryStore(new AppSettings
        {
            Dns = { ListenAddress = "127.0.0.1", ListenPort = 0, ActiveResolverId = "cloudflare-doh" },
        });
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var winDns = new StubWindowsDnsManager();
        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);
        var reverseCache = new DnsReverseLookupCache();

        var resolvedIps = new[] { IPAddress.Parse("203.0.113.99") };
        await using var engine = new DnsEngineService(
            settings,
            dnsCrypt,
            winDns,
            NullLogger<DnsEngineService>.Instance,
            [new FixedAnswerUpstream(resolvedIps[0])],
            reverseLookupCache: reverseCache);

        var ips = await engine.ResolveHostAsync("game.example.net");
        Assert.Single(ips);
        Assert.Equal(resolvedIps[0], ips[0]);
        Assert.True(reverseCache.TryResolve("203.0.113.99", out var domain));
        Assert.Equal("game.example.net", domain);
    }

    [Fact]
    public async Task SettingsV14_MigratesToV15_AndRoundTripsConnectionSettings()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 14, "general": { "language": "en" } }""");
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var loaded = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, loaded.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);
        Assert.False(loaded.Settings.Connections.EnableOnlineLookup);
        Assert.False(loaded.Settings.Connections.AlertNewUnknownProcess);
        Assert.True(loaded.Settings.Connections.HideLanConnections);
        Assert.True(loaded.Settings.Connections.AutoScroll);
        Assert.Empty(loaded.Settings.Connections.BlockedRules);
        Assert.Empty(loaded.Settings.Connections.IpNotes);

        loaded.Settings.Connections.BlockedRules.Add(new BlockedIpRule
        {
            Target = "198.51.100.99/24",
            Note = "Telemetry subnet",
            IsEnabled = true,
        });
        loaded.Settings.Connections.IpNotes["203.0.113.42"] = "Game relay";

        await store.SaveAsync(loaded.Settings);
        var reloaded = store.Load();
        Assert.Single(reloaded.Settings.Connections.BlockedRules);
        Assert.Equal("198.51.100.0/24", reloaded.Settings.Connections.BlockedRules[0].Target);
        Assert.Equal("Game relay", reloaded.Settings.Connections.IpNotes["203.0.113.42"]);
    }

    [Fact]
    public async Task ServiceRegistration_ResolvesConnectionMonitorGraphCleanly()
    {
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var initial = store.Load();
        await using var provider = ServiceRegistration.Build(_paths, NullLoggerFactory.Instance, store, initial);

        Assert.NotNull(provider.GetService(typeof(IDnsReverseLookupCache)));
        Assert.NotNull(provider.GetService(typeof(IConnectionMonitorService)));
        Assert.NotNull(provider.GetService(typeof(IIpEnrichmentService)));
        Assert.NotNull(provider.GetService(typeof(IWindowsFirewallManager)));
        Assert.NotNull(provider.GetService(typeof(IFirewallBlocklistCoordinator)));
        using var vm = provider.GetService(typeof(ConnectionMonitorViewModel)) as ConnectionMonitorViewModel;
        Assert.NotNull(vm);
    }

    [Fact]
    public async Task WindowsConnectionReader_AndFirewallStatus_ExecuteCleanly()
    {
        var reader = new JustCryptDns.Network.Monitoring.WindowsConnectionTableReader(
            NullLogger<JustCryptDns.Network.Monitoring.WindowsConnectionTableReader>.Instance);
        var entries = reader.CaptureSnapshot();
        Assert.NotNull(entries);
        // On a live Windows host there is always at least one UDP or TCP endpoint.
        if (OperatingSystem.IsWindows())
        {
            Assert.NotEmpty(entries);
            Assert.All(entries, e =>
            {
                Assert.False(string.IsNullOrWhiteSpace(e.RemoteIp));
                Assert.False(string.IsNullOrWhiteSpace(e.ProcessName));
                Assert.True(e.LocalPort >= 0);
            });
        }

        using var firewall = new WindowsFirewallService(NullLogger<WindowsFirewallService>.Instance);
        var fwStatus = await firewall.GetStatusAsync();
        Assert.NotNull(fwStatus);
        Assert.True(fwStatus.ManagedRuleCount >= 0);
    }

    private sealed class FakeTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now = _now.Add(delta);
    }

    private sealed class FixedAnswerUpstream(IPAddress answerIp) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWireFormat,
            DnsResolverEndpoint endpoint,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            var resp = BuildAResponse(queryWireFormat.Span, answerIp, 120);
            return Task.FromResult(new DnsQueryResult(true, resp, 4.2, endpoint.Id, Protocol));
        }

        private static byte[] BuildAResponse(ReadOnlySpan<byte> query, IPAddress ip, uint ttl)
        {
            var qLen = query.Length;
            var buffer = new byte[qLen + 16];
            query.CopyTo(buffer);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), 0x8180); // QR=1, NoError
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(6, 2), 1);      // ANCOUNT=1
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(qLen, 2), 0xC00C); // Pointer to QNAME
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(qLen + 2, 2), 1);   // Type A
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(qLen + 4, 2), 1);   // Class IN
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(qLen + 6, 4), ttl);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(qLen + 10, 2), 4);
            ip.TryWriteBytes(buffer.AsSpan(qLen + 12, 4), out _);
            return buffer;
        }
    }

    private sealed class MemoryStore(AppSettings initial) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(initial, SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class StubWindowsDnsManager : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;

        public AdapterDnsBackupDocument? ReadBackup() => null;

        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
            string? targetAdapterId,
            string ipv4Dns,
            string? ipv6Dns,
            Func<CancellationToken, Task<bool>> connectivityProbe,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));

        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(
            string? targetAdapterId = null,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));

        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
