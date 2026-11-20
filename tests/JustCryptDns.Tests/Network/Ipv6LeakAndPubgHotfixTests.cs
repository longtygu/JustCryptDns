using System.Net;
using System.Net.NetworkInformation;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Wire;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Bypass;
using JustCryptDns.Service;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class Ipv6LeakAndPubgHotfixTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-v152-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public Ipv6LeakAndPubgHotfixTests()
    {
        _paths = new AppPaths(_root);
        _paths.EnsureCreated();
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch
        {
            // Ignore temp cleanup locks.
        }
    }

    [Theory]
    [InlineData("2402:800:20ff:109c::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("::1", false)]
    [InlineData("fec0:0:0:ffff::1", false)]
    [InlineData("fec0:0:0:ffff::2", false)]
    [InlineData("fec0:0:0:ffff::3", false)]
    [InlineData("127.0.0.2", false)]
    [InlineData("8.8.8.8", false)]
    public void DnsEngineService_IsExternalIpv6Dns_ClassifiesCorrectly(string ipText, bool expectedExternal)
    {
        var ip = IPAddress.Parse(ipText);
        Assert.Equal(expectedExternal, DnsEngineService.IsExternalIpv6Dns(ip));
    }

    [Fact]
    public void DnsEngineService_EvaluateAdapterTrafficStatus_DetectsIpv6LeakAndCleanStates()
    {
        var listenIp = IPAddress.Parse("127.0.0.2");

        // Adapter has our IPv4 loopback + ISP IPv6 DNS -> Ipv6DnsLeakDetected
        var (leakStatus, leaking) = DnsEngineService.EvaluateAdapterTrafficStatus(
            [listenIp, IPAddress.Parse("2402:800:20ff:109c::1"), IPAddress.Parse("fe80::1")],
            listenIp,
            allowIpv6Loopback: true);
        Assert.Equal(SystemTrafficStatus.Ipv6DnsLeakDetected, leakStatus);
        Assert.NotNull(leaking);
        Assert.Contains("2402:800:20ff:109c::1", leaking!);
        Assert.Contains("fe80::1", leaking);

        // Sealed via IPv6 loopback -> clean
        var (sealedStatus, sealedLeaks) = DnsEngineService.EvaluateAdapterTrafficStatus(
            [listenIp, IPAddress.IPv6Loopback],
            listenIp,
            allowIpv6Loopback: true);
        Assert.Equal(SystemTrafficStatus.InterceptingSystemTraffic, sealedStatus);
        Assert.Null(sealedLeaks);

        // Windows fec0:0:0:ffff::1 placeholder only -> clean
        var (placeholderStatus, placeholderLeaks) = DnsEngineService.EvaluateAdapterTrafficStatus(
            [listenIp, IPAddress.Parse("fec0:0:0:ffff::1")],
            listenIp,
            allowIpv6Loopback: false);
        Assert.Equal(SystemTrafficStatus.InterceptingSystemTraffic, placeholderStatus);
        Assert.Null(placeholderLeaks);

        // Adapter missing our loopback DNS -> AdapterNotConfigured
        var (unconfiguredStatus, _) = DnsEngineService.EvaluateAdapterTrafficStatus(
            [IPAddress.Parse("8.8.8.8")],
            listenIp,
            allowIpv6Loopback: true);
        Assert.Equal(SystemTrafficStatus.AdapterNotConfigured, unconfiguredStatus);

        // Dashboard/DnsManager banner formatting preserves details + conflicting service hint
        var banner = DashboardViewModel.FormatTrafficWarning(new DnsEngineRuntimeStats
        {
            State = DnsEngineState.Running,
            ActiveResolverId = "cloudflare-doh",
            ActiveResolverName = "Cloudflare (DoH)",
            ActiveProtocol = DnsProtocol.DnsOverHttps,
            ListenEndpoint = "127.0.0.2:53",
            BoundPort = 53,
            TrafficStatus = SystemTrafficStatus.Ipv6DnsLeakDetected,
            LeakingIpv6DnsServers = leaking,
            Port53ServiceName = "dnscrypt-proxy",
            Port53OwnerDescription = "dnscrypt-proxy (PID 5084)",
        });
        Assert.NotNull(banner);
        Assert.Contains("2402:800:20ff:109c::1", banner, StringComparison.Ordinal);
        Assert.Contains("dnscrypt-proxy", banner, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WindowsNetworkDnsService_AppliesIpv6LoopbackAndIgnoresDisabledIpv6Errors()
    {
        var configurator = new DualStackFakeConfigurator
        {
            HasAdapterIpv6 = true,
            CurrentIpv4 = ["192.168.1.1"],
            CurrentIpv6 = ["2402:800:20ff:109c::1"],
        };
        var netInfo = new StaticNetworkInfoService(
        [
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("2402:800:20ff:109c::1"),
        ], hasIpv6Addresses: true);
        using var service = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance, configurator);

        var applied = await service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", "::1", _ => Task.FromResult(true));
        Assert.True(applied.Success, applied.ErrorMessage);
        Assert.Equal(["127.0.0.2"], configurator.CurrentIpv4);
        Assert.Equal(["::1"], configurator.CurrentIpv6);

        var restored = await service.RestoreOriginalDnsAsync();
        Assert.True(restored.Success, restored.ErrorMessage);
        Assert.True(configurator.UsedDhcpIpv6);

        // When adapter has IPv6 disabled and netsh IPv6 fails, IPv4 apply must NOT roll back.
        var noV6Net = new StaticNetworkInfoService([IPAddress.Parse("192.168.1.1")], hasIpv6Addresses: false);
        var noV6Config = new DualStackFakeConfigurator { HasAdapterIpv6 = false, FailIpv6 = true };
        using var noV6Service = new WindowsNetworkDnsService(_paths, noV6Net, NullLogger<WindowsNetworkDnsService>.Instance, noV6Config);

        var ok = await noV6Service.ApplyLocalProxyDnsAsync(null, "127.0.0.2", "::1", _ => Task.FromResult(true));
        Assert.True(ok.Success, ok.ErrorMessage);
        Assert.False(ok.RolledBack);
        Assert.Equal(["127.0.0.2"], noV6Config.CurrentIpv4);
    }

    [Theory]
    [InlineData("zk-ga-pcprod-b2a1cc0c.acs.pubg.com:40002", "zk-ga-pcprod-b2a1cc0c.acs.pubg.com", 40002, true)]
    [InlineData("https://prod-live-front.playbattlegrounds.com/test?a=1", "prod-live-front.playbattlegrounds.com", 443, false)]
    [InlineData("https://example.com:8443/path", "example.com", 8443, true)]
    [InlineData("pubg.com", "pubg.com", 443, false)]
    [InlineData("[::1]:8443", "::1", 8443, true)]
    public void BypassRuleMatcher_ParseHostAndPort_ParsesAllFormats(
        string rawInput,
        string expectedHost,
        int expectedPort,
        bool expectedExplicit)
    {
        var (host, port, explicitPort) = BypassRuleMatcher.ParseHostAndPort(rawInput);
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
        Assert.Equal(expectedExplicit, explicitPort);
    }

    [Fact]
    public async Task SettingsMigration_V16ToV17_AppendsPubgRulesWithoutDuplicatingOrDroppingCustom()
    {
        const string v16Json = """
            {
              "schemaVersion": 16,
              "bypass": {
                "rules": [
                  {
                    "id": "gaming-pubg",
                    "name": "PUBG",
                    "pattern": "pubg.com",
                    "matchKind": "DomainSuffix",
                    "mode": "AutoHybrid",
                    "category": "Gaming",
                    "enabled": true,
                    "isBuiltIn": true
                  },
                  {
                    "id": "custom-my-site",
                    "name": "My Site",
                    "pattern": "example.org",
                    "matchKind": "Exact",
                    "mode": "DpiFragment",
                    "category": "Custom",
                    "enabled": true,
                    "isBuiltIn": false
                  }
                ]
              }
            }
            """;
        await File.WriteAllTextAsync(_paths.SettingsFile, v16Json);

        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var loaded = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, loaded.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);

        var rules = loaded.Settings.Bypass.Rules!;
        Assert.Single(rules, r => r.Id == "gaming-pubg");
        Assert.Contains(rules, r => r.Id == "gaming-playbattlegrounds" && r.Pattern == "playbattlegrounds.com" && r.Enabled);
        Assert.Contains(rules, r => r.Id == "gaming-krafton" && r.Pattern == "krafton.com" && r.Enabled);
        Assert.Contains(rules, r => r.Id == "custom-my-site" && r.Pattern == "example.org");
    }

    [Fact]
    public async Task ServiceStateManager_InitializeFromSettings_AutoSyncsDnsLeakGuardWhenEnabled()
    {
        var freePort = PortConflictDetector.GetEphemeralPort(IPAddress.Loopback);
        var store = new MemorySettingsStore(new AppSettings
        {
            General = { AutoStartDnsEngine = true, EnableGamingModeOnStartup = false },
            Dns = { ListenAddress = "127.0.0.1", ListenPort = freePort, ConfigureWindowsAdapter = false, ActiveResolverId = "cloudflare-doh" },
            Bypass = { IsBypassEnabled = false, AutoStartWithDnsEngine = false },
            Connections = { EnableDnsLeakGuard = true },
        });
        using var settings = new SettingsService(store, NullLogger<SettingsService>.Instance);
        var netInfo = new StaticNetworkInfoService([IPAddress.Parse("192.168.1.1")], hasIpv6Addresses: false);
        var winDns = new WindowsNetworkDnsService(_paths, netInfo, NullLogger<WindowsNetworkDnsService>.Instance, new DualStackFakeConfigurator());
        await using var dnsCrypt = new DnsCryptProxyManager(_paths, NullLogger<DnsCryptProxyManager>.Instance);
        await using var engine = new DnsEngineService(
            settings,
            dnsCrypt,
            winDns,
            NullLogger<DnsEngineService>.Instance,
            [new FakeDohUpstream()]);
        var fakeFw = new RecordingFirewallManager();

        var stateManager = new ServiceStateManager(
            settings,
            engine,
            winDns,
            NullLogger<ServiceStateManager>.Instance,
            firewallManager: fakeFw,
            networkInfo: netInfo);

        await stateManager.InitializeFromSettingsAsync();

        var syncCall = Assert.Single(fakeFw.Payloads);
        Assert.True(syncCall.EnableDnsLeakGuard);
        Assert.False(syncCall.EnableEmergencyLockdown);
        Assert.NotNull(syncCall.AllowedDnsResolverIps);
    }

    private sealed class FakeDohUpstream : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            var resp = DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError);
            return Task.FromResult(new DnsQueryResult(true, resp, 5.0, resolver.Id, Protocol));
        }
    }

    private sealed class RecordingFirewallManager : IWindowsFirewallManager
    {
        public List<FirewallSyncRequestPayload> Payloads { get; } = [];

        public Task<FirewallSyncResult> SyncRulesAsync(IReadOnlyList<BlockedIpRule> rules, ProtectedIpContext protectedContext, CancellationToken cancellationToken = default) =>
            SyncSecurityPoliciesAsync(new FirewallSyncRequestPayload(rules), protectedContext, cancellationToken);

        public Task<FirewallSyncResult> SyncSecurityPoliciesAsync(FirewallSyncRequestPayload payload, ProtectedIpContext protectedContext, CancellationToken cancellationToken = default)
        {
            Payloads.Add(payload);
            return Task.FromResult(new FirewallSyncResult(true, payload.Rules.Count, 0, 0, true, false, null));
        }

        public Task<FirewallSyncResult> ClearLockdownAndLeakGuardAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallSyncResult(true, 0, 0, 0, true, false, null));

        public Task<FirewallSyncResult> ClearAllManagedRulesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallSyncResult(true, 0, 0, 0, true, false, null));

        public Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new FirewallStatusSnapshot(0, false, false, []));
    }

    private sealed class StaticNetworkInfoService(IReadOnlyList<IPAddress> dnsServers, bool hasIpv6Addresses) : INetworkInfoService
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
                Id = "{TEST-DUAL-STACK}",
                Name = "Ethernet",
                Description = "Test Adapter",
                Kind = AdapterKind.Ethernet,
                Status = OperationalStatus.Up,
                IPv4Addresses = [IPAddress.Parse("192.168.1.10")],
                IPv6Addresses = hasIpv6Addresses ? [IPAddress.Parse("2402:800:1::10")] : [],
                Gateways = [IPAddress.Parse("192.168.1.1")],
                DnsServers = dnsServers,
            };
            return new NetworkSnapshot([adapter], adapter, LocalConnectivity.GatewayAvailable, DateTimeOffset.UtcNow);
        }
    }

    private sealed class DualStackFakeConfigurator : IAdapterDnsConfigurator
    {
        public bool HasAdapterIpv6 { get; set; }
        public bool FailIpv6 { get; set; }
        public bool UsedDhcpIpv6 { get; private set; }
        public bool IsIpv6Dhcp { get; set; } = true;
        public List<string> CurrentIpv4 { get; set; } = ["9.9.9.9"];
        public List<string> CurrentIpv6 { get; set; } = [];

        public (bool IsIpv4Dhcp, IReadOnlyList<string> StaticIpv4, bool IsIpv6Dhcp, IReadOnlyList<string> StaticIpv6) ReadStaticConfiguration(NetworkAdapterInfo adapter) =>
            (false, CurrentIpv4.ToList(), IsIpv6Dhcp, HasAdapterIpv6 ? CurrentIpv6.ToList() : []);

        public Task<(bool Success, string? Error)> SetDnsAsync(
            string adapterName,
            bool ipv6,
            bool useDhcp,
            IReadOnlyList<string> servers,
            CancellationToken cancellationToken = default)
        {
            if (ipv6 && FailIpv6)
            {
                return Task.FromResult<(bool, string?)>((false, "IPv6 not bound on adapter"));
            }

            if (!ipv6)
            {
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

    private sealed class MemorySettingsStore(AppSettings initial) : ISettingsStore
    {
        public SettingsLoadResult Load() => new(initial.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
