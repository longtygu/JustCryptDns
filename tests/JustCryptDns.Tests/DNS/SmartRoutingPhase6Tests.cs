using System.Globalization;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Routing;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.DNS;

public sealed class SmartRoutingPhase6Tests
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

    private sealed class RecordingUpstreamClient(DnsProtocol protocol) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => protocol;

        public List<string> QueriedResolverIds { get; } = [];

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            lock (QueriedResolverIds)
            {
                QueriedResolverIds.Add(resolver.Id);
            }

            var response = DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError);
            return Task.FromResult(new DnsQueryResult(true, response, 11.2, resolver.Id, Protocol));
        }
    }

    private sealed class NoopDnsCryptManager : IDnsCryptProxyManager
    {
        public bool IsInstalled => true;
        public bool IsRunning => true;
        public string? InstalledVersion => "2.1.5";
        public string ExecutablePath => "dnscrypt-proxy.exe";
        public Task<string?> DetectInstalledVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>("2.1.5");
        public Task<(bool Success, string? Version, string? Error)> InstallOrUpdateAsync(HttpClient? httpClient = null, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?, string?)>((true, "2.1.5", null));
        public Task<(bool Success, string? Error)> EnsureRunningAsync(DnsResolverEndpoint resolver, int internalPort, CancellationToken cancellationToken = default) => Task.FromResult<(bool, string?)>((true, null));
        public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoopWindowsDnsManager : IWindowsDnsManager
    {
        public bool HasActiveBackup() => false;
        public AdapterDnsBackupDocument? ReadBackup() => null;
        public Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(string? targetAdapterId, string ipv4Loopback, string? ipv6Loopback, Func<CancellationToken, Task<bool>> connectivityProbe, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(string? targetAdapterId = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsDnsOperationResult(true));
        public Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private static (DnsRoutingService Routing, ResolverLibraryService Resolvers, ISettingsService Settings) CreateServices()
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var resolvers = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance);
        var routing = new DnsRoutingService(settings, NullLogger<DnsRoutingService>.Instance, resolvers);
        return (routing, resolvers, settings);
    }

    [Fact]
    public void RoutingMatcher_MatchesExactSuffixAndWildcardAccurately()
    {
        // Exact
        Assert.True(RoutingMatcher.IsMatch("steamcommunity.com", "steamcommunity.com", RoutingMatchKind.Exact));
        Assert.False(RoutingMatcher.IsMatch("sub.steamcommunity.com", "steamcommunity.com", RoutingMatchKind.Exact));

        // DomainSuffix
        Assert.True(RoutingMatcher.IsMatch("steampowered.com", "steampowered.com", RoutingMatchKind.DomainSuffix));
        Assert.True(RoutingMatcher.IsMatch("store.steampowered.com", "steampowered.com", RoutingMatchKind.DomainSuffix));
        Assert.False(RoutingMatcher.IsMatch("fakesteampowered.com", "steampowered.com", RoutingMatchKind.DomainSuffix));

        // Wildcard
        Assert.True(RoutingMatcher.IsMatch("riotgames.com", "*.riotgames.com", RoutingMatchKind.Wildcard));
        Assert.True(RoutingMatcher.IsMatch("auth.riotgames.com", "*.riotgames.com", RoutingMatchKind.Wildcard));
        Assert.True(RoutingMatcher.IsMatch("ads.example.net", "ads.*", RoutingMatchKind.Wildcard));
        Assert.False(RoutingMatcher.IsMatch("cdn.example.net", "ads.*", RoutingMatchKind.Wildcard));

        // Validation
        Assert.False(RoutingMatcher.IsValidPattern("*.invalid.com", RoutingMatchKind.Exact, out _));
        Assert.True(RoutingMatcher.IsValidPattern("*.valid.com", RoutingMatchKind.Wildcard, out _));
    }

    [Fact]
    public async Task PriorityAndEnableDisable_DetermineWinningRuleOrFallback()
    {
        var (routing, _, _) = CreateServices();
        await routing.SetActiveProfileAsync(BuiltInRoutingProfiles.CustomProfileId);
        await routing.SetProfileFallbackResolverAsync(BuiltInRoutingProfiles.CustomProfileId, "quad9-doh");

        // Add broad rule (priority 50 -> cloudflare-doh) and specific higher-priority rule (priority 5 -> mullvad-doh)
        await routing.AddOrUpdateRuleAsync(new DnsRoutingRule
        {
            Id = "broad-gaming",
            ProfileId = BuiltInRoutingProfiles.CustomProfileId,
            Name = "All Steam",
            Pattern = "steampowered.com",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "cloudflare-doh",
            Priority = 50,
            IsEnabled = true,
        });

        await routing.AddOrUpdateRuleAsync(new DnsRoutingRule
        {
            Id = "specific-store",
            ProfileId = BuiltInRoutingProfiles.CustomProfileId,
            Name = "Steam Store Override",
            Pattern = "store.steampowered.com",
            MatchKind = RoutingMatchKind.Exact,
            ResolverId = "mullvad-doh",
            Priority = 5,
            IsEnabled = true,
        });

        var decision1 = routing.ResolveForDomain("store.steampowered.com");
        Assert.False(decision1.IsFallback);
        Assert.Equal("specific-store", decision1.MatchedRuleId);
        Assert.Equal("mullvad-doh", decision1.ResolverId);

        // Disable high-priority rule -> falls through to priority 50 rule
        await routing.SetRuleEnabledAsync("specific-store", false);
        var decision2 = routing.ResolveForDomain("store.steampowered.com");
        Assert.False(decision2.IsFallback);
        Assert.Equal("broad-gaming", decision2.MatchedRuleId);
        Assert.Equal("cloudflare-doh", decision2.ResolverId);

        // Unmatched domain -> falls back to profile fallback (quad9-doh)
        var fallbackDecision = routing.ResolveForDomain("unmatched-domain.example");
        Assert.True(fallbackDecision.IsFallback);
        Assert.Equal("quad9-doh", fallbackDecision.ResolverId);
    }

    [Fact]
    public async Task DnsEngine_RoutesQueriesByDomainRules_AndLogsDecisions()
    {
        var (routing, resolvers, settings) = CreateServices();
        await settings.UpdateAsync(s =>
        {
            s.Dns.ListenPort = 0;
            s.Dns.ConfigureWindowsAdapter = false;
        });

        await routing.SetActiveProfileAsync(BuiltInRoutingProfiles.GamingProfileId);
        await routing.AddOrUpdateRuleAsync(new DnsRoutingRule
        {
            Id = "dot-security-rule",
            ProfileId = BuiltInRoutingProfiles.GamingProfileId,
            Name = "Security Domain via DoT",
            Pattern = "secure.bank.example",
            MatchKind = RoutingMatchKind.DomainSuffix,
            ResolverId = "quad9-dot",
            Priority = 5,
            IsEnabled = true,
        });

        var dohUpstream = new RecordingUpstreamClient(DnsProtocol.DnsOverHttps);
        var dotUpstream = new RecordingUpstreamClient(DnsProtocol.DnsOverTls);
        await using var engine = new DnsEngineService(
            settings,
            new NoopDnsCryptManager(),
            new NoopWindowsDnsManager(),
            NullLogger<DnsEngineService>.Instance,
            [dohUpstream, dotUpstream],
            resolvers,
            routing);

        var (started, err) = await engine.StartAsync();
        Assert.True(started, err);

        var port = int.Parse(engine.GetStats().ListenEndpoint.Split(':')[1], CultureInfo.InvariantCulture);
        using var udp = new UdpClient();

        // Query 1: store.steampowered.com -> Gaming profile routes to cloudflare-doh (DoH)
        var q1 = DnsPacket.CreateQuery("store.steampowered.com", DnsRecordType.A);
        await udp.SendAsync(q1, new IPEndPoint(IPAddress.Loopback, port));
        var r1 = await udp.ReceiveAsync();
        Assert.True(r1.Buffer.Length >= DnsPacket.HeaderSize);

        // Query 2: api.secure.bank.example -> routes to quad9-dot (DoT)
        var q2 = DnsPacket.CreateQuery("api.secure.bank.example", DnsRecordType.A);
        await udp.SendAsync(q2, new IPEndPoint(IPAddress.Loopback, port));
        var r2 = await udp.ReceiveAsync();
        Assert.True(r2.Buffer.Length >= DnsPacket.HeaderSize);

        Assert.Contains("cloudflare-doh", dohUpstream.QueriedResolverIds);
        Assert.Contains("quad9-dot", dotUpstream.QueriedResolverIds);

        var logs = routing.GetRecentLogs();
        Assert.Equal(2, logs.Count);
        Assert.Contains(logs, l => l.Domain == "api.secure.bank.example" && l.MatchedRuleName == "Security Domain via DoT");
        Assert.Contains(logs, l => l.Domain == "store.steampowered.com" && l.MatchedRuleName == "Steam Store & CDN");
    }

    [Fact]
    public async Task ViewModel_SupportsProfileCreationRuleEditingAndDomainTesting()
    {
        var (routing, resolvers, _) = CreateServices();
        using var vm = new RoutingViewModel(routing, resolvers);

        Assert.Equal(BuiltInRoutingProfiles.GamingProfileId, vm.SelectedProfile.Id);
        Assert.NotEmpty(vm.ProfileRules);

        vm.TestDomainInput = "auth.riotgames.com";
        vm.TestDomainCommand.Execute(null);
        Assert.NotNull(vm.LastTestDecision);
        Assert.False(vm.LastTestDecision!.IsFallback);
        Assert.Equal("Riot Games", vm.LastTestDecision.MatchedRuleName);

        // Create custom profile
        vm.NewProfileName = "Work VPN";
        await vm.AddProfileCommand.ExecuteAsync(null);
        Assert.Equal("Work VPN", vm.SelectedProfile.Name);
        Assert.True(vm.CanDeleteSelectedProfile);

        // Add rule to custom profile
        vm.OpenAddRuleCommand.Execute(null);
        vm.RuleName = "Internal Corp";
        vm.RulePattern = "corp.internal";
        vm.RuleMatchKind = RoutingMatchKind.DomainSuffix;
        vm.RulePriorityText = "15";
        await vm.SaveRuleCommand.ExecuteAsync(null);

        Assert.Single(vm.ProfileRules);
        Assert.Equal("Internal Corp", vm.ProfileRules[0].Name);
    }
}
