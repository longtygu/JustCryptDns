using System.Net;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.DNS;

public sealed class ResolverLibraryPhase5Tests
{
    private sealed class MemorySettingsStore : ISettingsStore
    {
        private AppSettings _current = new();

        public SettingsLoadResult Load() => new(_current.Clone(), SettingsLoadOutcome.Loaded);

        public Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
        {
            _current = settings.Clone();
            return Task.CompletedTask;
        }
    }

    private sealed class FakeUpstreamClient(DnsProtocol protocol, bool succeed = true, double latencyMs = 14.5) : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => protocol;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            if (!succeed)
            {
                return Task.FromResult(new DnsQueryResult(false, [], latencyMs, resolver.Id, Protocol, "Simulated timeout"));
            }

            var response = DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NoError);
            return Task.FromResult(new DnsQueryResult(true, response, latencyMs, resolver.Id, Protocol));
        }
    }

    private sealed class FakeDnsEngine : IDnsEngine
    {
        public string SwitchedResolverId { get; private set; } = BuiltInResolvers.DefaultResolverId;

        public event EventHandler<DnsEngineRuntimeStats>? StateChanged
        {
            add { }
            remove { }
        }

        public DnsEngineRuntimeStats GetStats() => new()
        {
            State = DnsEngineState.Running,
            ActiveResolverId = SwitchedResolverId,
            ActiveResolverName = SwitchedResolverId,
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
            SwitchedResolverId = resolverId;
            return Task.FromResult<(bool, string?)>((true, null));
        }

        public Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new DnsQueryResult(true, [], 10.0, SwitchedResolverId, DnsProtocol.DnsOverHttps));

        public Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult((true, 10.0, "OK"));

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private static (ResolverLibraryService Library, ISettingsService Settings) CreateService(bool upstreamSucceeds = true)
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
        var upstreams = new IDnsUpstreamClient[]
        {
            new FakeUpstreamClient(DnsProtocol.DnsOverHttps, upstreamSucceeds, 12.4),
            new FakeUpstreamClient(DnsProtocol.DnsOverTls, upstreamSucceeds, 18.2),
            new FakeUpstreamClient(DnsProtocol.DnsCrypt, upstreamSucceeds, 15.0),
            new FakeUpstreamClient(DnsProtocol.UdpTcp, upstreamSucceeds, 9.1),
        };
        var library = new ResolverLibraryService(settings, NullLogger<ResolverLibraryService>.Instance, upstreams);
        return (library, settings);
    }

    [Fact]
    public void BuiltInResolvers_IncludeAllNineRequiredProviders_AndAllPassValidation()
    {
        var providers = BuiltInResolvers.All.Select(r => r.Provider).Distinct(StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);

        string[] requiredProviders =
        [
            "Cloudflare",
            "Google Public DNS",
            "Quad9",
            "OpenDNS",
            "AdGuard DNS",
            "Control D",
            "NextDNS",
            "Mullvad DNS",
            "DNS0",
        ];

        foreach (var provider in requiredProviders)
        {
            Assert.Contains(provider, providers);
        }

        foreach (var resolver in BuiltInResolvers.All)
        {
            var validation = ResolverValidator.Validate(resolver);
            Assert.True(validation.IsValid, $"Built-in resolver {resolver.Id} failed validation: {validation.ErrorMessage}");
            Assert.False(string.IsNullOrWhiteSpace(resolver.PrimaryIpv6), $"Built-in resolver {resolver.Id} missing IPv6");
        }
    }

    [Fact]
    public void ResolverValidator_ValidatesEachProtocolAndRejectsMalformedInputs()
    {
        var validDoh = BuiltInResolvers.GetByIdOrDefault("cloudflare-doh");
        Assert.True(ResolverValidator.Validate(validDoh).IsValid);

        Assert.False(ResolverValidator.Validate(validDoh with { Name = " " }).IsValid);
        Assert.False(ResolverValidator.Validate(validDoh with { Provider = "" }).IsValid);
        Assert.False(ResolverValidator.Validate(validDoh with { Port = 70000 }).IsValid);
        Assert.False(ResolverValidator.Validate(validDoh with { PrimaryIp = "999.999.1.1" }).IsValid);
        Assert.False(ResolverValidator.Validate(validDoh with { PrimaryIpv6 = "not-ipv6" }).IsValid);
        Assert.False(ResolverValidator.Validate(validDoh with { Endpoint = "http://insecure.example/dns-query" }).IsValid);

        var dot = validDoh with { Protocol = DnsProtocol.DnsOverTls, Endpoint = "dns.quad9.net", Port = 853 };
        Assert.True(ResolverValidator.Validate(dot).IsValid);
        Assert.False(ResolverValidator.Validate(dot with { Endpoint = "https://dns.quad9.net" }).IsValid);

        var dnscrypt = BuiltInResolvers.GetByIdOrDefault("quad9-dnscrypt");
        Assert.True(ResolverValidator.Validate(dnscrypt).IsValid);
        Assert.False(ResolverValidator.Validate(dnscrypt with { Endpoint = "sdns://invalid!" }).IsValid);

        var udp = validDoh with { Protocol = DnsProtocol.UdpTcp, Endpoint = "1.1.1.1", Port = 53 };
        Assert.True(ResolverValidator.Validate(udp).IsValid);
        Assert.False(ResolverValidator.Validate(udp with { Endpoint = "not.an.ip.address" }).IsValid);
    }

    [Fact]
    public async Task CustomResolver_CrudAndPrimarySecondarySelection_WorkEndToEnd()
    {
        var (library, _) = CreateService();
        var initialCount = library.GetAll().Count;

        var custom = new DnsResolverEndpoint
        {
            Id = "custom-cleanbrowsing-doh",
            Name = "CleanBrowsing Security (DoH)",
            Provider = "CleanBrowsing",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://doh.cleanbrowsing.org/doh/security-filter/",
            PrimaryIp = "185.228.168.9",
            SecondaryIp = "185.228.169.9",
            PrimaryIpv6 = "2a0d:2a00:1::2",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            GroupName = "Corporate",
            IsCustom = true,
        };

        var addResult = await library.AddCustomResolverAsync(custom);
        Assert.True(addResult.Success);
        Assert.Equal(initialCount + 1, library.GetAll().Count);
        Assert.Contains("Corporate", library.GetGroups());

        // Set as primary and secondary
        var (primOk, _) = await library.SetPrimaryResolverAsync(custom.Id);
        Assert.True(primOk);
        Assert.Equal(custom.Id, library.GetPrimaryResolver().Id);

        // Update custom resolver
        var updated = custom with { Name = "CleanBrowsing Security Plus (DoH)" };
        var updateResult = await library.UpdateResolverAsync(updated);
        Assert.True(updateResult.Success);
        Assert.Equal("CleanBrowsing Security Plus (DoH)", library.GetByIdOrDefault(custom.Id).Name);

        // Disable resolver -> cannot set as secondary while disabled
        await library.SetResolverEnabledAsync(custom.Id, false);
        var (secOk, _) = await library.SetSecondaryResolverAsync(custom.Id);
        Assert.False(secOk);

        // Remove custom resolver -> primary falls back to default
        var removed = await library.RemoveCustomResolverAsync(custom.Id);
        Assert.True(removed);
        Assert.Equal(initialCount, library.GetAll().Count);
        Assert.Equal(BuiltInResolvers.DefaultResolverId, library.GetPrimaryResolver().Id);
    }

    [Fact]
    public async Task ExportAndImportProfile_RoundTripsCustomResolversAndGroups()
    {
        var (sourceLib, _) = CreateService();
        await sourceLib.AddCustomResolverAsync(new DnsResolverEndpoint
        {
            Id = "my-custom-dot",
            Name = "My Private DoT",
            Provider = "SelfHosted",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dot.example.org",
            PrimaryIp = "9.9.9.10",
            Port = 853,
            GroupName = "Homelab",
            IsCustom = true,
        });
        await sourceLib.SetPrimaryResolverAsync("my-custom-dot");
        await sourceLib.SetSecondaryResolverAsync("mullvad-doh");

        var json = sourceLib.ExportProfileJson();

        var (targetLib, _) = CreateService();
        var (importOk, importedCount, err) = await targetLib.ImportProfileJsonAsync(json);

        Assert.True(importOk, err);
        Assert.Equal(1, importedCount);
        Assert.Equal("my-custom-dot", targetLib.GetPrimaryResolver().Id);
        Assert.Equal("mullvad-doh", targetLib.GetSecondaryResolver().Id);
        Assert.Contains("Homelab", targetLib.GetGroups());
    }

    [Fact]
    public async Task CheckHealthAsync_MeasuresLatencyAndComputesReliabilityScore()
    {
        var (library, _) = CreateService(upstreamSucceeds: true);

        var status = await library.CheckHealthAsync("cloudflare-doh");
        Assert.True(status.IsAvailable);
        Assert.NotNull(status.LastLatencyMs);
        Assert.True(status.ReliabilityScore > 90.0);
        Assert.Equal(1, status.TotalProbes);
        Assert.Equal(1, status.SuccessfulProbes);

        var allStatuses = await library.CheckAllEnabledHealthAsync();
        Assert.Equal(library.GetEnabled().Count, allStatuses.Count);
        Assert.All(allStatuses, s => Assert.True(s.IsAvailable));
    }

    [Fact]
    public async Task ViewModel_FiltersByGroupProtocolAndSearch_AndAddsCustomResolver()
    {
        var (library, _) = CreateService();
        var engine = new FakeDnsEngine();
        using var vm = new ResolverLibraryViewModel(library, engine);

        var total = vm.FilteredResolvers.Count;
        Assert.True(total >= 25);

        vm.SelectedProtocolFilter = "DNSCrypt";
        Assert.All(vm.FilteredResolvers, r => Assert.Equal(DnsProtocol.DnsCrypt, r.Protocol));

        vm.SelectedProtocolFilter = ResolverLibraryViewModel.AllFilterValue;
        vm.SelectedGroupFilter = ResolverGroups.Privacy;
        Assert.All(vm.FilteredResolvers, r => Assert.Equal(ResolverGroups.Privacy, r.GroupName));

        vm.SelectedGroupFilter = ResolverLibraryViewModel.AllFilterValue;
        vm.SearchQuery = "Mullvad";
        Assert.NotEmpty(vm.FilteredResolvers);
        Assert.All(vm.FilteredResolvers, r => Assert.Equal("Mullvad DNS", r.Provider));

        vm.SearchQuery = string.Empty;
        vm.OpenAddResolverCommand.Execute(null);
        Assert.True(vm.IsEditorOpen);

        vm.EditorName = "Custom Gaming DoH";
        vm.EditorProvider = "CustomNet";
        vm.EditorProtocol = DnsProtocol.DnsOverHttps;
        vm.EditorEndpoint = "https://dns.customnet.example/dns-query";
        vm.EditorPrimaryIp = "1.0.0.1";
        vm.EditorGroupName = ResolverGroups.Gaming;

        await vm.SaveEditorCommand.ExecuteAsync(null);
        Assert.False(vm.IsEditorOpen);
        Assert.Equal(total + 1, vm.TotalCount);

        var addedItem = vm.FilteredResolvers.First(r => r.Name == "Custom Gaming DoH");
        await vm.SetPrimaryCommand.ExecuteAsync(addedItem);
        Assert.Equal(addedItem.Id, engine.SwitchedResolverId);
    }
}
