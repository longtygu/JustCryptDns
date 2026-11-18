using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.DNS.Cache;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Filtering;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.DNS;

public sealed class FilteringAndCachePhase7Tests
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

    private sealed class CountingUpstreamClient : IDnsUpstreamClient
    {
        public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

        public int CallCount;

        public Task<DnsQueryResult> QueryAsync(
            ReadOnlyMemory<byte> queryWire,
            DnsResolverEndpoint resolver,
            TimeSpan timeout,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref CallCount);
            var response = CreatePositiveAResponse(queryWire.Span, IPAddress.Parse("93.184.216.34"), ttlSeconds: 120);
            return Task.FromResult(new DnsQueryResult(true, response, 8.5, resolver.Id, Protocol));
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

    private static SettingsService CreateSettings()
    {
        var store = new MemorySettingsStore();
        return new SettingsService(store, NullLogger<SettingsService>.Instance, store.Load());
    }

    private static byte[] CreatePositiveAResponse(ReadOnlySpan<byte> requestWire, IPAddress ip, uint ttlSeconds)
    {
        var baseResp = DnsPacket.CreateErrorResponse(requestWire, DnsResponseCode.NoError);
        // Set ANCOUNT = 1
        BinaryPrimitives.WriteUInt16BigEndian(baseResp.AsSpan(6, 2), 1);

        using var ms = new MemoryStream();
        ms.Write(baseResp);
        // Name pointer to offset 12 (0xC00C), Type A (1), Class IN (1), TTL, RDLENGTH 4, IPv4 bytes
        Span<byte> rr = stackalloc byte[16];
        rr[0] = 0xC0;
        rr[1] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(rr[2..4], (ushort)DnsRecordType.A);
        BinaryPrimitives.WriteUInt16BigEndian(rr[4..6], 1);
        BinaryPrimitives.WriteUInt32BigEndian(rr[6..10], ttlSeconds);
        BinaryPrimitives.WriteUInt16BigEndian(rr[10..12], 4);
        ip.GetAddressBytes().CopyTo(rr[12..16]);
        ms.Write(rr);
        return ms.ToArray();
    }

    [Fact]
    public void HostsFileParser_ParsesHostsDomainsAndAdblock_ProtectsWindows_AndRejectsHtml()
    {
        const string hostsText = """
            # Comment line
            127.0.0.1 localhost
            0.0.0.0 tracker.example.com ads.example.com
            ||badbanner.example.net^
            plain-malware.example.org
            0.0.0.0 www.msftconnecttest.com
            """;

        var (valid, domains, error) = HostsFileParser.ParseAndValidate(hostsText);
        Assert.True(valid, error);
        Assert.Contains("tracker.example.com", domains);
        Assert.Contains("ads.example.com", domains);
        Assert.Contains("badbanner.example.net", domains);
        Assert.Contains("plain-malware.example.org", domains);
        Assert.DoesNotContain("localhost", domains);
        Assert.DoesNotContain("www.msftconnecttest.com", domains);

        var (htmlValid, _, _) = HostsFileParser.ParseAndValidate("<!DOCTYPE html><html><body>404</body></html>");
        Assert.False(htmlValid);
    }

    [Fact]
    public async Task FilteringService_EnforcesEssentialGuardAllowlistAndBlocklists()
    {
        var settings = CreateSettings();
        var filtering = new DnsFilteringService(settings, NullLogger<DnsFilteringService>.Instance);

        // 1. Essential Windows domain is never blocked
        var winDecision = filtering.EvaluateDomain("www.msftconnecttest.com");
        Assert.False(winDecision.IsBlocked);
        Assert.Equal(FilterAction.AllowedByEssentialWindowsGuard, winDecision.Action);
        Assert.False(await filtering.AddCustomBlockedDomainAsync("www.msftconnecttest.com"));

        // 2. Built-in seed ad domain and its subdomain are blocked
        var adDecision = filtering.EvaluateDomain("sub.ad.doubleclick.net", recordStats: true);
        Assert.True(adDecision.IsBlocked);
        Assert.Equal(FilterAction.BlockedByBlocklist, adDecision.Action);
        Assert.Equal(1, filtering.BlockedQueryCount);

        // 3. Temporary exception overrides blocklist
        await filtering.AddAllowlistEntryAsync("doubleclick.net", "Temp test", TimeSpan.FromMinutes(15));
        var allowedDecision = filtering.EvaluateDomain("sub.ad.doubleclick.net");
        Assert.False(allowedDecision.IsBlocked);
        Assert.Equal(FilterAction.AllowedByTemporaryException, allowedDecision.Action);

        // 4. Custom hosts import adds custom blocklist
        var (impOk, impCount, impErr) = await filtering.ImportHostsTextAsync("0.0.0.0 imported-bad.example.com", "My Hosts");
        Assert.True(impOk, impErr);
        Assert.Equal(1, impCount);
        Assert.True(filtering.EvaluateDomain("imported-bad.example.com").IsBlocked);
    }

    [Fact]
    public void CacheService_RespectsTtlRewritesTransactionIdAndNeverServesExpiredRecords()
    {
        var settings = CreateSettings();
        var now = DateTimeOffset.UtcNow;
        var cache = new DnsCacheService(settings, () => now);

        var q1 = DnsPacket.CreateQuery("example.com", DnsRecordType.A, id: 0x1111);
        var resp1 = CreatePositiveAResponse(q1, IPAddress.Loopback, ttlSeconds: 30);

        cache.StoreResponse(q1, resp1);
        Assert.Equal(1, cache.GetStats().PositiveEntries);

        // Query with a different transaction ID (0x2222) within TTL
        var q2 = DnsPacket.CreateQuery("example.com", DnsRecordType.A, id: 0x2222);
        Assert.True(cache.TryGetResponse(q2, out var cachedBytes));
        Assert.True(DnsPacket.TryReadTransactionId(cachedBytes, out var txId));
        Assert.Equal((ushort)0x2222, txId);
        Assert.Equal(1, cache.GetStats().CacheHits);

        // Advance clock past 30-second TTL -> must not serve expired record
        now = now.AddSeconds(31);
        Assert.False(cache.TryGetResponse(q2, out _));
        Assert.Equal(0, cache.GetStats().CurrentEntries);
        Assert.Equal(1, cache.GetStats().ExpiredEvictions);

        // Negative response caching (NXDOMAIN)
        var nxQuery = DnsPacket.CreateQuery("missing.example.com", DnsRecordType.A, id: 0x3333);
        var nxResp = DnsPacket.CreateErrorResponse(nxQuery, DnsResponseCode.NxDomain);
        cache.StoreResponse(nxQuery, nxResp);
        Assert.Equal(1, cache.GetStats().NegativeEntries);
        Assert.True(cache.TryGetResponse(nxQuery, out _));

        // SERVFAIL must never be cached
        var failQuery = DnsPacket.CreateQuery("fail.example.com", DnsRecordType.A, id: 0x4444);
        var failResp = DnsPacket.CreateErrorResponse(failQuery, DnsResponseCode.ServFail);
        cache.StoreResponse(failQuery, failResp);
        Assert.False(cache.TryGetResponse(failQuery, out _));
    }

    [Fact]
    public async Task DnsEngine_IntegratesFilteringAndCacheInProxyPipeline()
    {
        var settings = CreateSettings();
        await settings.UpdateAsync(s =>
        {
            s.Dns.ListenPort = 0;
            s.Dns.ConfigureWindowsAdapter = false;
        });

        var filtering = new DnsFilteringService(settings, NullLogger<DnsFilteringService>.Instance);
        var cache = new DnsCacheService(settings);
        var upstream = new CountingUpstreamClient();

        await using var engine = new DnsEngineService(
            settings,
            new NoopDnsCryptManager(),
            new NoopWindowsDnsManager(),
            NullLogger<DnsEngineService>.Instance,
            [upstream],
            filteringService: filtering,
            cacheService: cache);

        var (started, err) = await engine.StartAsync();
        Assert.True(started, err);

        var port = int.Parse(engine.GetStats().ListenEndpoint.Split(':')[1], CultureInfo.InvariantCulture);
        using var udp = new UdpClient();

        // 1. Blocked domain -> NXDOMAIN without hitting upstream
        var blockedQ = DnsPacket.CreateQuery("ad.doubleclick.net", DnsRecordType.A);
        await udp.SendAsync(blockedQ, new IPEndPoint(IPAddress.Loopback, port));
        var blockedR = await udp.ReceiveAsync();
        Assert.True(DnsPacket.TryParse(blockedR.Buffer, out var parsedBlocked));
        Assert.Equal(DnsResponseCode.NxDomain, parsedBlocked!.Header.ResponseCode);
        Assert.Equal(0, upstream.CallCount);
        Assert.Equal(1, engine.GetStats().BlockedQueries);

        // 2. Allowed domain -> 1st query hits upstream, 2nd query served from cache
        var allowedQ1 = DnsPacket.CreateQuery("cached.example.com", DnsRecordType.A, id: 0x1001);
        await udp.SendAsync(allowedQ1, new IPEndPoint(IPAddress.Loopback, port));
        var allowedR1 = await udp.ReceiveAsync();
        Assert.Equal(1, upstream.CallCount);

        var allowedQ2 = DnsPacket.CreateQuery("cached.example.com", DnsRecordType.A, id: 0x1002);
        await udp.SendAsync(allowedQ2, new IPEndPoint(IPAddress.Loopback, port));
        var allowedR2 = await udp.ReceiveAsync();
        Assert.Equal(1, upstream.CallCount); // Still 1!
        Assert.True(DnsPacket.TryReadTransactionId(allowedR2.Buffer, out var id2));
        Assert.Equal((ushort)0x1002, id2);
        Assert.Equal(1, engine.GetStats().CacheHits);
    }
}
