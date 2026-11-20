using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using JustCryptDns.App.Composition;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using JustCryptDns.Infrastructure.Storage;
using JustCryptDns.Infrastructure.Windows;
using JustCryptDns.Network.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace JustCryptDns.Tests.Network;

public sealed class SecurityShieldTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "jcd-shield-tests", Guid.NewGuid().ToString("N"));
    private readonly AppPaths _paths;

    public SecurityShieldTests()
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
    public void OfflineOrganizationDatabase_ResolvesMajorOrgsVnIspsAndDomainsWithoutNetwork()
    {
        Assert.True(OfflineOrganizationDatabase.TryResolve("1.1.1.1", null, out var cf));
        Assert.Contains("Cloudflare", cf.Organization, StringComparison.OrdinalIgnoreCase);

        Assert.True(OfflineOrganizationDatabase.TryResolve("8.8.8.8", null, out var google));
        Assert.Contains("Google", google.Organization, StringComparison.OrdinalIgnoreCase);

        Assert.True(OfflineOrganizationDatabase.TryResolve("155.133.240.10", null, out var steam));
        Assert.Contains("Steam", steam.Organization, StringComparison.OrdinalIgnoreCase);

        Assert.True(OfflineOrganizationDatabase.TryResolve("14.161.10.20", null, out var vnpt));
        Assert.Contains("VNPT", vnpt.Organization, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("VN", vnpt.CountryCode);

        // Domain fallback when IP falls outside curated prefix list
        Assert.True(OfflineOrganizationDatabase.TryResolve("203.0.113.55", "cdn.zalo.me", out var zalo));
        Assert.Contains("Zalo", zalo.Organization, StringComparison.OrdinalIgnoreCase);

        // LAN and wildcards never attributed
        Assert.False(OfflineOrganizationDatabase.TryResolve("127.0.0.1", "cloudflare.com", out _));
        Assert.False(OfflineOrganizationDatabase.TryResolve("192.168.1.10", null, out _));
        Assert.False(OfflineOrganizationDatabase.TryResolve("*", null, out _));
    }

    [Fact]
    public void IpRangeComplement_CarvesLoopbackAndResolversFromDnsLeakAndLockdownRanges()
    {
        var leakV4 = IpRangeComplement.BuildDnsLeakBlockRangesV4(["1.1.1.1", "9.9.9.9"]);
        var parsedRanges = ParseRangeList(leakV4, AddressFamily.InterNetwork);

        // Loopback, LAN DNS resolvers allowed, other external DNS IPs covered
        Assert.False(ContainsAny(parsedRanges, IPAddress.Loopback));
        Assert.False(ContainsAny(parsedRanges, IPAddress.Parse("1.1.1.1")));
        Assert.False(ContainsAny(parsedRanges, IPAddress.Parse("9.9.9.9")));
        Assert.True(ContainsAny(parsedRanges, IPAddress.Parse("8.8.8.8")));
        Assert.True(ContainsAny(parsedRanges, IPAddress.Parse("203.0.113.5")));

        var leakV6 = IpRangeComplement.BuildDnsLeakBlockRangesV6(["2606:4700:4700::1111"]);
        var parsedV6 = ParseRangeList(leakV6, AddressFamily.InterNetworkV6);
        Assert.False(ContainsAny(parsedV6, IPAddress.IPv6Loopback));
        Assert.False(ContainsAny(parsedV6, IPAddress.Parse("2606:4700:4700::1111")));
        Assert.True(ContainsAny(parsedV6, IPAddress.Parse("2001:4860:4860::8888")));

        var lockdownV4 = ParseRangeList(IpRangeComplement.BuildLockdownBlockRangesV4(), AddressFamily.InterNetwork);
        Assert.False(ContainsAny(lockdownV4, IPAddress.Loopback));
        Assert.False(ContainsAny(lockdownV4, IPAddress.Parse("192.168.1.1")));
        Assert.False(ContainsAny(lockdownV4, IPAddress.Parse("10.0.0.5")));
        Assert.True(ContainsAny(lockdownV4, IPAddress.Parse("1.1.1.1")));
    }

    [Fact]
    public void AppBlockerGuard_ProtectsCriticalSystemAndOwnBinaries()
    {
        Assert.False(AppBlockerGuard.Evaluate(@"C:\Windows\System32\svchost.exe").IsValid);
        Assert.False(AppBlockerGuard.Evaluate(@"C:\Windows\explorer.exe").IsValid);
        Assert.False(AppBlockerGuard.Evaluate(@"C:\Program Files\JustCryptDns\JustCryptDns.exe").IsValid);
        Assert.False(AppBlockerGuard.Evaluate(@"C:\Custom\App\dnscrypt-proxy.exe").IsValid);
        Assert.False(AppBlockerGuard.Evaluate(Path.Combine(_paths.DataDirectory, "helper.exe"), _paths.DataDirectory).IsValid);
        Assert.False(AppBlockerGuard.Evaluate("relative\\app.exe").IsValid);
        Assert.False(AppBlockerGuard.Evaluate(@"C:\Tools\script.bat").IsValid);

        var allowed = AppBlockerGuard.Evaluate(@"C:\Program Files\Game\launcher.exe");
        Assert.True(allowed.IsValid);
        Assert.False(allowed.IsProtectedSystemApp);
        Assert.Equal(@"C:\Program Files\Game\launcher.exe", allowed.NormalizedPath);
    }

    [Fact]
    public void ProcessTrustInspector_DetectsRiskyPathsMasqueradesAndSignedWindowsBinaries()
    {
        var inspector = new ProcessTrustInspector();

        var masq = inspector.Inspect(@"C:\Users\alice\AppData\Local\Temp\svchost.exe", "svchost.exe");
        Assert.Equal(ProcessTrustLevel.Suspicious, masq.Level);
        Assert.True(masq.IsMasqueradingSystemBinary);
        Assert.True(masq.IsRiskyPath);

        var tempBin = Path.Combine(_paths.DataDirectory, "Downloads", "dropper.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(tempBin)!);
        File.WriteAllBytes(tempBin, [0x4D, 0x5A, 0x90, 0x00]); // Unsigned stub MZ header
        var riskyUnsigned = inspector.Inspect(tempBin, "dropper.exe");
        Assert.Equal(ProcessTrustLevel.Suspicious, riskyUnsigned.Level);
        Assert.True(riskyUnsigned.IsRiskyPath);

        if (OperatingSystem.IsWindows())
        {
            var notepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
            if (File.Exists(notepad))
            {
                var verified = inspector.Inspect(notepad, "notepad.exe");
                Assert.Equal(ProcessTrustLevel.TrustedSystem, verified.Level);
            }
        }
    }

    [Fact]
    public async Task ThreatIntelligenceService_ParsesFeedsMatchesSafelyAndPersistsToDisk()
    {
        const string fakeFeodo = """
            # Feodo Tracker C2 list
            198.51.100.77
            127.0.0.1
            1.1.1.1
            """;
        const string fakeDrop = """
            ; Spamhaus DROP list
            203.0.113.0/24 ; SBL999999
            192.168.0.0/16 ; SBL000001
            """;

        using var handler = new StubFeedHttpHandler(fakeFeodo, fakeDrop);
        using var http = new HttpClient(handler);
        using var intel = new ThreatIntelligenceService(_paths, NullLogger<ThreatIntelligenceService>.Instance, http);

        var status = await intel.RefreshFeedsAsync();
        Assert.Equal(5, status.IndicatorCount);
        Assert.Equal(2, status.CidrCount);

        var protectedCtx = ProtectedIpContext.Build(null, BuiltInResolvers.All, new DnsSettings(), new BypassSettings());

        // True threat matches
        Assert.True(intel.TryMatch("198.51.100.77", protectedCtx, out var m1));
        Assert.Contains("Feodo", m1.Source, StringComparison.OrdinalIgnoreCase);

        Assert.True(intel.TryMatch("203.0.113.42", protectedCtx, out var m2));
        Assert.Contains("Spamhaus", m2.Source, StringComparison.OrdinalIgnoreCase);

        // Protected & LAN never flagged even if present in feed
        Assert.False(intel.TryMatch("127.0.0.1", protectedCtx, out _));
        Assert.False(intel.TryMatch("1.1.1.1", protectedCtx, out _));
        Assert.False(intel.TryMatch("192.168.1.5", protectedCtx, out _));

        // Reload persisted cache from disk with a new instance (offline)
        using var reloaded = new ThreatIntelligenceService(_paths, NullLogger<ThreatIntelligenceService>.Instance, http);
        Assert.Equal(5, reloaded.GetStatus().IndicatorCount);
        Assert.True(reloaded.TryMatch("203.0.113.42", protectedCtx, out _));
    }

    [Fact]
    public async Task SettingsV15_MigratesToV16_AndResolvesSecurityShieldDi()
    {
        await File.WriteAllTextAsync(_paths.SettingsFile, """{ "schemaVersion": 15, "general": { "language": "vi" } }""");
        var store = new JsonSettingsStore(_paths, NullLogger<JsonSettingsStore>.Instance);
        var loaded = store.Load();

        Assert.Equal(SettingsLoadOutcome.Migrated, loaded.Outcome);
        Assert.Equal(AppSettings.CurrentSchemaVersion, loaded.Settings.SchemaVersion);
        Assert.False(loaded.Settings.Connections.EnableDnsLeakGuard);
        Assert.True(loaded.Settings.Connections.EnableThreatIntelligence);
        Assert.True(loaded.Settings.Connections.VerifyProcessSignatures);
        Assert.Empty(loaded.Settings.Connections.BlockedApps);

        loaded.Settings.Connections.BlockedApps.Add(new BlockedAppRule
        {
            ExecutablePath = @"C:\Tools\telemetry_client.exe",
            ProcessName = "telemetry_client.exe",
            IsEnabled = true,
        });
        await store.SaveAsync(loaded.Settings);

        var reloaded = store.Load();
        Assert.Single(reloaded.Settings.Connections.BlockedApps);

        await using var provider = ServiceRegistration.Build(_paths, NullLoggerFactory.Instance, store, reloaded);
        Assert.NotNull(provider.GetService(typeof(IProcessTrustInspector)));
        Assert.NotNull(provider.GetService(typeof(IThreatIntelligenceService)));
        using var vm = provider.GetService(typeof(ConnectionMonitorViewModel)) as ConnectionMonitorViewModel;
        Assert.NotNull(vm);
    }

    private sealed class StubFeedHttpHandler(string feodoBody, string dropBody) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.RequestUri?.AbsoluteUri.Contains("feodo", StringComparison.OrdinalIgnoreCase) == true
                ? feodoBody
                : dropBody;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
        }
    }

    private static List<(UInt128 Start, UInt128 End)> ParseRangeList(string csv, AddressFamily family)
    {
        var list = new List<(UInt128, UInt128)>();
        foreach (var part in csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-', StringComparison.Ordinal);
            if (dash < 0)
            {
                var v = IpToUInt128(IPAddress.Parse(part), family);
                list.Add((v, v));
            }
            else
            {
                var s = IpToUInt128(IPAddress.Parse(part[..dash]), family);
                var e = IpToUInt128(IPAddress.Parse(part[(dash + 1)..]), family);
                list.Add((s, e));
            }
        }

        return list;
    }

    private static bool ContainsAny(List<(UInt128 Start, UInt128 End)> ranges, IPAddress ip)
    {
        var v = IpToUInt128(ip, ip.AddressFamily);
        return ranges.Any(r => v >= r.Start && v <= r.End);
    }

    private static UInt128 IpToUInt128(IPAddress ip, AddressFamily expected)
    {
        if (ip.AddressFamily != expected)
        {
            throw new InvalidOperationException("Unexpected family.");
        }

        if (expected == AddressFamily.InterNetwork)
        {
            Span<byte> b4 = stackalloc byte[4];
            ip.TryWriteBytes(b4, out _);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b4);
        }

        Span<byte> b16 = stackalloc byte[16];
        ip.TryWriteBytes(b16, out _);
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt128BigEndian(b16);
    }
}
