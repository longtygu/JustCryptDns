using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Security;

public sealed record ProtectedTargetEntry(CidrNetwork Network, string ReasonCode, string Detail);

public sealed record IpBlockValidationResult(
    bool IsValid,
    bool IsProtectedViolation,
    bool RequiresConfirmation,
    CidrNetwork? NormalizedNetwork,
    string? ErrorCode,
    string? Message,
    string? WarningCode = null,
    string? WarningMessage = null);

public sealed class ProtectedIpContext
{
    private ProtectedIpContext(IReadOnlyList<ProtectedTargetEntry> entries) => Entries = entries;

    public IReadOnlyList<ProtectedTargetEntry> Entries { get; }

    public static ProtectedIpContext Build(
        NetworkSnapshot? networkSnapshot = null,
        IEnumerable<DnsResolverEndpoint>? resolvers = null,
        DnsSettings? dnsSettings = null,
        BypassSettings? bypassSettings = null,
        IDnsReverseLookupCache? reverseLookupCache = null)
    {
        var entries = new List<ProtectedTargetEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddCidr(string cidrText, string reasonCode, string detail)
        {
            if (CidrNetwork.TryParse(cidrText, out var parsed, out _) && seen.Add($"{reasonCode}|{parsed.CanonicalText}"))
            {
                entries.Add(new ProtectedTargetEntry(parsed, reasonCode, detail));
            }
        }

        void AddIp(IPAddress? ip, string reasonCode, string detail)
        {
            if (ip is null)
            {
                return;
            }

            if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
            {
                return;
            }

            var net = CidrNetwork.FromAddress(ip);
            if (seen.Add($"{reasonCode}|{net.CanonicalText}"))
            {
                entries.Add(new ProtectedTargetEntry(net, reasonCode, detail));
            }
        }

        // Mandatory core OS / loopback / unspecified / link-local protections
        AddCidr("127.0.0.0/8", "Loopback", "IPv4 loopback (127.0.0.0/8)");
        AddIp(IPAddress.IPv6Loopback, "Loopback", "IPv6 loopback (::1)");
        if (CidrNetwork.TryParse("0.0.0.0/32", out var zeroV4, out _) && seen.Add($"Unspecified|{zeroV4.CanonicalText}"))
        {
            entries.Add(new ProtectedTargetEntry(zeroV4, "Unspecified", "Unspecified IPv4 (0.0.0.0)"));
        }

        if (CidrNetwork.TryParse("::/128", out var zeroV6, out _) && seen.Add($"Unspecified|{zeroV6.CanonicalText}"))
        {
            entries.Add(new ProtectedTargetEntry(zeroV6, "Unspecified", "Unspecified IPv6 (::)"));
        }

        AddCidr("169.254.0.0/16", "LinkLocal", "IPv4 link-local (169.254.0.0/16)");
        AddCidr("fe80::/10", "LinkLocal", "IPv6 link-local (fe80::/10)");

        if (dnsSettings is not null && IPAddress.TryParse(dnsSettings.ListenAddress, out var dnsListen))
        {
            AddIp(dnsListen, "LocalDnsProxy", $"Local DNS listener ({dnsListen})");
        }

        if (bypassSettings is not null && IPAddress.TryParse(bypassSettings.ListenAddress, out var bypassListen))
        {
            AddIp(bypassListen, "LocalBypassProxy", $"Local DPI bypass proxy ({bypassListen})");
        }

        if (networkSnapshot is not null)
        {
            foreach (var adapter in networkSnapshot.Adapters)
            {
                foreach (var ip in adapter.IPv4Addresses)
                {
                    AddIp(ip, "LocalInterface", $"Adapter '{adapter.Name}' IPv4 ({ip})");
                }

                foreach (var ip in adapter.IPv6Addresses)
                {
                    AddIp(ip, "LocalInterface", $"Adapter '{adapter.Name}' IPv6 ({ip})");
                }

                foreach (var gw in adapter.Gateways)
                {
                    AddIp(gw, "DefaultGateway", $"Default gateway on '{adapter.Name}' ({gw})");
                }

                foreach (var dns in adapter.DnsServers)
                {
                    AddIp(dns, "LanDnsServer", $"Configured adapter DNS on '{adapter.Name}' ({dns})");
                }
            }
        }

        if (resolvers is not null)
        {
            foreach (var resolver in resolvers)
            {
                if (resolver is null)
                {
                    continue;
                }

                var label = $"DNS Resolver '{resolver.Name}'";
                if (IPAddress.TryParse(resolver.PrimaryIp, out var p4))
                {
                    AddIp(p4, "UpstreamDnsResolver", $"{label} ({p4})");
                }

                if (IPAddress.TryParse(resolver.SecondaryIp, out var s4))
                {
                    AddIp(s4, "UpstreamDnsResolver", $"{label} secondary ({s4})");
                }

                if (IPAddress.TryParse(resolver.PrimaryIpv6, out var p6))
                {
                    AddIp(p6, "UpstreamDnsResolver", $"{label} IPv6 ({p6})");
                }

                var endpointHost = ExtractResolverHost(resolver);
                if (!string.IsNullOrWhiteSpace(endpointHost))
                {
                    if (IPAddress.TryParse(endpointHost, out var hostIp))
                    {
                        AddIp(hostIp, "UpstreamDnsResolver", $"{label} endpoint ({hostIp})");
                    }
                    else if (reverseLookupCache is not null)
                    {
                        foreach (var resolvedIpText in reverseLookupCache.GetIpsForDomain(endpointHost))
                        {
                            if (IPAddress.TryParse(resolvedIpText, out var cachedIp))
                            {
                                AddIp(cachedIp, "UpstreamDnsResolver", $"{label} resolved IP ({cachedIp})");
                            }
                        }
                    }
                }
            }
        }

        return new ProtectedIpContext(entries);
    }

    private static string? ExtractResolverHost(DnsResolverEndpoint resolver)
    {
        if (string.IsNullOrWhiteSpace(resolver.Endpoint))
        {
            return null;
        }

        if (resolver.Protocol == DnsProtocol.DnsOverHttps
            && Uri.TryCreate(resolver.Endpoint.Trim(), UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        if (resolver.Protocol is DnsProtocol.DnsOverTls or DnsProtocol.UdpTcp)
        {
            return resolver.Endpoint.Trim();
        }

        return null;
    }
}

/// <summary>
/// Mandatory anti-self-lockout validation and broad-range risk detector for IP/CIDR firewall blocking.
/// </summary>
public static class IpBlockerGuard
{
    private static readonly (CidrNetwork Range, string ProviderName)[] MajorInfrastructureRanges = InitializeMajorRanges();

    public static IpBlockValidationResult Evaluate(string? rawTarget, ProtectedIpContext? context)
    {
        if (!CidrNetwork.TryParse(rawTarget, out var network, out var parseError))
        {
            return new IpBlockValidationResult(
                IsValid: false,
                IsProtectedViolation: false,
                RequiresConfirmation: false,
                NormalizedNetwork: null,
                ErrorCode: "InvalidTarget",
                Message: parseError);
        }

        if (context is not null)
        {
            foreach (var protectedEntry in context.Entries)
            {
                if (network.Overlaps(protectedEntry.Network))
                {
                    return new IpBlockValidationResult(
                        IsValid: false,
                        IsProtectedViolation: true,
                        RequiresConfirmation: false,
                        NormalizedNetwork: network,
                        ErrorCode: protectedEntry.ReasonCode,
                        Message: $"Protected target cannot be blocked: overlaps {protectedEntry.Detail}.");
                }
            }
        }

        var isWideCidr = (network.AddressFamily == AddressFamily.InterNetwork && network.PrefixLength < 20)
            || (network.AddressFamily == AddressFamily.InterNetworkV6 && network.PrefixLength < 48);

        string? matchedProvider = null;
        foreach (var (range, providerName) in MajorInfrastructureRanges)
        {
            if (network.Overlaps(range))
            {
                matchedProvider = providerName;
                break;
            }
        }

        if (isWideCidr || matchedProvider is not null)
        {
            var warningCode = isWideCidr && matchedProvider is not null
                ? "WideCidrAndMajorCdn"
                : isWideCidr
                    ? "WideCidr"
                    : "MajorCdnOrCloud";

            var warningMessage = (isWideCidr, matchedProvider) switch
            {
                (true, not null) => $"'{network.CanonicalText}' is a wide subnet (/{network.PrefixLength}) overlapping major cloud/CDN infrastructure ({matchedProvider}). Blocking it may interrupt many unrelated services.",
                (true, null) => $"'{network.CanonicalText}' is a wide CIDR range (/{network.PrefixLength}) and may block thousands of unrelated hosts.",
                (false, not null) => $"'{network.CanonicalText}' belongs to shared {matchedProvider} cloud/CDN infrastructure. Other websites or services sharing this IP range may stop working.",
                _ => null,
            };

            return new IpBlockValidationResult(
                IsValid: true,
                IsProtectedViolation: false,
                RequiresConfirmation: true,
                NormalizedNetwork: network,
                ErrorCode: null,
                Message: null,
                WarningCode: warningCode,
                WarningMessage: warningMessage);
        }

        return new IpBlockValidationResult(
            IsValid: true,
            IsProtectedViolation: false,
            RequiresConfirmation: false,
            NormalizedNetwork: network,
            ErrorCode: null,
            Message: null);
    }

    private static (CidrNetwork Range, string ProviderName)[] InitializeMajorRanges()
    {
        (string Cidr, string Name)[] defs =
        [
            ("1.1.1.0/24", "Cloudflare"),
            ("1.0.0.0/24", "Cloudflare"),
            ("104.16.0.0/12", "Cloudflare CDN"),
            ("172.64.0.0/13", "Cloudflare CDN"),
            ("8.8.8.0/24", "Google Public DNS"),
            ("8.8.4.0/24", "Google Public DNS"),
            ("142.250.0.0/15", "Google / YouTube"),
            ("172.217.0.0/16", "Google / YouTube"),
            ("9.9.9.0/24", "Quad9 DNS"),
            ("13.64.0.0/11", "Microsoft Azure"),
            ("20.0.0.0/11", "Microsoft Azure"),
            ("52.96.0.0/12", "Microsoft 365 / Azure"),
            ("3.0.0.0/9", "Amazon AWS"),
            ("52.0.0.0/11", "Amazon AWS"),
            ("54.0.0.0/10", "Amazon AWS"),
            ("151.101.0.0/16", "Fastly CDN"),
            ("23.0.0.0/12", "Akamai CDN"),
            ("104.64.0.0/10", "Akamai CDN"),
        ];

        var list = new List<(CidrNetwork, string)>(defs.Length);
        foreach (var (cidr, name) in defs)
        {
            if (CidrNetwork.TryParse(cidr, out var parsed, out _))
            {
                list.Add((parsed, name));
            }
        }

        return [.. list];
    }
}

public sealed record AppBlockValidationResult(
    bool IsValid,
    bool IsProtectedSystemApp,
    string? NormalizedPath,
    string? ErrorMessage);

/// <summary>
/// Prevents blocking core Windows processes or JustCryptDns executables via Per-App Firewall rules.
/// </summary>
public static class AppBlockerGuard
{
    private static readonly HashSet<string> ProtectedExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "JustCryptDns.exe",
        "JustCryptDns.Service.exe",
        "dnscrypt-proxy.exe",
        "System",
        "System Idle",
        "Registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "explorer.exe",
        "dwm.exe",
        "spoolsv.exe",
        "MsMpEng.exe",
        "NisSrv.exe",
        "taskmgr.exe",
        "conhost.exe",
        "RuntimeBroker.exe",
        "sihost.exe",
    };

    public static AppBlockValidationResult Evaluate(string? executablePath, string? appBaseDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return new AppBlockValidationResult(false, false, null, "Executable full path is unavailable for this process.");
        }

        var trimmed = executablePath.Trim();
        if (!Path.IsPathRooted(trimmed))
        {
            return new AppBlockValidationResult(false, false, null, "Executable path must be a rooted full path.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(trimmed);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return new AppBlockValidationResult(false, false, null, $"Invalid executable path: {ex.Message}");
        }

        if (!fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return new AppBlockValidationResult(false, false, null, "Only .exe executable files can be blocked by Windows Firewall.");
        }

        var fileName = Path.GetFileName(fullPath);
        if (ProtectedExecutableNames.Contains(fileName))
        {
            return new AppBlockValidationResult(
                false,
                true,
                fullPath,
                $"Critical system or JustCryptDns executable '{fileName}' cannot be blocked.");
        }

        var effectiveBaseDir = appBaseDirectory ?? AppContext.BaseDirectory;
        if (!string.IsNullOrWhiteSpace(effectiveBaseDir))
        {
            var normalizedBase = Path.GetFullPath(effectiveBaseDir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(normalizedBase, StringComparison.OrdinalIgnoreCase))
            {
                return new AppBlockValidationResult(
                    false,
                    true,
                    fullPath,
                    "Executables inside JustCryptDns application directory are protected from blocking.");
            }
        }

        return new AppBlockValidationResult(true, false, fullPath, null);
    }
}
