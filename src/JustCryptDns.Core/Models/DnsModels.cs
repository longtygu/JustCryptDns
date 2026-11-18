using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using JustCryptDns.Core.Ipc;

namespace JustCryptDns.Core.Models;

[JsonConverter(typeof(JsonStringEnumConverter<DnsProtocol>))]
public enum DnsProtocol
{
    DnsOverHttps,
    DnsOverTls,
    DnsCrypt,
    UdpTcp,
}

[JsonConverter(typeof(JsonStringEnumConverter<DnsFilteringCapability>))]
public enum DnsFilteringCapability
{
    None,
    Malware,
    AdsAndTrackers,
    Family,
}

public sealed record DnsResolverEndpoint
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Provider { get; init; }

    public required DnsProtocol Protocol { get; init; }

    /// <summary>
    /// Protocol endpoint: HTTPS URI for DoH, TLS hostname for DoT, <c>sdns://</c> stamp for DNSCrypt,
    /// or IP address for plain UDP/TCP.
    /// </summary>
    public required string Endpoint { get; init; }

    /// <summary>Bootstrap or target IPv4 address so encrypted upstreams never trigger recursive OS DNS lookups.</summary>
    public required string PrimaryIp { get; init; }

    public string? SecondaryIp { get; init; }

    public string? PrimaryIpv6 { get; init; }

    public int Port { get; init; } = 443;

    public DnsFilteringCapability Filtering { get; init; } = DnsFilteringCapability.None;

    public bool SupportsDnssec { get; init; } = true;

    public bool NoLogPolicy { get; init; } = true;

    public bool SupportsEcs { get; init; }

    public string GroupName { get; init; } = ResolverGroups.General;

    public bool IsCustom { get; init; }

    public bool IsEnabled { get; init; } = true;

    [JsonIgnore]
    public bool IsEncrypted => Protocol != DnsProtocol.UdpTcp;
}

public static class ResolverGroups
{
    public const string General = "General";
    public const string Privacy = "Privacy";
    public const string Security = "Security";
    public const string Gaming = "Gaming";
    public const string AdBlocking = "Ad-Blocking";

    public static IReadOnlyList<string> BuiltIn { get; } =
    [
        General,
        Privacy,
        Security,
        Gaming,
        AdBlocking,
    ];
}

public sealed record ResolverHealthStatus
{
    public required string ResolverId { get; init; }

    public bool? IsAvailable { get; init; }

    public double? LastLatencyMs { get; init; }

    /// <summary>0..100 score computed from probe success ratio and latency stability.</summary>
    public double? ReliabilityScore { get; init; }

    public int TotalProbes { get; init; }

    public int SuccessfulProbes { get; init; }

    public DateTimeOffset? LastCheckedAt { get; init; }

    public string? LastError { get; init; }
}

public sealed record ResolverValidationResult(bool IsValid, string? ErrorKey = null, string? ErrorMessage = null);

public static class ResolverValidator
{
    public static ResolverValidationResult Validate(DnsResolverEndpoint resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        if (string.IsNullOrWhiteSpace(resolver.Name))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_NameRequired", "Resolver name is required.");
        }

        if (string.IsNullOrWhiteSpace(resolver.Provider))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_ProviderRequired", "Provider name is required.");
        }

        if (resolver.Port is < 1 or > 65535)
        {
            return new ResolverValidationResult(false, "Resolvers_Err_InvalidPort", "Port must be between 1 and 65535.");
        }

        if (!IsValidIpv4(resolver.PrimaryIp))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_InvalidIpv4", "Primary IPv4 address is not a valid IPv4 address.");
        }

        if (!string.IsNullOrWhiteSpace(resolver.SecondaryIp) && !IsValidIpv4(resolver.SecondaryIp))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_InvalidSecondaryIpv4", "Secondary IPv4 address is not valid.");
        }

        if (!string.IsNullOrWhiteSpace(resolver.PrimaryIpv6) && !IsValidIpv6(resolver.PrimaryIpv6))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_InvalidIpv6", "Primary IPv6 address is not a valid IPv6 address.");
        }

        var endpoint = resolver.Endpoint?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(endpoint))
        {
            return new ResolverValidationResult(false, "Resolvers_Err_EndpointRequired", "Endpoint is required.");
        }

        switch (resolver.Protocol)
        {
            case DnsProtocol.DnsOverHttps:
                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
                    || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(uri.Host))
                {
                    return new ResolverValidationResult(false, "Resolvers_Err_InvalidDohUri", "DoH endpoint must be a valid https:// URL.");
                }
                break;

            case DnsProtocol.DnsOverTls:
                if (endpoint.Contains("://", StringComparison.Ordinal)
                    || Uri.CheckHostName(endpoint) is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6))
                {
                    return new ResolverValidationResult(false, "Resolvers_Err_InvalidDotHost", "DoT endpoint must be a valid TLS hostname.");
                }
                break;

            case DnsProtocol.DnsCrypt:
                if (!TryValidateDnsCryptStamp(endpoint, out var stampError))
                {
                    return new ResolverValidationResult(false, "Resolvers_Err_InvalidStamp", stampError);
                }
                break;

            case DnsProtocol.UdpTcp:
                if (!IPAddress.TryParse(endpoint, out _))
                {
                    return new ResolverValidationResult(false, "Resolvers_Err_InvalidUdpIp", "UDP/TCP endpoint must be a valid IP address.");
                }
                break;
        }

        return new ResolverValidationResult(true);
    }

    public static bool TryValidateDnsCryptStamp(string stamp, out string? errorMessage)
    {
        if (string.IsNullOrWhiteSpace(stamp) || !stamp.StartsWith("sdns://", StringComparison.OrdinalIgnoreCase))
        {
            errorMessage = "DNSCrypt endpoint must start with sdns://.";
            return false;
        }

        var payload = stamp[7..].Trim();
        if (payload.Length < 12)
        {
            errorMessage = "DNSCrypt stamp payload is too short.";
            return false;
        }

        var base64 = payload.Replace('-', '+').Replace('_', '/');
        var mod = base64.Length % 4;
        if (mod == 2)
        {
            base64 += "==";
        }
        else if (mod == 3)
        {
            base64 += "=";
        }
        else if (mod == 1)
        {
            errorMessage = "DNSCrypt stamp has invalid Base64URL length.";
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(base64);
            if (bytes.Length < 9)
            {
                errorMessage = "Decoded DNSCrypt stamp is truncated.";
                return false;
            }

            // Stamp protocol type: 0x01 = DNSCrypt, 0x02 = DoH, 0x03 = DoT, 0x05 = ODoH, 0x81 = Anonymized DNSCrypt
            var proto = bytes[0];
            if (proto is not (0x01 or 0x02 or 0x03 or 0x05 or 0x81))
            {
                errorMessage = $"Unsupported DNS stamp protocol byte 0x{proto:X2}.";
                return false;
            }

            errorMessage = null;
            return true;
        }
        catch (FormatException)
        {
            errorMessage = "DNSCrypt stamp contains invalid Base64URL characters.";
            return false;
        }
    }

    private static bool IsValidIpv4(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && IPAddress.TryParse(text.Trim(), out var ip)
        && ip.AddressFamily == AddressFamily.InterNetwork;

    private static bool IsValidIpv6(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && IPAddress.TryParse(text.Trim(), out var ip)
        && ip.AddressFamily == AddressFamily.InterNetworkV6;
}

public sealed record ResolverProfileExportDocument
{
    public int FormatVersion { get; init; } = 1;

    public DateTimeOffset ExportedAt { get; init; } = DateTimeOffset.UtcNow;

    public required string PrimaryResolverId { get; init; }

    public string? SecondaryResolverId { get; init; }

    public required IReadOnlyList<DnsResolverEndpoint> CustomResolvers { get; init; }

    public IReadOnlyList<string> DisabledResolverIds { get; init; } = [];

    public IReadOnlyDictionary<string, string> GroupOverrides { get; init; } = new Dictionary<string, string>();

    public IReadOnlyList<string> CustomGroups { get; init; } = [];
}

public static class BuiltInResolvers
{
    public const string DefaultResolverId = "cloudflare-doh";
    public const string DefaultSecondaryResolverId = "quad9-doh";

    public static IReadOnlyList<DnsResolverEndpoint> All { get; } =
    [
        // 1. Cloudflare
        new DnsResolverEndpoint
        {
            Id = "cloudflare-doh",
            Name = "Cloudflare (DoH)",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://cloudflare-dns.com/dns-query",
            PrimaryIp = "1.1.1.1",
            SecondaryIp = "1.0.0.1",
            PrimaryIpv6 = "2606:4700:4700::1111",
            Port = 443,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "cloudflare-dot",
            Name = "Cloudflare (DoT)",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "cloudflare-dns.com",
            PrimaryIp = "1.1.1.1",
            SecondaryIp = "1.0.0.1",
            PrimaryIpv6 = "2606:4700:4700::1111",
            Port = 853,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "cloudflare-dnscrypt",
            Name = "Cloudflare (DNSCrypt)",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.DnsCrypt,
            Endpoint = "sdns://AgcAAAAAAAAABzEuMC4wLjGgENk8mGSlIfMGXMOlIlCcKvq7AVgcrZxtjon911-ep0cg63Ul-I8NlFj4GplQGb_TTLiczclX57DvMV8Q-JdjgRgSZG5zY3J5cHQuY2VydC5jbG91ZGZsYXJlLmNvbQ",
            PrimaryIp = "1.1.1.1",
            SecondaryIp = "1.0.0.1",
            PrimaryIpv6 = "2606:4700:4700::1111",
            Port = 443,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "cloudflare-udp",
            Name = "Cloudflare (UDP/TCP)",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.UdpTcp,
            Endpoint = "1.1.1.1",
            PrimaryIp = "1.1.1.1",
            SecondaryIp = "1.0.0.1",
            PrimaryIpv6 = "2606:4700:4700::1111",
            Port = 53,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Gaming,
        },
        new DnsResolverEndpoint
        {
            Id = "cloudflare-security-doh",
            Name = "Cloudflare Malware Block (DoH)",
            Provider = "Cloudflare",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://security.cloudflare-dns.com/dns-query",
            PrimaryIp = "1.1.1.2",
            SecondaryIp = "1.0.0.2",
            PrimaryIpv6 = "2606:4700:4700::1112",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },

        // 2. Google Public DNS
        new DnsResolverEndpoint
        {
            Id = "google-doh",
            Name = "Google Public DNS (DoH)",
            Provider = "Google Public DNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.google/dns-query",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 443,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = false,
            SupportsEcs = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "google-dot",
            Name = "Google Public DNS (DoT)",
            Provider = "Google Public DNS",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.google",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 853,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = false,
            SupportsEcs = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "google-udp",
            Name = "Google Public DNS (UDP/TCP)",
            Provider = "Google Public DNS",
            Protocol = DnsProtocol.UdpTcp,
            Endpoint = "8.8.8.8",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 53,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = false,
            SupportsEcs = true,
            GroupName = ResolverGroups.Gaming,
        },

        // 3. Quad9
        new DnsResolverEndpoint
        {
            Id = "quad9-doh",
            Name = "Quad9 Security (DoH)",
            Provider = "Quad9",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.quad9.net/dns-query",
            PrimaryIp = "9.9.9.9",
            SecondaryIp = "149.112.112.112",
            PrimaryIpv6 = "2620:fe::fe",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "quad9-dot",
            Name = "Quad9 Security (DoT)",
            Provider = "Quad9",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.quad9.net",
            PrimaryIp = "9.9.9.9",
            SecondaryIp = "149.112.112.112",
            PrimaryIpv6 = "2620:fe::fe",
            Port = 853,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "quad9-dnscrypt",
            Name = "Quad9 Security (DNSCrypt)",
            Provider = "Quad9",
            Protocol = DnsProtocol.DnsCrypt,
            Endpoint = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
            PrimaryIp = "9.9.9.9",
            SecondaryIp = "149.112.112.112",
            PrimaryIpv6 = "2620:fe::fe",
            Port = 8443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },

        // 4. OpenDNS
        new DnsResolverEndpoint
        {
            Id = "opendns-doh",
            Name = "OpenDNS Home (DoH)",
            Provider = "OpenDNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://doh.opendns.com/dns-query",
            PrimaryIp = "208.67.222.222",
            SecondaryIp = "208.67.220.220",
            PrimaryIpv6 = "2620:119:35::35",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = false,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "opendns-dot",
            Name = "OpenDNS Home (DoT)",
            Provider = "OpenDNS",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.opendns.com",
            PrimaryIp = "208.67.222.222",
            SecondaryIp = "208.67.220.220",
            PrimaryIpv6 = "2620:119:35::35",
            Port = 853,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = false,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "opendns-dnscrypt",
            Name = "OpenDNS Home (DNSCrypt)",
            Provider = "OpenDNS",
            Protocol = DnsProtocol.DnsCrypt,
            Endpoint = "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ",
            PrimaryIp = "208.67.222.222",
            SecondaryIp = "208.67.220.220",
            PrimaryIpv6 = "2620:119:35::35",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = false,
            GroupName = ResolverGroups.Security,
        },

        // 5. AdGuard DNS
        new DnsResolverEndpoint
        {
            Id = "adguard-doh",
            Name = "AdGuard DNS (DoH)",
            Provider = "AdGuard DNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.adguard-dns.com/dns-query",
            PrimaryIp = "94.140.14.14",
            SecondaryIp = "94.140.15.15",
            PrimaryIpv6 = "2a10:50c0::ad1:ff",
            Port = 443,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.AdBlocking,
        },
        new DnsResolverEndpoint
        {
            Id = "adguard-dot",
            Name = "AdGuard DNS (DoT)",
            Provider = "AdGuard DNS",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.adguard-dns.com",
            PrimaryIp = "94.140.14.14",
            SecondaryIp = "94.140.15.15",
            PrimaryIpv6 = "2a10:50c0::ad1:ff",
            Port = 853,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.AdBlocking,
        },
        new DnsResolverEndpoint
        {
            Id = "adguard-dnscrypt",
            Name = "AdGuard DNS (DNSCrypt)",
            Provider = "AdGuard DNS",
            Protocol = DnsProtocol.DnsCrypt,
            Endpoint = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
            PrimaryIp = "94.140.14.14",
            SecondaryIp = "94.140.15.15",
            PrimaryIpv6 = "2a10:50c0::ad1:ff",
            Port = 5443,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.AdBlocking,
        },

        // 6. Control D
        new DnsResolverEndpoint
        {
            Id = "controld-unfiltered-doh",
            Name = "Control D Unfiltered (DoH)",
            Provider = "Control D",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://freedns.controld.com/p0",
            PrimaryIp = "76.76.2.0",
            SecondaryIp = "76.76.10.0",
            PrimaryIpv6 = "2606:1a40::",
            Port = 443,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.General,
        },
        new DnsResolverEndpoint
        {
            Id = "controld-malware-doh",
            Name = "Control D Malware Filter (DoH)",
            Provider = "Control D",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://freedns.controld.com/p1",
            PrimaryIp = "76.76.2.1",
            SecondaryIp = "76.76.10.1",
            PrimaryIpv6 = "2606:1a40::1",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "controld-ads-dot",
            Name = "Control D Ads & Trackers (DoT)",
            Provider = "Control D",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "p2.freedns.controld.com",
            PrimaryIp = "76.76.2.2",
            SecondaryIp = "76.76.10.2",
            PrimaryIpv6 = "2606:1a40::2",
            Port = 853,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.AdBlocking,
        },

        // 7. NextDNS
        new DnsResolverEndpoint
        {
            Id = "nextdns-doh",
            Name = "NextDNS Anycast (DoH)",
            Provider = "NextDNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.nextdns.io/dns-query",
            PrimaryIp = "45.90.28.0",
            SecondaryIp = "45.90.30.0",
            PrimaryIpv6 = "2a07:a8c0::",
            Port = 443,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Privacy,
        },
        new DnsResolverEndpoint
        {
            Id = "nextdns-dot",
            Name = "NextDNS Anycast (DoT)",
            Provider = "NextDNS",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.nextdns.io",
            PrimaryIp = "45.90.28.0",
            SecondaryIp = "45.90.30.0",
            PrimaryIpv6 = "2a07:a8c0::",
            Port = 853,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Privacy,
        },

        // 8. Mullvad DNS
        new DnsResolverEndpoint
        {
            Id = "mullvad-doh",
            Name = "Mullvad Public DNS (DoH)",
            Provider = "Mullvad DNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.mullvad.net/dns-query",
            PrimaryIp = "194.242.2.2",
            SecondaryIp = "194.242.2.3",
            PrimaryIpv6 = "2a07:e340::2",
            Port = 443,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Privacy,
        },
        new DnsResolverEndpoint
        {
            Id = "mullvad-adblock-doh",
            Name = "Mullvad Ad-Blocking (DoH)",
            Provider = "Mullvad DNS",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://adblock.dns.mullvad.net/dns-query",
            PrimaryIp = "194.242.2.3",
            SecondaryIp = "194.242.2.2",
            PrimaryIpv6 = "2a07:e340::3",
            Port = 443,
            Filtering = DnsFilteringCapability.AdsAndTrackers,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Privacy,
        },
        new DnsResolverEndpoint
        {
            Id = "mullvad-dot",
            Name = "Mullvad Public DNS (DoT)",
            Provider = "Mullvad DNS",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.mullvad.net",
            PrimaryIp = "194.242.2.2",
            SecondaryIp = "194.242.2.3",
            PrimaryIpv6 = "2a07:e340::2",
            Port = 853,
            Filtering = DnsFilteringCapability.None,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Privacy,
        },

        // 9. DNS0
        new DnsResolverEndpoint
        {
            Id = "dns0-zero-doh",
            Name = "DNS0.eu ZERO Security (DoH)",
            Provider = "DNS0",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://zero.dns0.eu/",
            PrimaryIp = "193.110.81.9",
            SecondaryIp = "185.253.5.9",
            PrimaryIpv6 = "2a0f:fc80::9",
            Port = 443,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "dns0-zero-dot",
            Name = "DNS0.eu ZERO Security (DoT)",
            Provider = "DNS0",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "zero.dns0.eu",
            PrimaryIp = "193.110.81.9",
            SecondaryIp = "185.253.5.9",
            PrimaryIpv6 = "2a0f:fc80::9",
            Port = 853,
            Filtering = DnsFilteringCapability.Malware,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
        new DnsResolverEndpoint
        {
            Id = "dns0-kids-doh",
            Name = "DNS0.eu KIDS Family (DoH)",
            Provider = "DNS0",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://kids.dns0.eu/",
            PrimaryIp = "193.110.81.1",
            SecondaryIp = "185.253.5.1",
            PrimaryIpv6 = "2a0f:fc80::1",
            Port = 443,
            Filtering = DnsFilteringCapability.Family,
            SupportsDnssec = true,
            NoLogPolicy = true,
            GroupName = ResolverGroups.Security,
        },
    ];

    public static DnsResolverEndpoint GetByIdOrDefault(string? id) =>
        All.FirstOrDefault(r => string.Equals(r.Id, id, StringComparison.OrdinalIgnoreCase)) ?? All[0];
}

public sealed record PortConflictInfo(
    bool HasConflict,
    string Endpoint,
    string Protocol,
    int SuggestedPort,
    string Message);

public sealed record AdapterDnsBackupEntry
{
    public required string AdapterId { get; init; }

    public required string AdapterName { get; init; }

    public required bool WasIpv4Dhcp { get; init; }

    public required IReadOnlyList<string> Ipv4DnsServers { get; init; }

    public required bool WasIpv6Dhcp { get; init; }

    public required IReadOnlyList<string> Ipv6DnsServers { get; init; }
}

public sealed record AdapterDnsBackupDocument
{
    public required DateTimeOffset CreatedAt { get; init; }

    public required bool IsActive { get; init; }

    public required IReadOnlyList<AdapterDnsBackupEntry> Adapters { get; init; }

    public required string IntegrityHash { get; init; }

    public static string ComputeHash(IReadOnlyList<AdapterDnsBackupEntry> adapters)
    {
        var sb = new StringBuilder();
        foreach (var a in adapters.OrderBy(x => x.AdapterId, StringComparer.Ordinal))
        {
            sb.Append(a.AdapterId).Append('|')
              .Append(a.AdapterName).Append('|')
              .Append(a.WasIpv4Dhcp ? '1' : '0').Append('|')
              .Append(string.Join(',', a.Ipv4DnsServers)).Append('|')
              .Append(a.WasIpv6Dhcp ? '1' : '0').Append('|')
              .Append(string.Join(',', a.Ipv6DnsServers)).Append('\n');
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(hash);
    }

    public bool VerifyIntegrity() =>
        Adapters is not null && string.Equals(IntegrityHash, ComputeHash(Adapters), StringComparison.OrdinalIgnoreCase);
}

public sealed record DnsEngineRuntimeStats
{
    public required DnsEngineState State { get; init; }

    public required string ActiveResolverId { get; init; }

    public required string ActiveResolverName { get; init; }

    public required DnsProtocol ActiveProtocol { get; init; }

    public required string ListenEndpoint { get; init; }

    public long TotalQueries { get; init; }

    public long SuccessfulQueries { get; init; }

    public long FailedQueries { get; init; }

    public double? LastLatencyMs { get; init; }

    public string? LastError { get; init; }

    public PortConflictInfo? PortConflict { get; init; }

    public string? DnsCryptVersion { get; init; }

    public bool HasAdapterBackup { get; init; }
}
