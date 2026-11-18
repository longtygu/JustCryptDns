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

public sealed record DnsResolverEndpoint
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Provider { get; init; }

    public required DnsProtocol Protocol { get; init; }

    /// <summary>
    /// Protocol endpoint: HTTPS URI for DoH, TLS hostname for DoT, server name or <c>sdns://</c> stamp for DNSCrypt,
    /// or IP address for plain UDP/TCP.
    /// </summary>
    public required string Endpoint { get; init; }

    /// <summary>Bootstrap or target IPv4 address so encrypted upstreams never trigger recursive OS DNS lookups.</summary>
    public required string PrimaryIp { get; init; }

    public string? SecondaryIp { get; init; }

    public string? PrimaryIpv6 { get; init; }

    public int Port { get; init; } = 443;

    public bool IsEncrypted => Protocol != DnsProtocol.UdpTcp;
}

public static class BuiltInResolvers
{
    public const string DefaultResolverId = "cloudflare-doh";

    public static IReadOnlyList<DnsResolverEndpoint> All { get; } =
    [
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
        },
        new DnsResolverEndpoint
        {
            Id = "google-doh",
            Name = "Google Public DNS (DoH)",
            Provider = "Google",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.google/dns-query",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 443,
        },
        new DnsResolverEndpoint
        {
            Id = "google-dot",
            Name = "Google Public DNS (DoT)",
            Provider = "Google",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.google",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 853,
        },
        new DnsResolverEndpoint
        {
            Id = "google-udp",
            Name = "Google Public DNS (UDP/TCP)",
            Provider = "Google",
            Protocol = DnsProtocol.UdpTcp,
            Endpoint = "8.8.8.8",
            PrimaryIp = "8.8.8.8",
            SecondaryIp = "8.8.4.4",
            PrimaryIpv6 = "2001:4860:4860::8888",
            Port = 53,
        },
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
        },
        new DnsResolverEndpoint
        {
            Id = "adguard-doh",
            Name = "AdGuard DNS (DoH)",
            Provider = "AdGuard",
            Protocol = DnsProtocol.DnsOverHttps,
            Endpoint = "https://dns.adguard-dns.com/dns-query",
            PrimaryIp = "94.140.14.14",
            SecondaryIp = "94.140.15.15",
            PrimaryIpv6 = "2a10:50c0::ad1:ff",
            Port = 443,
        },
        new DnsResolverEndpoint
        {
            Id = "adguard-dot",
            Name = "AdGuard DNS (DoT)",
            Provider = "AdGuard",
            Protocol = DnsProtocol.DnsOverTls,
            Endpoint = "dns.adguard-dns.com",
            PrimaryIp = "94.140.14.14",
            SecondaryIp = "94.140.15.15",
            PrimaryIpv6 = "2a10:50c0::ad1:ff",
            Port = 853,
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
