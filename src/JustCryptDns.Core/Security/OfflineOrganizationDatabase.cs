using System.Net;

namespace JustCryptDns.Core.Security;

public sealed record OfflineOrgMatch(string Organization, string? CountryCode = null);

/// <summary>
/// Zero-network, in-memory IPv4/IPv6 CIDR prefix and DNS domain-suffix database providing instant
/// organization attribution for major cloud providers, CDNs, gaming networks, DNS resolvers, and Vietnam ISPs.
/// </summary>
public static class OfflineOrganizationDatabase
{
    private readonly record struct PrefixEntry(CidrNetwork Network, OfflineOrgMatch Match);

    private static readonly PrefixEntry[] IpPrefixes = BuildIpPrefixes();
    private static readonly (string Suffix, OfflineOrgMatch Match)[] DomainSuffixes = BuildDomainSuffixes();

    public static bool TryResolve(string? ipText, string? domain, out OfflineOrgMatch match)
    {
        if (!string.IsNullOrWhiteSpace(ipText))
        {
            var trimmedIp = ipText.Trim();
            if (trimmedIp == "*")
            {
                match = default!;
                return false;
            }

            if (IPAddress.TryParse(trimmedIp, out var ip))
            {
                if (CidrNetwork.IsLanOrLocal(ip))
                {
                    match = default!;
                    return false;
                }

                if (TryResolveByIp(ip, out match))
                {
                    return true;
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(domain) && TryResolveByDomain(domain, out match))
        {
            return true;
        }

        match = default!;
        return false;
    }

    public static bool TryResolveByIp(IPAddress ip, out OfflineOrgMatch match)
    {
        ArgumentNullException.ThrowIfNull(ip);
        if (CidrNetwork.IsLanOrLocal(ip))
        {
            match = default!;
            return false;
        }

        foreach (var entry in IpPrefixes)
        {
            if (entry.Network.Contains(ip))
            {
                match = entry.Match;
                return true;
            }
        }

        match = default!;
        return false;
    }

    public static bool TryResolveByDomain(string? domain, out OfflineOrgMatch match)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            match = default!;
            return false;
        }

        var normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var (suffix, orgMatch) in DomainSuffixes)
        {
            if (string.Equals(normalized, suffix, StringComparison.OrdinalIgnoreCase)
                || normalized.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
            {
                match = orgMatch;
                return true;
            }
        }

        match = default!;
        return false;
    }

    private static PrefixEntry[] BuildIpPrefixes()
    {
        (string Cidr, string Org, string? Cc)[] defs =
        [
            // DNS & Security Resolvers
            ("1.1.1.0/24", "Cloudflare DNS", "AU"),
            ("1.0.0.0/24", "Cloudflare DNS", "AU"),
            ("8.8.8.0/24", "Google Public DNS", "US"),
            ("8.8.4.0/24", "Google Public DNS", "US"),
            ("9.9.9.0/24", "Quad9 DNS", "CH"),
            ("149.112.112.0/24", "Quad9 DNS", "CH"),
            ("2620:fe::/48", "Quad9 DNS", "CH"),
            ("94.140.14.0/23", "AdGuard DNS", "CY"),
            ("2a10:50c0::/32", "AdGuard DNS", "CY"),
            ("76.76.2.0/24", "Control D DNS", "CA"),
            ("76.76.10.0/24", "Control D DNS", "CA"),
            ("45.90.28.0/22", "NextDNS", "FR"),
            ("208.67.220.0/22", "Cisco OpenDNS", "US"),
            ("146.112.0.0/16", "Cisco OpenDNS", "US"),
            ("194.242.2.0/24", "Mullvad DNS", "SE"),

            // GitHub
            ("140.82.112.0/20", "GitHub Inc.", "US"),
            ("185.199.108.0/22", "GitHub Pages / Fastly", "US"),
            ("192.30.252.0/22", "GitHub Inc.", "US"),

            // Discord
            ("162.159.128.0/20", "Discord / Cloudflare", "US"),
            ("66.22.192.0/18", "Discord Voice Servers", "US"),

            // Valve / Steam
            ("155.133.224.0/19", "Valve / Steam", "US"),
            ("162.254.192.0/21", "Valve / Steam", "US"),
            ("192.69.96.0/22", "Valve / Steam", "US"),
            ("205.196.6.0/24", "Valve / Steam", "US"),
            ("208.64.200.0/22", "Valve / Steam", "US"),
            ("208.78.164.0/22", "Valve / Steam", "US"),

            // Riot Games
            ("104.160.128.0/18", "Riot Games", "US"),
            ("185.40.64.0/22", "Riot Games EU", "NL"),
            ("192.207.0.0/16", "Riot Games", "US"),

            // Telegram
            ("91.108.4.0/22", "Telegram Messenger", "NL"),
            ("91.108.8.0/22", "Telegram Messenger", "NL"),
            ("91.108.12.0/22", "Telegram Messenger", "NL"),
            ("91.108.16.0/22", "Telegram Messenger", "NL"),
            ("91.108.56.0/22", "Telegram Messenger", "NL"),
            ("149.154.160.0/20", "Telegram Messenger", "GB"),
            ("2001:67c:4e8::/48", "Telegram Messenger", "NL"),
            ("2001:b28:f23d::/48", "Telegram Messenger", "NL"),

            // Cloudflare
            ("104.16.0.0/12", "Cloudflare Inc.", "US"),
            ("172.64.0.0/13", "Cloudflare Inc.", "US"),
            ("162.158.0.0/15", "Cloudflare Inc.", "US"),
            ("108.162.192.0/18", "Cloudflare Inc.", "US"),
            ("188.114.96.0/20", "Cloudflare Inc.", "US"),
            ("198.41.128.0/17", "Cloudflare Inc.", "US"),
            ("2606:4700::/32", "Cloudflare Inc.", "US"),

            // Google / YouTube / GCP
            ("142.250.0.0/15", "Google LLC", "US"),
            ("172.217.0.0/16", "Google LLC", "US"),
            ("216.58.192.0/19", "Google LLC", "US"),
            ("74.125.0.0/16", "Google LLC", "US"),
            ("64.233.160.0/19", "Google LLC", "US"),
            ("34.0.0.0/9", "Google Cloud", "US"),
            ("35.184.0.0/13", "Google Cloud", "US"),
            ("35.192.0.0/12", "Google Cloud", "US"),
            ("35.208.0.0/12", "Google Cloud", "US"),
            ("2001:4860::/32", "Google LLC", "US"),
            ("2607:f8b0::/32", "Google LLC", "US"),

            // Microsoft / Azure
            ("13.64.0.0/11", "Microsoft Azure", "US"),
            ("13.96.0.0/13", "Microsoft Azure", "US"),
            ("20.0.0.0/11", "Microsoft Azure", "US"),
            ("20.32.0.0/11", "Microsoft Azure", "US"),
            ("20.64.0.0/10", "Microsoft Azure", "US"),
            ("40.64.0.0/10", "Microsoft Azure", "US"),
            ("52.96.0.0/12", "Microsoft 365", "US"),
            ("52.112.0.0/14", "Microsoft Teams / 365", "US"),
            ("52.144.0.0/12", "Microsoft Azure", "US"),
            ("52.160.0.0/11", "Microsoft Azure", "US"),
            ("52.224.0.0/11", "Microsoft Azure", "US"),
            ("104.40.0.0/13", "Microsoft Azure", "US"),
            ("168.61.0.0/16", "Microsoft Azure", "US"),
            ("168.62.0.0/15", "Microsoft Azure", "US"),
            ("2603:1000::/24", "Microsoft Azure", "US"),
            ("2620:1ec::/36", "Microsoft Edge / Office", "US"),

            // Meta / Facebook / Instagram
            ("31.13.24.0/21", "Meta Platforms", "US"),
            ("31.13.64.0/18", "Meta Platforms", "IE"),
            ("66.220.144.0/20", "Meta Platforms", "US"),
            ("69.63.176.0/20", "Meta Platforms", "US"),
            ("69.171.224.0/19", "Meta Platforms", "US"),
            ("157.240.0.0/16", "Meta Platforms", "US"),
            ("173.252.64.0/18", "Meta Platforms", "US"),
            ("185.60.216.0/22", "Meta Platforms", "IE"),
            ("2a03:2880::/32", "Meta Platforms", "US"),

            // Amazon AWS
            ("3.0.0.0/9", "Amazon AWS", "US"),
            ("15.160.0.0/11", "Amazon AWS", "US"),
            ("18.32.0.0/11", "Amazon AWS", "US"),
            ("18.64.0.0/10", "Amazon AWS", "US"),
            ("18.128.0.0/9", "Amazon AWS", "US"),
            ("52.0.0.0/11", "Amazon AWS", "US"),
            ("52.32.0.0/11", "Amazon AWS", "US"),
            ("52.64.0.0/12", "Amazon AWS", "US"),
            ("54.64.0.0/11", "Amazon AWS", "US"),
            ("54.144.0.0/12", "Amazon AWS", "US"),
            ("54.160.0.0/11", "Amazon AWS", "US"),
            ("54.192.0.0/12", "Amazon CloudFront", "US"),
            ("54.224.0.0/12", "Amazon AWS", "US"),
            ("2600:1f00::/24", "Amazon AWS", "US"),

            // Fastly & Akamai & Apple
            ("151.101.0.0/16", "Fastly CDN", "US"),
            ("199.232.0.0/16", "Fastly CDN", "US"),
            ("2a04:4e40::/32", "Fastly CDN", "US"),
            ("23.0.0.0/12", "Akamai CDN", "US"),
            ("23.32.0.0/11", "Akamai CDN", "US"),
            ("23.64.0.0/14", "Akamai CDN", "US"),
            ("104.64.0.0/10", "Akamai CDN", "US"),
            ("2600:1400::/24", "Akamai CDN", "US"),
            ("17.0.0.0/8", "Apple Inc.", "US"),
            ("2620:149::/32", "Apple Inc.", "US"),

            // Hosting / Cloud (DigitalOcean, Oracle, Linode, Vultr, OVH, Hetzner)
            ("104.131.0.0/16", "DigitalOcean", "US"),
            ("134.122.0.0/16", "DigitalOcean", "US"),
            ("137.184.0.0/16", "DigitalOcean", "US"),
            ("138.197.0.0/16", "DigitalOcean", "US"),
            ("143.198.0.0/16", "DigitalOcean", "US"),
            ("159.89.0.0/16", "DigitalOcean", "US"),
            ("164.90.0.0/16", "DigitalOcean", "US"),
            ("167.99.0.0/16", "DigitalOcean", "US"),
            ("129.146.0.0/16", "Oracle Cloud", "US"),
            ("132.145.0.0/16", "Oracle Cloud", "US"),
            ("140.238.0.0/16", "Oracle Cloud", "US"),
            ("150.136.0.0/16", "Oracle Cloud", "US"),
            ("152.67.0.0/16", "Oracle Cloud", "US"),
            ("158.101.0.0/16", "Oracle Cloud", "US"),
            ("45.33.0.0/16", "Akamai / Linode", "US"),
            ("45.79.0.0/16", "Akamai / Linode", "US"),
            ("139.162.0.0/16", "Akamai / Linode", "SG"),
            ("172.104.0.0/15", "Akamai / Linode", "US"),
            ("45.32.0.0/16", "Vultr / Constant", "US"),
            ("45.76.0.0/15", "Vultr / Constant", "US"),
            ("108.61.0.0/16", "Vultr / Constant", "US"),
            ("149.28.0.0/16", "Vultr / Constant", "US"),
            ("51.38.0.0/16", "OVHcloud", "FR"),
            ("51.68.0.0/15", "OVHcloud", "FR"),
            ("54.36.0.0/14", "OVHcloud", "FR"),
            ("137.74.0.0/16", "OVHcloud", "FR"),
            ("49.12.0.0/14", "Hetzner Online", "DE"),
            ("65.108.0.0/15", "Hetzner Online", "FI"),
            ("88.198.0.0/16", "Hetzner Online", "DE"),
            ("95.216.0.0/15", "Hetzner Online", "FI"),
            ("135.181.0.0/16", "Hetzner Online", "FI"),
            ("168.119.0.0/16", "Hetzner Online", "DE"),

            // Vietnam ISPs & Local Tech
            ("116.193.64.0/18", "VNG / Zalo Group", "VN"),
            ("49.213.64.0/18", "VNG Corporation", "VN"),
            ("120.138.64.0/18", "VNG Corporation", "VN"),
            ("103.18.0.0/22", "CMC Telecom", "VN"),
            ("101.99.0.0/16", "CMC Telecom", "VN"),
            ("14.160.0.0/11", "VNPT Group", "VN"),
            ("113.160.0.0/11", "VNPT Group", "VN"),
            ("123.16.0.0/12", "VNPT Group", "VN"),
            ("222.252.0.0/14", "VNPT Group", "VN"),
            ("27.64.0.0/12", "Viettel Group", "VN"),
            ("115.72.0.0/13", "Viettel Group", "VN"),
            ("171.224.0.0/11", "Viettel Group", "VN"),
            ("1.52.0.0/14", "FPT Telecom", "VN"),
            ("118.68.0.0/14", "FPT Telecom", "VN"),
            ("183.80.0.0/12", "FPT Telecom", "VN"),
        ];

        var list = new List<PrefixEntry>(defs.Length);
        foreach (var (cidr, org, cc) in defs)
        {
            if (CidrNetwork.TryParse(cidr, out var network, out _))
            {
                list.Add(new PrefixEntry(network, new OfflineOrgMatch(org, cc)));
            }
        }

        // Most-specific prefix wins when a narrower sub-allocation sits inside a broader range.
        return [.. list.OrderByDescending(e => e.Network.PrefixLength)];
    }

    private static (string Suffix, OfflineOrgMatch Match)[] BuildDomainSuffixes() =>
    [
        ("steampowered.com", new OfflineOrgMatch("Valve / Steam", "US")),
        ("steamstatic.com", new OfflineOrgMatch("Valve / Steam CDN", "US")),
        ("steamcontent.com", new OfflineOrgMatch("Valve / Steam CDN", "US")),
        ("riotgames.com", new OfflineOrgMatch("Riot Games", "US")),
        ("valorant.com", new OfflineOrgMatch("Riot Games", "US")),
        ("leagueoflegends.com", new OfflineOrgMatch("Riot Games", "US")),
        ("discord.com", new OfflineOrgMatch("Discord Inc.", "US")),
        ("discord.gg", new OfflineOrgMatch("Discord Inc.", "US")),
        ("discordapp.com", new OfflineOrgMatch("Discord Inc.", "US")),
        ("garena.vn", new OfflineOrgMatch("Garena / Sea", "VN")),
        ("garena.com", new OfflineOrgMatch("Garena / Sea", "SG")),
        ("zalo.me", new OfflineOrgMatch("VNG / Zalo", "VN")),
        ("zaloapp.com", new OfflineOrgMatch("VNG / Zalo", "VN")),
        ("zing.vn", new OfflineOrgMatch("VNG Corporation", "VN")),
        ("vng.com.vn", new OfflineOrgMatch("VNG Corporation", "VN")),
        ("tiktokcdn.com", new OfflineOrgMatch("ByteDance / TikTok", "SG")),
        ("tiktok.com", new OfflineOrgMatch("ByteDance / TikTok", "SG")),
        ("bytedance.com", new OfflineOrgMatch("ByteDance Ltd.", "SG")),
        ("youtube.com", new OfflineOrgMatch("Google / YouTube", "US")),
        ("googlevideo.com", new OfflineOrgMatch("Google / YouTube CDN", "US")),
        ("googleapis.com", new OfflineOrgMatch("Google LLC", "US")),
        ("gstatic.com", new OfflineOrgMatch("Google LLC", "US")),
        ("google.com", new OfflineOrgMatch("Google LLC", "US")),
        ("facebook.com", new OfflineOrgMatch("Meta Platforms", "US")),
        ("fbcdn.net", new OfflineOrgMatch("Meta CDN", "US")),
        ("messenger.com", new OfflineOrgMatch("Meta Platforms", "US")),
        ("instagram.com", new OfflineOrgMatch("Meta Platforms", "US")),
        ("github.com", new OfflineOrgMatch("GitHub Inc.", "US")),
        ("githubusercontent.com", new OfflineOrgMatch("GitHub CDN", "US")),
        ("cloudflare-dns.com", new OfflineOrgMatch("Cloudflare DNS", "US")),
        ("cloudflare.com", new OfflineOrgMatch("Cloudflare Inc.", "US")),
        ("windowsupdate.com", new OfflineOrgMatch("Microsoft Windows Update", "US")),
        ("microsoft.com", new OfflineOrgMatch("Microsoft Corp.", "US")),
        ("live.com", new OfflineOrgMatch("Microsoft Corp.", "US")),
        ("office.com", new OfflineOrgMatch("Microsoft 365", "US")),
        ("azure.com", new OfflineOrgMatch("Microsoft Azure", "US")),
        ("apple.com", new OfflineOrgMatch("Apple Inc.", "US")),
        ("icloud.com", new OfflineOrgMatch("Apple iCloud", "US")),
        ("amazonaws.com", new OfflineOrgMatch("Amazon AWS", "US")),
        ("twitch.tv", new OfflineOrgMatch("Amazon / Twitch", "US")),
        ("ttvnw.net", new OfflineOrgMatch("Twitch CDN", "US")),
        ("epicgames.com", new OfflineOrgMatch("Epic Games", "US")),
        ("blizzard.com", new OfflineOrgMatch("Blizzard Entertainment", "US")),
        ("battle.net", new OfflineOrgMatch("Blizzard Entertainment", "US")),
        ("telegram.org", new OfflineOrgMatch("Telegram Messenger", "NL")),
        ("openai.com", new OfflineOrgMatch("OpenAI", "US")),
        ("chatgpt.com", new OfflineOrgMatch("OpenAI", "US")),
        ("nvidia.com", new OfflineOrgMatch("NVIDIA Corp.", "US")),
    ];
}
