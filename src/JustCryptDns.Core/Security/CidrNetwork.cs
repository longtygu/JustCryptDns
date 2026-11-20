using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace JustCryptDns.Core.Security;

/// <summary>
/// Parsed, canonicalized IPv4 or IPv6 host or CIDR network range.
/// </summary>
public readonly record struct CidrNetwork
{
    private readonly uint _v4Address;
    private readonly uint _v4Mask;
    private readonly UInt128 _v6Address;
    private readonly UInt128 _v6Mask;

    private CidrNetwork(IPAddress networkAddress, int prefixLength, uint v4Address, uint v4Mask, UInt128 v6Address, UInt128 v6Mask)
    {
        NetworkAddress = networkAddress;
        PrefixLength = prefixLength;
        _v4Address = v4Address;
        _v4Mask = v4Mask;
        _v6Address = v6Address;
        _v6Mask = v6Mask;
    }

    public IPAddress NetworkAddress { get; }

    public int PrefixLength { get; }

    public AddressFamily AddressFamily => NetworkAddress?.AddressFamily ?? AddressFamily.Unspecified;

    public bool IsSingleHost =>
        (AddressFamily == AddressFamily.InterNetwork && PrefixLength == 32)
        || (AddressFamily == AddressFamily.InterNetworkV6 && PrefixLength == 128);

    /// <summary>
    /// Canonical string representation (<c>x.x.x.x</c> for single IP or <c>x.x.x.0/24</c> for CIDR).
    /// </summary>
    public string CanonicalText => NetworkAddress is null
        ? string.Empty
        : IsSingleHost
            ? NetworkAddress.ToString()
            : string.Create(CultureInfo.InvariantCulture, $"{NetworkAddress}/{PrefixLength}");

    /// <summary>
    /// Windows Firewall <c>RemoteAddresses</c> compatible string (bare IP for single hosts, <c>net/prefix</c> for CIDR).
    /// </summary>
    public string FirewallRemoteAddress => CanonicalText;

    public static bool TryParse(string? input, out CidrNetwork network, out string? error)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Enter a valid IP address or CIDR range (e.g. 203.0.113.10 or 198.51.100.0/24).";
            return false;
        }

        var trimmed = input.Trim();
        var slashIndex = trimmed.IndexOf('/', StringComparison.Ordinal);
        string ipPart;
        string? prefixPart = null;

        if (slashIndex >= 0)
        {
            ipPart = trimmed[..slashIndex].Trim();
            prefixPart = trimmed[(slashIndex + 1)..].Trim();
            if (trimmed.IndexOf('/', slashIndex + 1) >= 0)
            {
                error = "Invalid CIDR format: multiple '/' separators found.";
                return false;
            }
        }
        else
        {
            ipPart = trimmed;
        }

        // Strip any IPv6 zone index (%eth0) if pasted by user.
        var percentIndex = ipPart.IndexOf('%', StringComparison.Ordinal);
        if (percentIndex >= 0)
        {
            ipPart = ipPart[..percentIndex];
        }

        if (!IPAddress.TryParse(ipPart, out var parsedIp))
        {
            error = $"'{trimmed}' is not a valid IPv4 or IPv6 address.";
            return false;
        }

        if (parsedIp.IsIPv4MappedToIPv6)
        {
            parsedIp = parsedIp.MapToIPv4();
        }

        if (parsedIp.AddressFamily == AddressFamily.InterNetwork)
        {
            var prefix = 32;
            if (prefixPart is not null)
            {
                if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)
                    || prefix is < 0 or > 32)
                {
                    error = "IPv4 CIDR prefix length must be between 1 and 32.";
                    return false;
                }
            }

            if (prefix == 0)
            {
                error = "Blocking the entire IPv4 internet (/0) is not allowed.";
                return false;
            }

            Span<byte> bytes = stackalloc byte[4];
            parsedIp.TryWriteBytes(bytes, out _);
            var raw = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            var masked = raw & mask;
            BinaryPrimitives.WriteUInt32BigEndian(bytes, masked);
            var canonicalIp = new IPAddress(bytes);

            network = new CidrNetwork(canonicalIp, prefix, masked, mask, UInt128.Zero, UInt128.Zero);
            error = null;
            return true;
        }

        if (parsedIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var prefix = 128;
            if (prefixPart is not null)
            {
                if (!int.TryParse(prefixPart, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)
                    || prefix is < 0 or > 128)
                {
                    error = "IPv6 CIDR prefix length must be between 1 and 128.";
                    return false;
                }
            }

            if (prefix == 0)
            {
                error = "Blocking the entire IPv6 internet (/0) is not allowed.";
                return false;
            }

            Span<byte> bytes = stackalloc byte[16];
            parsedIp.TryWriteBytes(bytes, out _);
            var raw = BinaryPrimitives.ReadUInt128BigEndian(bytes);
            var mask = prefix == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - prefix);
            var masked = raw & mask;
            BinaryPrimitives.WriteUInt128BigEndian(bytes, masked);
            var canonicalIp = new IPAddress(bytes);

            network = new CidrNetwork(canonicalIp, prefix, 0, 0, masked, mask);
            error = null;
            return true;
        }

        error = $"Unsupported address family '{parsedIp.AddressFamily}'.";
        return false;
    }

    public static CidrNetwork FromAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (normalized.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> bytes = stackalloc byte[4];
            normalized.TryWriteBytes(bytes, out _);
            var raw = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            return new CidrNetwork(new IPAddress(bytes), 32, raw, uint.MaxValue, UInt128.Zero, UInt128.Zero);
        }

        if (normalized.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Span<byte> bytes = stackalloc byte[16];
            normalized.TryWriteBytes(bytes, out _);
            var raw = BinaryPrimitives.ReadUInt128BigEndian(bytes);
            return new CidrNetwork(new IPAddress(bytes), 128, 0, 0, raw, UInt128.MaxValue);
        }

        throw new ArgumentException($"Unsupported address family '{address.AddressFamily}'.", nameof(address));
    }

    public bool Contains(IPAddress? address)
    {
        if (address is null || NetworkAddress is null)
        {
            return false;
        }

        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (normalized.AddressFamily != AddressFamily)
        {
            return false;
        }

        if (AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> bytes = stackalloc byte[4];
            normalized.TryWriteBytes(bytes, out _);
            var candidate = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            return (candidate & _v4Mask) == _v4Address;
        }

        if (AddressFamily == AddressFamily.InterNetworkV6)
        {
            Span<byte> bytes = stackalloc byte[16];
            normalized.TryWriteBytes(bytes, out _);
            var candidate = BinaryPrimitives.ReadUInt128BigEndian(bytes);
            return (candidate & _v6Mask) == _v6Address;
        }

        return false;
    }

    public bool Overlaps(CidrNetwork other)
    {
        if (NetworkAddress is null || other.NetworkAddress is null || AddressFamily != other.AddressFamily)
        {
            return false;
        }

        return PrefixLength <= other.PrefixLength
            ? Contains(other.NetworkAddress)
            : other.Contains(NetworkAddress);
    }

    public static bool IsLanOrLocal(IPAddress? address)
    {
        if (address is null)
        {
            return true;
        }

        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (IPAddress.IsLoopback(normalized)
            || normalized.Equals(IPAddress.Any)
            || normalized.Equals(IPAddress.IPv6Any)
            || normalized.Equals(IPAddress.Broadcast)
            || normalized.Equals(IPAddress.IPv6Loopback))
        {
            return true;
        }

        if (normalized.AddressFamily == AddressFamily.InterNetwork)
        {
            Span<byte> b = stackalloc byte[4];
            normalized.TryWriteBytes(b, out _);
            return b[0] == 10
                || b[0] == 127
                || b[0] == 0
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] >= 224); // multicast & reserved
        }

        if (normalized.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (normalized.IsIPv6LinkLocal || normalized.IsIPv6SiteLocal || normalized.IsIPv6Multicast)
            {
                return true;
            }

            Span<byte> b = stackalloc byte[16];
            normalized.TryWriteBytes(b, out _);
            // ULA fc00::/7
            return (b[0] & 0xFE) == 0xFC;
        }

        return false;
    }

    public static bool IsLanOrLocalString(string? ipText) =>
        string.IsNullOrWhiteSpace(ipText)
        || ipText == "*"
        || (IPAddress.TryParse(ipText.Trim(), out var ip) && IsLanOrLocal(ip));

    public override string ToString() => CanonicalText;
}
