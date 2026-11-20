using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace JustCryptDns.Core.Security;

/// <summary>
/// Computes exact disjoint IPv4/IPv6 Windows Firewall <c>RemoteAddresses</c> complement ranges so
/// explicit Block rules (e.g., DNS Leak Guard or Emergency Lockdown) mathematically exclude
/// loopback, LAN, or authorized upstream DNS resolver IPs without relying on Allow-overrides-Block.
/// </summary>
public static class IpRangeComplement
{
    private const ulong MaxIpv4 = 0xFFFFFFFFUL;
    private static readonly UInt128 GlobalUnicastV6Start = ParseV6UInt128("2000::");
    private static readonly UInt128 GlobalUnicastV6End = ParseV6UInt128("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

    public static string BuildDnsLeakBlockRangesV4(IEnumerable<string>? allowedResolverIps)
    {
        var excluded = new List<CidrNetwork>();
        AddDefaultsV4(excluded);

        if (allowedResolverIps is not null)
        {
            foreach (var raw in allowedResolverIps)
            {
                if (CidrNetwork.TryParse(raw, out var net, out _) && net.AddressFamily == AddressFamily.InterNetwork)
                {
                    excluded.Add(net);
                }
            }
        }

        return ComputeIpv4Complement(excluded);
    }

    public static string BuildDnsLeakBlockRangesV6(IEnumerable<string>? allowedResolverIps)
    {
        var excluded = new List<CidrNetwork>();
        if (allowedResolverIps is not null)
        {
            foreach (var raw in allowedResolverIps)
            {
                if (CidrNetwork.TryParse(raw, out var net, out _) && net.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    excluded.Add(net);
                }
            }
        }

        return ComputeIpv6Complement(excluded, GlobalUnicastV6Start, GlobalUnicastV6End);
    }

    public static string BuildLockdownBlockRangesV4()
    {
        var excluded = new List<CidrNetwork>();
        AddDefaultsV4(excluded);
        foreach (var lan in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" })
        {
            if (CidrNetwork.TryParse(lan, out var net, out _))
            {
                excluded.Add(net);
            }
        }

        return ComputeIpv4Complement(excluded);
    }

    public static string BuildLockdownBlockRangesV6() =>
        $"{ToIpv6(GlobalUnicastV6Start)}-{ToIpv6(GlobalUnicastV6End)}";

    public static string ComputeIpv4Complement(IEnumerable<CidrNetwork> excludedRanges)
    {
        ArgumentNullException.ThrowIfNull(excludedRanges);
        var intervals = new List<(ulong Start, ulong End)>();
        Span<byte> b = stackalloc byte[4];
        foreach (var net in excludedRanges)
        {
            if (net.AddressFamily != AddressFamily.InterNetwork || net.NetworkAddress is null)
            {
                continue;
            }

            net.NetworkAddress.TryWriteBytes(b, out _);
            ulong start = BinaryPrimitives.ReadUInt32BigEndian(b);
            ulong mask = net.PrefixLength == 0 ? 0UL : (0xFFFFFFFFUL << (32 - net.PrefixLength)) & MaxIpv4;
            ulong end = start | (~mask & MaxIpv4);
            intervals.Add((start, end));
        }

        if (intervals.Count == 0)
        {
            return "0.0.0.0-255.255.255.255";
        }

        intervals.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));
        var merged = new List<(ulong Start, ulong End)>(intervals.Count);
        foreach (var cur in intervals)
        {
            if (merged.Count == 0)
            {
                merged.Add(cur);
                continue;
            }

            var last = merged[^1];
            if (cur.Start <= (last.End == MaxIpv4 ? MaxIpv4 : last.End + 1))
            {
                merged[^1] = (last.Start, Math.Max(last.End, cur.End));
            }
            else
            {
                merged.Add(cur);
            }
        }

        var parts = new List<string>(merged.Count + 1);
        ulong cursor = 0;
        var exhausted = false;
        foreach (var iv in merged)
        {
            if (iv.Start > cursor)
            {
                parts.Add(FormatV4Range(cursor, iv.Start - 1));
            }

            if (iv.End >= MaxIpv4)
            {
                exhausted = true;
                break;
            }

            cursor = iv.End + 1;
        }

        if (!exhausted && cursor <= MaxIpv4)
        {
            parts.Add(FormatV4Range(cursor, MaxIpv4));
        }

        return string.Join(',', parts);
    }

    public static string ComputeIpv6Complement(
        IEnumerable<CidrNetwork> excludedRanges,
        UInt128? minBound = null,
        UInt128? maxBound = null)
    {
        ArgumentNullException.ThrowIfNull(excludedRanges);
        var min = minBound ?? UInt128.Zero;
        var max = maxBound ?? UInt128.MaxValue;
        var intervals = new List<(UInt128 Start, UInt128 End)>();
        Span<byte> b = stackalloc byte[16];

        foreach (var net in excludedRanges)
        {
            if (net.AddressFamily != AddressFamily.InterNetworkV6 || net.NetworkAddress is null)
            {
                continue;
            }

            net.NetworkAddress.TryWriteBytes(b, out _);
            var start = BinaryPrimitives.ReadUInt128BigEndian(b);
            var mask = net.PrefixLength == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - net.PrefixLength);
            var end = start | ~mask;

            if (end < min || start > max)
            {
                continue;
            }

            intervals.Add((start < min ? min : start, end > max ? max : end));
        }

        if (intervals.Count == 0)
        {
            return FormatV6Range(min, max);
        }

        intervals.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));
        var merged = new List<(UInt128 Start, UInt128 End)>(intervals.Count);
        foreach (var cur in intervals)
        {
            if (merged.Count == 0)
            {
                merged.Add(cur);
                continue;
            }

            var last = merged[^1];
            if (last.End == UInt128.MaxValue || cur.Start <= last.End + 1)
            {
                merged[^1] = (last.Start, cur.End > last.End ? cur.End : last.End);
            }
            else
            {
                merged.Add(cur);
            }
        }

        var parts = new List<string>(merged.Count + 1);
        var cursor = min;
        var exhausted = false;
        foreach (var iv in merged)
        {
            if (iv.Start > cursor)
            {
                parts.Add(FormatV6Range(cursor, iv.Start - 1));
            }

            if (iv.End >= max)
            {
                exhausted = true;
                break;
            }

            cursor = iv.End + 1;
        }

        if (!exhausted && cursor <= max)
        {
            parts.Add(FormatV6Range(cursor, max));
        }

        return string.Join(',', parts);
    }

    private static void AddDefaultsV4(List<CidrNetwork> excluded)
    {
        foreach (var cidr in new[] { "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3" })
        {
            if (CidrNetwork.TryParse(cidr, out var net, out _))
            {
                excluded.Add(net);
            }
        }
    }

    private static string FormatV4Range(ulong start, ulong end) =>
        start == end ? ToIpv4(start).ToString() : $"{ToIpv4(start)}-{ToIpv4(end)}";

    private static string FormatV6Range(UInt128 start, UInt128 end) =>
        start == end ? ToIpv6(start).ToString() : $"{ToIpv6(start)}-{ToIpv6(end)}";

    private static IPAddress ToIpv4(ulong value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)value);
        return new IPAddress(bytes);
    }

    private static IPAddress ToIpv6(UInt128 value)
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    private static UInt128 ParseV6UInt128(string ipText)
    {
        var ip = IPAddress.Parse(ipText);
        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt128BigEndian(bytes);
    }
}
