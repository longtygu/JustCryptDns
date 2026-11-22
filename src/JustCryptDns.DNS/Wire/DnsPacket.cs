using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using JustCryptDns.Core.Models;

namespace JustCryptDns.DNS.Wire;

public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    HTTPS = 65,
    ANY = 255,
}

public enum DnsResponseCode : byte
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

public readonly record struct DnsHeader(
    ushort Id,
    ushort Flags,
    ushort QuestionCount,
    ushort AnswerCount,
    ushort AuthorityCount,
    ushort AdditionalCount)
{
    public bool IsResponse => (Flags & 0x8000) != 0;

    public bool IsTruncated => (Flags & 0x0200) != 0;

    public bool RecursionDesired => (Flags & 0x0100) != 0;

    public bool RecursionAvailable => (Flags & 0x0080) != 0;

    public bool IsAuthenticData => (Flags & 0x0020) != 0;

    public DnsResponseCode ResponseCode => (DnsResponseCode)(Flags & 0x000F);
}

public sealed record DnsQuestion(string Name, DnsRecordType Type, ushort Class);

public sealed record DnsResourceRecord(
    string Name,
    DnsRecordType Type,
    ushort Class,
    uint Ttl,
    string DataSummary);

/// <summary>
/// Minimal, bounds-checked RFC 1035 wire-format parser and encoder.
/// Never throws on malformed network packets when using <see cref="TryParse"/>.
/// </summary>
public sealed class DnsPacket
{
    public const int HeaderSize = 12;
    private const int MaxCompressionJumps = 16;

    public required DnsHeader Header { get; init; }

    public required IReadOnlyList<DnsQuestion> Questions { get; init; }

    public required IReadOnlyList<DnsResourceRecord> Answers { get; init; }

    public string? PrimaryQuestionName => Questions.Count > 0 ? Questions[0].Name : null;

    public DnsRecordType PrimaryQuestionType => Questions.Count > 0 ? Questions[0].Type : DnsRecordType.A;

    /// <summary>Minimum positive TTL across answer records, or null if no answer records exist.</summary>
    public uint? MinAnswerTtl => Answers.Count > 0 ? Answers.Min(a => a.Ttl) : null;

    public static ushort GenerateTransactionId()
    {
        Span<byte> bytes = stackalloc byte[2];
        RandomNumberGenerator.Fill(bytes);
        return BinaryPrimitives.ReadUInt16BigEndian(bytes);
    }

    public static bool TryReadTransactionId(ReadOnlySpan<byte> wire, out ushort id)
    {
        if (wire.Length < 2)
        {
            id = 0;
            return false;
        }

        id = BinaryPrimitives.ReadUInt16BigEndian(wire);
        return true;
    }

    public static void WriteTransactionId(Span<byte> wire, ushort id)
    {
        if (wire.Length >= 2)
        {
            BinaryPrimitives.WriteUInt16BigEndian(wire, id);
        }
    }

    public static byte[] CreateQuery(
        string domain,
        DnsRecordType type = DnsRecordType.A,
        ushort? id = null,
        bool recursionDesired = true,
        bool dnssecOk = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        var txId = id ?? GenerateTransactionId();
        var flags = recursionDesired ? (ushort)0x0100 : (ushort)0x0000;
        if (dnssecOk)
        {
            flags |= 0x0020; // RFC 6840 §5.7 AD bit in query requests AD validation indicator
        }

        var arCount = dnssecOk ? (ushort)1 : (ushort)0;

        using var ms = new MemoryStream(64);
        Span<byte> header = stackalloc byte[HeaderSize];
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], txId);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], flags);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1); // QDCOUNT = 1
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[8..10], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], arCount);
        ms.Write(header);

        WriteDomainName(ms, domain);

        Span<byte> qTail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qTail[0..2], (ushort)type);
        BinaryPrimitives.WriteUInt16BigEndian(qTail[2..4], 1); // IN
        ms.Write(qTail);

        if (dnssecOk)
        {
            // EDNS0 OPT pseudo-record (RFC 6891): root name (0), type OPT (41), UDP payload 1232, DO bit (0x8000).
            Span<byte> opt = stackalloc byte[11];
            opt[0] = 0;
            BinaryPrimitives.WriteUInt16BigEndian(opt[1..3], (ushort)DnsRecordType.OPT);
            BinaryPrimitives.WriteUInt16BigEndian(opt[3..5], 1232);
            BinaryPrimitives.WriteUInt32BigEndian(opt[5..9], 0x00008000u);
            BinaryPrimitives.WriteUInt16BigEndian(opt[9..11], 0);
            ms.Write(opt);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Builds a valid DNS response echoing the request's ID and Question section with the specified <paramref name="rcode"/>.
    /// </summary>
    public static byte[] CreateErrorResponse(ReadOnlySpan<byte> requestWire, DnsResponseCode rcode)
    {
        if (requestWire.Length < HeaderSize)
        {
            return [];
        }

        var id = BinaryPrimitives.ReadUInt16BigEndian(requestWire[0..2]);
        var reqFlags = BinaryPrimitives.ReadUInt16BigEndian(requestWire[2..4]);
        var rd = (ushort)(reqFlags & 0x0100);
        var flags = (ushort)(0x8000 | rd | 0x0080 | ((byte)rcode & 0x0F)); // QR=1, RD=copied, RA=1, RCODE

        // Locate end of first question if present so we can echo it back.
        var qdCount = BinaryPrimitives.ReadUInt16BigEndian(requestWire[4..6]);
        var offset = HeaderSize;
        var echoQuestion = false;
        if (qdCount > 0 && TryReadDomainName(requestWire, ref offset, out _) && offset + 4 <= requestWire.Length)
        {
            offset += 4;
            echoQuestion = true;
        }

        var responseLength = echoQuestion ? offset : HeaderSize;
        var response = new byte[responseLength];
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(0, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), echoQuestion ? (ushort)1 : (ushort)0);
        if (echoQuestion)
        {
            requestWire[HeaderSize..offset].CopyTo(response.AsSpan(HeaderSize));
        }

        return response;
    }

    /// <summary>
    /// Overwrites TTL values on answer resource records (e.g., to 30 seconds for RFC 8767 Serve-Stale responses).
    /// </summary>
    public static void RewriteAnswerTtls(Span<byte> wire, uint newTtlSeconds)
    {
        if (wire.Length < HeaderSize)
        {
            return;
        }

        ReadOnlySpan<byte> ro = wire;
        var qdCount = BinaryPrimitives.ReadUInt16BigEndian(ro[4..6]);
        var anCount = BinaryPrimitives.ReadUInt16BigEndian(ro[6..8]);
        var offset = HeaderSize;

        for (var i = 0; i < qdCount; i++)
        {
            if (!TryReadDomainName(ro, ref offset, out _) || offset + 4 > wire.Length)
            {
                return;
            }

            offset += 4;
        }

        for (var i = 0; i < anCount; i++)
        {
            if (!TryReadDomainName(ro, ref offset, out _) || offset + 10 > wire.Length)
            {
                return;
            }

            var rrType = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(ro.Slice(offset, 2));
            var rdLength = BinaryPrimitives.ReadUInt16BigEndian(ro.Slice(offset + 8, 2));
            if (offset + 10 + rdLength > wire.Length)
            {
                return;
            }

            if (rrType != DnsRecordType.OPT)
            {
                var existingTtl = BinaryPrimitives.ReadUInt32BigEndian(ro.Slice(offset + 4, 4));
                BinaryPrimitives.WriteUInt32BigEndian(wire.Slice(offset + 4, 4), Math.Min(existingTtl, newTtlSeconds));
            }

            offset += 10 + rdLength;
        }
    }

    /// <summary>
    /// Builds a valid RFC 1035 wire response answering the first question from a Local DNS Rewrite rule.
    /// </summary>
    public static byte[] CreateLocalRewriteResponse(
        ReadOnlySpan<byte> requestWire,
        LocalDnsRewriteRecordType recordType,
        string targetValue,
        uint ttlSeconds)
    {
        if (requestWire.Length < HeaderSize)
        {
            return [];
        }

        var id = BinaryPrimitives.ReadUInt16BigEndian(requestWire[0..2]);
        var reqFlags = BinaryPrimitives.ReadUInt16BigEndian(requestWire[2..4]);
        var qdCount = BinaryPrimitives.ReadUInt16BigEndian(requestWire[4..6]);
        if (qdCount == 0)
        {
            return [];
        }

        var qEnd = HeaderSize;
        if (!TryReadDomainName(requestWire, ref qEnd, out _) || qEnd + 4 > requestWire.Length)
        {
            return [];
        }

        qEnd += 4;

        DnsRecordType wireType;
        byte[] rdata;
        var cleanTarget = (targetValue ?? string.Empty).Trim();
        switch (recordType)
        {
            case LocalDnsRewriteRecordType.A:
                if (!IPAddress.TryParse(cleanTarget, out var ipv4) || ipv4.AddressFamily != AddressFamily.InterNetwork)
                {
                    return [];
                }

                wireType = DnsRecordType.A;
                rdata = ipv4.GetAddressBytes();
                break;

            case LocalDnsRewriteRecordType.AAAA:
                if (!IPAddress.TryParse(cleanTarget, out var ipv6) || ipv6.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    return [];
                }

                wireType = DnsRecordType.AAAA;
                rdata = ipv6.GetAddressBytes();
                break;

            case LocalDnsRewriteRecordType.CNAME:
            {
                try
                {
                    using var cnameStream = new MemoryStream(64);
                    WriteDomainName(cnameStream, cleanTarget);
                    wireType = DnsRecordType.CNAME;
                    rdata = cnameStream.ToArray();
                }
                catch (ArgumentException)
                {
                    return CreateErrorResponse(requestWire, DnsResponseCode.ServFail);
                }

                break;
            }

            default:
                return [];
        }

        var flags = (ushort)(0x8000 | (reqFlags & 0x0100) | 0x0080); // QR=1, RD=copied, RA=1, NOERROR
        using var ms = new MemoryStream(qEnd + 16 + rdata.Length);

        Span<byte> header = stackalloc byte[HeaderSize];
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], flags);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1); // QDCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 1); // ANCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[8..10], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], 0);
        ms.Write(header);

        ms.Write(requestWire[HeaderSize..qEnd]);

        Span<byte> rrHeader = stackalloc byte[12];
        rrHeader[0] = 0xC0; // Compression pointer to QNAME at offset 12
        rrHeader[1] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader[2..4], (ushort)wireType);
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader[4..6], 1); // IN
        BinaryPrimitives.WriteUInt32BigEndian(rrHeader[6..10], Math.Max(1u, ttlSeconds));
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader[10..12], (ushort)rdata.Length);
        ms.Write(rrHeader);
        ms.Write(rdata);

        return ms.ToArray();
    }

    public static bool TryParse(ReadOnlySpan<byte> buffer, out DnsPacket? packet)
    {
        packet = null;
        if (buffer.Length < HeaderSize)
        {
            return false;
        }

        var header = new DnsHeader(
            Id: BinaryPrimitives.ReadUInt16BigEndian(buffer[0..2]),
            Flags: BinaryPrimitives.ReadUInt16BigEndian(buffer[2..4]),
            QuestionCount: BinaryPrimitives.ReadUInt16BigEndian(buffer[4..6]),
            AnswerCount: BinaryPrimitives.ReadUInt16BigEndian(buffer[6..8]),
            AuthorityCount: BinaryPrimitives.ReadUInt16BigEndian(buffer[8..10]),
            AdditionalCount: BinaryPrimitives.ReadUInt16BigEndian(buffer[10..12]));

        if (header.QuestionCount > 64 || header.AnswerCount > 256)
        {
            return false;
        }

        var offset = HeaderSize;
        var questions = new List<DnsQuestion>(Math.Min((int)header.QuestionCount, 16));
        for (var i = 0; i < header.QuestionCount; i++)
        {
            if (!TryReadDomainName(buffer, ref offset, out var qname) || offset + 4 > buffer.Length)
            {
                return false;
            }

            var qtype = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
            var qclass = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset + 2, 2));
            offset += 4;
            questions.Add(new DnsQuestion(qname, qtype, qclass));
        }

        var answers = new List<DnsResourceRecord>(Math.Min((int)header.AnswerCount, 32));
        for (var i = 0; i < header.AnswerCount; i++)
        {
            if (!TryReadResourceRecord(buffer, ref offset, out var rr))
            {
                return false;
            }

            answers.Add(rr!);
        }

        packet = new DnsPacket
        {
            Header = header,
            Questions = questions,
            Answers = answers,
        };
        return true;
    }

    private static bool TryReadResourceRecord(ReadOnlySpan<byte> buffer, ref int offset, out DnsResourceRecord? record)
    {
        record = null;
        if (!TryReadDomainName(buffer, ref offset, out var name) || offset + 10 > buffer.Length)
        {
            return false;
        }

        var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
        var rclass = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset + 2, 2));
        var ttl = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(offset + 4, 4));
        var rdLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset + 8, 2));
        offset += 10;

        if (offset + rdLength > buffer.Length)
        {
            return false;
        }

        var rdataOffset = offset;
        var summary = FormatRData(buffer, type, rdataOffset, rdLength);
        offset += rdLength;

        record = new DnsResourceRecord(name, type, rclass, ttl, summary);
        return true;
    }

    private static string FormatRData(ReadOnlySpan<byte> packet, DnsRecordType type, int offset, int length)
    {
        var slice = packet.Slice(offset, length);
        switch (type)
        {
            case DnsRecordType.A when length == 4:
            case DnsRecordType.AAAA when length == 16:
                return new IPAddress(slice).ToString();

            case DnsRecordType.CNAME:
            case DnsRecordType.NS:
            case DnsRecordType.PTR:
            {
                var pos = offset;
                return TryReadDomainName(packet, ref pos, out var target) ? target : $"({length} bytes)";
            }

            case DnsRecordType.MX when length >= 3:
            {
                var pref = BinaryPrimitives.ReadUInt16BigEndian(slice[0..2]);
                var pos = offset + 2;
                return TryReadDomainName(packet, ref pos, out var exchange) ? $"{pref} {exchange}" : $"({length} bytes)";
            }

            case DnsRecordType.TXT when length >= 1:
            {
                var sb = new StringBuilder();
                var idx = 0;
                while (idx < slice.Length)
                {
                    var txtLen = slice[idx++];
                    if (idx + txtLen > slice.Length)
                    {
                        break;
                    }

                    if (sb.Length > 0)
                    {
                        sb.Append(' ');
                    }

                    sb.Append(Encoding.UTF8.GetString(slice.Slice(idx, txtLen)));
                    idx += txtLen;
                }

                return sb.ToString();
            }

            default:
                return $"({length} bytes)";
        }
    }

    private static void WriteDomainName(Stream stream, string domain)
    {
        var trimmed = domain.Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            stream.WriteByte(0);
            return;
        }

        foreach (var label in trimmed.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
            {
                throw new ArgumentException($"Invalid DNS label '{label}'.", nameof(domain));
            }

            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
    }

    internal static bool TryReadDomainName(ReadOnlySpan<byte> buffer, ref int offset, out string name)
    {
        name = string.Empty;
        if (offset < 0 || offset >= buffer.Length)
        {
            return false;
        }

        var sb = new StringBuilder();
        var current = offset;
        var jumped = false;
        var jumps = 0;

        while (true)
        {
            if (current >= buffer.Length)
            {
                return false;
            }

            var len = buffer[current];
            if (len == 0)
            {
                if (!jumped)
                {
                    offset = current + 1;
                }

                name = sb.ToString();
                return true;
            }

            // RFC 1035 §4.1.4 compression pointer: top two bits are 11 (0xC0).
            if ((len & 0xC0) == 0xC0)
            {
                if (current + 1 >= buffer.Length || ++jumps > MaxCompressionJumps)
                {
                    return false;
                }

                var pointer = ((len & 0x3F) << 8) | buffer[current + 1];
                // Pointer must point strictly backward within the DNS payload (after the 12-byte header).
                if (pointer < HeaderSize || pointer >= current || pointer >= buffer.Length)
                {
                    return false;
                }

                if (!jumped)
                {
                    offset = current + 2;
                    jumped = true;
                }

                current = pointer;
                continue;
            }

            if ((len & 0xC0) != 0 || current + 1 + len > buffer.Length)
            {
                return false;
            }

            if (sb.Length > 0)
            {
                sb.Append('.');
            }

            if (sb.Length + len > 253)
            {
                return false;
            }

            sb.Append(Encoding.ASCII.GetString(buffer.Slice(current + 1, len)));
            current += 1 + len;
        }
    }
}
