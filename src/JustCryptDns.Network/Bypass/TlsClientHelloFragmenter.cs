using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Network.Bypass;

public sealed record InitialPayloadReadResult(
    byte[] FirstPayload,
    byte[] TrailingBytes,
    bool IsCompleteTlsClientHello);

/// <summary>
/// Pure-C# TLS ClientHello and HTTP Host header analyzer and fragmenter.
/// Splits initial handshake records below DPI inspection boundaries while keeping byte-identical TLS payloads.
/// </summary>
public static class TlsClientHelloFragmenter
{
    public const int MaxClientHelloRecordBytes = 16384 + 5;

    public static bool IsTlsClientHelloHeader(ReadOnlySpan<byte> header) =>
        header.Length >= 6
        && header[0] == 0x16 // Handshake record
        && header[1] == 0x03 // TLS/SSL 3.x major version
        && header[2] <= 0x04 // TLS 1.0..1.3 record version
        && header[5] == 0x01; // ClientHello handshake type

    /// <summary>
    /// Locates the ASCII SNI hostname slice inside a TLS ClientHello record.
    /// <paramref name="hostStart"/> is relative to <paramref name="clientHelloRecord"/>.
    /// </summary>
    public static bool TryFindSniHostSpan(
        ReadOnlySpan<byte> clientHelloRecord,
        out int hostStart,
        out int hostLength)
    {
        hostStart = 0;
        hostLength = 0;

        if (!IsTlsClientHelloHeader(clientHelloRecord))
        {
            return false;
        }

        var recordLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(3, 2));
        var limit = Math.Min(clientHelloRecord.Length, 5 + recordLen);

        // Record header (5) + Handshake type (1) + length (3) = 9
        var pos = 9;
        // ClientHello: legacy_version (2) + random (32) = 34
        if (pos + 34 > limit)
        {
            return false;
        }

        pos += 34;

        // session_id
        if (pos + 1 > limit)
        {
            return false;
        }

        var sessionIdLen = clientHelloRecord[pos++];
        pos += sessionIdLen;
        if (pos + 2 > limit)
        {
            return false;
        }

        // cipher_suites
        var cipherSuitesLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(pos, 2));
        pos += 2 + cipherSuitesLen;
        if (pos + 1 > limit)
        {
            return false;
        }

        // compression_methods
        var compressionLen = clientHelloRecord[pos++];
        pos += compressionLen;
        if (pos + 2 > limit)
        {
            return false;
        }

        // extensions
        var extensionsLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(pos, 2));
        pos += 2;
        var extensionsEnd = Math.Min(limit, pos + extensionsLen);

        while (pos + 4 <= extensionsEnd)
        {
            var extType = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(pos, 2));
            var extLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(pos + 2, 2));
            pos += 4;
            var nextExt = pos + extLen;
            if (nextExt > extensionsEnd)
            {
                return false;
            }

            if (extType == 0x0000 && pos + 2 <= nextExt)
            {
                var listLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(pos, 2));
                var sniPos = pos + 2;
                var sniEnd = Math.Min(nextExt, sniPos + listLen);
                while (sniPos + 3 <= sniEnd)
                {
                    var nameType = clientHelloRecord[sniPos];
                    var nameLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(sniPos + 1, 2));
                    sniPos += 3;
                    if (sniPos + nameLen > sniEnd)
                    {
                        return false;
                    }

                    if (nameType == 0x00 && nameLen > 0)
                    {
                        hostStart = sniPos;
                        hostLength = nameLen;
                        return true;
                    }

                    sniPos += nameLen;
                }
            }

            pos = nextExt;
        }

        return false;
    }

    /// <summary>
    /// Splits a single TLS ClientHello record into multiple valid TLS Handshake records.
    /// Ensures the SNI hostname itself is cut across a record boundary whenever SNI is present.
    /// </summary>
    public static IReadOnlyList<byte[]> BuildFragmentedTlsRecords(
        ReadOnlySpan<byte> clientHelloRecord,
        TlsFragmentationStrategy strategy,
        int fragmentSizeBytes)
    {
        if (!IsTlsClientHelloHeader(clientHelloRecord))
        {
            return [clientHelloRecord.ToArray()];
        }

        var recordLen = BinaryPrimitives.ReadUInt16BigEndian(clientHelloRecord.Slice(3, 2));
        var payloadLen = Math.Min(recordLen, clientHelloRecord.Length - 5);
        if (payloadLen <= 8)
        {
            return [clientHelloRecord[..(5 + payloadLen)].ToArray()];
        }

        var verMajor = clientHelloRecord[1];
        var verMinor = clientHelloRecord[2];
        var payload = clientHelloRecord.Slice(5, payloadLen);

        int? sniMidPayloadOffset = null;
        if (TryFindSniHostSpan(clientHelloRecord[..(5 + payloadLen)], out var sniStart, out var sniLen) && sniLen >= 2)
        {
            sniMidPayloadOffset = (sniStart - 5) + Math.Max(1, sniLen / 2);
        }

        if (strategy == TlsFragmentationStrategy.SniMidpointSplit && sniMidPayloadOffset is { } splitAt && splitAt > 0 && splitAt < payloadLen)
        {
            return
            [
                WrapRecord(verMajor, verMinor, payload[..splitAt]),
                WrapRecord(verMajor, verMinor, payload[splitAt..]),
            ];
        }

        var chunkSize = strategy == TlsFragmentationStrategy.AggressiveSmallRecords
            ? 16
            : Math.Clamp(fragmentSizeBytes, 8, 256);

        var records = new List<byte[]>((payloadLen / chunkSize) + 2);
        var offset = 0;
        while (offset < payloadLen)
        {
            var take = Math.Min(chunkSize, payloadLen - offset);

            // Guarantee an additional boundary inside SNI even if chunkSize would otherwise encompass the whole hostname.
            if (sniMidPayloadOffset is { } mid && offset < mid && offset + take >= mid && mid - offset < take)
            {
                take = mid - offset;
            }

            records.Add(WrapRecord(verMajor, verMinor, payload.Slice(offset, take)));
            offset += take;
        }

        return records;
    }

    public static bool TrySplitHttpHostHeader(ReadOnlySpan<byte> httpRequest, out int splitOffset)
    {
        splitOffset = 0;
        if (httpRequest.Length < 16)
        {
            return false;
        }

        var headerEnd = httpRequest.IndexOf("\r\n\r\n"u8);
        var limit = headerEnd >= 0 ? headerEnd : httpRequest.Length;
        ReadOnlySpan<byte> prefixLower = "\nhost:"u8;

        for (var i = 0; i <= limit - prefixLower.Length; i++)
        {
            if (MatchesAsciiCaseInsensitive(httpRequest.Slice(i, prefixLower.Length), prefixLower))
            {
                var valStart = i + prefixLower.Length;
                while (valStart < limit && (httpRequest[valStart] == (byte)' ' || httpRequest[valStart] == (byte)'\t'))
                {
                    valStart++;
                }

                var valEnd = valStart;
                while (valEnd < limit && httpRequest[valEnd] != (byte)'\r' && httpRequest[valEnd] != (byte)'\n' && httpRequest[valEnd] != (byte)':')
                {
                    valEnd++;
                }

                var hostLen = valEnd - valStart;
                if (hostLen >= 2)
                {
                    splitOffset = valStart + Math.Max(1, hostLen / 2);
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Reads the complete first payload from the client stream. When the payload starts with a TLS ClientHello
    /// record (which can exceed 1,600 bytes with post-quantum TLS 1.3), loops until the entire declared record arrives.
    /// </summary>
    public static async Task<InitialPayloadReadResult> ReadCompleteFirstPayloadAsync(
        Stream clientStream,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientStream);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(Math.Clamp(timeoutMs, 500, 15000));

        var buffer = new byte[4096];
        var filled = 0;

        while (filled < 6)
        {
            int n;
            try
            {
                n = await clientStream.ReadAsync(buffer.AsMemory(filled), cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }
            catch (IOException)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }

            if (n == 0)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }

            filled += n;
            if (!MightBeTlsRecordHeader(buffer.AsSpan(0, filled)))
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }
        }

        if (!IsTlsClientHelloHeader(buffer.AsSpan(0, filled)))
        {
            return new InitialPayloadReadResult(buffer[..filled], [], false);
        }

        var recordLen = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(3, 2));
        var targetBytes = 5 + recordLen;
        if (targetBytes > MaxClientHelloRecordBytes)
        {
            return new InitialPayloadReadResult(buffer[..filled], [], false);
        }

        if (targetBytes > buffer.Length)
        {
            Array.Resize(ref buffer, targetBytes);
        }

        while (filled < targetBytes)
        {
            int n;
            try
            {
                n = await clientStream.ReadAsync(buffer.AsMemory(filled, buffer.Length - filled), cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }
            catch (IOException)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }

            if (n == 0)
            {
                return new InitialPayloadReadResult(buffer[..filled], [], false);
            }

            filled += n;
        }

        var clientHello = buffer[..targetBytes];
        var trailing = filled > targetBytes ? buffer[targetBytes..filled] : [];
        return new InitialPayloadReadResult(clientHello, trailing, true);
    }

    private static bool MightBeTlsRecordHeader(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 1 && bytes[0] != 0x16)
        {
            return false;
        }

        if (bytes.Length >= 2 && bytes[1] != 0x03)
        {
            return false;
        }

        if (bytes.Length >= 3 && bytes[2] > 0x04)
        {
            return false;
        }

        if (bytes.Length >= 6 && bytes[5] != 0x01)
        {
            return false;
        }

        return true;
    }

    private static byte[] WrapRecord(byte major, byte minor, ReadOnlySpan<byte> payload)
    {
        var rec = new byte[5 + payload.Length];
        rec[0] = 0x16;
        rec[1] = major;
        rec[2] = minor;
        BinaryPrimitives.WriteUInt16BigEndian(rec.AsSpan(3, 2), (ushort)payload.Length);
        payload.CopyTo(rec.AsSpan(5));
        return rec;
    }

    private static bool MatchesAsciiCaseInsensitive(ReadOnlySpan<byte> slice, ReadOnlySpan<byte> lowerPattern)
    {
        if (slice.Length != lowerPattern.Length)
        {
            return false;
        }

        for (var i = 0; i < slice.Length; i++)
        {
            var b = slice[i];
            if (b is >= (byte)'A' and <= (byte)'Z')
            {
                b = (byte)(b + 32);
            }

            if (b != lowerPattern[i])
            {
                return false;
            }
        }

        return true;
    }
}
