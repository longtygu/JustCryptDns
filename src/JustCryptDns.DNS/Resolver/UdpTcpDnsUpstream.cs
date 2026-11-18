using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.DNS.Resolver;

/// <summary>
/// Traditional RFC 1035 DNS over UDP with automatic TCP fallback on truncation (<c>TC=1</c>).
/// </summary>
public sealed class UdpTcpDnsUpstream : IDnsUpstreamClient
{
    public DnsProtocol Protocol => DnsProtocol.UdpTcp;

    public async Task<DnsQueryResult> QueryAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint resolver,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (!IPAddress.TryParse(resolver.PrimaryIp, out var ip))
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, Protocol, $"Invalid resolver IP '{resolver.PrimaryIp}'.");
        }

        var port = resolver.Port is > 0 and <= 65535 ? resolver.Port : 53;
        return await QueryEndpointAsync(queryWire, new IPEndPoint(ip, port), resolver.Id, Protocol, timeout, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<DnsQueryResult> QueryEndpointAsync(
        ReadOnlyMemory<byte> queryWire,
        IPEndPoint endpoint,
        string resolverId,
        DnsProtocol reportedProtocol,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (queryWire.Length < DnsPacket.HeaderSize)
        {
            return new DnsQueryResult(false, [], 0, resolverId, reportedProtocol, "Query packet is shorter than 12 bytes.");
        }

        var callerId = BinaryPrimitives.ReadUInt16BigEndian(queryWire.Span[0..2]);
        var outboundId = DnsPacket.GenerateTransactionId();
        var outbound = queryWire.ToArray();
        DnsPacket.WriteTransactionId(outbound, outboundId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        var sw = Stopwatch.StartNew();
        try
        {
            var response = await QueryUdpAsync(outbound, outboundId, endpoint, cts.Token).ConfigureAwait(false);
            if (DnsPacket.TryParse(response, out var parsed) && parsed!.Header.IsTruncated)
            {
                response = await QueryTcpAsync(outbound, outboundId, endpoint, cts.Token).ConfigureAwait(false);
            }

            sw.Stop();
            DnsPacket.WriteTransactionId(response, callerId);
            return new DnsQueryResult(true, response, sw.Elapsed.TotalMilliseconds, resolverId, reportedProtocol);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException or InvalidDataException)
        {
            sw.Stop();
            var reason = ex is OperationCanceledException && !cancellationToken.IsCancellationRequested
                ? "DNS query timed out."
                : ex.Message;
            return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolverId, reportedProtocol, reason);
        }
    }

    private static async Task<byte[]> QueryUdpAsync(byte[] outbound, ushort expectedId, IPEndPoint endpoint, CancellationToken ct)
    {
        using var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(endpoint, ct).ConfigureAwait(false);
        await socket.SendAsync(outbound, SocketFlags.None, ct).ConfigureAwait(false);

        var buffer = new byte[4096];
        while (true)
        {
            var received = await socket.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false);
            if (received < DnsPacket.HeaderSize)
            {
                continue;
            }

            var rxId = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(0, 2));
            var flags = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2, 2));
            if (rxId == expectedId && (flags & 0x8000) != 0)
            {
                return buffer.AsSpan(0, received).ToArray();
            }
        }
    }

    public static async Task<byte[]> QueryTcpAsync(byte[] outbound, ushort expectedId, IPEndPoint endpoint, CancellationToken ct)
    {
        using var client = new TcpClient(endpoint.AddressFamily);
        await client.ConnectAsync(endpoint.Address, endpoint.Port, ct).ConfigureAwait(false);
        var stream = client.GetStream();

        var framed = new byte[2 + outbound.Length];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)outbound.Length);
        outbound.CopyTo(framed.AsSpan(2));
        await stream.WriteAsync(framed, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        var lenBuf = new byte[2];
        await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
        var respLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
        if (respLen < DnsPacket.HeaderSize)
        {
            throw new InvalidDataException($"TCP DNS response too short ({respLen} bytes).");
        }

        var response = new byte[respLen];
        await stream.ReadExactlyAsync(response, ct).ConfigureAwait(false);
        var rxId = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(0, 2));
        if (rxId != expectedId)
        {
            throw new InvalidDataException("TCP DNS response transaction ID mismatch.");
        }

        return response;
    }
}
