using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.DNS.DNSOverTLS;

/// <summary>
/// RFC 7858 DNS over TLS (DoT) client on port 853 with strict TLS SNI and X.509 certificate verification.
/// </summary>
public sealed class DotDnsUpstream : IDnsUpstreamClient
{
    public DnsProtocol Protocol => DnsProtocol.DnsOverTls;

    public async Task<DnsQueryResult> QueryAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint resolver,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (queryWire.Length < DnsPacket.HeaderSize)
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, Protocol, "Query packet is shorter than 12 bytes.");
        }

        if (!IPAddress.TryParse(resolver.PrimaryIp, out var ip))
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, Protocol, $"Invalid DoT IP '{resolver.PrimaryIp}'.");
        }

        var tlsHost = string.IsNullOrWhiteSpace(resolver.Endpoint) ? resolver.PrimaryIp : resolver.Endpoint;
        var port = resolver.Port is > 0 and <= 65535 ? resolver.Port : 853;

        var callerId = BinaryPrimitives.ReadUInt16BigEndian(queryWire.Span[0..2]);
        var outboundId = DnsPacket.GenerateTransactionId();
        var outbound = queryWire.ToArray();
        DnsPacket.WriteTransactionId(outbound, outboundId);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);

            await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = tlsHost,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            };
            await ssl.AuthenticateAsClientAsync(sslOptions, cts.Token).ConfigureAwait(false);

            var framed = new byte[2 + outbound.Length];
            BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)outbound.Length);
            outbound.CopyTo(framed.AsSpan(2));
            await ssl.WriteAsync(framed, cts.Token).ConfigureAwait(false);
            await ssl.FlushAsync(cts.Token).ConfigureAwait(false);

            var lenBuf = new byte[2];
            await ssl.ReadExactlyAsync(lenBuf, cts.Token).ConfigureAwait(false);
            var respLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
            if (respLen < DnsPacket.HeaderSize)
            {
                throw new InvalidDataException($"DoT response too short ({respLen} bytes).");
            }

            var response = new byte[respLen];
            await ssl.ReadExactlyAsync(response, cts.Token).ConfigureAwait(false);
            sw.Stop();

            DnsPacket.WriteTransactionId(response, callerId);
            return new DnsQueryResult(true, response, sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or InvalidDataException or OperationCanceledException)
        {
            sw.Stop();
            var reason = ex is OperationCanceledException && !cancellationToken.IsCancellationRequested
                ? "DoT query timed out."
                : ex.Message;
            return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol, reason);
        }
    }
}
