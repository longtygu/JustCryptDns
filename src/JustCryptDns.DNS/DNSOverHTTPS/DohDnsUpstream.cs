using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.DNS.DNSOverHTTPS;

/// <summary>
/// RFC 8484 DNS over HTTPS (DoH) client.
/// Uses a single shared <see cref="HttpClient"/> with bootstrap IP socket connection so DoH resolution
/// never depends on OS DNS or loops back into the local proxy.
/// </summary>
public sealed class DohDnsUpstream : IDnsUpstreamClient, IDisposable
{
    private const string DnsMessageMediaType = "application/dns-message";
    private static readonly HttpRequestOptionsKey<IPAddress> BootstrapIpKey = new("JustCryptDns.BootstrapIp");

    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public DohDnsUpstream(HttpClient? customHttpClient = null)
    {
        if (customHttpClient is not null)
        {
            _httpClient = customHttpClient;
            _ownsClient = false;
            return;
        }

        var handler = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            EnableMultipleHttp2Connections = true,
            AutomaticDecompression = DecompressionMethods.None,
            UseProxy = false,
            ConnectCallback = ConnectWithBootstrapIpAsync,
        };
        _httpClient = new HttpClient(handler, disposeHandler: true)
        {
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        _ownsClient = true;
    }

    public DnsProtocol Protocol => DnsProtocol.DnsOverHttps;

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

        if (!Uri.TryCreate(resolver.Endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, Protocol, $"Invalid DoH HTTPS endpoint '{resolver.Endpoint}'.");
        }

        var callerId = BinaryPrimitives.ReadUInt16BigEndian(queryWire.Span[0..2]);
        var payload = queryWire.ToArray();
        // RFC 8484 §4.1 recommends transaction ID 0 for HTTP caching compatibility; restored after response.
        DnsPacket.WriteTransactionId(payload, 0);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = new ByteArrayContent(payload),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(DnsMessageMediaType);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DnsMessageMediaType));

        if (IPAddress.TryParse(resolver.PrimaryIp, out var bootstrapIp))
        {
            request.Options.Set(BootstrapIpKey, bootstrapIp);
        }

        var sw = Stopwatch.StartNew();
        try
        {
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead, cts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                sw.Stop();
                return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
            }

            var bytes = await response.Content.ReadAsByteArrayAsync(cts.Token).ConfigureAwait(false);
            sw.Stop();
            if (bytes.Length < DnsPacket.HeaderSize)
            {
                return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol, "DoH response shorter than 12 bytes.");
            }

            DnsPacket.WriteTransactionId(bytes, callerId);
            return new DnsQueryResult(true, bytes, sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol);
        }
        catch (Exception ex) when (ex is HttpRequestException or SocketException or System.Security.Authentication.AuthenticationException or OperationCanceledException or IOException)
        {
            sw.Stop();
            var reason = ex is OperationCanceledException && !cancellationToken.IsCancellationRequested
                ? "DoH query timed out."
                : ex.Message;
            return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol, reason);
        }
    }

    public void Dispose()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }
    }

    private static async ValueTask<Stream> ConnectWithBootstrapIpAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        IPAddress? targetIp = null;
        if (context.InitialRequestMessage.Options.TryGetValue(BootstrapIpKey, out var bootstrapIp))
        {
            targetIp = bootstrapIp;
        }
        else if (IPAddress.TryParse(context.DnsEndPoint.Host, out var literalIp))
        {
            targetIp = literalIp;
        }

        var socket = targetIp is not null
            ? new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true }
            : new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            if (targetIp is not null)
            {
                await socket.ConnectAsync(new IPEndPoint(targetIp, context.DnsEndPoint.Port), cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
            }

            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
