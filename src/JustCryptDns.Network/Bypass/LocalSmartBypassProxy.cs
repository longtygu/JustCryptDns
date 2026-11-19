using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Pure-C# local unified HTTP CONNECT + HTTP + SOCKS5 smart bypass proxy.
/// Performs TLS ClientHello record fragmentation, HTTP Host fragmentation,
/// and seamless AutoHybrid fallback to an upstream tunnel without any kernel drivers.
/// </summary>
public sealed class LocalSmartBypassProxy : IAsyncDisposable
{
    private const int RelayBufferSize = 32 * 1024;

    private readonly IPAddress _listenAddress;
    private readonly int _requestedPort;
    private readonly Func<int> _getPacPort;
    private readonly Func<BypassSettings> _getSettings;
    private readonly Func<bool> _getAllowIpv6;
    private readonly BypassRuleMatcher _matcher;
    private readonly UpstreamTunnelConnector _connector;
    private readonly Action<BypassActionKind, string, int, string, string, double, string?> _recordEvent;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();

    private TcpListener? _listener;
    private Task? _acceptTask;
    private bool _disposed;
    private int _activeTunnels;

    public LocalSmartBypassProxy(
        IPAddress listenAddress,
        int port,
        Func<int> getPacPort,
        Func<BypassSettings> getSettings,
        Func<bool> getAllowIpv6,
        BypassRuleMatcher matcher,
        UpstreamTunnelConnector connector,
        Action<BypassActionKind, string, int, string, string, double, string?> recordEvent,
        ILogger logger)
    {
        _listenAddress = listenAddress;
        _requestedPort = port;
        _getPacPort = getPacPort;
        _getSettings = getSettings;
        _getAllowIpv6 = getAllowIpv6;
        _matcher = matcher;
        _connector = connector;
        _recordEvent = recordEvent;
        _logger = logger;
    }

    public int BoundPort { get; private set; }

    public int ActiveTunnels => Volatile.Read(ref _activeTunnels);

    public void Start()
    {
        if (_listener is not null)
        {
            return;
        }

        _listener = new TcpListener(_listenAddress, _requestedPort);
        _listener.Start(256);
        BoundPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token), _cts.Token);
        _logger.LogInformation("Smart bypass proxy listening on {Address}:{Port}", _listenAddress, BoundPort);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            TcpClient? client = null;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleClientConnectionAsync(client, ct), ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                client?.Dispose();
                break;
            }
            catch (ObjectDisposedException)
            {
                client?.Dispose();
                break;
            }
            catch (SocketException ex)
            {
                client?.Dispose();
                if (!ct.IsCancellationRequested)
                {
                    _logger.LogDebug(ex, "Smart bypass accept error.");
                }
            }
        }
    }

    private async Task HandleClientConnectionAsync(TcpClient client, CancellationToken ct)
    {
        Interlocked.Increment(ref _activeTunnels);
        try
        {
            using (client)
            {
                client.NoDelay = true;
                var stream = client.GetStream();

                // Peek first byte to auto-detect SOCKS5 vs HTTP/HTTPS proxy.
                var firstByte = new byte[1];
                using var peekCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                peekCts.CancelAfter(3000);
                var peeked = await client.Client.ReceiveAsync(firstByte, SocketFlags.Peek, peekCts.Token).ConfigureAwait(false);
                if (peeked == 0)
                {
                    return;
                }

                if (firstByte[0] == 0x05)
                {
                    await HandleSocks5ClientAsync(client, stream, ct).ConfigureAwait(false);
                }
                else
                {
                    await HandleHttpProxyClientAsync(client, stream, ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown or connection timeout.
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _logger.LogDebug(ex, "Client connection ended with network error.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unhandled exception inside smart bypass session.");
        }
        finally
        {
            Interlocked.Decrement(ref _activeTunnels);
        }
    }

    private async Task HandleSocks5ClientAsync(TcpClient client, NetworkStream stream, CancellationToken ct)
    {
        var head = new byte[2];
        await stream.ReadExactlyAsync(head, ct).ConfigureAwait(false);
        if (head[0] != 0x05)
        {
            return;
        }

        var methodCount = head[1];
        var methods = new byte[methodCount];
        await stream.ReadExactlyAsync(methods, ct).ConfigureAwait(false);
        if (!methods.Contains((byte)0x00))
        {
            await stream.WriteAsync(new byte[] { 0x05, 0xFF }, ct).ConfigureAwait(false);
            return;
        }

        await stream.WriteAsync(new byte[] { 0x05, 0x00 }, ct).ConfigureAwait(false);

        var reqHead = new byte[4];
        await stream.ReadExactlyAsync(reqHead, ct).ConfigureAwait(false);
        if (reqHead[0] != 0x05 || reqHead[1] != 0x01)
        {
            await SendSocks5ReplyAsync(stream, 0x07, ct).ConfigureAwait(false);
            return;
        }

        string targetHost;
        switch (reqHead[3])
        {
            case 0x01:
            {
                var ipBytes = new byte[4];
                await stream.ReadExactlyAsync(ipBytes, ct).ConfigureAwait(false);
                targetHost = new IPAddress(ipBytes).ToString();
                break;
            }
            case 0x03:
            {
                var lenBuf = new byte[1];
                await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
                var domainBytes = new byte[lenBuf[0]];
                await stream.ReadExactlyAsync(domainBytes, ct).ConfigureAwait(false);
                targetHost = Encoding.ASCII.GetString(domainBytes);
                break;
            }
            case 0x04:
            {
                var ipBytes = new byte[16];
                await stream.ReadExactlyAsync(ipBytes, ct).ConfigureAwait(false);
                targetHost = new IPAddress(ipBytes).ToString();
                break;
            }
            default:
                await SendSocks5ReplyAsync(stream, 0x08, ct).ConfigureAwait(false);
                return;
        }

        var portBytes = new byte[2];
        await stream.ReadExactlyAsync(portBytes, ct).ConfigureAwait(false);
        var targetPort = BinaryPrimitives.ReadUInt16BigEndian(portBytes);

        if (IsSelfLoop(targetHost, targetPort))
        {
            await SendSocks5ReplyAsync(stream, 0x02, ct).ConfigureAwait(false);
            _recordEvent(BypassActionKind.Failed, targetHost, targetPort, "SOCKS5", "LoopPrevented", 0, "Blocked proxy self-loop.");
            return;
        }

        await SendSocks5ReplyAsync(stream, 0x00, ct).ConfigureAwait(false);
        await StreamSessionAsync(client, stream, targetHost, targetPort, "SOCKS5", preBufferedPayload: null, ct).ConfigureAwait(false);
    }

    private static Task SendSocks5ReplyAsync(NetworkStream stream, byte rep, CancellationToken ct) =>
        stream.WriteAsync(new byte[] { 0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, ct).AsTask();

    private async Task HandleHttpProxyClientAsync(TcpClient client, NetworkStream stream, CancellationToken ct)
    {
        using var headerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        headerCts.CancelAfter(4000);
        var headerBytes = await UpstreamTunnelConnector.ReadHttpHeadersExactAsync(client.Client, stream, 8192, headerCts.Token).ConfigureAwait(false);
        if (headerBytes.Length == 0)
        {
            return;
        }

        var headerText = Encoding.ASCII.GetString(headerBytes);
        var lines = headerText.Split(["\r\n"], StringSplitOptions.None);
        if (lines.Length == 0)
        {
            return;
        }

        var parts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            await stream.WriteAsync("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
            return;
        }

        var method = parts[0];
        var target = parts[1];
        var version = parts[2];

        if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryParseHostPort(target, defaultPort: 443, out var host, out var port))
            {
                await stream.WriteAsync("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
                return;
            }

            if (IsSelfLoop(host, port))
            {
                await stream.WriteAsync("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
                _recordEvent(BypassActionKind.Failed, host, port, "HTTP CONNECT", "LoopPrevented", 0, "Blocked proxy self-loop.");
                return;
            }

            await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            await StreamSessionAsync(client, stream, host, port, "HTTP CONNECT", preBufferedPayload: null, ct).ConfigureAwait(false);
            return;
        }

        // Plain HTTP proxy request (GET http://example.com/path HTTP/1.1)
        string plainHost;
        int plainPort;
        string pathAndQuery;
        if (Uri.TryCreate(target, UriKind.Absolute, out var absUri))
        {
            plainHost = absUri.Host;
            plainPort = absUri.Port > 0 ? absUri.Port : 80;
            pathAndQuery = string.IsNullOrEmpty(absUri.PathAndQuery) ? "/" : absUri.PathAndQuery;
        }
        else
        {
            var hostHeader = lines.Skip(1).FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
            var rawHost = hostHeader is not null ? hostHeader[5..].Trim() : string.Empty;
            if (!TryParseHostPort(rawHost, defaultPort: 80, out plainHost, out plainPort))
            {
                await stream.WriteAsync("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
                return;
            }

            pathAndQuery = string.IsNullOrEmpty(target) ? "/" : target;
        }

        if (IsSelfLoop(plainHost, plainPort))
        {
            await stream.WriteAsync("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), ct).ConfigureAwait(false);
            _recordEvent(BypassActionKind.Failed, plainHost, plainPort, "HTTP", "LoopPrevented", 0, "Blocked proxy self-loop.");
            return;
        }

        var rebuilt = new StringBuilder(headerText.Length);
        rebuilt.Append(method).Append(' ').Append(pathAndQuery).Append(' ').Append(version).Append("\r\n");
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrEmpty(line))
            {
                continue;
            }

            if (line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            rebuilt.Append(line).Append("\r\n");
        }

        rebuilt.Append("\r\n");
        var rewrittenHeaderBytes = Encoding.ASCII.GetBytes(rebuilt.ToString());
        await StreamSessionAsync(client, stream, plainHost, plainPort, "HTTP", rewrittenHeaderBytes, ct).ConfigureAwait(false);
    }

    private async Task StreamSessionAsync(
        TcpClient client,
        NetworkStream clientStream,
        string targetHost,
        int targetPort,
        string clientProtocol,
        byte[]? preBufferedPayload,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        var settings = _getSettings();
        var allowIpv6 = _getAllowIpv6();
        var mode = _matcher.Evaluate(targetHost, settings);

        if (mode == BypassMode.Direct)
        {
            TcpClient? direct = null;
            try
            {
                (direct, _) = await _connector.ConnectDirectAsync(
                    targetHost,
                    targetPort,
                    settings.ResolveTargetViaLocalDns,
                    allowIpv6,
                    settings.ConnectTimeoutMs,
                    ct).ConfigureAwait(false);

                var directStream = direct.GetStream();
                if (preBufferedPayload is { Length: > 0 })
                {
                    await directStream.WriteAsync(preBufferedPayload, ct).ConfigureAwait(false);
                    await directStream.FlushAsync(ct).ConfigureAwait(false);
                }

                sw.Stop();
                _recordEvent(BypassActionKind.DirectPassthrough, targetHost, targetPort, clientProtocol, "Direct", Math.Round(sw.Elapsed.TotalMilliseconds, 1), null);
                await RelayBidirectionalAsync(client, clientStream, direct, directStream, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                direct?.Dispose();
                sw.Stop();
                _recordEvent(BypassActionKind.Failed, targetHost, targetPort, clientProtocol, "Direct", Math.Round(sw.Elapsed.TotalMilliseconds, 1), ex.Message);
            }

            return;
        }

        if (mode == BypassMode.UpstreamTunnel)
        {
            if (!settings.Upstream.Enabled || settings.Upstream.Kind == UpstreamTunnelKind.None)
            {
                mode = BypassMode.DpiFragment;
            }
            else
            {
                TcpClient? upstream = null;
                try
                {
                    upstream = await UpstreamTunnelConnector.ConnectViaUpstreamAsync(
                        targetHost,
                        targetPort,
                        settings.Upstream,
                        settings.ConnectTimeoutMs,
                        ct).ConfigureAwait(false);
                    var upstreamStream = upstream.GetStream();
                    if (preBufferedPayload is { Length: > 0 })
                    {
                        await upstreamStream.WriteAsync(preBufferedPayload, ct).ConfigureAwait(false);
                        await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
                    }

                    sw.Stop();
                    _recordEvent(BypassActionKind.UpstreamTunneled, targetHost, targetPort, clientProtocol, settings.Upstream.Kind.ToString(), Math.Round(sw.Elapsed.TotalMilliseconds, 1), null);
                    await RelayBidirectionalAsync(client, clientStream, upstream, upstreamStream, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    upstream?.Dispose();
                    sw.Stop();
                    _recordEvent(BypassActionKind.Failed, targetHost, targetPort, clientProtocol, settings.Upstream.Kind.ToString(), Math.Round(sw.Elapsed.TotalMilliseconds, 1), ex.Message);
                }

                return;
            }
        }

        // DpiFragment or AutoHybrid: read the complete first payload (ClientHello or HTTP request)
        // so we can fragment it cleanly AND replay it cleanly over upstream if AutoHybrid fallback is needed.
        InitialPayloadReadResult initial;
        if (preBufferedPayload is { Length: > 0 })
        {
            initial = new InitialPayloadReadResult(preBufferedPayload, [], false);
        }
        else
        {
            initial = await TlsClientHelloFragmenter.ReadCompleteFirstPayloadAsync(
                clientStream,
                Math.Min(settings.ConnectTimeoutMs, 4000),
                ct).ConfigureAwait(false);
        }

        if (initial.FirstPayload.Length == 0)
        {
            return;
        }

        var canFallbackToUpstream = mode == BypassMode.AutoHybrid
            && settings.AutoFallbackToTunnelOnDpiFailure
            && settings.Upstream.Enabled
            && settings.Upstream.Kind != UpstreamTunnelKind.None;

        var firstResponseBuf = new byte[4096];
        var firstResponseLen = 0;
        var strategyLabel = DescribeStrategy(initial.FirstPayload, settings);
        TcpClient? dpiUpstream = null;

        try
        {
            (dpiUpstream, _) = await _connector.ConnectDirectAsync(
                targetHost,
                targetPort,
                settings.ResolveTargetViaLocalDns,
                allowIpv6,
                settings.ConnectTimeoutMs,
                ct).ConfigureAwait(false);

            var upstreamStream = dpiUpstream.GetStream();
            await SendPotentiallyFragmentedFirstPayloadAsync(upstreamStream, initial, settings, ct).ConfigureAwait(false);

            // Verify first server response byte before committing (enables seamless AutoHybrid fallback).
            using var firstByteCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            firstByteCts.CancelAfter(Math.Clamp(settings.ConnectTimeoutMs, 1000, 4000));
            firstResponseLen = await upstreamStream.ReadAsync(firstResponseBuf, firstByteCts.Token).ConfigureAwait(false);
            if (firstResponseLen <= 0)
            {
                throw new IOException("Remote host closed connection before handshake response.");
            }

            await clientStream.WriteAsync(firstResponseBuf.AsMemory(0, firstResponseLen), ct).ConfigureAwait(false);
            await clientStream.FlushAsync(ct).ConfigureAwait(false);

            sw.Stop();
            _recordEvent(BypassActionKind.DpiFragmented, targetHost, targetPort, clientProtocol, strategyLabel, Math.Round(sw.Elapsed.TotalMilliseconds, 1), null);
            await RelayBidirectionalAsync(client, clientStream, dpiUpstream, upstreamStream, ct).ConfigureAwait(false);
            return;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            dpiUpstream?.Dispose();
            if (!canFallbackToUpstream)
            {
                sw.Stop();
                _recordEvent(BypassActionKind.Failed, targetHost, targetPort, clientProtocol, strategyLabel, Math.Round(sw.Elapsed.TotalMilliseconds, 1), ex.Message);
                return;
            }

            _logger.LogDebug(ex, "DPI bypass failed for {Host}:{Port}; falling back to upstream tunnel.", targetHost, targetPort);
        }

        // AutoHybrid transparent fallback to upstream tunnel, replaying original intact ClientHello.
        TcpClient? fallbackTunnel = null;
        try
        {
            fallbackTunnel = await UpstreamTunnelConnector.ConnectViaUpstreamAsync(
                targetHost,
                targetPort,
                settings.Upstream,
                settings.ConnectTimeoutMs,
                ct).ConfigureAwait(false);

            var tunnelStream = fallbackTunnel.GetStream();
            await tunnelStream.WriteAsync(initial.FirstPayload, ct).ConfigureAwait(false);
            if (initial.TrailingBytes.Length > 0)
            {
                await tunnelStream.WriteAsync(initial.TrailingBytes, ct).ConfigureAwait(false);
            }

            await tunnelStream.FlushAsync(ct).ConfigureAwait(false);

            _matcher.RecordAutoFallbackHint(targetHost);
            sw.Stop();
            _recordEvent(
                BypassActionKind.AutoFallbackTunnel,
                targetHost,
                targetPort,
                clientProtocol,
                $"Fallback -> {settings.Upstream.Kind}",
                Math.Round(sw.Elapsed.TotalMilliseconds, 1),
                null);
            await RelayBidirectionalAsync(client, clientStream, fallbackTunnel, tunnelStream, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            fallbackTunnel?.Dispose();
            sw.Stop();
            _recordEvent(BypassActionKind.Failed, targetHost, targetPort, clientProtocol, $"Fallback -> {settings.Upstream.Kind}", Math.Round(sw.Elapsed.TotalMilliseconds, 1), ex.Message);
        }
    }

    private static string DescribeStrategy(ReadOnlySpan<byte> payload, BypassSettings settings)
    {
        if (TlsClientHelloFragmenter.IsTlsClientHelloHeader(payload))
        {
            return settings.FragmentationStrategy switch
            {
                TlsFragmentationStrategy.SniMidpointSplit => "TLS SNI Split",
                TlsFragmentationStrategy.AggressiveSmallRecords => "TLS 16B Split",
                _ => $"TLS {settings.FragmentSizeBytes}B Split",
            };
        }

        if (settings.FragmentHttpHostHeader && TlsClientHelloFragmenter.TrySplitHttpHostHeader(payload, out _))
        {
            return "HTTP Host Split";
        }

        return "DirectStream";
    }

    private static async Task SendPotentiallyFragmentedFirstPayloadAsync(
        NetworkStream upstreamStream,
        InitialPayloadReadResult initial,
        BypassSettings settings,
        CancellationToken ct)
    {
        if (TlsClientHelloFragmenter.IsTlsClientHelloHeader(initial.FirstPayload))
        {
            var records = TlsClientHelloFragmenter.BuildFragmentedTlsRecords(
                initial.FirstPayload,
                settings.FragmentationStrategy,
                settings.FragmentSizeBytes);
            for (var i = 0; i < records.Count; i++)
            {
                await upstreamStream.WriteAsync(records[i], ct).ConfigureAwait(false);
                await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
                if (settings.FragmentDelayMs > 0 && i < records.Count - 1)
                {
                    await Task.Delay(settings.FragmentDelayMs, ct).ConfigureAwait(false);
                }
            }
        }
        else if (settings.FragmentHttpHostHeader
            && TlsClientHelloFragmenter.TrySplitHttpHostHeader(initial.FirstPayload, out var splitOffset)
            && splitOffset > 0
            && splitOffset < initial.FirstPayload.Length)
        {
            await upstreamStream.WriteAsync(initial.FirstPayload.AsMemory(0, splitOffset), ct).ConfigureAwait(false);
            await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
            if (settings.FragmentDelayMs > 0)
            {
                await Task.Delay(settings.FragmentDelayMs, ct).ConfigureAwait(false);
            }

            await upstreamStream.WriteAsync(initial.FirstPayload.AsMemory(splitOffset), ct).ConfigureAwait(false);
            await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
        }
        else
        {
            await upstreamStream.WriteAsync(initial.FirstPayload, ct).ConfigureAwait(false);
            await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
        }

        if (initial.TrailingBytes.Length > 0)
        {
            await upstreamStream.WriteAsync(initial.TrailingBytes, ct).ConfigureAwait(false);
            await upstreamStream.FlushAsync(ct).ConfigureAwait(false);
        }
    }

    private static async Task RelayBidirectionalAsync(
        TcpClient client,
        NetworkStream clientStream,
        TcpClient upstream,
        NetworkStream upstreamStream,
        CancellationToken ct)
    {
        using (upstream)
        {
            var c2u = CopyOneDirectionAsync(clientStream, upstreamStream, upstream.Client, ct);
            var u2c = CopyOneDirectionAsync(upstreamStream, clientStream, client.Client, ct);
            await Task.WhenAll(c2u, u2c).ConfigureAwait(false);
        }
    }

    private static async Task CopyOneDirectionAsync(
        NetworkStream source,
        NetworkStream destination,
        Socket destinationSocket,
        CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(RelayBufferSize);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, RelayBufferSize), ct).ConfigureAwait(false);
                if (read <= 0)
                {
                    try { destinationSocket.Shutdown(SocketShutdown.Send); } catch { }
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                await destination.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            try { destinationSocket.Shutdown(SocketShutdown.Send); } catch { }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private bool IsSelfLoop(string host, int port)
    {
        var pacPort = _getPacPort();
        if (port != BoundPort && (pacPort <= 0 || port != pacPort))
        {
            return false;
        }

        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var ip) && (IPAddress.IsLoopback(ip) || ip.Equals(_listenAddress));
    }

    private static bool TryParseHostPort(string value, int defaultPort, out string host, out int port)
    {
        host = string.Empty;
        port = defaultPort;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith('['))
        {
            var closeIdx = trimmed.IndexOf(']');
            if (closeIdx <= 1)
            {
                return false;
            }

            host = trimmed[1..closeIdx];
            if (closeIdx + 1 < trimmed.Length && trimmed[closeIdx + 1] == ':' && int.TryParse(trimmed[(closeIdx + 2)..], out var parsedPort))
            {
                port = parsedPort;
            }

            return port is > 0 and <= 65535;
        }

        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(trimmed[(lastColon + 1)..], out var p))
        {
            host = trimmed[..lastColon];
            port = p;
        }
        else
        {
            host = trimmed;
        }

        return !string.IsNullOrWhiteSpace(host) && port is > 0 and <= 65535;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _cts.CancelAsync().ConfigureAwait(false);
        try { _listener?.Stop(); } catch { }
        if (_acceptTask is not null)
        {
            try { await _acceptTask.ConfigureAwait(false); } catch { }
        }

        _cts.Dispose();
    }
}
