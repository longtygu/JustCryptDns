using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.DNS.Proxy;

public static class DnsLoopGuard
{
    /// <summary>
    /// Returns true when forwarding to <paramref name="resolver"/> could loop back into the local proxy listening on
    /// <paramref name="listenIp"/>:<paramref name="listenPort"/>.
    /// </summary>
    public static bool WouldLoop(DnsResolverEndpoint resolver, IPAddress listenIp, int listenPort)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(listenIp);

        var targetPort = resolver.Port > 0 ? resolver.Port : 53;
        if (targetPort != listenPort)
        {
            return false;
        }

        if (IPAddress.TryParse(resolver.PrimaryIp, out var primaryIp))
        {
            if (IPAddress.IsLoopback(primaryIp) || primaryIp.Equals(listenIp) || primaryIp.Equals(IPAddress.Any) || primaryIp.Equals(IPAddress.IPv6Any))
            {
                return true;
            }
        }

        if (resolver.Protocol == DnsProtocol.DnsOverHttps
            && Uri.TryCreate(resolver.Endpoint, UriKind.Absolute, out var uri)
            && uri.Port == listenPort
            && (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                || (IPAddress.TryParse(uri.Host, out var hostIp) && (IPAddress.IsLoopback(hostIp) || hostIp.Equals(listenIp)))))
        {
            return true;
        }

        return false;
    }
}

public static class PortConflictDetector
{
    private static readonly int[] CandidateFallbackPorts = [5355, 15353, 25353, 35353];

    public static PortConflictInfo? CheckConflict(IPAddress listenAddress, int port)
    {
        ArgumentNullException.ThrowIfNull(listenAddress);
        if (!IsPortInUse(listenAddress, port, out var proto))
        {
            return null;
        }

        var suggested = FindAvailablePort(listenAddress);
        return new PortConflictInfo(
            HasConflict: true,
            Endpoint: $"{listenAddress}:{port}",
            Protocol: proto,
            SuggestedPort: suggested,
            Message: $"Port {port} ({proto}) on {listenAddress} is already in use by another process. Stop the conflicting service or use port {suggested}.");
    }

    public static bool IsPortInUse(IPAddress listenAddress, int port, out string protocol)
    {
        protocol = string.Empty;
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var udpClash = props.GetActiveUdpListeners().Any(ep => ep.Port == port && EndpointsOverlap(ep.Address, listenAddress));
            var tcpClash = props.GetActiveTcpListeners().Any(ep => ep.Port == port && EndpointsOverlap(ep.Address, listenAddress));
            if (!udpClash && !tcpClash)
            {
                return false;
            }

            protocol = udpClash && tcpClash ? "UDP/TCP" : udpClash ? "UDP" : "TCP";
            return true;
        }
        catch (NetworkInformationException)
        {
            return false;
        }
    }

    public static int FindAvailablePort(IPAddress listenAddress)
    {
        ArgumentNullException.ThrowIfNull(listenAddress);
        foreach (var candidate in CandidateFallbackPorts)
        {
            if (!IsPortInUse(listenAddress, candidate, out _))
            {
                return candidate;
            }
        }

        using var socket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(listenAddress, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    public static int GetEphemeralPort(IPAddress listenAddress)
    {
        ArgumentNullException.ThrowIfNull(listenAddress);
        using var socket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(listenAddress, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static bool EndpointsOverlap(IPAddress bound, IPAddress requested)
    {
        if (bound.Equals(requested))
        {
            return true;
        }

        if (bound.AddressFamily == requested.AddressFamily
            && (bound.Equals(IPAddress.Any) || bound.Equals(IPAddress.IPv6Any)
                || requested.Equals(IPAddress.Any) || requested.Equals(IPAddress.IPv6Any)))
        {
            return true;
        }

        return false;
    }
}

/// <summary>
/// Local UDP + TCP DNS proxy listener (Part 2.2) with bounded concurrency.
/// </summary>
public sealed class LocalDnsProxy : IAsyncDisposable
{
    private const int MaxConcurrentQueries = 128;

    private readonly IPAddress _listenAddress;
    private readonly int _port;
    private readonly bool _enableIpv6;
    private readonly Func<ReadOnlyMemory<byte>, CancellationToken, Task<byte[]>> _queryHandler;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentQueries, MaxConcurrentQueries);
    private readonly List<Socket> _udpSockets = [];
    private readonly List<TcpListener> _tcpListeners = [];
    private readonly List<Task> _loops = [];
    private CancellationTokenSource? _cts;

    public LocalDnsProxy(
        IPAddress listenAddress,
        int port,
        bool enableIpv6,
        Func<ReadOnlyMemory<byte>, CancellationToken, Task<byte[]>> queryHandler,
        ILogger logger)
    {
        _listenAddress = listenAddress;
        _port = port;
        _enableIpv6 = enableIpv6;
        _queryHandler = queryHandler;
        _logger = logger;
    }

    public int BoundPort { get; private set; }

    public void Start()
    {
        if (_cts is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        try
        {
            BindEndpoint(_listenAddress, _port, _cts.Token);
            if (_enableIpv6 && _listenAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                BindEndpoint(IPAddress.IPv6Loopback, BoundPort, _cts.Token);
            }
        }
        catch
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        foreach (var udp in _udpSockets)
        {
            try
            {
                udp.Close();
                udp.Dispose();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        foreach (var tcp in _tcpListeners)
        {
            try
            {
                tcp.Stop();
            }
            catch (SocketException)
            {
            }
        }

        if (_loops.Count > 0)
        {
            try
            {
                await Task.WhenAll(_loops).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Loops terminated on cancellation/socket close.
            }
        }

        _udpSockets.Clear();
        _tcpListeners.Clear();
        _loops.Clear();
        _cts?.Dispose();
        _cts = null;
        _concurrency.Dispose();
    }

    private void BindEndpoint(IPAddress address, int port, CancellationToken ct)
    {
        var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(address, port));
        var actualPort = ((IPEndPoint)udp.LocalEndPoint!).Port;
        if (BoundPort == 0)
        {
            BoundPort = actualPort;
        }

        var tcp = new TcpListener(address, actualPort);
        tcp.Start();

        _udpSockets.Add(udp);
        _tcpListeners.Add(tcp);
        _loops.Add(Task.Run(() => UdpReceiveLoopAsync(udp, ct), ct));
        _loops.Add(Task.Run(() => TcpAcceptLoopAsync(tcp, ct), ct));
        _logger.LogInformation("Local DNS proxy bound on {Address}:{Port} (UDP/TCP)", address, actualPort);
    }

    private async Task UdpReceiveLoopAsync(Socket udp, CancellationToken ct)
    {
        var buffer = new byte[4096];
        EndPoint remote = udp.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await udp.ReceiveFromAsync(buffer, SocketFlags.None, remote, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                continue;
            }

            if (received.ReceivedBytes < DnsPacket.HeaderSize)
            {
                continue;
            }

            var queryCopy = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
            var clientEndpoint = received.RemoteEndPoint;
            _ = HandleUdpClientAsync(udp, queryCopy, clientEndpoint, ct);
        }
    }

    private async Task HandleUdpClientAsync(Socket udp, byte[] query, EndPoint clientEndpoint, CancellationToken ct)
    {
        if (!await _concurrency.WaitAsync(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false))
        {
            return;
        }

        try
        {
            var response = await _queryHandler(query, ct).ConfigureAwait(false);
            if (response.Length < DnsPacket.HeaderSize)
            {
                response = DnsPacket.CreateErrorResponse(query, DnsResponseCode.ServFail);
            }

            if (response.Length >= DnsPacket.HeaderSize)
            {
                await udp.SendToAsync(response, SocketFlags.None, clientEndpoint, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException)
        {
            // Ignore send failure to disconnected client.
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private async Task TcpAcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                break;
            }

            _ = HandleTcpClientAsync(client, ct);
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        if (!await _concurrency.WaitAsync(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false))
        {
            client.Dispose();
            return;
        }

        try
        {
            using (client)
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(8));
                var stream = client.GetStream();

                var lenBuf = new byte[2];
                await stream.ReadExactlyAsync(lenBuf, timeoutCts.Token).ConfigureAwait(false);
                var queryLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
                if (queryLen < DnsPacket.HeaderSize)
                {
                    return;
                }

                var query = new byte[queryLen];
                await stream.ReadExactlyAsync(query, timeoutCts.Token).ConfigureAwait(false);

                var response = await _queryHandler(query, timeoutCts.Token).ConfigureAwait(false);
                if (response.Length < DnsPacket.HeaderSize)
                {
                    response = DnsPacket.CreateErrorResponse(query, DnsResponseCode.ServFail);
                }

                if (response.Length >= DnsPacket.HeaderSize)
                {
                    var framed = new byte[2 + response.Length];
                    BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)response.Length);
                    response.CopyTo(framed.AsSpan(2));
                    await stream.WriteAsync(framed, timeoutCts.Token).ConfigureAwait(false);
                    await stream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException)
        {
            // Client closed connection early.
        }
        finally
        {
            _concurrency.Release();
        }
    }
}
