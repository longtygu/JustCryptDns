using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Establishes outbound direct TCP connections (using JustCryptDns's encrypted resolver when configured
/// with a fast 60-second host IP cache) and upstream split-tunnel connections via Cloudflare WARP, SOCKS5, or HTTP CONNECT.
/// </summary>
public sealed class UpstreamTunnelConnector
{
    private const int MaxDnsCacheEntries = 512;
    private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromSeconds(60);

    private readonly IDnsEngine? _dnsEngine;
    private readonly ConcurrentDictionary<string, (IReadOnlyList<IPAddress> Ips, DateTimeOffset ExpiresAt)> _dnsCache = new(StringComparer.OrdinalIgnoreCase);

    public UpstreamTunnelConnector(IDnsEngine? dnsEngine = null)
    {
        _dnsEngine = dnsEngine;
    }

    public void ClearDnsCache() => _dnsCache.Clear();

    public async Task<(TcpClient Client, IPAddress RemoteIp)> ConnectDirectAsync(
        string host,
        int port,
        bool resolveViaLocalDns,
        bool allowIpv6,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var candidates = await ResolveTargetIpsAsync(host, resolveViaLocalDns, allowIpv6, cancellationToken).ConfigureAwait(false);
        if (candidates.Count == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        Exception? lastException = null;
        foreach (var ip in candidates)
        {
            var client = new TcpClient(ip.AddressFamily) { NoDelay = true };
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(Math.Clamp(timeoutMs, 1000, 20000));
            try
            {
                await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
                return (client, ip);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                lastException = ex;
                client.Dispose();
                if (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        throw lastException ?? new SocketException((int)SocketError.TimedOut);
    }

    public static async Task<TcpClient> ConnectViaUpstreamAsync(
        string targetHost,
        int targetPort,
        UpstreamTunnelSettings upstream,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
        ArgumentNullException.ThrowIfNull(upstream);

        foreach (var ch in targetHost)
        {
            if (char.IsControl(ch) || ch is ' ' or '\'' or '"' or '\\')
            {
                throw new ArgumentException("Target host contains invalid control characters.", nameof(targetHost));
            }
        }

        if (!upstream.Enabled || upstream.Kind == UpstreamTunnelKind.None)
        {
            throw new InvalidOperationException("Upstream tunnel is not enabled.");
        }

        var upstreamHost = string.IsNullOrWhiteSpace(upstream.Host) ? UpstreamTunnelSettings.DefaultHost : upstream.Host.Trim();
        var upstreamPort = upstream.Port > 0 ? upstream.Port : UpstreamTunnelSettings.DefaultWarpPort;
        var effectiveTimeout = Math.Clamp(timeoutMs, 1000, 20000);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(effectiveTimeout);

        var client = new TcpClient { NoDelay = true };
        try
        {
            if (IPAddress.TryParse(upstreamHost, out var upstreamIp))
            {
                await client.ConnectAsync(upstreamIp, upstreamPort, cts.Token).ConfigureAwait(false);
            }
            else
            {
                await client.ConnectAsync(upstreamHost, upstreamPort, cts.Token).ConfigureAwait(false);
            }

            var stream = client.GetStream();
            if (upstream.Kind == UpstreamTunnelKind.HttpConnect)
            {
                await PerformHttpConnectHandshakeAsync(client, stream, targetHost, targetPort, upstream.Username, upstream.Password, cts.Token).ConfigureAwait(false);
            }
            else
            {
                await PerformSocks5HandshakeAsync(stream, targetHost, targetPort, upstream.Username, upstream.Password, cts.Token).ConfigureAwait(false);
            }

            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public static async Task<(bool Available, string Summary)> DetectCloudflareWarpAsync(CancellationToken cancellationToken = default)
    {
        var warpCliInstalled = File.Exists(@"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe")
            || File.Exists(@"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe");

        var listening = await ProbeSocks5PortAsync(UpstreamTunnelSettings.DefaultHost, UpstreamTunnelSettings.DefaultWarpPort, cancellationToken).ConfigureAwait(false);
        if (listening)
        {
            return (true, "Cloudflare WARP SOCKS5 proxy detected on 127.0.0.1:40000 and ready.");
        }

        return warpCliInstalled
            ? (false, "Cloudflare WARP is installed, but SOCKS5 proxy is not active on 127.0.0.1:40000. Run 'warp-cli mode proxy' then 'warp-cli connect'.")
            : (false, "Cloudflare WARP proxy (127.0.0.1:40000) not detected. You can install Cloudflare WARP or enter any SOCKS5 / HTTP Proxy.");
    }

    public static async Task<(bool Success, double LatencyMs, string Summary)> TestUpstreamAsync(
        UpstreamTunnelSettings upstream,
        CancellationToken cancellationToken = default)
    {
        if (upstream.Kind == UpstreamTunnelKind.None)
        {
            return (false, 0, "Select an upstream proxy type (Cloudflare WARP, SOCKS5, or HTTP CONNECT).");
        }

        var sw = Stopwatch.StartNew();
        try
        {
            var probeSettings = new UpstreamTunnelSettings
            {
                Enabled = true,
                Kind = upstream.Kind,
                Host = upstream.Host,
                Port = upstream.Port,
                Username = upstream.Username,
                Password = upstream.Password,
            };
            probeSettings.Normalize();

            using var tcp = await ConnectViaUpstreamAsync("1.1.1.1", 443, probeSettings, 4000, cancellationToken).ConfigureAwait(false);
            sw.Stop();
            var ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
            return (true, ms, $"Upstream tunnel {probeSettings.Host}:{probeSettings.Port} ({probeSettings.Kind}) connected cleanly in {ms:0.#} ms.");
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), $"Upstream tunnel check failed: {ex.Message}");
        }
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveTargetIpsAsync(
        string host,
        bool resolveViaLocalDns,
        bool allowIpv6,
        CancellationToken cancellationToken)
    {
        var cleanHost = BypassRuleMatcher.NormalizeHost(host);
        if (IPAddress.TryParse(cleanHost, out var literal))
        {
            return [literal];
        }

        var cacheKey = $"{cleanHost}|v6={allowIpv6}";
        if (_dnsCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return cached.Ips;
        }

        if (resolveViaLocalDns && _dnsEngine is not null)
        {
            var encrypted = await _dnsEngine.ResolveHostAsync(cleanHost, includeIpv6: allowIpv6, cancellationToken).ConfigureAwait(false);
            if (encrypted.Count > 0)
            {
                StoreDnsCache(cacheKey, encrypted);
                return encrypted;
            }
        }

        try
        {
            var all = await Dns.GetHostAddressesAsync(cleanHost, cancellationToken).ConfigureAwait(false);
            var filtered = allowIpv6
                ? all
                : all.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            if (filtered.Length > 0)
            {
                StoreDnsCache(cacheKey, filtered);
            }

            return filtered;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return [];
        }
    }

    private void StoreDnsCache(string cacheKey, IReadOnlyList<IPAddress> ips)
    {
        if (_dnsCache.Count >= MaxDnsCacheEntries)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var item in _dnsCache)
            {
                if (item.Value.ExpiresAt <= now)
                {
                    _dnsCache.TryRemove(item.Key, out _);
                }
            }

            if (_dnsCache.Count >= MaxDnsCacheEntries)
            {
                _dnsCache.Clear();
            }
        }

        _dnsCache[cacheKey] = (ips, DateTimeOffset.UtcNow.Add(DnsCacheTtl));
    }

    private static async Task<bool> ProbeSocks5PortAsync(string host, int port, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(1200);
        using var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            var stream = tcp.GetStream();
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cts.Token).ConfigureAwait(false);
            var reply = new byte[2];
            await stream.ReadExactlyAsync(reply, cts.Token).ConfigureAwait(false);
            return reply[0] == 0x05 && reply[1] != 0xFF;
        }
        catch
        {
            return false;
        }
    }

    private static async Task PerformSocks5HandshakeAsync(
        NetworkStream stream,
        string targetHost,
        int targetPort,
        string? username,
        string? password,
        CancellationToken ct)
    {
        var hasCreds = !string.IsNullOrEmpty(username);
        byte[] greeting = hasCreds ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00];
        await stream.WriteAsync(greeting, ct).ConfigureAwait(false);

        var methodReply = new byte[2];
        await stream.ReadExactlyAsync(methodReply, ct).ConfigureAwait(false);
        if (methodReply[0] != 0x05 || methodReply[1] == 0xFF)
        {
            throw new IOException("SOCKS5 upstream rejected authentication methods.");
        }

        if (methodReply[1] == 0x02)
        {
            if (!hasCreds)
            {
                throw new IOException("SOCKS5 upstream requires username/password authentication.");
            }

            var userBytes = Encoding.UTF8.GetBytes(username!);
            var passBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
            if (userBytes.Length > 255 || passBytes.Length > 255)
            {
                throw new ArgumentException("SOCKS5 username or password exceeds 255 bytes.");
            }

            var authReq = new byte[3 + userBytes.Length + passBytes.Length];
            authReq[0] = 0x01;
            authReq[1] = (byte)userBytes.Length;
            userBytes.CopyTo(authReq, 2);
            authReq[2 + userBytes.Length] = (byte)passBytes.Length;
            passBytes.CopyTo(authReq, 3 + userBytes.Length);
            await stream.WriteAsync(authReq, ct).ConfigureAwait(false);

            var authReply = new byte[2];
            await stream.ReadExactlyAsync(authReply, ct).ConfigureAwait(false);
            if (authReply[1] != 0x00)
            {
                throw new IOException("SOCKS5 username/password authentication failed.");
            }
        }

        byte[] connectReq;
        if (IPAddress.TryParse(targetHost, out var targetIp))
        {
            var addrBytes = targetIp.GetAddressBytes();
            var atyp = targetIp.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)0x04 : (byte)0x01;
            connectReq = new byte[6 + addrBytes.Length];
            connectReq[0] = 0x05;
            connectReq[1] = 0x01;
            connectReq[2] = 0x00;
            connectReq[3] = atyp;
            addrBytes.CopyTo(connectReq, 4);
            BinaryPrimitives.WriteUInt16BigEndian(connectReq.AsSpan(4 + addrBytes.Length, 2), (ushort)targetPort);
        }
        else
        {
            var hostBytes = Encoding.ASCII.GetBytes(targetHost);
            if (hostBytes.Length > 255)
            {
                throw new ArgumentException("Hostname exceeds SOCKS5 maximum length.");
            }

            connectReq = new byte[7 + hostBytes.Length];
            connectReq[0] = 0x05;
            connectReq[1] = 0x01;
            connectReq[2] = 0x00;
            connectReq[3] = 0x03;
            connectReq[4] = (byte)hostBytes.Length;
            hostBytes.CopyTo(connectReq, 5);
            BinaryPrimitives.WriteUInt16BigEndian(connectReq.AsSpan(5 + hostBytes.Length, 2), (ushort)targetPort);
        }

        await stream.WriteAsync(connectReq, ct).ConfigureAwait(false);

        var respHead = new byte[4];
        await stream.ReadExactlyAsync(respHead, ct).ConfigureAwait(false);
        if (respHead[0] != 0x05 || respHead[1] != 0x00)
        {
            throw new IOException($"SOCKS5 CONNECT failed with code 0x{respHead[1]:X2}.");
        }

        var skipLen = respHead[3] switch
        {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => await ReadDomainSkipLengthAsync(stream, ct).ConfigureAwait(false),
            _ => throw new IOException($"Unsupported SOCKS5 reply ATYP 0x{respHead[3]:X2}."),
        };

        var discard = new byte[skipLen];
        await stream.ReadExactlyAsync(discard, ct).ConfigureAwait(false);
    }

    private static async Task<int> ReadDomainSkipLengthAsync(NetworkStream stream, CancellationToken ct)
    {
        var lenBuf = new byte[1];
        await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
        return lenBuf[0] + 2;
    }

    private static async Task PerformHttpConnectHandshakeAsync(
        TcpClient client,
        NetworkStream stream,
        string targetHost,
        int targetPort,
        string? username,
        string? password,
        CancellationToken ct)
    {
        var formattedHost = targetHost.Contains(':', StringComparison.Ordinal) ? $"[{targetHost}]" : targetHost;
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"CONNECT {formattedHost}:{targetPort} HTTP/1.1\r\nHost: {formattedHost}:{targetPort}\r\n");
        if (!string.IsNullOrEmpty(username))
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password ?? string.Empty}"));
            sb.Append(CultureInfo.InvariantCulture, $"Proxy-Authorization: Basic {token}\r\n");
        }

        sb.Append("Proxy-Connection: Keep-Alive\r\n\r\n");
        var reqBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(reqBytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);

        // Read exact HTTP response headers using Peek so zero subsequent TLS bytes are consumed.
        var headerBytes = await ReadHttpHeadersExactAsync(client.Client, stream, 4096, ct).ConfigureAwait(false);
        var headerText = Encoding.ASCII.GetString(headerBytes);
        var firstLine = headerText.Split('\n')[0].Trim();
        if (!firstLine.Contains(" 200", StringComparison.Ordinal))
        {
            throw new IOException($"Upstream HTTP CONNECT rejected: {firstLine}");
        }
    }

    internal static async Task<byte[]> ReadHttpHeadersExactAsync(
        Socket socket,
        NetworkStream stream,
        int maxBytes,
        CancellationToken ct)
    {
        var peekBuf = ArrayPool<byte>.Shared.Rent(maxBytes);
        try
        {
            while (true)
            {
                var peeked = await socket.ReceiveAsync(peekBuf.AsMemory(0, maxBytes), SocketFlags.Peek, ct).ConfigureAwait(false);
                if (peeked == 0)
                {
                    return [];
                }

                var endIdx = peekBuf.AsSpan(0, peeked).IndexOf("\r\n\r\n"u8);
                if (endIdx >= 0)
                {
                    var exactLen = endIdx + 4;
                    var exact = new byte[exactLen];
                    await stream.ReadExactlyAsync(exact, ct).ConfigureAwait(false);
                    return exact;
                }

                if (peeked >= maxBytes)
                {
                    throw new IOException("HTTP proxy header block exceeded maximum buffer size.");
                }

                await Task.Delay(5, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(peekBuf);
        }
    }
}
