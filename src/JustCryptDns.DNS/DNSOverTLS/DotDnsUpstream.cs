using System.Buffers.Binary;
using System.Collections.Concurrent;
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
/// RFC 7858 DNS over TLS (DoT) client on port 853 with connection pooling,
/// in-flight transaction pipelining, strict TLS SNI / X.509 verification, and 1x idle-socket retry.
/// </summary>
public sealed class DotDnsUpstream : IDnsUpstreamClient, IDisposable
{
    private const int IdleTimeoutMs = 45_000;

    private readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
    private readonly ConcurrentDictionary<string, PooledDotConnection> _pools = new(StringComparer.OrdinalIgnoreCase);
    private long _connectionsCreated;
    private long _queriesReusedConnection;
    private int _disposed;

    public DotDnsUpstream(RemoteCertificateValidationCallback? certificateValidationCallback = null)
    {
        _certificateValidationCallback = certificateValidationCallback;
    }

    public DnsProtocol Protocol => DnsProtocol.DnsOverTls;

    public long ConnectionsCreated => Interlocked.Read(ref _connectionsCreated);

    public long QueriesReusedConnection => Interlocked.Read(ref _queriesReusedConnection);

    public async Task<DnsQueryResult> QueryAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint resolver,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        if (Volatile.Read(ref _disposed) != 0)
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, Protocol, "DoT upstream has been disposed.");
        }

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
        var poolKey = $"{ip}|{port}|{tlsHost.ToLowerInvariant()}";
        var callerId = BinaryPrimitives.ReadUInt16BigEndian(queryWire.Span[0..2]);

        var pool = _pools.GetOrAdd(
            poolKey,
            _ => new PooledDotConnection(
                ip,
                port,
                tlsHost,
                _certificateValidationCallback,
                () => Interlocked.Increment(ref _connectionsCreated),
                () => Interlocked.Increment(ref _queriesReusedConnection)));

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        var sw = Stopwatch.StartNew();
        try
        {
            var response = await pool.ExecuteQueryAsync(queryWire, timeout, cts.Token).ConfigureAwait(false);
            sw.Stop();

            DnsPacket.WriteTransactionId(response, callerId);
            return new DnsQueryResult(true, response, sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol);
        }
        catch (Exception ex) when (ex is SocketException or AuthenticationException or IOException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
        {
            sw.Stop();
            var reason = (ex is OperationCanceledException or ObjectDisposedException) && !cancellationToken.IsCancellationRequested
                ? "DoT query timed out."
                : ex.Message;
            return new DnsQueryResult(false, [], sw.Elapsed.TotalMilliseconds, resolver.Id, Protocol, reason);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var pool in _pools.Values)
        {
            pool.Dispose();
        }

        _pools.Clear();
    }

    private sealed class PooledDotConnection : IDisposable
    {
        private readonly IPAddress _ip;
        private readonly int _port;
        private readonly string _tlsHost;
        private readonly RemoteCertificateValidationCallback? _certCallback;
        private readonly Action _onConnectionCreated;
        private readonly Action _onConnectionReused;
        private readonly SemaphoreSlim _connectGate = new(1, 1);
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        private readonly ConcurrentDictionary<ushort, TaskCompletionSource<byte[]>> _pending = new();

        private TcpClient? _tcp;
        private SslStream? _ssl;
        private CancellationTokenSource? _connCts;
        private Task? _readLoopTask;
        private long _lastUsedTick;
        private int _txCounter = Random.Shared.Next(1, 60000);
        private int _disposed;

        public PooledDotConnection(
            IPAddress ip,
            int port,
            string tlsHost,
            RemoteCertificateValidationCallback? certCallback,
            Action onConnectionCreated,
            Action onConnectionReused)
        {
            _ip = ip;
            _port = port;
            _tlsHost = tlsHost;
            _certCallback = certCallback;
            _onConnectionCreated = onConnectionCreated;
            _onConnectionReused = onConnectionReused;
        }

        public async Task<byte[]> ExecuteQueryAsync(
            ReadOnlyMemory<byte> queryWire,
            TimeSpan timeout,
            CancellationToken ct)
        {
            try
            {
                return await SendOnceAsync(queryWire, timeout, forceReconnect: false, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested
                && ex is IOException or SocketException or ObjectDisposedException)
            {
                return await SendOnceAsync(queryWire, timeout, forceReconnect: true, ct).ConfigureAwait(false);
            }
        }

        private async Task<byte[]> SendOnceAsync(
            ReadOnlyMemory<byte> queryWire,
            TimeSpan timeout,
            bool forceReconnect,
            CancellationToken ct)
        {
            var (ssl, reused) = await EnsureConnectedAsync(timeout, forceReconnect, ct).ConfigureAwait(false);
            if (reused)
            {
                _onConnectionReused();
            }

            ushort outboundId = 0;
            TaskCompletionSource<byte[]>? tcs = null;
            for (var attempt = 0; attempt < 65536; attempt++)
            {
                var candidate = unchecked((ushort)Interlocked.Increment(ref _txCounter));
                if (candidate == 0)
                {
                    candidate = 1;
                }

                var created = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (_pending.TryAdd(candidate, created))
                {
                    outboundId = candidate;
                    tcs = created;
                    break;
                }
            }

            if (tcs is null)
            {
                throw new IOException("No available DoT pipeline transaction slot.");
            }

            try
            {
                var payload = queryWire.ToArray();
                DnsPacket.WriteTransactionId(payload, outboundId);

                var framed = new byte[2 + payload.Length];
                BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), (ushort)payload.Length);
                payload.CopyTo(framed.AsSpan(2));

                await _writeGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (!ReferenceEquals(_ssl, ssl))
                    {
                        throw new IOException("DoT socket rotated before write.");
                    }

                    await ssl.WriteAsync(framed, ct).ConfigureAwait(false);
                    await ssl.FlushAsync(ct).ConfigureAwait(false);
                }
                finally
                {
                    _writeGate.Release();
                }

                var response = await tcs.Task.WaitAsync(ct).ConfigureAwait(false);
                Volatile.Write(ref _lastUsedTick, Environment.TickCount64);
                return response;
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
            {
                InvalidateIfCurrent(ssl);
                throw;
            }
            finally
            {
                _pending.TryRemove(outboundId, out _);
            }
        }

        private async Task<(SslStream Stream, bool Reused)> EnsureConnectedAsync(
            TimeSpan timeout,
            bool forceReconnect,
            CancellationToken ct)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

            await _connectGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

                var idleElapsed = Environment.TickCount64 - Volatile.Read(ref _lastUsedTick);
                if (!forceReconnect
                    && _ssl is { CanRead: true, CanWrite: true } currentSsl
                    && _tcp is { Connected: true }
                    && _readLoopTask is { IsCompleted: false }
                    && idleElapsed <= IdleTimeoutMs)
                {
                    return (currentSsl, true);
                }

                CloseCurrentLocked();

                var tcp = new TcpClient(_ip.AddressFamily) { NoDelay = true };
                SslStream? ssl = null;
                CancellationTokenSource? connCts = null;
                try
                {
                    using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    connectCts.CancelAfter(timeout);
                    using var abortReg = connectCts.Token.Register(() =>
                    {
                        try { tcp.Dispose(); } catch { }
                    });

                    await tcp.ConnectAsync(_ip, _port, connectCts.Token).ConfigureAwait(false);
                    ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, _certCallback);
                    var sslOptions = new SslClientAuthenticationOptions
                    {
                        TargetHost = _tlsHost,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    };
                    await ssl.AuthenticateAsClientAsync(sslOptions, connectCts.Token).ConfigureAwait(false);

                    connCts = new CancellationTokenSource();
                    _tcp = tcp;
                    _ssl = ssl;
                    _connCts = connCts;
                    Volatile.Write(ref _lastUsedTick, Environment.TickCount64);
                    _readLoopTask = Task.Run(() => ReadLoopAsync(ssl, connCts.Token), CancellationToken.None);
                    _onConnectionCreated();
                    return (ssl, false);
                }
                catch
                {
                    connCts?.Dispose();
                    if (ssl is not null)
                    {
                        try { await ssl.DisposeAsync().ConfigureAwait(false); } catch { }
                    }

                    try { tcp.Dispose(); } catch { }
                    throw;
                }
            }
            finally
            {
                _connectGate.Release();
            }
        }

        private async Task ReadLoopAsync(SslStream ssl, CancellationToken ct)
        {
            var lenBuf = new byte[2];
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await ssl.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
                    var respLen = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
                    if (respLen < DnsPacket.HeaderSize)
                    {
                        throw new InvalidDataException($"DoT response too short ({respLen} bytes).");
                    }

                    var response = new byte[respLen];
                    await ssl.ReadExactlyAsync(response, ct).ConfigureAwait(false);
                    Volatile.Write(ref _lastUsedTick, Environment.TickCount64);

                    if (DnsPacket.TryReadTransactionId(response, out var txId)
                        && _pending.TryRemove(txId, out var tcs))
                    {
                        tcs.TrySetResult(response);
                    }
                }
            }
            catch (Exception ex) when (ex is EndOfStreamException or IOException or SocketException or InvalidDataException or OperationCanceledException or ObjectDisposedException)
            {
                var failure = ex is OperationCanceledException
                    ? new OperationCanceledException("DoT connection closed.", ex)
                    : (Exception)new IOException($"DoT connection terminated: {ex.Message}", ex);
                FailAllPending(failure);
                InvalidateIfCurrent(ssl);
            }
        }

        private void FailAllPending(Exception error)
        {
            foreach (var key in _pending.Keys.ToList())
            {
                if (_pending.TryRemove(key, out var tcs))
                {
                    if (error is OperationCanceledException)
                    {
                        tcs.TrySetCanceled();
                    }
                    else
                    {
                        tcs.TrySetException(error);
                    }
                }
            }
        }

        private void InvalidateIfCurrent(SslStream expected)
        {
            if (!_connectGate.Wait(0))
            {
                return;
            }

            try
            {
                if (ReferenceEquals(_ssl, expected))
                {
                    CloseCurrentLocked();
                }
            }
            finally
            {
                _connectGate.Release();
            }
        }

        private void CloseCurrentLocked()
        {
            try { _connCts?.Cancel(); } catch { }
            try { _ssl?.Dispose(); } catch { }
            try { _tcp?.Dispose(); } catch { }
            _connCts?.Dispose();
            _connCts = null;
            _ssl = null;
            _tcp = null;
            _readLoopTask = null;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            FailAllPending(new OperationCanceledException("DoT pool disposed."));
            try { _connCts?.Cancel(); } catch { }
            try { _ssl?.Dispose(); } catch { }
            try { _tcp?.Dispose(); } catch { }
            _connCts?.Dispose();
            _connectGate.Dispose();
            _writeGate.Dispose();
        }
    }
}
