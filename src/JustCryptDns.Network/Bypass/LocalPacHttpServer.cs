using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Network;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Lightweight pure-<see cref="TcpListener"/> HTTP server serving <c>/proxy.pac</c> on localhost without requiring HttpListener URLACL.
/// </summary>
public sealed class LocalPacHttpServer : IAsyncDisposable
{
    private static readonly byte[] NotFoundResponse = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();

    private readonly IPAddress _listenAddress;
    private readonly int _requestedPort;
    private readonly Func<string> _getPacScript;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _cacheLock = new();

    private TcpListener? _listener;
    private Task? _acceptTask;
    private string? _cachedPacScript;
    private byte[]? _cachedHttpResponse;
    private int _disposed;

    public LocalPacHttpServer(
        IPAddress listenAddress,
        int port,
        Func<string> getPacScript,
        ILogger logger)
    {
        _listenAddress = listenAddress;
        _requestedPort = port;
        _getPacScript = getPacScript;
        _logger = logger;
    }

    public int BoundPort { get; private set; }

    public string PacUrl => $"http://{_listenAddress}:{BoundPort}/proxy.pac";

    public void Start()
    {
        if (_listener is not null)
        {
            return;
        }

        _listener = new TcpListener(_listenAddress, _requestedPort);
        SocketHandleGuard.DisableInheritance(_listener.Server);
        _listener.Start();
        BoundPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token), _cts.Token);
        _logger.LogDebug("Local PAC HTTP server listening at {Url}", PacUrl);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener is not null)
        {
            TcpClient? client = null;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                _ = Task.Run(() => HandleRequestAsync(client, ct), ct);
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
                    _logger.LogDebug(ex, "PAC accept loop socket error.");
                }
            }
        }
    }

    private async Task HandleRequestAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            try
            {
                client.NoDelay = true;
                using var stream = client.GetStream();
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(2000);

                var buffer = ArrayPool<byte>.Shared.Rent(2048);
                int read;
                try
                {
                    read = await stream.ReadAsync(buffer.AsMemory(0, 2048), readCts.Token).ConfigureAwait(false);
                    if (read <= 0)
                    {
                        return;
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }

                var requestLine = Encoding.ASCII.GetString(buffer, 0, Math.Min(read, 256));
                var firstLineEnd = requestLine.IndexOf('\n');
                if (firstLineEnd > 0)
                {
                    requestLine = requestLine[..firstLineEnd].Trim();
                }

                var isPacPath = requestLine.StartsWith("GET /proxy.pac", StringComparison.OrdinalIgnoreCase)
                    || requestLine.StartsWith("GET /wpad.dat", StringComparison.OrdinalIgnoreCase)
                    || requestLine.StartsWith("GET / ", StringComparison.OrdinalIgnoreCase);

                byte[] response;
                if (isPacPath)
                {
                    response = GetOrBuildPacHttpResponse();
                }
                else
                {
                    response = NotFoundResponse;
                }

                using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                writeCts.CancelAfter(3000);
                await stream.WriteAsync(response, writeCts.Token).ConfigureAwait(false);
                await stream.FlushAsync(writeCts.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Ignore client abort / malformed PAC request.
            }
        }
    }

    private byte[] GetOrBuildPacHttpResponse()
    {
        var body = _getPacScript();
        lock (_cacheLock)
        {
            if (_cachedHttpResponse is not null && string.Equals(_cachedPacScript, body, StringComparison.Ordinal))
            {
                return _cachedHttpResponse;
            }

            var bodyBytes = Encoding.UTF8.GetBytes(body);
            var header =
                $"HTTP/1.1 200 OK\r\n" +
                $"Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n" +
                $"X-Content-Type-Options: nosniff\r\n" +
                $"Cross-Origin-Resource-Policy: same-origin\r\n" +
                $"Cache-Control: no-cache, no-store, must-revalidate\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                $"Connection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(header);
            var built = new byte[headerBytes.Length + bodyBytes.Length];
            headerBytes.CopyTo(built, 0);
            bodyBytes.CopyTo(built, headerBytes.Length);
            _cachedPacScript = body;
            _cachedHttpResponse = built;
            return built;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await _cts.CancelAsync().ConfigureAwait(false);
        try { _listener?.Stop(); } catch { }
        if (_acceptTask is not null)
        {
            try { await _acceptTask.ConfigureAwait(false); } catch { }
        }

        _cts.Dispose();
    }
}
