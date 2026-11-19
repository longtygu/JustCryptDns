using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Lightweight pure-<see cref="TcpListener"/> HTTP server serving <c>/proxy.pac</c> on localhost without requiring HttpListener URLACL.
/// </summary>
public sealed class LocalPacHttpServer : IAsyncDisposable
{
    private readonly IPAddress _listenAddress;
    private readonly int _requestedPort;
    private readonly Func<string> _getPacScript;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts = new();

    private TcpListener? _listener;
    private Task? _acceptTask;
    private bool _disposed;

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

                var buffer = new byte[2048];
                var read = await stream.ReadAsync(buffer, readCts.Token).ConfigureAwait(false);
                if (read <= 0)
                {
                    return;
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
                    var body = _getPacScript();
                    var bodyBytes = Encoding.UTF8.GetBytes(body);
                    var header =
                        $"HTTP/1.1 200 OK\r\n" +
                        $"Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n" +
                        $"Cache-Control: no-cache, no-store, must-revalidate\r\n" +
                        $"Content-Length: {bodyBytes.Length}\r\n" +
                        $"Connection: close\r\n\r\n";
                    var headerBytes = Encoding.ASCII.GetBytes(header);
                    response = new byte[headerBytes.Length + bodyBytes.Length];
                    headerBytes.CopyTo(response, 0);
                    bodyBytes.CopyTo(response, headerBytes.Length);
                }
                else
                {
                    response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray();
                }

                await stream.WriteAsync(response, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Ignore client abort / malformed PAC request.
            }
        }
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
