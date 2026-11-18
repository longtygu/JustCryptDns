using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Ipc;

/// <summary>
/// Local Named Pipe server with explicit ACLs (LocalSystem, Administrators, current owner, and local AuthenticatedUsers;
/// NetworkSid is explicitly denied so remote pipe connections are rejected).
/// </summary>
public sealed class NamedPipeIpcServer : IAsyncDisposable
{
    private const int MaxConcurrentClients = 8;

    private readonly string _pipeName;
    private readonly IServiceIpcHandler _handler;
    private readonly ILogger<NamedPipeIpcServer> _logger;
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentClients, MaxConcurrentClients);
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    public NamedPipeIpcServer(IServiceIpcHandler handler, ILogger<NamedPipeIpcServer> logger, string pipeName = IpcConstants.DefaultPipeName)
    {
        _handler = handler;
        _logger = logger;
        _pipeName = pipeName;
    }

    public void Start()
    {
        if (_acceptLoop is not null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        _logger.LogInformation("IPC server listening on pipe {PipeName}", _pipeName);
    }

    public async ValueTask DisposeAsync()
    {
        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        _cts?.Dispose();
        _concurrency.Dispose();
    }

    internal static PipeSecurity CreatePipeSecurity()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.User is { } ownerSid)
            {
                security.AddAccessRule(new PipeAccessRule(
                    ownerSid,
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
            }
        }

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        return security;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        var security = CreatePipeSecurity();
        while (!cancellationToken.IsCancellationRequested)
        {
            await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
            NamedPipeServerStream? server = null;
            try
            {
                server = NamedPipeServerStreamAcl.Create(
                    _pipeName,
                    PipeDirection.InOut,
                    MaxConcurrentClients,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    security);

                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                var connected = server;
                server = null; // ownership transferred to client task
                _ = HandleClientAsync(connected, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                server?.Dispose();
                _concurrency.Release();
                break;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                server?.Dispose();
                _concurrency.Release();
                _logger.LogWarning(ex, "IPC accept error on {PipeName}", _pipeName);
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream stream, CancellationToken cancellationToken)
    {
        try
        {
            await using (stream.ConfigureAwait(false))
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

                var request = await IpcFraming.ReadMessageAsync<IpcRequest>(stream, timeoutCts.Token).ConfigureAwait(false);
                if (request is null)
                {
                    return;
                }

                IpcResponse response;
                if (request.ProtocolVersion != IpcConstants.ProtocolVersion)
                {
                    var fallback = await _handler.HandleAsync(new IpcRequest(IpcRequestKind.GetStatus), timeoutCts.Token).ConfigureAwait(false);
                    response = new IpcResponse(
                        Success: false,
                        Status: fallback.Status,
                        ErrorCode: "ProtocolMismatch",
                        Message: $"Unsupported IPC protocol version {request.ProtocolVersion}.");
                }
                else
                {
                    response = await _handler.HandleAsync(request, timeoutCts.Token).ConfigureAwait(false);
                }

                await IpcFraming.WriteMessageAsync(stream, response, timeoutCts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or OperationCanceledException)
        {
            _logger.LogDebug(ex, "IPC client session ended early.");
        }
        finally
        {
            _concurrency.Release();
        }
    }
}
