using System.IO.Pipes;
using System.Security.Principal;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Ipc;

/// <summary>
/// Short-lived request/response client over the local Named Pipe.
/// Connects on demand with a bounded timeout and never blocks the UI thread.
/// </summary>
public sealed class NamedPipeServiceClient : IServiceClient
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(600);
    private static readonly TimeSpan IoTimeout = TimeSpan.FromSeconds(4);

    private readonly string _pipeName;
    private readonly ILogger<NamedPipeServiceClient> _logger;

    public NamedPipeServiceClient(ILogger<NamedPipeServiceClient> logger, string pipeName = IpcConstants.DefaultPipeName)
    {
        _logger = logger;
        _pipeName = pipeName;
    }

    public ServiceConnectionState ConnectionState { get; private set; } = ServiceConnectionState.Unknown;

    public ServiceStatusSnapshot? LastStatus { get; private set; }

    public event EventHandler? StateChanged;

    public async Task<IpcResponse?> SendAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".",
                _pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);

            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectCts.CancelAfter(ConnectTimeout);
                await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false);
            }

            using var ioCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            ioCts.CancelAfter(IoTimeout);

            await IpcFraming.WriteMessageAsync(pipe, request, ioCts.Token).ConfigureAwait(false);
            var response = await IpcFraming.ReadMessageAsync<IpcResponse>(pipe, ioCts.Token).ConfigureAwait(false);
            if (response is not null)
            {
                UpdateState(ServiceConnectionState.Connected, response.Status);
            }

            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Connect timeout means the background service is not currently running.
            UpdateState(ServiceConnectionState.ServiceNotRunning, null);
            return null;
        }
        catch (TimeoutException)
        {
            UpdateState(ServiceConnectionState.ServiceNotRunning, null);
            return null;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Access denied connecting to service pipe {PipeName}", _pipeName);
            UpdateState(ServiceConnectionState.AccessDenied, null);
            return null;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            _logger.LogDebug(ex, "IPC communication error on {PipeName}", _pipeName);
            UpdateState(ServiceConnectionState.Error, null);
            return null;
        }
    }

    public async Task<ServiceStatusSnapshot?> RefreshStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendAsync(new IpcRequest(IpcRequestKind.GetStatus), cancellationToken).ConfigureAwait(false);
        return response?.Status;
    }

    private void UpdateState(ServiceConnectionState state, ServiceStatusSnapshot? status)
    {
        var changed = state != ConnectionState || !Equals(status, LastStatus);
        ConnectionState = state;
        if (status is not null || state != ServiceConnectionState.Connected)
        {
            LastStatus = status;
        }

        if (changed)
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }
}
