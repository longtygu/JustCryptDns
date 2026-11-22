using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Ipc;

/// <summary>
/// Short-lived request/response client over the local Named Pipe.
/// Connects on demand with a bounded timeout, verifies server identity against pipe squatting,
/// and distinguishes connection timeouts from long-running command execution timeouts.
/// </summary>
public sealed class NamedPipeServiceClient : IServiceClient
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromMilliseconds(750);
    private static readonly TimeSpan FastIoTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan LongOperationIoTimeout = TimeSpan.FromSeconds(18);

    private readonly string _pipeName;
    private readonly ILogger<NamedPipeServiceClient> _logger;
    private readonly object _stateLock = new();
    private ServiceConnectionState _connectionState = ServiceConnectionState.Unknown;
    private ServiceStatusSnapshot? _lastStatus;

    public NamedPipeServiceClient(ILogger<NamedPipeServiceClient> logger, string pipeName = IpcConstants.DefaultPipeName)
    {
        _logger = logger;
        _pipeName = pipeName;
    }

    public ServiceConnectionState ConnectionState
    {
        get
        {
            lock (_stateLock)
            {
                return _connectionState;
            }
        }
    }

    public ServiceStatusSnapshot? LastStatus
    {
        get
        {
            lock (_stateLock)
            {
                return _lastStatus;
            }
        }
    }

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

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(ConnectTimeout);
                await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or (OperationCanceledException and not TaskCanceledException) || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // Connect timeout means the background service pipe is not currently listening.
                UpdateState(ServiceConnectionState.ServiceNotRunning, null);
                return null;
            }

            if (!IsTrustedPipeServer(pipe))
            {
                _logger.LogWarning("Rejected untrusted Named Pipe server on {PipeName}.", _pipeName);
                UpdateState(ServiceConnectionState.AccessDenied, null);
                return null;
            }

            using var ioCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var timeout = IsLongRunningRequest(request.Kind) ? LongOperationIoTimeout : FastIoTimeout;
            ioCts.CancelAfter(timeout);

            try
            {
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
                // IO timeout while waiting for a connected service command does NOT mean the service stopped;
                // keep current connection state so the UI never starts a duplicate standalone engine.
                _logger.LogWarning("IPC request {Kind} timed out after {Seconds}s on {PipeName}.", request.Kind, timeout.TotalSeconds, _pipeName);
                return null;
            }
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

    private static bool IsLongRunningRequest(IpcRequestKind kind) =>
        kind is IpcRequestKind.SetEngineEnabled
            or IpcRequestKind.RestartEngine
            or IpcRequestKind.ReloadConfiguration
            or IpcRequestKind.SetGamingMode
            or IpcRequestKind.RestoreOriginalDns
            or IpcRequestKind.SetBypassEnabled
            or IpcRequestKind.RestartBypassEngine
            or IpcRequestKind.SyncFirewallBlocklist
            or IpcRequestKind.ClearFirewallBlocklist
            or IpcRequestKind.ProbeActiveResolver
            or IpcRequestKind.TestLocalProxy
            or IpcRequestKind.PauseCaptivePortal
            or IpcRequestKind.ResumeCaptivePortal
            or IpcRequestKind.InstallOrUpdateDnsCrypt;

    private static bool IsTrustedPipeServer(NamedPipeClientStream pipe)
    {
        try
        {
            var handle = pipe.SafePipeHandle.DangerousGetHandle();
            if (!GetNamedPipeServerProcessId(handle, out var serverPid) || serverPid == 0)
            {
                return true;
            }

            if (serverPid == (uint)Environment.ProcessId)
            {
                return true;
            }

            var serverExePath = NamedPipeIpcServer.TryGetProcessImagePath(serverPid);
            if (string.IsNullOrWhiteSpace(serverExePath))
            {
                // If OpenProcess failed with ERROR_ACCESS_DENIED (5), the server is running in a higher privilege session (LocalSystem).
                return Marshal.GetLastWin32Error() == 5;
            }

            var fileName = Path.GetFileName(serverExePath);
            return string.Equals(fileName, "JustCryptDns.Service.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "JustCryptDns.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "testhost.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "dotnet.exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true;
        }
    }

    private void UpdateState(ServiceConnectionState state, ServiceStatusSnapshot? status)
    {
        bool changed;
        lock (_stateLock)
        {
            changed = state != _connectionState || !Equals(status, _lastStatus);
            _connectionState = state;
            if (status is not null || state != ServiceConnectionState.Connected)
            {
                _lastStatus = status;
            }
        }

        if (changed)
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId);
}
