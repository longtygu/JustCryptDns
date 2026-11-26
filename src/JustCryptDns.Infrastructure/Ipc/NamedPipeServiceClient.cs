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
    private int _consecutiveConnectTimeouts;
    private uint _lastTrustedServerPid;

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
            catch (FileNotFoundException)
            {
                Volatile.Write(ref _consecutiveConnectTimeouts, 0);
                UpdateState(ServiceConnectionState.ServiceNotRunning, null);
                return null;
            }
            catch (Exception ex) when (ex is TimeoutException or (OperationCanceledException and not TaskCanceledException) || (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested))
            {
                // Distinguish a missing pipe server (ERROR_FILE_NOT_FOUND) from a busy live server.
                if (IsPipeDefinitelyMissing(_pipeName))
                {
                    Volatile.Write(ref _consecutiveConnectTimeouts, 0);
                    UpdateState(ServiceConnectionState.ServiceNotRunning, null);
                    return null;
                }

                // Transient connect timeout while already connected (pipe busy under load) shouldn't immediately
                // flip state to ServiceNotRunning and cause the desktop app to launch a competing engine.
                var timeouts = Interlocked.Increment(ref _consecutiveConnectTimeouts);
                if (ConnectionState != ServiceConnectionState.Connected || timeouts >= 2)
                {
                    UpdateState(ServiceConnectionState.ServiceNotRunning, null);
                }

                return null;
            }

            Volatile.Write(ref _consecutiveConnectTimeouts, 0);

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

    private bool IsTrustedPipeServer(NamedPipeClientStream pipe)
    {
        try
        {
            var handle = pipe.SafePipeHandle.DangerousGetHandle();
            if (!GetNamedPipeServerProcessId(handle, out var serverPid) || serverPid == 0)
            {
                return true;
            }

            if (serverPid == (uint)Environment.ProcessId || serverPid == Volatile.Read(ref _lastTrustedServerPid))
            {
                return true;
            }

            var serverExePath = NamedPipeIpcServer.TryGetProcessImagePath(serverPid);
            if (string.IsNullOrWhiteSpace(serverExePath))
            {
                // If OpenProcess failed with ERROR_ACCESS_DENIED (5), the server is running in a higher privilege session (LocalSystem).
                if (Marshal.GetLastWin32Error() == 5)
                {
                    Volatile.Write(ref _lastTrustedServerPid, serverPid);
                    return true;
                }

                return false;
            }

            var fileName = Path.GetFileName(serverExePath);
            var trusted = string.Equals(fileName, "JustCryptDns.Service.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "JustCryptDns.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "testhost.exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(fileName, "dotnet.exe", StringComparison.OrdinalIgnoreCase);
            if (trusted)
            {
                Volatile.Write(ref _lastTrustedServerPid, serverPid);
            }

            return trusted;
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
            var previousState = _connectionState;
            var previousStatus = _lastStatus;
            changed = state != previousState || HasMeaningfulStatusChange(previousStatus, status);
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

    private static bool HasMeaningfulStatusChange(ServiceStatusSnapshot? prev, ServiceStatusSnapshot? next)
    {
        if (prev is null || next is null)
        {
            return prev is not null != (next is not null);
        }

        return prev.EngineState != next.EngineState
            || prev.IsEngineEnabled != next.IsEngineEnabled
            || prev.IsGamingModeEnabled != next.IsGamingModeEnabled
            || !string.Equals(prev.ActiveResolverId, next.ActiveResolverId, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(prev.ActiveProtocol, next.ActiveProtocol, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(prev.ListenEndpoint, next.ListenEndpoint, StringComparison.OrdinalIgnoreCase)
            || prev.IsBypassRunning != next.IsBypassRunning
            || !string.Equals(prev.BypassEndpoint, next.BypassEndpoint, StringComparison.OrdinalIgnoreCase)
            || prev.HasAdapterBackup != next.HasAdapterBackup
            || prev.IsCaptivePortalPaused != next.IsCaptivePortalPaused
            || !string.Equals(prev.ActiveVpnAdapterName, next.ActiveVpnAdapterName, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(prev.LastError, next.LastError, StringComparison.Ordinal);
    }

    private static bool IsPipeDefinitelyMissing(string pipeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        if (WaitNamedPipeW($@"\\.\pipe\{pipeName}", 1))
        {
            return false;
        }

        // ERROR_FILE_NOT_FOUND (2) indicates no server has an active instance of this pipe.
        return Marshal.GetLastWin32Error() == 2;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr Pipe, out uint ServerProcessId);

    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WaitNamedPipeW(string lpNamedPipeName, uint nTimeOut);
}
