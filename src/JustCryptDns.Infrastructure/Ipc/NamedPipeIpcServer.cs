using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Ipc;

/// <summary>
/// Local Named Pipe server with explicit ACLs (LocalSystem, Administrators, current owner, and local AuthenticatedUsers;
/// NetworkSid is explicitly denied so remote pipe connections are rejected) and client binary path / privilege verification.
/// </summary>
public sealed class NamedPipeIpcServer : IAsyncDisposable
{
    private const int MaxConcurrentClients = 8;
    private const int AcceptLoopCount = 2;
    private const int MaxInboundRequestBytes = 512 * 1024;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private readonly string _pipeName;
    private readonly IServiceIpcHandler _handler;
    private readonly ILogger<NamedPipeIpcServer> _logger;
    private readonly SemaphoreSlim _concurrency = new(MaxConcurrentClients, MaxConcurrentClients);
    private readonly ConcurrentDictionary<Task, byte> _activeClients = new();
    private CancellationTokenSource? _cts;
    private Task[]? _acceptLoops;
    private int _disposed;

    public NamedPipeIpcServer(IServiceIpcHandler handler, ILogger<NamedPipeIpcServer> logger, string pipeName = IpcConstants.DefaultPipeName)
    {
        _handler = handler;
        _logger = logger;
        _pipeName = pipeName;
    }

    public void Start()
    {
        if (_acceptLoops is not null || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        var loops = new Task[AcceptLoopCount];
        for (var i = 0; i < loops.Length; i++)
        {
            loops[i] = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        _acceptLoops = loops;
        _logger.LogInformation("IPC server listening on pipe {PipeName}", _pipeName);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (_cts is not null)
        {
            await _cts.CancelAsync().ConfigureAwait(false);
        }

        if (_acceptLoops is { Length: > 0 } loops)
        {
            try
            {
                await Task.WhenAll(loops).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown.
            }
        }

        var inFlight = _activeClients.Keys.ToArray();
        if (inFlight.Length > 0)
        {
            try
            {
                await Task.WhenAll(inFlight).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Ignore client cancellation/timeouts on shutdown.
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
            var acquired = false;
            NamedPipeServerStream? server = null;
            try
            {
                await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;

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
                acquired = false;

                Task? clientTask = null;
                clientTask = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(connected, cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        if (clientTask is not null)
                        {
                            _activeClients.TryRemove(clientTask, out _);
                        }
                    }
                }, CancellationToken.None);
                _activeClients.TryAdd(clientTask, 0);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                server?.Dispose();
                if (acquired)
                {
                    ReleaseConcurrencySafe();
                }

                break;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                server?.Dispose();
                if (acquired)
                {
                    ReleaseConcurrencySafe();
                }

                _logger.LogWarning(ex, "IPC accept error on {PipeName}", _pipeName);
                try
                {
                    await Task.Delay(250, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream stream, CancellationToken cancellationToken)
    {
        try
        {
            await using (stream.ConfigureAwait(false))
            {
                IpcRequest? request;
                using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    readCts.CancelAfter(TimeSpan.FromSeconds(3));
                    request = await IpcFraming.ReadMessageAsync<IpcRequest>(stream, MaxInboundRequestBytes, readCts.Token).ConfigureAwait(false);
                }

                if (request is null)
                {
                    return;
                }

                using var execCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                execCts.CancelAfter(TimeSpan.FromSeconds(20));

                IpcResponse response;
                if (request.Kind != IpcRequestKind.GetStatus && !IsAuthorizedClientProcess(stream))
                {
                    _logger.LogWarning("Rejected unauthorized IPC request {Kind} on {PipeName}.", request.Kind, _pipeName);
                    var fallback = await _handler.HandleAsync(new IpcRequest(IpcRequestKind.GetStatus), execCts.Token).ConfigureAwait(false);
                    response = new IpcResponse(
                        Success: false,
                        Status: fallback.Status,
                        ErrorCode: "UnauthorizedCaller",
                        Message: "Caller process is not authorized to control JustCryptDnsService.");
                }
                else if (request.ProtocolVersion != IpcConstants.ProtocolVersion)
                {
                    var fallback = await _handler.HandleAsync(new IpcRequest(IpcRequestKind.GetStatus), execCts.Token).ConfigureAwait(false);
                    response = new IpcResponse(
                        Success: false,
                        Status: fallback.Status,
                        ErrorCode: "ProtocolMismatch",
                        Message: $"Unsupported IPC protocol version {request.ProtocolVersion}.");
                }
                else
                {
                    response = await _handler.HandleAsync(request, execCts.Token).ConfigureAwait(false);
                }

                await IpcFraming.WriteMessageAsync(stream, response, execCts.Token).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "IPC client session ended early.");
        }
        finally
        {
            ReleaseConcurrencySafe();
        }
    }

    private void ReleaseConcurrencySafe()
    {
        try
        {
            _concurrency.Release();
        }
        catch (ObjectDisposedException)
        {
            // Expected if DisposeAsync completed after timeout.
        }
    }

    internal static bool IsAuthorizedClientProcess(NamedPipeServerStream stream)
    {
        try
        {
            var handle = stream.SafePipeHandle.DangerousGetHandle();
            if (!GetNamedPipeClientProcessId(handle, out var clientPid) || clientPid == 0)
            {
                return false;
            }

            if (clientPid == (uint)Environment.ProcessId)
            {
                return true;
            }

            var isAdminOrSystem = false;
            try
            {
                stream.RunAsClient(() =>
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    if (identity.IsSystem)
                    {
                        isAdminOrSystem = true;
                        return;
                    }

                    var principal = new WindowsPrincipal(identity);
                    isAdminOrSystem = principal.IsInRole(WindowsBuiltInRole.Administrator);
                });
            }
            catch
            {
                // Fall back to binary path verification below.
            }

            if (isAdminOrSystem)
            {
                return true;
            }

            var clientExePath = TryGetProcessImagePath(clientPid);
            if (string.IsNullOrWhiteSpace(clientExePath))
            {
                return false;
            }

            var fileName = Path.GetFileName(clientExePath);
            if (!string.Equals(fileName, "JustCryptDns.exe", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(fileName, "JustCryptDns.Service.exe", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var clientDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetDirectoryName(clientExePath)!));
            var baseDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
            return string.Equals(clientDir, baseDir, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    internal static string? TryGetProcessImagePath(uint pid)
    {
        var hProcess = OpenProcess(ProcessQueryLimitedInformation, bInheritHandle: false, pid);
        if (hProcess == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;
            return QueryFullProcessImageNameW(hProcess, 0, buffer, ref size) && size > 0
                ? new string(buffer, 0, (int)size)
                : null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
