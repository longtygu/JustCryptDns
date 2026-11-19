using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
    private static readonly string[] CandidateLoopbackIps = ["127.0.0.2", "127.0.0.3", "127.0.0.53", "127.0.0.54"];
    private static readonly HashSet<string> ProtectedWindowsServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "Dnscache", "RpcSs", "Dhcp", "NlaSvc", "nsi", "EventLog", "Winmgmt", "BFE", "mpssvc", "Netman", "LanmanWorkstation",
    };

    public static PortConflictInfo? CheckConflict(IPAddress listenAddress, int port)
    {
        ArgumentNullException.ThrowIfNull(listenAddress);
        if (!IsPortInUse(listenAddress, port, out var proto))
        {
            return null;
        }

        var suggested = FindAvailablePort(listenAddress);
        var suggestedLoopback = port == 53 ? FindAvailableLoopbackForPort53(excludeIp: listenAddress) : null;
        var (ownerName, ownerPid, serviceName) = TryFindPortOwnerDetails(port);
        var ownerText = ownerName is not null && ownerPid.HasValue
            ? $"'{ownerName}' (PID {ownerPid.Value})"
            : "another process";
        var loopbackHint = suggestedLoopback is not null
            ? $" You can bind directly to {suggestedLoopback}:53 without stopping {ownerText}."
            : string.Empty;
        return new PortConflictInfo(
            HasConflict: true,
            Endpoint: $"{listenAddress}:{port}",
            Protocol: proto,
            SuggestedPort: suggested,
            Message: $"Port {port} ({proto}) on {listenAddress} is already in use by {ownerText}.{loopbackHint}",
            ConflictingProcessName: ownerName,
            ConflictingPid: ownerPid,
            SuggestedLoopbackIp: suggestedLoopback,
            ConflictingServiceName: serviceName);
    }

    /// <summary>
    /// Probes alternate IPv4 loopback addresses (127.0.0.2..127.0.0.54) on standard port 53 so JustCryptDns
    /// can intercept Windows system DNS on port 53 even while another proxy occupies 127.0.0.1:53.
    /// </summary>
    public static string? FindAvailableLoopbackForPort53(IPAddress? excludeIp = null)
    {
        foreach (var ipText in CandidateLoopbackIps)
        {
            var candidate = IPAddress.Parse(ipText);
            if (excludeIp is not null && candidate.Equals(excludeIp))
            {
                continue;
            }

            if (CanBindUdpAndTcp(candidate, 53))
            {
                return ipText;
            }
        }

        return null;
    }

    public static bool CanBindUdpAndTcp(IPAddress address, int port)
    {
        Socket? udp = null;
        TcpListener? tcp = null;
        try
        {
            udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(address, port));
            tcp = new TcpListener(address, port);
            tcp.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        finally
        {
            try { tcp?.Stop(); } catch { }
            try { udp?.Dispose(); } catch { }
        }
    }

    public static (string? ProcessName, int? Pid) TryFindPortOwner(int port)
    {
        var (proc, pid, _) = TryFindPortOwnerDetails(port);
        return (proc, pid);
    }

    public static (string? ProcessName, int? Pid, string? ServiceName) TryFindPortOwnerDetails(int port)
    {
        if (!OperatingSystem.IsWindows() || port <= 0)
        {
            return (null, null, null);
        }

        try
        {
            var pid = FindUdpOwnerPid(port) ?? FindTcpOwnerPid(port);
            if (pid is > 4)
            {
                string? procName = null;
                try
                {
                    using var proc = Process.GetProcessById(pid.Value);
                    procName = proc.ProcessName;
                }
                catch
                {
                    // Process may be protected or exited.
                }

                var svcName = TryFindWindowsServiceForPid(pid.Value);
                if (svcName is not null && ProtectedWindowsServices.Contains(svcName))
                {
                    svcName = null;
                }

                return (procName, pid.Value, svcName);
            }
        }
        catch
        {
            // Ignore lookup failures on restricted sessions.
        }

        return (null, null, null);
    }

    public static async Task<(bool Success, string? Error)> StopConflictingServiceAsync(
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(serviceName))
        {
            return (false, "Invalid Windows service name.");
        }

        var trimmed = serviceName.Trim();
        if (ProtectedWindowsServices.Contains(trimmed))
        {
            return (false, $"Service '{trimmed}' is a protected Windows system service and will not be stopped.");
        }

        try
        {
            var psi = new ProcessStartInfo("sc.exe", $"stop \"{trimmed}\"")
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "Failed to start sc.exe.");
            }

            await proc.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            if (proc.ExitCode != 0 && proc.ExitCode != 1062) // 1062 = already stopped
            {
                return (false, $"sc.exe stop \"{trimmed}\" exited with code {proc.ExitCode}.");
            }

            // Wait up to 5 seconds for 127.0.0.1:53 to be released
            for (var i = 0; i < 25; i++)
            {
                if (CanBindUdpAndTcp(IPAddress.Loopback, 53))
                {
                    return (true, null);
                }

                await Task.Delay(200, cancellationToken).ConfigureAwait(false);
            }

            return (false, $"Service '{trimmed}' was signaled to stop, but port 53 is still busy.");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (false, "Administrator permission prompt (UAC) was cancelled.");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static string? TryFindWindowsServiceForPid(int targetPid)
    {
        var scm = OpenSCManagerW(null, null, 0x0004 /* SC_MANAGER_ENUMERATE_SERVICE */);
        if (scm == nint.Zero)
        {
            return null;
        }

        try
        {
            uint bytesNeeded = 0;
            uint servicesReturned = 0;
            uint resumeHandle = 0;
            _ = EnumServicesStatusExW(scm, 0, 0x30 /* SERVICE_WIN32 */, 1 /* SERVICE_ACTIVE */, nint.Zero, 0, out bytesNeeded, out servicesReturned, ref resumeHandle, null);
            if (bytesNeeded == 0)
            {
                return null;
            }

            var buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (!EnumServicesStatusExW(scm, 0, 0x30, 1, buffer, bytesNeeded, out _, out servicesReturned, ref resumeHandle, null))
                {
                    return null;
                }

                var structSize = Marshal.SizeOf<EnumServiceStatusProcess>();
                for (var i = 0; i < servicesReturned; i++)
                {
                    var item = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + (i * structSize));
                    if (item.ServiceStatusProcess.dwProcessId == targetPid && !string.IsNullOrWhiteSpace(item.lpServiceName))
                    {
                        return item.lpServiceName;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }

        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EnumServiceStatusProcess
    {
        public string lpServiceName;
        public string lpDisplayName;
        public ServiceStatusProcess ServiceStatusProcess;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        nint hSCManager,
        int infoLevel,
        uint dwServiceType,
        uint dwServiceState,
        nint lpServices,
        uint cbBufSize,
        out uint pcbBytesNeeded,
        out uint lpServicesReturned,
        ref uint lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(nint hSCObject);

    private static int? FindUdpOwnerPid(int targetPort)
    {
        var bufferSize = 0;
        _ = GetExtendedUdpTable(nint.Zero, ref bufferSize, false, 2 /* AF_INET */, 1 /* UDP_TABLE_OWNER_PID */, 0);
        if (bufferSize <= 0)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedUdpTable(buffer, ref bufferSize, false, 2, 1, 0) != 0)
            {
                return null;
            }

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            const int rowSize = 12; // localAddr (4) + localPort (4) + owningPid (4)
            for (var i = 0; i < count; i++)
            {
                var rawPort = Marshal.ReadInt32(rowPtr + 4);
                var port = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
                if (port == targetPort)
                {
                    return Marshal.ReadInt32(rowPtr + 8);
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return null;
    }

    private static int? FindTcpOwnerPid(int targetPort)
    {
        var bufferSize = 0;
        _ = GetExtendedTcpTable(nint.Zero, ref bufferSize, false, 2 /* AF_INET */, 5 /* TCP_TABLE_OWNER_PID_ALL */, 0);
        if (bufferSize <= 0)
        {
            return null;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, false, 2, 5, 0) != 0)
            {
                return null;
            }

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            const int rowSize = 24; // state(4)+localAddr(4)+localPort(4)+remoteAddr(4)+remotePort(4)+pid(4)
            for (var i = 0; i < count; i++)
            {
                var state = Marshal.ReadInt32(rowPtr);
                var rawPort = Marshal.ReadInt32(rowPtr + 8);
                var port = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
                if (state == 2 /* LISTEN */ && port == targetPort)
                {
                    return Marshal.ReadInt32(rowPtr + 20);
                }

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return null;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(nint pUdpTable, ref int pdwSize, bool sort, int ipVersion, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(nint pTcpTable, ref int pdwSize, bool sort, int ipVersion, int tableClass, uint reserved);

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
        var maxAttempts = port == 0 ? 8 : 1;
        Socket? udp = null;
        TcpListener? tcp = null;
        var actualPort = port;

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                udp.Bind(new IPEndPoint(address, port));
                actualPort = ((IPEndPoint)udp.LocalEndPoint!).Port;
                tcp = new TcpListener(address, actualPort);
                tcp.Start();
                break;
            }
            catch (SocketException) when (attempt < maxAttempts)
            {
                udp.Dispose();
                udp = null;
                tcp = null;
            }
        }

        if (BoundPort == 0)
        {
            BoundPort = actualPort;
        }

        _udpSockets.Add(udp!);
        _tcpListeners.Add(tcp!);
        _loops.Add(Task.Run(() => UdpReceiveLoopAsync(udp!, ct), ct));
        _loops.Add(Task.Run(() => TcpAcceptLoopAsync(tcp!, ct), ct));
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
