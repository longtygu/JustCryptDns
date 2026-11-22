using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Monitoring;

/// <summary>
/// Enumerates live TCP (IPv4/IPv6) and UDP (IPv4/IPv6) endpoints with owning PID and process name
/// via Win32 <c>iphlpapi.dll</c> without requiring Administrator privileges or kernel drivers.
/// </summary>
public sealed class WindowsConnectionTableReader : IConnectionMonitorService
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const int TcpStateListen = 2;
    private const uint Th32csSnapProcess = 0x00000002;
    private const uint ErrorInsufficientBuffer = 122;

    private readonly ILogger<WindowsConnectionTableReader> _logger;
    private readonly object _procCacheLock = new();
    private Dictionary<int, string> _processNames = new();
    private readonly Dictionary<int, (string Name, string? Path)> _exePathCache = new();
    private readonly Dictionary<int, DateTimeOffset> _missingPids = new();
    private DateTimeOffset _processCacheUpdatedAt = DateTimeOffset.MinValue;

    public WindowsConnectionTableReader(ILogger<WindowsConnectionTableReader> logger)
    {
        _logger = logger;
    }

    public IReadOnlyList<RawSocketConnection> CaptureSnapshot()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var procMap = GetProcessNameMap();
        var results = new List<RawSocketConnection>(128);
        var unknownPids = false;

        void AddEntry(ConnectionProtocol proto, string localIp, int localPort, string remoteIp, int remotePort, string state, int pid)
        {
            if (!TryResolveProcessName(procMap, pid, out var name))
            {
                unknownPids = true;
            }

            results.Add(new RawSocketConnection(proto, localIp, localPort, remoteIp, remotePort, state, pid, name));
        }

        ReadTcp4(AddEntry);
        ReadTcp6(AddEntry);
        ReadUdp4(AddEntry);
        ReadUdp6(AddEntry);

        if (unknownPids)
        {
            // A brand-new process appeared since the last toolhelp snapshot; refresh once and backfill.
            procMap = RefreshProcessNameMap();
            for (var i = 0; i < results.Count; i++)
            {
                var item = results[i];
                if (item.ProcessName.StartsWith("PID ", StringComparison.Ordinal)
                    && TryResolveProcessName(procMap, item.ProcessId, out var resolved))
                {
                    results[i] = item with { ProcessName = resolved };
                }
            }
        }

        // Enrich executable full paths only for PIDs present in the current connection snapshot.
        for (var i = 0; i < results.Count; i++)
        {
            var item = results[i];
            if (item.ProcessId > 4)
            {
                var exePath = ResolveExecutablePathCached(item.ProcessId, item.ProcessName);
                if (exePath is not null)
                {
                    results[i] = item with { ExecutablePath = exePath };
                }
            }
        }

        return results;
    }

    private string? ResolveExecutablePathCached(int pid, string procName)
    {
        lock (_procCacheLock)
        {
            if (_exePathCache.TryGetValue(pid, out var cached)
                && string.Equals(cached.Name, procName, StringComparison.OrdinalIgnoreCase))
            {
                return cached.Path;
            }
        }

        var resolved = TryQueryExecutablePath(pid);
        lock (_procCacheLock)
        {
            if (_exePathCache.Count > 1024)
            {
                _exePathCache.Clear();
            }

            _exePathCache[pid] = (procName, resolved);
        }

        return resolved;
    }

    private static string? TryQueryExecutablePath(int pid)
    {
        const uint processQueryLimitedInfo = 0x00001000;
        var handle = NativeMethods.OpenProcess(processQueryLimitedInfo, false, (uint)pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new char[1024];
            var size = buffer.Length;
            if (NativeMethods.QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0)
            {
                return new string(buffer, 0, size);
            }

            return null;
        }
        finally
        {
            _ = NativeMethods.CloseHandle(handle);
        }
    }

    private Dictionary<int, string> GetProcessNameMap()
    {
        lock (_procCacheLock)
        {
            if ((DateTimeOffset.UtcNow - _processCacheUpdatedAt).TotalMilliseconds < 1500 && _processNames.Count > 0)
            {
                return _processNames;
            }
        }

        return RefreshProcessNameMap();
    }

    private Dictionary<int, string> RefreshProcessNameMap()
    {
        var map = new Dictionary<int, string>(128)
        {
            [0] = "System Idle",
            [4] = "System",
        };

        var snapshot = NativeMethods.CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
        {
            return map;
        }

        try
        {
            var entry = new NativeMethods.ProcessEntry32W
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32W>(),
            };

            if (NativeMethods.Process32FirstW(snapshot, ref entry))
            {
                do
                {
                    var pid = (int)entry.th32ProcessID;
                    if (!string.IsNullOrWhiteSpace(entry.szExeFile) && !map.ContainsKey(pid))
                    {
                        map[pid] = entry.szExeFile;
                    }
                }
                while (NativeMethods.Process32NextW(snapshot, ref entry));
            }
        }
        finally
        {
            _ = NativeMethods.CloseHandle(snapshot);
        }

        lock (_procCacheLock)
        {
            _processNames = map;
            _processCacheUpdatedAt = DateTimeOffset.UtcNow;
        }

        return map;
    }

    private bool TryResolveProcessName(Dictionary<int, string> map, int pid, out string name)
    {
        if (map.TryGetValue(pid, out var mapped))
        {
            name = mapped;
            return true;
        }

        if (pid == 0)
        {
            name = "System Idle";
            return true;
        }

        if (pid == 4)
        {
            name = "System";
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        lock (_procCacheLock)
        {
            if (_missingPids.TryGetValue(pid, out var failedAt) && (now - failedAt).TotalMilliseconds < 2500)
            {
                name = $"PID {pid}";
                return true;
            }
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName + ".exe";
            return true;
        }
        catch (Exception)
        {
            lock (_procCacheLock)
            {
                if (_missingPids.Count > 512)
                {
                    _missingPids.Clear();
                }

                _missingPids[pid] = now;
            }

            name = $"PID {pid}";
            return false;
        }
    }

    private void ReadTcp4(Action<ConnectionProtocol, string, int, string, int, string, int> emit)
    {
        var (buffer, allocatedSize) = QueryTable((ptr, ref size) =>
            NativeMethods.GetExtendedTcpTable(ptr, ref size, false, AfInet, TcpTableOwnerPidAll, 0));
        if (buffer == nint.Zero)
        {
            return;
        }

        try
        {
            const int rowSize = 24;
            var count = GetSafeRowCount(buffer, allocatedSize, rowSize);
            var rowPtr = buffer + 4;
            var ip4 = new byte[4];

            for (var i = 0; i < count; i++)
            {
                var state = Marshal.ReadInt32(rowPtr);
                if (state != TcpStateListen)
                {
                    Marshal.Copy(rowPtr + 4, ip4, 0, 4);
                    var localIp = new IPAddress(ip4).ToString();
                    var localPort = DecodePort(Marshal.ReadInt32(rowPtr + 8));

                    Marshal.Copy(rowPtr + 12, ip4, 0, 4);
                    var remoteIp = new IPAddress(ip4).ToString();
                    var remotePort = DecodePort(Marshal.ReadInt32(rowPtr + 16));
                    var pid = Marshal.ReadInt32(rowPtr + 20);

                    if (!string.Equals(remoteIp, "0.0.0.0", StringComparison.Ordinal))
                    {
                        emit(ConnectionProtocol.Tcp4, localIp, localPort, remoteIp, remotePort, FormatTcpState(state), pid);
                    }
                }

                rowPtr += rowSize;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed parsing IPv4 TCP connection table.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void ReadTcp6(Action<ConnectionProtocol, string, int, string, int, string, int> emit)
    {
        var (buffer, allocatedSize) = QueryTable((ptr, ref size) =>
            NativeMethods.GetExtendedTcpTable(ptr, ref size, false, AfInet6, TcpTableOwnerPidAll, 0));
        if (buffer == nint.Zero)
        {
            return;
        }

        try
        {
            const int rowSize = 56;
            var count = GetSafeRowCount(buffer, allocatedSize, rowSize);
            var rowPtr = buffer + 4;
            var ip16 = new byte[16];

            for (var i = 0; i < count; i++)
            {
                var state = Marshal.ReadInt32(rowPtr + 48);
                if (state != TcpStateListen)
                {
                    Marshal.Copy(rowPtr, ip16, 0, 16);
                    var localAddr = NormalizeIp(new IPAddress(ip16));
                    var localPort = DecodePort(Marshal.ReadInt32(rowPtr + 20));

                    Marshal.Copy(rowPtr + 24, ip16, 0, 16);
                    var remoteAddr = NormalizeIp(new IPAddress(ip16));
                    var remotePort = DecodePort(Marshal.ReadInt32(rowPtr + 44));
                    var pid = Marshal.ReadInt32(rowPtr + 52);

                    if (!remoteAddr.Equals(IPAddress.IPv6Any) && !remoteAddr.Equals(IPAddress.Any))
                    {
                        var proto = remoteAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                            ? ConnectionProtocol.Tcp4
                            : ConnectionProtocol.Tcp6;
                        emit(proto, localAddr.ToString(), localPort, remoteAddr.ToString(), remotePort, FormatTcpState(state), pid);
                    }
                }

                rowPtr += rowSize;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed parsing IPv6 TCP connection table.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void ReadUdp4(Action<ConnectionProtocol, string, int, string, int, string, int> emit)
    {
        var (buffer, allocatedSize) = QueryTable((ptr, ref size) =>
            NativeMethods.GetExtendedUdpTable(ptr, ref size, false, AfInet, UdpTableOwnerPid, 0));
        if (buffer == nint.Zero)
        {
            return;
        }

        try
        {
            const int rowSize = 12;
            var count = GetSafeRowCount(buffer, allocatedSize, rowSize);
            var rowPtr = buffer + 4;
            var ip4 = new byte[4];

            for (var i = 0; i < count; i++)
            {
                Marshal.Copy(rowPtr, ip4, 0, 4);
                var localIp = new IPAddress(ip4).ToString();
                var localPort = DecodePort(Marshal.ReadInt32(rowPtr + 4));
                var pid = Marshal.ReadInt32(rowPtr + 8);

                if (localPort > 0)
                {
                    emit(ConnectionProtocol.Udp4, localIp, localPort, "*", localPort, "UDP", pid);
                }

                rowPtr += rowSize;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed parsing IPv4 UDP socket table.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private void ReadUdp6(Action<ConnectionProtocol, string, int, string, int, string, int> emit)
    {
        var (buffer, allocatedSize) = QueryTable((ptr, ref size) =>
            NativeMethods.GetExtendedUdpTable(ptr, ref size, false, AfInet6, UdpTableOwnerPid, 0));
        if (buffer == nint.Zero)
        {
            return;
        }

        try
        {
            const int rowSize = 28;
            var count = GetSafeRowCount(buffer, allocatedSize, rowSize);
            var rowPtr = buffer + 4;
            var ip16 = new byte[16];

            for (var i = 0; i < count; i++)
            {
                Marshal.Copy(rowPtr, ip16, 0, 16);
                var localAddr = NormalizeIp(new IPAddress(ip16));
                var localPort = DecodePort(Marshal.ReadInt32(rowPtr + 20));
                var pid = Marshal.ReadInt32(rowPtr + 24);

                if (localPort > 0)
                {
                    emit(ConnectionProtocol.Udp6, localAddr.ToString(), localPort, "*", localPort, "UDP6", pid);
                }

                rowPtr += rowSize;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed parsing IPv6 UDP socket table.");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int GetSafeRowCount(nint buffer, int allocatedSize, int rowSize)
    {
        if (allocatedSize < 4 || rowSize <= 0)
        {
            return 0;
        }

        var rawCount = Marshal.ReadInt32(buffer);
        if (rawCount <= 0)
        {
            return 0;
        }

        var maxRows = (allocatedSize - 4) / rowSize;
        return Math.Min(rawCount, maxRows);
    }

    private delegate uint TableQueryDelegate(nint buffer, ref int size);

    private static (nint Buffer, int AllocatedSize) QueryTable(TableQueryDelegate query)
    {
        var size = 0;
        _ = query(nint.Zero, ref size);
        if (size <= 0)
        {
            return (nint.Zero, 0);
        }

        size += 4096;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var allocSize = size;
            var buffer = Marshal.AllocHGlobal(allocSize);
            var keepBuffer = false;
            try
            {
                var status = query(buffer, ref size);
                if (status == 0)
                {
                    keepBuffer = true;
                    return (buffer, allocSize);
                }

                if (status != ErrorInsufficientBuffer)
                {
                    return (nint.Zero, 0);
                }
            }
            finally
            {
                if (!keepBuffer)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            size += 4096;
        }

        return (nint.Zero, 0);
    }

    private static int DecodePort(int rawPort) => ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);

    private static IPAddress NormalizeIp(IPAddress ip) => ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;

    private static string FormatTcpState(int state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    };

    private static class NativeMethods
    {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(
            nint pTcpTable,
            ref int pdwSize,
            [MarshalAs(UnmanagedType.Bool)] bool bOrder,
            int ulAf,
            int tableClass,
            uint reserved);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedUdpTable(
            nint pUdpTable,
            ref int pdwSize,
            [MarshalAs(UnmanagedType.Bool)] bool bOrder,
            int ulAf,
            int tableClass,
            uint reserved);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32FirstW(nint hSnapshot, ref ProcessEntry32W lppe);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32NextW(nint hSnapshot, ref ProcessEntry32W lppe);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(nint hObject);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint OpenProcess(
            uint dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            uint dwProcessId);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageNameW(
            nint hProcess,
            uint dwFlags,
            [Out] char[] lpExeName,
            ref int lpdwSize);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct ProcessEntry32W
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public nint th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}
