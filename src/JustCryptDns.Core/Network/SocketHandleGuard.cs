using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace JustCryptDns.Core.Network;

/// <summary>
/// Prevents listening socket handles from being inherited by child processes (such as <c>dnscrypt-proxy.exe</c>),
/// eliminating stale <c>WSAEADDRINUSE</c> port locks when stopping and restarting local servers.
/// </summary>
public static class SocketHandleGuard
{
    private const uint HandleFlagInherit = 0x00000001;

    public static void DisableInheritance(Socket? socket)
    {
        if (socket is null || !OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var handle = socket.Handle;
            if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            {
                _ = SetHandleInformation(handle, HandleFlagInherit, 0);
            }
        }
        catch (Exception ex) when (ex is ObjectDisposedException or SocketException)
        {
            // Ignore closed/disposed sockets during teardown races.
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(nint hObject, uint dwMask, uint dwFlags);
}
