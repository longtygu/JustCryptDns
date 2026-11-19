# JustCryptDns Performance & Resource Measurements

Measured on **Windows 10 22H2 (x64, build 19045)** with `.NET 8.0` **Release** builds (`dotnet build JustCryptDns.sln -c Release`).

## Measured Process Footprint (Release x64)

| Process / Mode | Working Set | Private Memory | Threads | Handles | Idle CPU |
|---|---:|---:|---:|---:|---:|
| `JustCryptDns.Service.exe` (Background Service + Named Pipe IPC) | **31.1 MB** | **8.9 MB** | 10 | 232 | ~0 % (0.25 s startup) |
| `JustCryptDns.exe --minimized` (System Tray Only) | **103.9 MB** | **61.2 MB** | 20 | 631 | ~0 % |
| `JustCryptDns.exe` (Main WPF Window Open) | **143.8 MB** | **96.1 MB** | 26 | 765 | ~0 % |

## Resource Optimization Techniques Implemented

1. **Zero Polling Architecture:** Local network adapter updates (`NetworkChange`), DNS engine state changes, routing logs, and live monitor updates are purely event-driven (`EventHandler` + `SemaphoreSlim`), consuming 0 % CPU while idle.
2. **On-Demand Page Lifecycle (`PageFactory`):** Only the currently visible page ViewModel and visual tree exist in memory; navigating away calls `OnNavigatedFrom()` and `Dispose()`, detaching event handlers immediately.
3. **Virtualized Live Monitor:** Uses `VirtualizingPanel.IsVirtualizing="True"` and `VirtualizingPanel.VirtualizationMode="Recycling"` backed by a bounded ring buffer sized according to `MonitoringMode` (`PowerSaving` = 100, `Balanced` = 300, `Performance` = 500 entries).
4. **Native Win32 System Tray:** Uses `Shell_NotifyIconW` P/Invoke directly with zero `System.Windows.Forms` assembly load (~10 MB saved).
5. **Automatic Working-Set Trimming:** Hiding the main window to the system tray (or clicking **Trim memory now** in Settings → Developer Performance Diagnostics) compacts the managed heap (`GCLargeObjectHeapCompactionMode.CompactOnce`) and calls `SetProcessWorkingSetSize(-1, -1)` to return unused pages to Windows.
6. **Pooled HTTP/2 DoH Connections:** `DohDnsUpstream` reuses a single `SocketsHttpHandler` with `PooledConnectionLifetime` and direct bootstrap IP connections.
