using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using JustCryptDns.App.Localization;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

public interface ITrayIconService : IDisposable
{
    event EventHandler? OpenRequested;

    event EventHandler? ExitRequested;

    void Initialize();
}

/// <summary>
/// Lightweight Win32 <c>Shell_NotifyIconW</c> system tray integration with a themed WPF <see cref="ContextMenu"/>.
/// Avoids any <c>System.Windows.Forms</c> dependency to keep memory footprint minimal.
/// </summary>
public sealed class TrayIconService : ITrayIconService
{
    private const int WmAppTray = 0x8001;
    private const int WmNull = 0x0000;
    private const int WmLButtonUp = 0x0202;
    private const int WmLButtonDblClk = 0x0203;
    private const int WmRButtonUp = 0x0205;
    private const int WmContextMenu = 0x007B;
    private const int NinSelect = 0x0400;

    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;

    private const uint ImageIcon = 1;
    private const uint LrShared = 0x00008000;
    private const int IdiApplication = 32512;

    private readonly IServiceClient _serviceClient;
    private readonly IDnsEngine? _localEngine;
    private readonly IWindowsDnsManager? _windowsDns;
    private readonly INavigationService _navigation;
    private readonly ILogger<TrayIconService> _logger;
    private readonly uint _taskbarCreatedMsg;

    private HwndSource? _hwndSource;
    private IntPtr _iconHandle;
    private bool _added;
    private bool _disposed;
    private ContextMenu? _contextMenu;

    public TrayIconService(
        IServiceClient serviceClient,
        INavigationService navigation,
        ILogger<TrayIconService> logger,
        IDnsEngine? localEngine = null,
        IWindowsDnsManager? windowsDns = null)
    {
        _serviceClient = serviceClient;
        _navigation = navigation;
        _logger = logger;
        _localEngine = localEngine;
        _windowsDns = windowsDns;
        _taskbarCreatedMsg = RegisterWindowMessageW("TaskbarCreated");
    }

    public event EventHandler? OpenRequested;

    public event EventHandler? ExitRequested;

    public void Initialize()
    {
        if (_hwndSource is not null || _disposed)
        {
            return;
        }

        var parameters = new HwndSourceParameters("JustCryptDnsTraySink")
        {
            Width = 0,
            Height = 0,
            PositionX = 0,
            PositionY = 0,
            WindowStyle = 0,
        };
        _hwndSource = new HwndSource(parameters);
        _hwndSource.AddHook(WndProc);

        _iconHandle = LoadAppIcon();
        AddOrUpdateIcon(NimAdd);
        LocalizationManager.Instance.PropertyChanged += OnLocalizationChanged;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        LocalizationManager.Instance.PropertyChanged -= OnLocalizationChanged;
        if (_added && _hwndSource is { Handle: var hwnd } && hwnd != IntPtr.Zero)
        {
            var data = CreateNotifyIconData(hwnd);
            Shell_NotifyIconW(NimDelete, ref data);
            _added = false;
        }

        _hwndSource?.Dispose();
        _hwndSource = null;
    }

    private void OnLocalizationChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (_added)
        {
            AddOrUpdateIcon(NimModify);
        }
    }

    private void AddOrUpdateIcon(uint action)
    {
        if (_hwndSource is not { Handle: var hwnd } || hwnd == IntPtr.Zero)
        {
            return;
        }

        var data = CreateNotifyIconData(hwnd);
        if (Shell_NotifyIconW(action, ref data))
        {
            _added = true;
        }
        else
        {
            _logger.LogDebug("Shell_NotifyIconW({Action}) returned false.", action);
        }
    }

    private NotifyIconData CreateNotifyIconData(IntPtr hwnd) => new()
    {
        cbSize = (uint)Marshal.SizeOf<NotifyIconData>(),
        hWnd = hwnd,
        uID = 1,
        uFlags = NifMessage | NifIcon | NifTip,
        uCallbackMessage = WmAppTray,
        hIcon = _iconHandle,
        szTip = $"{LocalizationManager.Instance["App_Name"]} — {LocalizationManager.Instance["App_Tagline"]}",
    };

    private static IntPtr LoadAppIcon()
    {
        var module = GetModuleHandleW(null);
        if (module != IntPtr.Zero)
        {
            // ApplicationIcon embedded by MSBuild is placed at resource ID 32512 (IDI_APPLICATION).
            var hIcon = LoadImageW(module, new IntPtr(IdiApplication), ImageIcon, 0, 0, LrShared);
            if (hIcon != IntPtr.Zero)
            {
                return hIcon;
            }
        }

        return LoadIconW(IntPtr.Zero, new IntPtr(IdiApplication));
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == _taskbarCreatedMsg && _taskbarCreatedMsg != 0)
        {
            _added = false;
            AddOrUpdateIcon(NimAdd);
        }
        else if (msg == WmAppTray)
        {
            var eventId = unchecked((int)lParam.ToInt64()) & 0xFFFF;
            switch (eventId)
            {
                case WmLButtonUp:
                case WmLButtonDblClk:
                case NinSelect:
                    OpenRequested?.Invoke(this, EventArgs.Empty);
                    handled = true;
                    break;
                case WmRButtonUp:
                case WmContextMenu:
                    ShowContextMenu(hwnd);
                    handled = true;
                    break;
            }
        }

        return IntPtr.Zero;
    }

    private void ShowContextMenu(IntPtr hwnd)
    {
        _ = _serviceClient.RefreshStatusAsync();
        _contextMenu = BuildContextMenu(hwnd);
        SetForegroundWindow(hwnd);
        _contextMenu.Placement = PlacementMode.MousePoint;
        _contextMenu.IsOpen = true;
    }

    internal ContextMenu BuildContextMenu(IntPtr hwnd = default)
    {
        var loc = LocalizationManager.Instance;
        var status = _serviceClient.LastStatus;
        var localStats = _localEngine?.GetStats();
        var engineEnabled = status?.IsEngineEnabled == true
            || localStats?.State is DnsEngineState.Running or DnsEngineState.Degraded;
        var gamingEnabled = status?.IsGamingModeEnabled == true;
        var resolverText = status?.ActiveResolverName ?? localStats?.ActiveResolverName ?? loc["Common_NotAvailable"];

        var menu = new ContextMenu();

        var openItem = CreateItem("\uE8A7", loc["Tray_Open"], () => OpenRequested?.Invoke(this, EventArgs.Empty));
        openItem.FontWeight = FontWeights.SemiBold;
        menu.Items.Add(openItem);
        menu.Items.Add(new Separator());

        var dnsLabel = engineEnabled ? loc["Tray_DisableDns"] : loc["Tray_EnableDns"];
        var dnsItem = CreateItem("\uEA18", dnsLabel, async () =>
        {
            if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
            {
                await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, !engineEnabled)).ConfigureAwait(false);
            }
            else if (_localEngine is not null)
            {
                if (engineEnabled)
                {
                    await _localEngine.StopAsync().ConfigureAwait(false);
                }
                else
                {
                    await _localEngine.StartAsync().ConfigureAwait(false);
                }
            }
        });
        menu.Items.Add(dnsItem);

        var gamingLabel = gamingEnabled ? loc["Tray_DisableGaming"] : loc["Tray_EnableGaming"];
        var gamingItem = CreateItem("\uE7FC", gamingLabel, async () =>
        {
            await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.SetGamingMode, !gamingEnabled)).ConfigureAwait(false);
        });
        menu.Items.Add(gamingItem);

        var resolverItem = CreateItem("\uE8F1", loc.Format("Tray_ActiveResolver", resolverText), () =>
        {
            OpenRequested?.Invoke(this, EventArgs.Empty);
            _navigation.Navigate(PageKeys.DnsManager);
        });
        menu.Items.Add(resolverItem);

        var restoreItem = CreateItem("\uE777", loc["Tray_RestoreDns"], async () =>
        {
            if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
            {
                await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.RestoreOriginalDns)).ConfigureAwait(false);
            }
            else if (_windowsDns is not null)
            {
                await _windowsDns.RestoreOriginalDnsAsync().ConfigureAwait(false);
            }
        });
        menu.Items.Add(restoreItem);

        menu.Items.Add(new Separator());

        var exitItem = CreateItem("\uE8BB", loc["Tray_Exit"], () => ExitRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add(exitItem);

        if (hwnd != IntPtr.Zero)
        {
            menu.Closed += (_, _) => PostMessageW(hwnd, WmNull, IntPtr.Zero, IntPtr.Zero);
        }

        return menu;
    }

    private static MenuItem CreateItem(string glyph, string header, Action onClick)
    {
        var icon = new TextBlock { Text = glyph, FontSize = 13 };
        icon.SetResourceReference(FrameworkElement.StyleProperty, "Text.Icon");
        var item = new MenuItem { Header = header, Icon = icon };
        item.Click += (_, _) => onClick();
        return item;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIconW(uint dwMessage, ref NotifyIconData lpData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint RegisterWindowMessageW(string lpString);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr GetModuleHandleW(string? lpModuleName);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr LoadImageW(IntPtr hInst, IntPtr name, uint type, int cx, int cy, uint fuLoad);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr LoadIconW(IntPtr hInstance, IntPtr lpIconName);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}
