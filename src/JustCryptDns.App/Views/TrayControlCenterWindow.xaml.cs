using System.Windows;
using System.Windows.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;

namespace JustCryptDns.App.Views;

public partial class TrayControlCenterWindow : Window
{
    private readonly IServiceClient? _serviceClient;
    private readonly IDnsEngine? _localEngine;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly IGamingEngineService? _gamingEngine;
    private readonly ISettingsService? _settings;
    private readonly IFirewallBlocklistCoordinator? _firewall;
    private readonly IDnsCacheService? _cache;
    private readonly Action? _openRequested;
    private readonly Action? _exitRequested;
    private bool _isCaptivePaused;

    public TrayControlCenterWindow()
        : this(null, null, null, null, null, null, null, null, null)
    {
    }

    public TrayControlCenterWindow(
        IServiceClient? serviceClient,
        IDnsEngine? localEngine,
        IBypassEngineService? bypassEngine,
        IGamingEngineService? gamingEngine,
        ISettingsService? settings,
        IFirewallBlocklistCoordinator? firewall,
        IDnsCacheService? cache,
        Action? openRequested,
        Action? exitRequested)
    {
        _serviceClient = serviceClient;
        _localEngine = localEngine;
        _bypassEngine = bypassEngine;
        _gamingEngine = gamingEngine;
        _settings = settings;
        _firewall = firewall;
        _cache = cache;
        _openRequested = openRequested;
        _exitRequested = exitRequested;

        InitializeComponent();

        // Auxiliary flyout windows must never claim Application.MainWindow while MainWindow creation is deferred.
        if (Application.Current is { } app && app.CheckAccess() && ReferenceEquals(app.MainWindow, this))
        {
            app.MainWindow = null;
        }

        Deactivated += (_, _) => SafeHide();
        PreviewKeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape)
            {
                e.Handled = true;
                SafeHide();
            }
        };
        SizeChanged += (_, _) => PositionNearTray();
        IsVisibleChanged += OnWindowVisibilityChanged;
        Closed += (_, _) => DetachServiceEvents();
    }

    private void OnWindowVisibilityChanged(object? sender, DependencyPropertyChangedEventArgs e)
    {
        if (IsVisible)
        {
            if (_serviceClient is not null)
            {
                _serviceClient.StateChanged -= OnServiceClientStateChanged;
                _serviceClient.StateChanged += OnServiceClientStateChanged;
            }
        }
        else
        {
            DetachServiceEvents();
        }
    }

    private void DetachServiceEvents()
    {
        if (_serviceClient is not null)
        {
            _serviceClient.StateChanged -= OnServiceClientStateChanged;
        }
    }

    private void OnServiceClientStateChanged(object? sender, EventArgs e)
    {
        if (!IsVisible)
        {
            return;
        }

        if (Dispatcher.CheckAccess())
        {
            RefreshState();
        }
        else
        {
            Dispatcher.BeginInvoke(RefreshState);
        }
    }

    public void ShowNearTray()
    {
        RefreshState();
        UpdateLayout();
        PositionNearTray();
        Show();
        Activate();
    }

    public void RefreshState()
    {
        var loc = LocalizationManager.Instance;
        var status = _serviceClient?.LastStatus;
        var dnsStats = _localEngine?.GetStats();
        var bypassStats = _bypassEngine?.GetStats();

        var dnsEnabled = status?.IsEngineEnabled == true
            || dnsStats?.State is DnsEngineState.Running or DnsEngineState.Degraded or DnsEngineState.Starting;
        var bypassEnabled = status?.IsBypassRunning == true
            || bypassStats?.State is BypassEngineState.Running or BypassEngineState.Degraded or BypassEngineState.Starting;
        var gamingEnabled = status?.IsGamingModeEnabled == true
            || _gamingEngine?.IsGamingModeEnabled == true;
        _isCaptivePaused = dnsStats?.IsCaptivePortalPaused == true;

        DnsToggle.IsChecked = dnsEnabled;
        DpiToggle.IsChecked = bypassEnabled;
        GameToggle.IsChecked = gamingEnabled;

        var resolverName = status?.ActiveResolverName ?? dnsStats?.ActiveResolverName ?? loc["Common_NotAvailable"];
        var stateText = dnsEnabled ? loc["Strip_On"] : loc["Strip_Off"];
        ResolverSummaryText.Text = $"{stateText} · {resolverName}";

        CaptiveButton.Content = loc[_isCaptivePaused ? "TrayPopup_CaptiveResume" : "TrayPopup_CaptivePause"];

        if (_firewall is not null)
        {
            _ = SyncFirewallToggleAsync();
        }
        else
        {
            LockdownToggle.IsChecked = false;
        }
    }

    private async Task SyncFirewallToggleAsync()
    {
        if (_firewall is null)
        {
            return;
        }

        try
        {
            var fwStatus = await _firewall.GetStatusAsync().ConfigureAwait(false);
            await Dispatcher.InvokeAsync(() => LockdownToggle.IsChecked = fwStatus.IsLockdownActive);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Ignore tray refresh transient errors.
        }
    }

    private void PositionNearTray()
    {
        var area = SystemParameters.WorkArea;
        var height = ActualHeight > 0 ? ActualHeight : 320;
        Left = Math.Max(area.Left, area.Right - Width - 10);
        Top = Math.Max(area.Top, area.Bottom - height - 10);
    }

    private void SafeHide()
    {
        if (IsVisible)
        {
            Hide();
        }
    }

    private void OnOpenDashboardClick(object sender, RoutedEventArgs e)
    {
        SafeHide();
        _openRequested?.Invoke();
    }

    private void OnQuitClick(object sender, RoutedEventArgs e)
    {
        SafeHide();
        _exitRequested?.Invoke();
    }

    private async void OnToggleDnsClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var enable = DnsToggle.IsChecked == true;
            if (_localEngine is not null)
            {
                if (enable)
                {
                    await _localEngine.StartAsync().ConfigureAwait(true);
                }
                else
                {
                    await _localEngine.StopAsync().ConfigureAwait(true);
                }
            }
            else if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.SetEngineEnabled, enable)).ConfigureAwait(true);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        finally
        {
            RefreshState();
        }
    }

    private async void OnToggleDpiClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var enable = DpiToggle.IsChecked == true;
            if (_bypassEngine is not null)
            {
                if (enable)
                {
                    await _bypassEngine.StartAsync().ConfigureAwait(true);
                }
                else
                {
                    await _bypassEngine.StopAsync().ConfigureAwait(true);
                }
            }
            else if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.SetBypassEnabled, enable)).ConfigureAwait(true);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        finally
        {
            RefreshState();
        }
    }

    private async void OnToggleGameClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var enable = GameToggle.IsChecked == true;
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.SetGamingMode, enable)).ConfigureAwait(true);
            }
            else if (_gamingEngine is not null)
            {
                await _gamingEngine.SetGamingModeAsync(enable).ConfigureAwait(true);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        finally
        {
            RefreshState();
        }
    }

    private async void OnToggleLockdownClick(object sender, RoutedEventArgs e)
    {
        if (_firewall is null || _settings is null)
        {
            return;
        }

        var enable = LockdownToggle.IsChecked == true;
        try
        {
            var conn = _settings.Current.Connections;
            var result = await _firewall.SyncSecurityAsync(new FirewallSyncRequestPayload(
                conn.BlockedRules.ToList(),
                conn.BlockedApps.ToList(),
                conn.EnableDnsLeakGuard,
                enable)).ConfigureAwait(true);

            if (!result.Success)
            {
                LockdownToggle.IsChecked = !enable;
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            LockdownToggle.IsChecked = !enable;
        }
    }

    private async void OnCaptiveToggleClick(object sender, RoutedEventArgs e)
    {
        if (_localEngine is null)
        {
            return;
        }

        try
        {
            if (_isCaptivePaused)
            {
                await _localEngine.ResumeFromCaptivePortalAsync().ConfigureAwait(true);
            }
            else
            {
                await _localEngine.PauseForCaptivePortalAsync(TimeSpan.FromMinutes(5)).ConfigureAwait(true);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        finally
        {
            RefreshState();
        }
    }

    private void OnFlushCacheClick(object sender, RoutedEventArgs e)
    {
        _cache?.Clear();
        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearDnsCache));
        }
    }
}
