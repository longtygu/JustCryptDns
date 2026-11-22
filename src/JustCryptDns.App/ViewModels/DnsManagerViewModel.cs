using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;

namespace JustCryptDns.App.ViewModels;

public sealed partial class DnsManagerViewModel : PageViewModel
{
    private readonly IDnsEngine _dnsEngine;
    private readonly IDnsCryptProxyManager _dnsCrypt;
    private readonly IWindowsDnsManager _windowsDns;
    private readonly ISettingsService _settings;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly IServiceClient? _serviceClient;
    private readonly SynchronizationContext? _ui;
    private bool _loading;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUnencryptedDnsActive))]
    private DnsEngineState _engineState = DnsEngineState.Stopped;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUnencryptedDnsActive))]
    private DnsProtocol _activeProtocol = DnsProtocol.DnsOverHttps;

    [ObservableProperty] private DnsResolverEndpoint _selectedResolver;
    [ObservableProperty] private string _listenAddress = DnsSettings.DefaultListenAddress;
    [ObservableProperty] private string _listenPortText = "53";
    [ObservableProperty] private bool _enableIpv6;
    [ObservableProperty] private bool _configureWindowsAdapter;
    [ObservableProperty] private bool _autoAdaptNetworkChanges = true;
    [ObservableProperty] private bool _autoDeferToVpn = true;
    [ObservableProperty] private bool _blockFirefoxDohCanary = true;
    [ObservableProperty] private bool _canPauseCaptivePortal;
    [ObservableProperty] private bool _isCaptivePortalPaused;
    [ObservableProperty] private bool _enableAutoFailover = true;
    [ObservableProperty] private FailoverPolicy _selectedFailoverPolicy = FailoverPolicy.EncryptedOnly;
    [ObservableProperty] private string _listenEndpoint = "127.0.0.1:53";
    [ObservableProperty] private long _totalQueries;
    [ObservableProperty] private long _successfulQueries;
    [ObservableProperty] private long _failedQueries;
    [ObservableProperty] private string _lastLatencyText = "—";
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string? _infoMessage;
    [ObservableProperty] private string? _trafficWarningBanner;
    [ObservableProperty] private bool _isNonStandardPort;
    [ObservableProperty] private string? _suggestedLoopbackIp;
    [ObservableProperty] private string? _conflictingServiceName;
    [ObservableProperty] private PortConflictInfo? _portConflict;
    [ObservableProperty] private bool _hasAdapterBackup;
    [ObservableProperty] private bool _isDnsCryptInstalled;
    [ObservableProperty] private string _dnsCryptVersion = "—";
    [ObservableProperty] private bool _isBusy;

    public DnsManagerViewModel(
        IDnsEngine dnsEngine,
        IDnsCryptProxyManager dnsCrypt,
        IWindowsDnsManager windowsDns,
        ISettingsService settings,
        IResolverLibraryService? resolverLibrary = null,
        IServiceClient? serviceClient = null)
        : base("Nav_DnsManager", "Page_DnsManager_Subtitle")
    {
        _dnsEngine = dnsEngine;
        _dnsCrypt = dnsCrypt;
        _windowsDns = windowsDns;
        _settings = settings;
        _resolverLibrary = resolverLibrary;
        _serviceClient = serviceClient;
        _ui = SynchronizationContext.Current;

        var dns = settings.Current.Dns;
        _loading = true;
        _selectedResolver = _resolverLibrary is not null
            ? _resolverLibrary.GetByIdOrDefault(dns.ActiveResolverId)
            : BuiltInResolvers.GetByIdOrDefault(dns.ActiveResolverId);
        _listenAddress = dns.ListenAddress;
        _listenPortText = dns.ListenPort.ToString(CultureInfo.InvariantCulture);
        _enableIpv6 = dns.EnableIpv6;
        _configureWindowsAdapter = dns.ConfigureWindowsAdapter;
        _autoAdaptNetworkChanges = dns.AutoAdaptNetworkChanges;
        _autoDeferToVpn = dns.AutoDeferToVpn;
        _blockFirefoxDohCanary = dns.BlockFirefoxDohCanary;
        _enableAutoFailover = settings.Current.Resilience.EnableAutoFailover;
        _selectedFailoverPolicy = settings.Current.Resilience.Policy;
        _loading = false;

        DnsCryptPath = dnsCrypt.ExecutablePath;
        ApplyStats(dnsEngine.GetStats());
    }

    public IReadOnlyList<DnsResolverEndpoint> Resolvers =>
        _resolverLibrary is not null ? _resolverLibrary.GetEnabled() : BuiltInResolvers.All;

    public IReadOnlyList<FailoverPolicy> FailoverPolicies { get; } = Enum.GetValues<FailoverPolicy>();

    public string DnsCryptPath { get; }

    public bool IsEngineRunning => EngineState is DnsEngineState.Running or DnsEngineState.Degraded;

    public bool IsUnencryptedDnsActive => IsEngineRunning && ActiveProtocol == DnsProtocol.UdpTcp;

    public override void OnNavigatedTo()
    {
        _dnsEngine.StateChanged += OnEngineStateChanged;
        ApplyStats(_dnsEngine.GetStats());
        _ = RefreshDnsCryptVersionAsync();
    }

    public override void OnNavigatedFrom()
    {
        _dnsEngine.StateChanged -= OnEngineStateChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _dnsEngine.StateChanged -= OnEngineStateChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnEngineStateChanged(DnsEngineState value) => OnPropertyChanged(nameof(IsEngineRunning));

    partial void OnSelectedResolverChanged(DnsResolverEndpoint value)
    {
        if (_loading || value is null)
        {
            return;
        }

        _ = SwitchResolverInternalAsync(value.Id);
    }

    partial void OnConfigureWindowsAdapterChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Dns.ConfigureWindowsAdapter = value);
        }
    }

    partial void OnEnableAutoFailoverChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Resilience.EnableAutoFailover = value);
        }
    }

    partial void OnSelectedFailoverPolicyChanged(FailoverPolicy value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Resilience.Policy = value);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleEngineAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            if (IsEngineRunning)
            {
                await _dnsEngine.StopAsync();
            }
            else
            {
                var (ok, err) = await _dnsEngine.StartAsync();
                if (!ok)
                {
                    ErrorMessage = err;
                }
                else
                {
                    _ = _dnsEngine.ProbeActiveResolverAsync();
                }
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RestartEngineAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            var (ok, err) = await _dnsEngine.RestartAsync();
            if (!ok)
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task TestLocalProxyAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            var (ok, _, summary) = await _dnsEngine.TestLocalProxyAsync();
            if (ok)
            {
                ErrorMessage = null;
                InfoMessage = summary;
            }
            else
            {
                ErrorMessage = summary;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SwitchToPort53Async()
    {
        ListenPortText = "53";
        await ApplyProxySettingsAsync();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task SwitchToEncryptedDnsAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        ErrorMessage = null;
        try
        {
            var (ok, err) = await _dnsEngine.SwitchResolverAsync(BuiltInResolvers.DefaultResolverId);
            if (ok)
            {
                _loading = true;
                SelectedResolver = _resolverLibrary is not null
                    ? _resolverLibrary.GetByIdOrDefault(BuiltInResolvers.DefaultResolverId)
                    : BuiltInResolvers.GetByIdOrDefault(BuiltInResolvers.DefaultResolverId);
                _loading = false;
                InfoMessage = LocalizationManager.Instance["DnsWarn_SwitchedToEncrypted"];
                _ = _dnsEngine.ProbeActiveResolverAsync();
            }
            else
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task UseAlternateLoopbackPort53Async()
    {
        var targetIp = SuggestedLoopbackIp ?? PortConflict?.SuggestedLoopbackIp;
        if (string.IsNullOrWhiteSpace(targetIp))
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        InfoMessage = null;
        try
        {
            await _settings.UpdateAsync(s =>
            {
                s.Dns.ListenAddress = targetIp;
                s.Dns.ListenPort = 53;
                s.Dns.EnableIpv6 = false;
                s.Dns.ConfigureWindowsAdapter = true;
            });

            _loading = true;
            ListenAddress = targetIp;
            ListenPortText = "53";
            EnableIpv6 = false;
            ConfigureWindowsAdapter = true;
            _loading = false;

            var (ok, err) = await _dnsEngine.RestartAsync();
            if (ok)
            {
                _ = _dnsEngine.ProbeActiveResolverAsync();
                InfoMessage = LocalizationManager.Instance.Format("TrafficFix_AlternateLoopbackSuccess", targetIp);
            }
            else
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task StopConflictingServiceAndUsePort53Async()
    {
        var svcName = ConflictingServiceName ?? PortConflict?.ConflictingServiceName;
        if (string.IsNullOrWhiteSpace(svcName))
        {
            return;
        }

        IsBusy = true;
        ErrorMessage = null;
        InfoMessage = null;
        try
        {
            var (stopped, stopErr) = await PortConflictDetector.StopConflictingServiceAsync(svcName);
            if (!stopped)
            {
                ErrorMessage = stopErr;
                return;
            }

            await _settings.UpdateAsync(s =>
            {
                s.Dns.ListenAddress = DnsSettings.DefaultListenAddress;
                s.Dns.ListenPort = 53;
                s.Dns.ConfigureWindowsAdapter = true;
            });

            _loading = true;
            ListenAddress = DnsSettings.DefaultListenAddress;
            ListenPortText = "53";
            _loading = false;

            var (ok, err) = await _dnsEngine.RestartAsync();
            if (ok)
            {
                _ = _dnsEngine.ProbeActiveResolverAsync();
                InfoMessage = LocalizationManager.Instance.Format("TrafficFix_ServiceStoppedSuccess", svcName);
            }
            else
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ProbeResolverAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            var result = await _dnsEngine.ProbeActiveResolverAsync();
            if (result.Success)
            {
                ErrorMessage = null;
                InfoMessage = LocalizationManager.Instance.Format("DnsMgr_ProbeSuccess", SelectedResolver.Name, Math.Round(result.LatencyMs, 1));
            }
            else
            {
                ErrorMessage = result.Error;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ApplyProxySettingsAsync()
    {
        if (!int.TryParse(ListenPortText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            ErrorMessage = LocalizationManager.Instance["DnsMgr_InvalidPort"];
            return;
        }

        await _settings.UpdateAsync(s =>
        {
            s.Dns.ListenAddress = ListenAddress.Trim();
            s.Dns.ListenPort = port;
            s.Dns.EnableIpv6 = EnableIpv6;
        });

        _loading = true;
        ListenAddress = _settings.Current.Dns.ListenAddress;
        ListenPortText = _settings.Current.Dns.ListenPort.ToString(CultureInfo.InvariantCulture);
        _loading = false;

        if (IsEngineRunning)
        {
            await RestartEngineAsync();
        }
        else
        {
            ErrorMessage = null;
            PortConflict = null;
            ApplyStats(_dnsEngine.GetStats());
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task UseSuggestedPortAsync()
    {
        if (PortConflict is not { SuggestedPort: > 0 } conflict)
        {
            return;
        }

        ListenPortText = conflict.SuggestedPort.ToString(CultureInfo.InvariantCulture);
        await ApplyProxySettingsAsync();
        if (!IsEngineRunning)
        {
            await ToggleEngineAsync();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task EmergencyRestoreDnsAsync()
    {
        IsBusy = true;
        try
        {
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                var ipcRes = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.RestoreOriginalDns));
                if (ipcRes is { Success: true })
                {
                    ErrorMessage = null;
                    InfoMessage = LocalizationManager.Instance["DnsMgr_RestoreSuccess"];
                    return;
                }
            }

            var result = await _windowsDns.RestoreOriginalDnsAsync(_settings.Current.Dns.TargetAdapterId);
            if (result.Success)
            {
                ErrorMessage = null;
                InfoMessage = LocalizationManager.Instance["DnsMgr_RestoreSuccess"];
            }
            else
            {
                ErrorMessage = result.ErrorMessage;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task PauseForCaptivePortalAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            var (ok, err) = await _dnsEngine.PauseForCaptivePortalAsync(TimeSpan.FromMinutes(5));
            if (ok)
            {
                ErrorMessage = null;
                InfoMessage = LocalizationManager.Instance["TrafficWarn_CaptivePortal"];
            }
            else
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ResumeFromCaptivePortalAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            var (ok, err) = await _dnsEngine.ResumeFromCaptivePortalAsync();
            if (ok)
            {
                ErrorMessage = null;
                InfoMessage = LocalizationManager.Instance["Dns_ResumeCaptivePortal"];
            }
            else
            {
                ErrorMessage = err;
            }
        }
        finally
        {
            ApplyStats(_dnsEngine.GetStats());
            IsBusy = false;
        }
    }

    partial void OnAutoAdaptNetworkChangesChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Dns.AutoAdaptNetworkChanges = value);
        }
    }

    partial void OnAutoDeferToVpnChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Dns.AutoDeferToVpn = value);
        }
    }

    partial void OnBlockFirefoxDohCanaryChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings.UpdateAsync(s => s.Dns.BlockFirefoxDohCanary = value);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task InstallOrUpdateDnsCryptAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                var ipcRes = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.InstallOrUpdateDnsCrypt));
                if (ipcRes is not null)
                {
                    if (ipcRes.Success)
                    {
                        ErrorMessage = null;
                        InfoMessage = LocalizationManager.Instance.Format("DnsMgr_DnsCryptInstalled", ipcRes.Message ?? "latest");
                    }
                    else
                    {
                        ErrorMessage = ipcRes.Message;
                    }

                    await RefreshDnsCryptVersionAsync();
                    return;
                }
            }

            var (ok, version, err) = await _dnsCrypt.InstallOrUpdateAsync();
            if (ok)
            {
                ErrorMessage = null;
                InfoMessage = LocalizationManager.Instance.Format("DnsMgr_DnsCryptInstalled", version ?? "latest");
            }
            else
            {
                ErrorMessage = err;
            }

            await RefreshDnsCryptVersionAsync();
        }
        finally
        {
            IsBusy = false;
        }
    }

    internal void ApplyStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveProtocol = stats.ActiveProtocol;
        ListenEndpoint = stats.ListenEndpoint;
        TotalQueries = stats.TotalQueries;
        SuccessfulQueries = stats.SuccessfulQueries;
        FailedQueries = stats.FailedQueries;
        LastLatencyText = stats.LastLatencyMs is { } ms ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms") : "—";
        IsNonStandardPort = stats.TrafficStatus == SystemTrafficStatus.NonStandardPort;
        SuggestedLoopbackIp = stats.SuggestedLoopbackIp ?? stats.PortConflict?.SuggestedLoopbackIp;
        ConflictingServiceName = stats.Port53ServiceName ?? stats.PortConflict?.ConflictingServiceName;
        IsCaptivePortalPaused = stats.IsCaptivePortalPaused;
        CanPauseCaptivePortal = stats.TrafficStatus == SystemTrafficStatus.CaptivePortalDetected && !stats.IsCaptivePortalPaused;
        TrafficWarningBanner = DashboardViewModel.FormatTrafficWarning(stats);
        PortConflict = stats.PortConflict;
        ErrorMessage = stats.PortConflict is null ? stats.LastError : null;
        HasAdapterBackup = stats.HasAdapterBackup;
        IsDnsCryptInstalled = _dnsCrypt.IsInstalled;
        if (stats.DnsCryptVersion is not null)
        {
            DnsCryptVersion = stats.DnsCryptVersion;
        }
    }

    private async Task SwitchResolverInternalAsync(string resolverId)
    {
        var (ok, err) = await _dnsEngine.SwitchResolverAsync(resolverId);
        if (!ok)
        {
            ErrorMessage = err;
        }

        ApplyStats(_dnsEngine.GetStats());
    }

    private async Task RefreshDnsCryptVersionAsync()
    {
        var version = await _dnsCrypt.DetectInstalledVersionAsync();
        IsDnsCryptInstalled = _dnsCrypt.IsInstalled;
        DnsCryptVersion = version ?? LocalizationManager.Instance["Common_NotAvailable"];
    }

    private void OnEngineStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyStats(stats));
        }
        else
        {
            ApplyStats(stats);
        }
    }
}
