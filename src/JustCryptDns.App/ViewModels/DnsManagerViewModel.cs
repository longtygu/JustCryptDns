using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DnsCrypt;

namespace JustCryptDns.App.ViewModels;

public sealed partial class DnsManagerViewModel : PageViewModel
{
    private readonly IDnsEngine _dnsEngine;
    private readonly IDnsCryptProxyManager _dnsCrypt;
    private readonly IWindowsDnsManager _windowsDns;
    private readonly ISettingsService _settings;
    private readonly SynchronizationContext? _ui;
    private bool _loading;

    [ObservableProperty] private DnsEngineState _engineState = DnsEngineState.Stopped;
    [ObservableProperty] private DnsResolverEndpoint _selectedResolver;
    [ObservableProperty] private string _listenAddress = DnsSettings.DefaultListenAddress;
    [ObservableProperty] private string _listenPortText = "53";
    [ObservableProperty] private bool _enableIpv6;
    [ObservableProperty] private bool _configureWindowsAdapter;
    [ObservableProperty] private string _listenEndpoint = "127.0.0.1:53";
    [ObservableProperty] private long _totalQueries;
    [ObservableProperty] private long _successfulQueries;
    [ObservableProperty] private long _failedQueries;
    [ObservableProperty] private string _lastLatencyText = "—";
    [ObservableProperty] private string? _errorMessage;
    [ObservableProperty] private string? _infoMessage;
    [ObservableProperty] private PortConflictInfo? _portConflict;
    [ObservableProperty] private bool _hasAdapterBackup;
    [ObservableProperty] private bool _isDnsCryptInstalled;
    [ObservableProperty] private string _dnsCryptVersion = "—";
    [ObservableProperty] private bool _isBusy;

    public DnsManagerViewModel(
        IDnsEngine dnsEngine,
        IDnsCryptProxyManager dnsCrypt,
        IWindowsDnsManager windowsDns,
        ISettingsService settings)
        : base("Nav_DnsManager", "Page_DnsManager_Subtitle")
    {
        _dnsEngine = dnsEngine;
        _dnsCrypt = dnsCrypt;
        _windowsDns = windowsDns;
        _settings = settings;
        _ui = SynchronizationContext.Current;

        var dns = settings.Current.Dns;
        _loading = true;
        _selectedResolver = BuiltInResolvers.GetByIdOrDefault(dns.ActiveResolverId);
        _listenAddress = dns.ListenAddress;
        _listenPortText = dns.ListenPort.ToString(CultureInfo.InvariantCulture);
        _enableIpv6 = dns.EnableIpv6;
        _configureWindowsAdapter = dns.ConfigureWindowsAdapter;
        _loading = false;

        DnsCryptPath = dnsCrypt.ExecutablePath;
        ApplyStats(dnsEngine.GetStats());
    }

    public IReadOnlyList<DnsResolverEndpoint> Resolvers => BuiltInResolvers.All;

    public string DnsCryptPath { get; }

    public bool IsEngineRunning => EngineState is DnsEngineState.Running or DnsEngineState.Degraded;

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
        await ToggleEngineAsync();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task EmergencyRestoreDnsAsync()
    {
        IsBusy = true;
        try
        {
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
    private async Task InstallOrUpdateDnsCryptAsync()
    {
        IsBusy = true;
        InfoMessage = null;
        try
        {
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
        ListenEndpoint = stats.ListenEndpoint;
        TotalQueries = stats.TotalQueries;
        SuccessfulQueries = stats.SuccessfulQueries;
        FailedQueries = stats.FailedQueries;
        LastLatencyText = stats.LastLatencyMs is { } ms ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms") : "—";
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
