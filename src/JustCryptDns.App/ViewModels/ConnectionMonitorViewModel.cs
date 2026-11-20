using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed partial class ConnectionMonitorViewModel : PageViewModel
{
    private const int MaxTrackedRows = 2000;

    private readonly IConnectionMonitorService _monitor;
    private readonly IDnsReverseLookupCache _reverseCache;
    private readonly IIpEnrichmentService _enrichment;
    private readonly IFirewallBlocklistCoordinator _firewall;
    private readonly INetworkInfoService _networkInfo;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly IDnsEngine _dnsEngine;
    private readonly ISettingsService _settings;
    private readonly IProcessTrustInspector _trustInspector;
    private readonly IThreatIntelligenceService _threatIntel;
    private readonly ILogger<ConnectionMonitorViewModel> _logger;
    private readonly DispatcherTimer _pollTimer;
    private readonly Dictionary<string, ConnectionRowViewModel> _rowsByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _knownExternalProcesses = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _alertedThreats = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(BlockedIpRule Rule, CidrNetwork Network)> _compiledRules = [];
    private readonly HashSet<string> _blockedAppPaths = new(StringComparer.OrdinalIgnoreCase);

    private ProtectedIpContext? _cachedProtectedContext;
    private DateTimeOffset _protectedContextBuiltAt = DateTimeOffset.MinValue;
    private bool _isNavigatedActive;
    private bool _isWindowVisible = true;
    private bool _pollInFlight;
    private bool _baselineCaptured;
    private bool _pendingFilterRefresh;
    private bool _suppressPreferencePersist;
    private int _pollCycle;
    private bool _disposed;

    [ObservableProperty]
    private ConnectionRowViewModel? _selectedConnection;

    [ObservableProperty]
    private bool _enableOnlineLookup;

    [ObservableProperty]
    private bool _alertNewUnknownProcess;

    [ObservableProperty]
    private bool _hideLanConnections = true;

    [ObservableProperty]
    private bool _autoScroll = true;

    [ObservableProperty]
    private bool _enableDnsLeakGuard;

    [ObservableProperty]
    private bool _enableThreatIntelligence = true;

    [ObservableProperty]
    private bool _autoBlockDetectedThreats;

    [ObservableProperty]
    private bool _verifyProcessSignatures = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LockdownButtonLabel))]
    private bool _isLockdownActive;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private int _activeCount;

    [ObservableProperty]
    private int _totalCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlockedListButtonLabel))]
    private int _blockedRuleCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(BlockedAppsButtonLabel))]
    private int _blockedAppCount;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SyncButtonLabel))]
    private int _unsyncedCount;

    [ObservableProperty]
    private bool _isWindowsFirewallEnabled = true;

    [ObservableProperty]
    private bool _requiresElevationHint;

    [ObservableProperty]
    private string? _statusBannerText;

    [ObservableProperty]
    private bool _statusBannerIsError;

    [ObservableProperty]
    private string? _newProcessAlertText;

    [ObservableProperty]
    private string? _threatAlertText;

    [ObservableProperty]
    private int _threatIndicatorCount;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private bool _isBlockCidrModalOpen;

    [ObservableProperty]
    private bool _isUnblockWebsiteModalOpen;

    [ObservableProperty]
    private bool _isBlockedListModalOpen;

    [ObservableProperty]
    private bool _isBlockedAppsModalOpen;

    [ObservableProperty]
    private bool _isNotesModalOpen;

    [ObservableProperty]
    private string _customCidrInput = string.Empty;

    [ObservableProperty]
    private string _customCidrNote = string.Empty;

    [ObservableProperty]
    private string? _cidrValidationError;

    [ObservableProperty]
    private string? _pendingRiskWarning;

    [ObservableProperty]
    private bool _isRiskConfirmed;

    [ObservableProperty]
    private string _unblockDomainInput = string.Empty;

    [ObservableProperty]
    private string? _unblockWebsiteStatus;

    [ObservableProperty]
    private string _noteEditorIp = string.Empty;

    [ObservableProperty]
    private string _noteEditorText = string.Empty;

    public ConnectionMonitorViewModel(
        IConnectionMonitorService monitor,
        IDnsReverseLookupCache reverseCache,
        IIpEnrichmentService enrichment,
        IFirewallBlocklistCoordinator firewall,
        INetworkInfoService networkInfo,
        IResolverLibraryService resolverLibrary,
        IDnsEngine dnsEngine,
        ISettingsService settings,
        IProcessTrustInspector trustInspector,
        IThreatIntelligenceService threatIntel,
        ILogger<ConnectionMonitorViewModel> logger)
        : base("Nav_Connections", "Page_Connections_Subtitle")
    {
        _monitor = monitor;
        _reverseCache = reverseCache;
        _enrichment = enrichment;
        _firewall = firewall;
        _networkInfo = networkInfo;
        _resolverLibrary = resolverLibrary;
        _dnsEngine = dnsEngine;
        _settings = settings;
        _trustInspector = trustInspector;
        _threatIntel = threatIntel;
        _logger = logger;

        ConnectionsView = CollectionViewSource.GetDefaultView(Connections);
        ConnectionsView.Filter = FilterConnection;

        LoadPreferencesFromSettings();
        RebuildCompiledRules();
        UpdateThreatFeedSummary();

        _pollTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(_settings.Current.Connections.PollIntervalMs),
        };
        _pollTimer.Tick += OnPollTimerTick;

        _enrichment.EnrichmentReady += OnEnrichmentReady;
        LocalizationManager.Instance.PropertyChanged += OnLocalizationChanged;
    }

    public event EventHandler<ConnectionRowViewModel>? AutoScrollRequested;

    public event EventHandler<ConnectionRowViewModel>? EditNoteRequested;

    public ObservableCollection<ConnectionRowViewModel> Connections { get; } = [];

    public ICollectionView ConnectionsView { get; }

    public ObservableCollection<BlockedRuleItemViewModel> ManagedBlockedRules { get; } = [];

    public ObservableCollection<BlockedAppItemViewModel> ManagedBlockedApps { get; } = [];

    public ObservableCollection<IpNoteItemViewModel> ManagedNotes { get; } = [];

    public bool IsEditingCell { get; set; }

    public bool IsAnyModalOpen =>
        IsBlockCidrModalOpen || IsUnblockWebsiteModalOpen || IsBlockedListModalOpen || IsBlockedAppsModalOpen || IsNotesModalOpen;

    public string BlockedListButtonLabel =>
        LocalizationManager.Instance.Format("Conn_Btn_BlockedList", BlockedRuleCount);

    public string BlockedAppsButtonLabel =>
        LocalizationManager.Instance.Format("Conn_Btn_BlockedApps", BlockedAppCount);

    public string SyncButtonLabel => UnsyncedCount > 0
        ? LocalizationManager.Instance.Format("Conn_Btn_SyncBlocklistCount", UnsyncedCount)
        : LocalizationManager.Instance.Get("Conn_Btn_SyncBlocklist");

    public string LockdownButtonLabel => IsLockdownActive
        ? LocalizationManager.Instance.Get("Conn_Btn_UnlockNetwork")
        : LocalizationManager.Instance.Get("Conn_Btn_Lockdown");

    public string ThreatFeedSummaryText => ThreatIndicatorCount > 0
        ? LocalizationManager.Instance.Format("Conn_ThreatSummary_Count", ThreatIndicatorCount)
        : LocalizationManager.Instance.Get("Conn_ThreatSummary_None");

    public override void OnNavigatedTo()
    {
        _isNavigatedActive = true;
        UpdateTimerAndEnrichmentState();
        _ = RefreshFirewallStatusAsync();
        _ = PollOnceAsync();
    }

    public override void OnNavigatedFrom()
    {
        _isNavigatedActive = false;
        UpdateTimerAndEnrichmentState();
    }

    public void SetWindowActive(bool isActive)
    {
        if (_isWindowVisible == isActive)
        {
            return;
        }

        _isWindowVisible = isActive;
        UpdateTimerAndEnrichmentState();
        if (isActive && _isNavigatedActive && !_disposed)
        {
            _ = PollOnceAsync();
        }
    }

    public void CommitInlineNote(ConnectionRowViewModel row)
    {
        ArgumentNullException.ThrowIfNull(row);
        PersistNoteForKey(GetNoteStorageKey(row), row.Note);
    }

    public void NotifyEditingEnded()
    {
        IsEditingCell = false;
        if (_pendingFilterRefresh)
        {
            _pendingFilterRefresh = false;
            RefreshFilterSafe();
        }
    }

    private void UpdateTimerAndEnrichmentState()
    {
        var shouldRun = _isNavigatedActive && _isWindowVisible && !_disposed;
        if (shouldRun)
        {
            if (EnableOnlineLookup)
            {
                _enrichment.Resume();
            }
            else
            {
                _enrichment.Pause();
            }

            if (!_pollTimer.IsEnabled)
            {
                _pollTimer.Start();
            }
        }
        else
        {
            if (_pollTimer.IsEnabled)
            {
                _pollTimer.Stop();
            }

            _enrichment.Pause();
        }
    }

    private void LoadPreferencesFromSettings()
    {
        var conn = _settings.Current.Connections;
        _suppressPreferencePersist = true;
        try
        {
            EnableOnlineLookup = conn.EnableOnlineLookup;
            AlertNewUnknownProcess = conn.AlertNewUnknownProcess;
            HideLanConnections = conn.HideLanConnections;
            AutoScroll = conn.AutoScroll;
            EnableDnsLeakGuard = conn.EnableDnsLeakGuard;
            EnableThreatIntelligence = conn.EnableThreatIntelligence;
            AutoBlockDetectedThreats = conn.AutoBlockDetectedThreats;
            VerifyProcessSignatures = conn.VerifyProcessSignatures;
        }
        finally
        {
            _suppressPreferencePersist = false;
        }

        BlockedRuleCount = conn.BlockedRules.Count(r => r.IsEnabled);
        BlockedAppCount = conn.BlockedApps.Count(a => a.IsEnabled);
        UnsyncedCount = conn.HasUnsyncedFirewallChanges ? Math.Max(1, BlockedRuleCount + BlockedAppCount) : 0;
        RefreshManagedCollections();
    }

    partial void OnEnableOnlineLookupChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.EnableOnlineLookup = value);
        if (value && _isNavigatedActive && _isWindowVisible)
        {
            _enrichment.Resume();
            foreach (var row in Connections.Where(r => !r.IsLan && r.RemoteIp != "*" && !_enrichment.TryGetCached(r.RemoteIp, out _)).Take(25))
            {
                _enrichment.EnqueueLookup(row.RemoteIp);
            }
        }
        else
        {
            _enrichment.Pause();
        }
    }

    partial void OnAlertNewUnknownProcessChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.AlertNewUnknownProcess = value);
        if (!value)
        {
            NewProcessAlertText = null;
        }
    }

    partial void OnHideLanConnectionsChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.HideLanConnections = value);
        RefreshFilterSafe();
    }

    partial void OnAutoScrollChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.AutoScroll = value);
    }

    partial void OnEnableDnsLeakGuardChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.EnableDnsLeakGuard = value);
        _ = ApplySecurityShieldToggleAsync(isLeakToggle: true, desiredState: value);
    }

    partial void OnEnableThreatIntelligenceChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.EnableThreatIntelligence = value);
        if (!value)
        {
            ThreatAlertText = null;
            foreach (var row in Connections)
            {
                row.IsThreatMatch = false;
                row.ThreatLabel = null;
            }
        }
    }

    partial void OnAutoBlockDetectedThreatsChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.AutoBlockDetectedThreats = value);
    }

    partial void OnVerifyProcessSignaturesChanged(bool value)
    {
        if (_suppressPreferencePersist)
        {
            return;
        }

        _settings.UpdateDeferred(s => s.Connections.VerifyProcessSignatures = value);
    }

    partial void OnSearchQueryChanged(string value) => RefreshFilterSafe();

    partial void OnCustomCidrInputChanged(string value)
    {
        CidrValidationError = null;
        PendingRiskWarning = null;
        IsRiskConfirmed = false;
    }

    private void NotifyModalFlagsChanged() => OnPropertyChanged(nameof(IsAnyModalOpen));

    private void OnLocalizationChanged(object? sender, PropertyChangedEventArgs e)
    {
        _ = RunOnUiAsync(() =>
        {
            if (_disposed)
            {
                return;
            }

            OnPropertyChanged(nameof(BlockedListButtonLabel));
            OnPropertyChanged(nameof(BlockedAppsButtonLabel));
            OnPropertyChanged(nameof(SyncButtonLabel));
            OnPropertyChanged(nameof(LockdownButtonLabel));
            OnPropertyChanged(nameof(ThreatFeedSummaryText));
            foreach (var row in Connections)
            {
                row.NotifyLocalizationChanged();
            }
        });
    }

    private void OpenExternalUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not launch browser URL {Url}.", url);
        }
    }

    private void SetBanner(string message, bool isError)
    {
        StatusBannerIsError = isError;
        StatusBannerText = message;
    }

    private static string BuildRowKey(RawSocketConnection raw) =>
        $"{raw.Protocol}|{raw.ProcessId}|{raw.RemoteIp}|{raw.RemotePort}";

    private static string GetNoteStorageKey(ConnectionRowViewModel row) =>
        row.RemoteIp == "*" ? $"{row.ProcessName}:{row.RemotePort}" : row.RemoteIp;

    private static string CsvEscape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        return $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
    }

    private static Task RunOnUiAsync(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is not { HasShutdownStarted: false, HasShutdownFinished: false } || dispatcher.CheckAccess())
        {
            action();
            return Task.CompletedTask;
        }

        return dispatcher.InvokeAsync(action).Task;
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _disposed = true;
            _isNavigatedActive = false;
            _pollTimer.Stop();
            _pollTimer.Tick -= OnPollTimerTick;
            _enrichment.EnrichmentReady -= OnEnrichmentReady;
            _enrichment.Pause();
            LocalizationManager.Instance.PropertyChanged -= OnLocalizationChanged;
        }

        base.Dispose(disposing);
    }
}
