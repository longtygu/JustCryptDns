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

public sealed partial class ConnectionRowViewModel : ObservableObject
{
    private readonly Action<ConnectionRowViewModel, string>? _noteCommitted;
    private string _note = string.Empty;

    public ConnectionRowViewModel(string key, Action<ConnectionRowViewModel, string>? noteCommitted = null)
    {
        Key = key;
        _noteCommitted = noteCommitted;
    }

    public string Key { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FirstSeenText))]
    private DateTimeOffset _firstSeen;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(LastSeenText))]
    private DateTimeOffset _lastSeen;

    [ObservableProperty]
    private int _processId;

    [ObservableProperty]
    private string _processName = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _executablePath;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProtocolLabel))]
    private ConnectionProtocol _protocol;

    [ObservableProperty]
    private string _remoteIp = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PortText))]
    private int _remotePort;

    [ObservableProperty]
    private int _connectionCount = 1;

    [ObservableProperty]
    private string _domain = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusText))]
    private ConnectionDisplayStatus _status = ConnectionDisplayStatus.Active;

    [ObservableProperty]
    private string _organization = string.Empty;

    [ObservableProperty]
    private bool _isLan;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private ProcessTrustLevel _trustLevel = ProcessTrustLevel.Unknown;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _publisher;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _riskReason;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private bool _isThreatMatch;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    [NotifyPropertyChangedFor(nameof(TrustTooltip))]
    private string? _threatLabel;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TrustBadgeText))]
    private bool _isAppBlocked;

    public string FirstSeenText => FirstSeen.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string LastSeenText => LastSeen.LocalDateTime.ToString("HH:mm:ss", CultureInfo.InvariantCulture);

    public string ProtocolLabel => Protocol switch
    {
        ConnectionProtocol.Tcp4 => "TCP",
        ConnectionProtocol.Tcp6 => "TCP6",
        ConnectionProtocol.Udp4 => "UDP",
        ConnectionProtocol.Udp6 => "UDP6",
        _ => "TCP",
    };

    public string PortText => Protocol is ConnectionProtocol.Udp4 or ConnectionProtocol.Udp6
        ? string.Create(CultureInfo.InvariantCulture, $"{RemotePort} (local)")
        : RemotePort.ToString(CultureInfo.InvariantCulture);

    public string StatusText => LocalizationManager.Instance.Get("ConnStatus_" + Status);

    public string TrustBadgeText
    {
        get
        {
            if (IsThreatMatch && !string.IsNullOrWhiteSpace(ThreatLabel))
            {
                return LocalizationManager.Instance.Format("Conn_Threat_MatchBadge", ThreatLabel);
            }

            if (IsAppBlocked)
            {
                return LocalizationManager.Instance.Get("Conn_AppBlocked_Badge");
            }

            var baseText = LocalizationManager.Instance.Get("Trust_" + TrustLevel);
            if ((TrustLevel is ProcessTrustLevel.Signed or ProcessTrustLevel.TrustedSystem)
                && !string.IsNullOrWhiteSpace(Publisher))
            {
                return $"{baseText} ({Publisher})";
            }

            return baseText;
        }
    }

    public string TrustTooltip
    {
        get
        {
            var sb = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(ExecutablePath))
            {
                sb.AppendLine(ExecutablePath);
            }

            if (!string.IsNullOrWhiteSpace(Publisher))
            {
                sb.AppendLine(Publisher);
            }

            if (!string.IsNullOrWhiteSpace(RiskReason))
            {
                sb.AppendLine(RiskReason);
            }

            if (IsThreatMatch && !string.IsNullOrWhiteSpace(ThreatLabel))
            {
                sb.Append(ThreatLabel);
            }

            return sb.ToString().Trim();
        }
    }

    public string Note
    {
        get => _note;
        set
        {
            var sanitized = value ?? string.Empty;
            if (SetProperty(ref _note, sanitized))
            {
                _noteCommitted?.Invoke(this, sanitized);
            }
        }
    }

    public void SetNoteSilent(string note)
    {
        var sanitized = note ?? string.Empty;
        if (!string.Equals(_note, sanitized, StringComparison.Ordinal))
        {
            _note = sanitized;
            OnPropertyChanged(nameof(Note));
        }
    }

    public void NotifyLocalizationChanged()
    {
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(TrustBadgeText));
    }
}

public sealed record BlockedRuleItemViewModel(string Target, string? Note, DateTimeOffset AddedAtUtc, bool IsEnabled);

public sealed record BlockedAppItemViewModel(string ExecutablePath, string ProcessName, string? Note, DateTimeOffset AddedAtUtc, bool IsEnabled);

public sealed record IpNoteItemViewModel(string Ip, string Note);

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

    [RelayCommand]
    private void BlockSelectedIp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        if (SelectedConnection.RemoteIp == "*" || !IPAddress.TryParse(SelectedConnection.RemoteIp, out _))
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_CannotBlockUdpWildcard"), isError: true);
            return;
        }

        var defaultNote = string.IsNullOrWhiteSpace(SelectedConnection.Domain)
            ? SelectedConnection.ProcessName
            : $"{SelectedConnection.Domain} ({SelectedConnection.ProcessName})";

        var protectedCtx = GetProtectedIpContext();
        var eval = IpBlockerGuard.Evaluate(SelectedConnection.RemoteIp, protectedCtx);
        if (!eval.IsValid || eval.IsProtectedViolation || eval.NormalizedNetwork is not { } cidr)
        {
            var reason = eval.Message ?? "Invalid target.";
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_ProtectedRejected", reason), isError: true);
            return;
        }

        if (eval.RequiresConfirmation)
        {
            CancelModals();
            CustomCidrInput = cidr.CanonicalText;
            CustomCidrNote = string.IsNullOrWhiteSpace(SelectedConnection.Note) ? defaultNote : SelectedConnection.Note;
            PendingRiskWarning = eval.WarningMessage;
            IsRiskConfirmed = false;
            IsBlockCidrModalOpen = true;
            NotifyModalFlagsChanged();
            return;
        }

        var noteToStore = string.IsNullOrWhiteSpace(SelectedConnection.Note) ? defaultNote : SelectedConnection.Note;
        AddBlockedTarget(cidr.CanonicalText, noteToStore);
    }

    [RelayCommand]
    private void UnblockSelectedIp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        var ip = SelectedConnection.RemoteIp;
        if (RemoveExactTarget(ip))
        {
            return;
        }

        if (IPAddress.TryParse(ip, out var parsedAddr))
        {
            var covering = _compiledRules.FirstOrDefault(r => r.Network.Contains(parsedAddr));
            if (covering.Rule is not null)
            {
                SetBanner(LocalizationManager.Instance.Format("Conn_Msg_CoveredByCidr", ip, covering.Rule.Target), isError: true);
                OpenBlockedListModal();
                return;
            }
        }

        SetBanner(LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_NoneFound", ip, ip), isError: false);
    }

    [RelayCommand]
    private void BlockSelectedApp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        var eval = AppBlockerGuard.Evaluate(SelectedConnection.ExecutablePath);
        if (!eval.IsValid || string.IsNullOrWhiteSpace(eval.NormalizedPath))
        {
            SetBanner(eval.ErrorMessage ?? "Cannot block selected process.", isError: true);
            return;
        }

        var exePath = eval.NormalizedPath;
        var procName = string.IsNullOrWhiteSpace(SelectedConnection.ProcessName)
            ? Path.GetFileName(exePath)
            : SelectedConnection.ProcessName;

        var existing = _settings.Current.Connections.BlockedApps.FirstOrDefault(a =>
            string.Equals(a.ExecutablePath, exePath, StringComparison.OrdinalIgnoreCase));
        if (existing is { IsEnabled: true })
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppAlreadyBlocked", procName), isError: false);
            return;
        }

        _settings.UpdateDeferred(s =>
        {
            if (existing is not null)
            {
                var idx = s.Connections.BlockedApps.IndexOf(existing);
                s.Connections.BlockedApps[idx] = existing with { IsEnabled = true };
            }
            else
            {
                s.Connections.BlockedApps.Add(new BlockedAppRule
                {
                    ExecutablePath = exePath,
                    ProcessName = procName,
                    Note = SelectedConnection.Note,
                    AddedAtUtc = DateTimeOffset.UtcNow,
                    IsEnabled = true,
                });
            }

            s.Connections.HasUnsyncedFirewallChanges = true;
        });

        UnsyncedCount++;
        RebuildCompiledRules();
        RefreshManagedCollections();
        RecomputeAllRowStatuses();
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppAdded", procName), isError: false);
    }

    [RelayCommand]
    private void UnblockSelectedApp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        if (string.IsNullOrWhiteSpace(SelectedConnection.ExecutablePath))
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppNotBlocked", SelectedConnection.ProcessName), isError: false);
            return;
        }

        if (!RemoveBlockedAppByPath(SelectedConnection.ExecutablePath))
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppNotBlocked", SelectedConnection.ProcessName), isError: false);
        }
    }

    [RelayCommand]
    private void OpenBlockCidrModal()
    {
        CancelModals();
        CustomCidrInput = SelectedConnection is { RemoteIp.Length: > 0 } && SelectedConnection.RemoteIp != "*"
            ? SelectedConnection.RemoteIp
            : string.Empty;
        CustomCidrNote = SelectedConnection?.Domain ?? string.Empty;
        CidrValidationError = null;
        PendingRiskWarning = null;
        IsRiskConfirmed = false;
        IsBlockCidrModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void ConfirmBlockCidr()
    {
        var protectedCtx = GetProtectedIpContext();
        var eval = IpBlockerGuard.Evaluate(CustomCidrInput, protectedCtx);
        if (!eval.IsValid || eval.NormalizedNetwork is not { } cidr)
        {
            CidrValidationError = eval.IsProtectedViolation
                ? LocalizationManager.Instance.Format("Conn_Msg_ProtectedRejected", eval.Message ?? string.Empty)
                : eval.Message;
            PendingRiskWarning = null;
            return;
        }

        if (eval.RequiresConfirmation && !IsRiskConfirmed)
        {
            PendingRiskWarning = eval.WarningMessage;
            CidrValidationError = null;
            return;
        }

        AddBlockedTarget(cidr.CanonicalText, CustomCidrNote);
        CancelModals();
    }

    [RelayCommand]
    private void OpenUnblockWebsiteModal()
    {
        CancelModals();
        UnblockDomainInput = SelectedConnection?.Domain ?? string.Empty;
        UnblockWebsiteStatus = null;
        IsUnblockWebsiteModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private async Task ExecuteUnblockWebsiteAsync()
    {
        var domain = UnblockDomainInput?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        IsBusy = true;
        try
        {
            var matchedIps = new HashSet<IPAddress>();
            foreach (var cachedIp in _reverseCache.GetIpsForDomain(domain))
            {
                if (IPAddress.TryParse(cachedIp, out var ip))
                {
                    matchedIps.Add(ip);
                }
            }

            var resolved = await _dnsEngine.ResolveHostAsync(domain, includeIpv6: true).ConfigureAwait(false);
            foreach (var ip in resolved)
            {
                matchedIps.Add(ip);
            }

            var ipStrings = matchedIps.Select(ip => ip.ToString()).ToList();
            if (matchedIps.Count == 0)
            {
                await RunOnUiAsync(() =>
                    UnblockWebsiteStatus = LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_NoneFound", domain, "—")).ConfigureAwait(false);
                return;
            }

            var removedCount = 0;
            await _settings.UpdateAsync(s =>
            {
                removedCount = s.Connections.BlockedRules.RemoveAll(rule =>
                    CidrNetwork.TryParse(rule.Target, out var net, out _)
                    && matchedIps.Any(ip => net.Contains(ip)));

                if (removedCount > 0)
                {
                    s.Connections.HasUnsyncedFirewallChanges = true;
                }
            }).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                if (removedCount > 0)
                {
                    UnsyncedCount += removedCount;
                    RebuildCompiledRules();
                    RefreshManagedCollections();
                    RecomputeAllRowStatuses();
                    var msg = LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_Removed", removedCount, domain);
                    UnblockWebsiteStatus = msg;
                    SetBanner(msg, isError: false);
                }
                else
                {
                    UnblockWebsiteStatus = LocalizationManager.Instance.Format(
                        "Conn_Modal_UnblockWeb_NoneFound",
                        domain,
                        string.Join(", ", ipStrings.Take(6)));
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void OpenBlockedListModal()
    {
        CancelModals();
        RefreshManagedCollections();
        IsBlockedListModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void OpenBlockedAppsModal()
    {
        CancelModals();
        RefreshManagedCollections();
        IsBlockedAppsModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void RemoveBlockedRule(string? target)
    {
        if (!string.IsNullOrWhiteSpace(target))
        {
            _ = RemoveExactTarget(target);
        }
    }

    [RelayCommand]
    private void ToggleBlockedRule(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        var changed = false;
        _settings.UpdateDeferred(s =>
        {
            var index = s.Connections.BlockedRules.FindIndex(r =>
                string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                var current = s.Connections.BlockedRules[index];
                s.Connections.BlockedRules[index] = current with { IsEnabled = !current.IsEnabled };
                s.Connections.HasUnsyncedFirewallChanges = true;
                changed = true;
            }
        });

        if (changed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
        }
    }

    [RelayCommand]
    private void RemoveBlockedApp(string? executablePath)
    {
        if (!string.IsNullOrWhiteSpace(executablePath))
        {
            _ = RemoveBlockedAppByPath(executablePath);
        }
    }

    [RelayCommand]
    private void ToggleBlockedApp(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return;
        }

        var changed = false;
        _settings.UpdateDeferred(s =>
        {
            var index = s.Connections.BlockedApps.FindIndex(a =>
                string.Equals(a.ExecutablePath, executablePath, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                var current = s.Connections.BlockedApps[index];
                s.Connections.BlockedApps[index] = current with { IsEnabled = !current.IsEnabled };
                s.Connections.HasUnsyncedFirewallChanges = true;
                changed = true;
            }
        });

        if (changed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
        }
    }

    [RelayCommand]
    private async Task ClearAllFirewallRulesAsync()
    {
        IsBusy = true;
        try
        {
            var result = await _firewall.ClearAllAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    _settings.UpdateDeferred(s =>
                    {
                        s.Connections.BlockedRules.Clear();
                        s.Connections.BlockedApps.Clear();
                        s.Connections.EnableDnsLeakGuard = false;
                        s.Connections.HasUnsyncedFirewallChanges = false;
                    });
                    _suppressPreferencePersist = true;
                    try
                    {
                        EnableDnsLeakGuard = false;
                    }
                    finally
                    {
                        _suppressPreferencePersist = false;
                    }

                    IsLockdownActive = false;
                    UnsyncedCount = 0;
                    RebuildCompiledRules();
                    RefreshManagedCollections();
                    RecomputeAllRowStatuses();
                    SetBanner(LocalizationManager.Instance.Format("Conn_Msg_ClearedAll", result.RemovedRuleCount), isError: false);
                }
                else
                {
                    SetBanner(result.Message ?? "Failed to clear Windows Firewall rules.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private async Task ToggleEmergencyLockdownAsync()
    {
        var targetState = !IsLockdownActive;
        await ApplySecurityShieldToggleAsync(isLeakToggle: false, desiredState: targetState).ConfigureAwait(false);
    }

    [RelayCommand]
    private async Task UpdateThreatFeedsAsync()
    {
        IsBusy = true;
        try
        {
            var status = await _threatIntel.RefreshFeedsAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                UpdateThreatFeedSummary();
                if (string.IsNullOrWhiteSpace(status.LastError))
                {
                    SetBanner(
                        LocalizationManager.Instance.Format("Conn_Msg_ThreatFeedsUpdated", status.IndicatorCount, status.IpCount, status.CidrCount),
                        isError: false);
                }
                else
                {
                    SetBanner(
                        LocalizationManager.Instance.Format("Conn_Msg_ThreatFeedsFailed", status.LastError),
                        isError: status.IndicatorCount == 0);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void InspectIpAbuseIpDb()
    {
        if (SelectedConnection is not { RemoteIp.Length: > 0 } row
            || !IPAddress.TryParse(row.RemoteIp, out var ip))
        {
            return;
        }

        OpenExternalUrl($"https://www.abuseipdb.com/check/{Uri.EscapeDataString(ip.ToString())}");
    }

    [RelayCommand]
    private void InspectIpVirusTotal()
    {
        if (SelectedConnection is not { RemoteIp.Length: > 0 } row
            || !IPAddress.TryParse(row.RemoteIp, out var ip))
        {
            return;
        }

        OpenExternalUrl($"https://www.virustotal.com/gui/ip-address/{Uri.EscapeDataString(ip.ToString())}");
    }

    [RelayCommand]
    private void OpenNotesModal()
    {
        CancelModals();
        if (SelectedConnection is not null)
        {
            NoteEditorIp = GetNoteStorageKey(SelectedConnection);
            NoteEditorText = SelectedConnection.Note;
        }
        else
        {
            NoteEditorIp = string.Empty;
            NoteEditorText = string.Empty;
        }

        RefreshManagedCollections();
        IsNotesModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void SaveNoteEntry()
    {
        var key = NoteEditorIp?.Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        PersistNoteForKey(key, NoteEditorText);
        NoteEditorIp = string.Empty;
        NoteEditorText = string.Empty;
    }

    [RelayCommand]
    private void DeleteNoteEntry(string? key)
    {
        if (!string.IsNullOrWhiteSpace(key))
        {
            PersistNoteForKey(key, string.Empty);
        }
    }

    [RelayCommand]
    private void CancelModals()
    {
        IsBlockCidrModalOpen = false;
        IsUnblockWebsiteModalOpen = false;
        IsBlockedListModalOpen = false;
        IsBlockedAppsModalOpen = false;
        IsNotesModalOpen = false;
        CidrValidationError = null;
        PendingRiskWarning = null;
        UnblockWebsiteStatus = null;
        IsRiskConfirmed = false;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private async Task SyncBlocklistAsync()
    {
        IsBusy = true;
        try
        {
            var conn = _settings.Current.Connections;
            var payload = new FirewallSyncRequestPayload(
                conn.BlockedRules.ToList(),
                conn.BlockedApps.ToList(),
                EnableDnsLeakGuard,
                IsLockdownActive);

            var result = await _firewall.SyncSecurityAsync(payload).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    _settings.UpdateDeferred(s => s.Connections.HasUnsyncedFirewallChanges = false);
                    UnsyncedCount = 0;

                    var msg = result.RejectedProtectedCount > 0
                        ? LocalizationManager.Instance.Format("Conn_Msg_SyncedWithRejected", result.AppliedRuleCount, result.RejectedProtectedCount)
                        : LocalizationManager.Instance.Format("Conn_Msg_Synced", result.AppliedRuleCount, result.RemovedRuleCount);
                    SetBanner(msg, isError: false);
                }
                else
                {
                    SetBanner(result.Message ?? "Failed to sync Windows Firewall.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void ExportCsv()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = $"JustCryptDns-Connections-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var rows = ConnectionsView.Cast<ConnectionRowViewModel>().ToList();
        var sb = new StringBuilder();
        sb.AppendLine("FirstSeen,LastSeen,Process,PID,Protocol,RemoteIP,Port,Count,Domain,Status,Organization,Trust,Threat,ExecutablePath,Note");
        foreach (var row in rows)
        {
            sb.Append(CsvEscape(row.FirstSeen.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
              .Append(CsvEscape(row.LastSeen.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
              .Append(CsvEscape(row.ProcessName)).Append(',')
              .Append(row.ProcessId.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(CsvEscape(row.ProtocolLabel)).Append(',')
              .Append(CsvEscape(row.RemoteIp)).Append(',')
              .Append(row.RemotePort.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(row.ConnectionCount.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(CsvEscape(row.Domain)).Append(',')
              .Append(CsvEscape(row.StatusText)).Append(',')
              .Append(CsvEscape(row.Organization)).Append(',')
              .Append(CsvEscape(row.TrustBadgeText)).Append(',')
              .Append(CsvEscape(row.ThreatLabel)).Append(',')
              .Append(CsvEscape(row.ExecutablePath)).Append(',')
              .AppendLine(CsvEscape(row.Note));
        }

        File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_Exported", rows.Count, Path.GetFileName(dialog.FileName)), isError: false);
    }

    [RelayCommand]
    private void CopySelectedIp()
    {
        if (SelectedConnection is null || string.IsNullOrWhiteSpace(SelectedConnection.RemoteIp))
        {
            return;
        }

        try
        {
            Clipboard.SetText(SelectedConnection.RemoteIp);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Clipboard copy failed cleanly.");
        }
    }

    [RelayCommand]
    private void RequestEditNote()
    {
        if (SelectedConnection is not null)
        {
            EditNoteRequested?.Invoke(this, SelectedConnection);
        }
    }

    [RelayCommand]
    private void DismissProcessAlert() => NewProcessAlertText = null;

    [RelayCommand]
    private void DismissThreatAlert() => ThreatAlertText = null;

    [RelayCommand]
    private void ClearClosedConnections()
    {
        var closedKeys = Connections
            .Where(r => r.Status == ConnectionDisplayStatus.Closed)
            .Select(r => r.Key)
            .ToList();

        foreach (var key in closedKeys)
        {
            if (_rowsByKey.TryGetValue(key, out var row))
            {
                _rowsByKey.Remove(key);
                Connections.Remove(row);
            }
        }

        UpdateSummaryCounts();
    }

    private async Task ApplySecurityShieldToggleAsync(bool isLeakToggle, bool desiredState)
    {
        IsBusy = true;
        try
        {
            var conn = _settings.Current.Connections;
            var payload = new FirewallSyncRequestPayload(
                conn.BlockedRules.ToList(),
                conn.BlockedApps.ToList(),
                isLeakToggle ? desiredState : EnableDnsLeakGuard,
                isLeakToggle ? IsLockdownActive : desiredState);

            var result = await _firewall.SyncSecurityAsync(payload).ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    if (!isLeakToggle)
                    {
                        IsLockdownActive = desiredState;
                        SetBanner(
                            LocalizationManager.Instance.Get(desiredState ? "Conn_Msg_LockdownEnabled" : "Conn_Msg_LockdownDisabled"),
                            isError: false);
                    }
                    else
                    {
                        SetBanner(
                            LocalizationManager.Instance.Get(desiredState ? "Conn_Msg_DnsLeakGuardEnabled" : "Conn_Msg_DnsLeakGuardDisabled"),
                            isError: false);
                    }
                }
                else
                {
                    if (isLeakToggle)
                    {
                        _suppressPreferencePersist = true;
                        try
                        {
                            EnableDnsLeakGuard = !desiredState;
                        }
                        finally
                        {
                            _suppressPreferencePersist = false;
                        }

                        _settings.UpdateDeferred(s => s.Connections.EnableDnsLeakGuard = !desiredState);
                    }

                    SetBanner(result.Message ?? "Failed to update Windows Firewall security policy.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    private void AddBlockedTarget(string canonicalTarget, string? note, bool autoSyncIfRequested = false)
    {
        var existing = _settings.Current.Connections.BlockedRules.FirstOrDefault(r =>
            string.Equals(r.Target, canonicalTarget, StringComparison.OrdinalIgnoreCase));

        if (existing is { IsEnabled: true })
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleAlreadyBlocked", canonicalTarget), isError: false);
            return;
        }

        var trimmedNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        _settings.UpdateDeferred(s =>
        {
            if (existing is not null)
            {
                var idx = s.Connections.BlockedRules.IndexOf(existing);
                s.Connections.BlockedRules[idx] = existing with
                {
                    IsEnabled = true,
                    Note = trimmedNote ?? existing.Note,
                };
            }
            else
            {
                s.Connections.BlockedRules.Add(new BlockedIpRule
                {
                    Target = canonicalTarget,
                    Note = trimmedNote,
                    AddedAtUtc = DateTimeOffset.UtcNow,
                    IsEnabled = true,
                });
            }

            if (!string.IsNullOrWhiteSpace(trimmedNote))
            {
                s.Connections.IpNotes[canonicalTarget] = trimmedNote;
            }

            s.Connections.HasUnsyncedFirewallChanges = true;
        });

        UnsyncedCount++;
        RebuildCompiledRules();
        RefreshManagedCollections();
        RecomputeAllRowStatuses();
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleAdded", canonicalTarget), isError: false);

        if (autoSyncIfRequested)
        {
            _ = SyncBlocklistAsync();
        }
    }

    private bool RemoveExactTarget(string target)
    {
        var normalized = CidrNetwork.TryParse(target, out var cidr, out _)
            ? cidr.CanonicalText
            : target.Trim();

        var removed = false;
        _settings.UpdateDeferred(s =>
        {
            removed = s.Connections.BlockedRules.RemoveAll(r =>
                string.Equals(r.Target, normalized, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                s.Connections.HasUnsyncedFirewallChanges = true;
            }
        });

        if (removed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleRemoved", normalized), isError: false);
        }

        return removed;
    }

    private bool RemoveBlockedAppByPath(string executablePath)
    {
        var fullPath = Path.GetFullPath(executablePath.Trim());
        var removed = false;
        _settings.UpdateDeferred(s =>
        {
            removed = s.Connections.BlockedApps.RemoveAll(a =>
                string.Equals(a.ExecutablePath, fullPath, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                s.Connections.HasUnsyncedFirewallChanges = true;
            }
        });

        if (removed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppRemoved", Path.GetFileName(fullPath)), isError: false);
        }

        return removed;
    }

    private void PersistNoteForKey(string key, string note)
    {
        var trimmed = string.IsNullOrWhiteSpace(note) ? string.Empty : note.Trim();
        _settings.UpdateDeferred(s =>
        {
            if (string.IsNullOrEmpty(trimmed))
            {
                s.Connections.IpNotes.Remove(key);
            }
            else
            {
                s.Connections.IpNotes[key] = trimmed;
            }
        });

        foreach (var row in Connections)
        {
            if (string.Equals(GetNoteStorageKey(row), key, StringComparison.OrdinalIgnoreCase))
            {
                row.SetNoteSilent(trimmed);
            }
        }

        RefreshManagedCollections();
        if (!IsEditingCell)
        {
            RefreshFilterSafe();
        }
    }

    private async void OnPollTimerTick(object? sender, EventArgs e)
    {
        if (!_isNavigatedActive || !_isWindowVisible || _disposed)
        {
            return;
        }

        await PollOnceAsync().ConfigureAwait(false);
    }

    private async Task PollOnceAsync()
    {
        if (_pollInFlight || _disposed)
        {
            return;
        }

        _pollInFlight = true;
        try
        {
            _pollCycle++;
            if ((_pollCycle % 2) == 1)
            {
                await _firewall.PullReverseDnsFromServiceIfConnectedAsync().ConfigureAwait(false);
            }

            var verifySigs = VerifyProcessSignatures;
            var checkThreats = EnableThreatIntelligence;
            var (rawList, trustByPath, threatsByIp) = await Task.Run(() =>
            {
                var snapshot = _monitor.CaptureSnapshot();
                var trustMap = new Dictionary<string, ProcessTrustInfo>(StringComparer.OrdinalIgnoreCase);
                var threatMap = new Dictionary<string, ThreatIntelMatch>(StringComparer.OrdinalIgnoreCase);
                ProtectedIpContext? protectedCtx = null;

                foreach (var raw in snapshot)
                {
                    if (verifySigs && !string.IsNullOrWhiteSpace(raw.ExecutablePath) && !trustMap.ContainsKey(raw.ExecutablePath))
                    {
                        trustMap[raw.ExecutablePath] = _trustInspector.Inspect(raw.ExecutablePath, raw.ProcessName);
                    }

                    if (checkThreats && raw.RemoteIp != "*" && !threatMap.ContainsKey(raw.RemoteIp))
                    {
                        protectedCtx ??= GetProtectedIpContext();
                        if (_threatIntel.TryMatch(raw.RemoteIp, protectedCtx, out var threat))
                        {
                            threatMap[raw.RemoteIp] = threat;
                        }
                    }
                }

                return (snapshot, trustMap, threatMap);
            }).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                if (_disposed || !_isNavigatedActive)
                {
                    return;
                }

                ApplySnapshotToUi(rawList, trustByPath, threatsByIp);
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Connection poll iteration failed cleanly.");
        }
        finally
        {
            _pollInFlight = false;
        }
    }

    private void ApplySnapshotToUi(
        IReadOnlyList<RawSocketConnection> rawList,
        Dictionary<string, ProcessTrustInfo> trustByPath,
        Dictionary<string, ThreatIntelMatch> threatsByIp)
    {
        if (IsEditingCell || (ConnectionsView is IEditableCollectionView editable && (editable.IsEditingItem || editable.IsAddingNew)))
        {
            return;
        }

        var now = DateTimeOffset.Now;
        var notes = _settings.Current.Connections.IpNotes;

        var grouped = new Dictionary<string, (RawSocketConnection Sample, int Count)>(rawList.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var raw in rawList)
        {
            var key = BuildRowKey(raw);
            if (grouped.TryGetValue(key, out var existing))
            {
                grouped[key] = (existing.Sample, existing.Count + 1);
            }
            else
            {
                grouped[key] = (raw, 1);
            }
        }

        ConnectionRowViewModel? lastNewVisible = null;
        var newlyAddedAny = false;
        string? autoBlockTarget = null;
        string? autoBlockReason = null;

        foreach (var (key, group) in grouped)
        {
            var raw = group.Sample;
            var socketCount = group.Count;
            var isUdp = raw.Protocol is ConnectionProtocol.Udp4 or ConnectionProtocol.Udp6;
            var isLan = !isUdp && CidrNetwork.IsLanOrLocalString(raw.RemoteIp);
            var status = EvaluateRowStatus(raw.RemoteIp, activeInSnapshot: true);
            var resolvedDomain = ResolveDisplayDomain(raw.RemoteIp);
            var resolvedOrg = ResolveDisplayOrg(raw.RemoteIp, resolvedDomain);
            var isAppBlocked = !string.IsNullOrWhiteSpace(raw.ExecutablePath) && _blockedAppPaths.Contains(raw.ExecutablePath);

            ProcessTrustInfo? trustInfo = null;
            if (!string.IsNullOrWhiteSpace(raw.ExecutablePath) && trustByPath.TryGetValue(raw.ExecutablePath, out var ti))
            {
                trustInfo = ti;
            }
            else if (string.Equals(raw.ProcessName, "System", StringComparison.OrdinalIgnoreCase)
                || string.Equals(raw.ProcessName, "System Idle", StringComparison.OrdinalIgnoreCase))
            {
                trustInfo = new ProcessTrustInfo(raw.ProcessName, ProcessTrustLevel.TrustedSystem, "Microsoft Windows", false, false, null);
            }

            var hasThreat = threatsByIp.TryGetValue(raw.RemoteIp, out var threatMatch);
            var threatLabel = hasThreat && threatMatch is not null ? $"{threatMatch.Source} ({threatMatch.Category})" : null;

            if (hasThreat && threatMatch is not null)
            {
                if (_alertedThreats.Add(raw.RemoteIp))
                {
                    ThreatAlertText = LocalizationManager.Instance.Format(
                        "Conn_Alert_ThreatDetected",
                        raw.ProcessName,
                        raw.RemoteIp,
                        threatMatch.Source,
                        threatMatch.Category);
                }

                if (AutoBlockDetectedThreats
                    && autoBlockTarget is null
                    && status != ConnectionDisplayStatus.BlockedIp
                    && status != ConnectionDisplayStatus.BlockedRange)
                {
                    var eval = IpBlockerGuard.Evaluate(raw.RemoteIp, GetProtectedIpContext());
                    if (eval.IsValid && !eval.IsProtectedViolation && eval.NormalizedNetwork is { } cidr)
                    {
                        autoBlockTarget = cidr.CanonicalText;
                        autoBlockReason = $"{threatMatch.Source}: {threatMatch.Category} ({raw.ProcessName})";
                    }
                }
            }

            if (!isUdp && !isLan)
            {
                if (_baselineCaptured && AlertNewUnknownProcess && !_knownExternalProcesses.Contains(raw.ProcessName))
                {
                    _knownExternalProcesses.Add(raw.ProcessName);
                    var targetLabel = string.IsNullOrEmpty(resolvedDomain)
                        ? $"{raw.RemoteIp}:{raw.RemotePort}"
                        : $"{resolvedDomain} ({raw.RemoteIp}:{raw.RemotePort})";
                    NewProcessAlertText = LocalizationManager.Instance.Format("Conn_Alert_NewProcess", raw.ProcessName, targetLabel);
                }
                else
                {
                    _knownExternalProcesses.Add(raw.ProcessName);
                }
            }

            if (_rowsByKey.TryGetValue(key, out var row))
            {
                var wasClosed = row.Status == ConnectionDisplayStatus.Closed;
                row.LastSeen = now;
                if (!string.Equals(row.ProcessName, raw.ProcessName, StringComparison.Ordinal))
                {
                    row.ProcessName = raw.ProcessName;
                }

                if (!string.IsNullOrWhiteSpace(raw.ExecutablePath)
                    && !string.Equals(row.ExecutablePath, raw.ExecutablePath, StringComparison.Ordinal))
                {
                    row.ExecutablePath = raw.ExecutablePath;
                }

                row.ConnectionCount = wasClosed
                    ? row.ConnectionCount + socketCount
                    : Math.Max(row.ConnectionCount, socketCount);

                if (!string.IsNullOrEmpty(resolvedDomain))
                {
                    row.Domain = resolvedDomain;
                }

                if (!string.IsNullOrEmpty(resolvedOrg))
                {
                    row.Organization = resolvedOrg;
                }

                if (row.Status != status)
                {
                    row.Status = status;
                }

                if (trustInfo is not null)
                {
                    row.TrustLevel = trustInfo.Level;
                    row.Publisher = trustInfo.Publisher;
                    row.RiskReason = trustInfo.RiskReason;
                }

                row.IsThreatMatch = hasThreat;
                row.ThreatLabel = threatLabel;
                row.IsAppBlocked = isAppBlocked;
            }
            else
            {
                var created = new ConnectionRowViewModel(key, (r, text) => PersistNoteForKey(GetNoteStorageKey(r), text))
                {
                    FirstSeen = now,
                    LastSeen = now,
                    ProcessId = raw.ProcessId,
                    ProcessName = raw.ProcessName,
                    ExecutablePath = raw.ExecutablePath,
                    Protocol = raw.Protocol,
                    RemoteIp = raw.RemoteIp,
                    RemotePort = raw.RemotePort,
                    ConnectionCount = socketCount,
                    Domain = resolvedDomain,
                    Organization = resolvedOrg,
                    Status = status,
                    IsLan = isLan,
                    TrustLevel = trustInfo?.Level ?? ProcessTrustLevel.Unknown,
                    Publisher = trustInfo?.Publisher,
                    RiskReason = trustInfo?.RiskReason,
                    IsThreatMatch = hasThreat,
                    ThreatLabel = threatLabel,
                    IsAppBlocked = isAppBlocked,
                };

                var noteKey = GetNoteStorageKey(created);
                if (notes.TryGetValue(noteKey, out var storedNote))
                {
                    created.SetNoteSilent(storedNote);
                }

                _rowsByKey[key] = created;
                Connections.Add(created);
                newlyAddedAny = true;

                if (FilterConnection(created))
                {
                    lastNewVisible = created;
                }
            }

            if (EnableOnlineLookup && !isUdp && !isLan && !_enrichment.TryGetCached(raw.RemoteIp, out _))
            {
                _enrichment.EnqueueLookup(raw.RemoteIp);
            }
        }

        foreach (var (key, row) in _rowsByKey)
        {
            if (!grouped.ContainsKey(key) && row.Status != ConnectionDisplayStatus.Closed)
            {
                row.Status = ConnectionDisplayStatus.Closed;
            }
        }

        _baselineCaptured = true;
        PruneHistoryIfNeeded();
        UpdateSummaryCounts();

        if (autoBlockTarget is not null)
        {
            AddBlockedTarget(autoBlockTarget, autoBlockReason, autoSyncIfRequested: true);
        }

        if (newlyAddedAny && AutoScroll && lastNewVisible is not null && !IsEditingCell)
        {
            AutoScrollRequested?.Invoke(this, lastNewVisible);
        }
    }

    private string ResolveDisplayDomain(string remoteIp)
    {
        if (remoteIp == "*")
        {
            return string.Empty;
        }

        if (_reverseCache.TryResolve(remoteIp, out var cachedDomain))
        {
            return cachedDomain;
        }

        if (_enrichment.TryGetCached(remoteIp, out var info) && !string.IsNullOrWhiteSpace(info.ReverseDns))
        {
            return info.ReverseDns;
        }

        return string.Empty;
    }

    private string ResolveDisplayOrg(string remoteIp, string? domain)
    {
        if (remoteIp == "*")
        {
            return string.Empty;
        }

        // 1. Persisted / online enrichment cache (zero network calls here)
        if (_enrichment.TryGetCached(remoteIp, out var info) && !string.IsNullOrWhiteSpace(info.Organization))
        {
            return !string.IsNullOrWhiteSpace(info.Country)
                ? $"{info.Organization} ({info.Country})"
                : info.Organization;
        }

        // 2. Instant zero-network offline IP CIDR + DNS suffix attribution
        if (OfflineOrganizationDatabase.TryResolve(remoteIp, domain, out var offline))
        {
            return !string.IsNullOrWhiteSpace(offline.CountryCode)
                ? $"{offline.Organization} ({offline.CountryCode})"
                : offline.Organization;
        }

        // 3. Fallback cached rDNS hostname if any
        if (info is not null && !string.IsNullOrWhiteSpace(info.ReverseDns))
        {
            return info.ReverseDns;
        }

        return string.Empty;
    }

    private ConnectionDisplayStatus EvaluateRowStatus(string remoteIp, bool activeInSnapshot)
    {
        if (!activeInSnapshot)
        {
            return ConnectionDisplayStatus.Closed;
        }

        if (remoteIp != "*" && IPAddress.TryParse(remoteIp, out var ip))
        {
            var matchedExact = false;
            var matchedRange = false;
            foreach (var (_, network) in _compiledRules)
            {
                if (!network.Contains(ip))
                {
                    continue;
                }

                if (network.IsSingleHost)
                {
                    matchedExact = true;
                    break;
                }

                matchedRange = true;
            }

            if (matchedExact)
            {
                return ConnectionDisplayStatus.BlockedIp;
            }

            if (matchedRange)
            {
                return ConnectionDisplayStatus.BlockedRange;
            }
        }

        return ConnectionDisplayStatus.Active;
    }

    private void RecomputeAllRowStatuses()
    {
        foreach (var row in Connections)
        {
            if (row.Status != ConnectionDisplayStatus.Closed)
            {
                row.Status = EvaluateRowStatus(row.RemoteIp, activeInSnapshot: true);
            }

            row.IsAppBlocked = !string.IsNullOrWhiteSpace(row.ExecutablePath)
                && _blockedAppPaths.Contains(row.ExecutablePath);
        }

        UpdateSummaryCounts();
    }

    private void UpdateSummaryCounts()
    {
        TotalCount = Connections.Count;
        ActiveCount = Connections.Count(r => r.Status != ConnectionDisplayStatus.Closed);
        BlockedRuleCount = _compiledRules.Count;
        BlockedAppCount = _blockedAppPaths.Count;
    }

    private void RebuildCompiledRules()
    {
        _compiledRules.Clear();
        foreach (var rule in _settings.Current.Connections.BlockedRules)
        {
            if (rule.IsEnabled && CidrNetwork.TryParse(rule.Target, out var network, out _))
            {
                _compiledRules.Add((rule, network));
            }
        }

        _blockedAppPaths.Clear();
        foreach (var appRule in _settings.Current.Connections.BlockedApps)
        {
            if (appRule.IsEnabled && !string.IsNullOrWhiteSpace(appRule.ExecutablePath))
            {
                _blockedAppPaths.Add(appRule.ExecutablePath);
            }
        }

        BlockedRuleCount = _compiledRules.Count;
        BlockedAppCount = _blockedAppPaths.Count;
    }

    private void RefreshManagedCollections()
    {
        ManagedBlockedRules.Clear();
        foreach (var rule in _settings.Current.Connections.BlockedRules.OrderByDescending(r => r.AddedAtUtc))
        {
            ManagedBlockedRules.Add(new BlockedRuleItemViewModel(rule.Target, rule.Note, rule.AddedAtUtc, rule.IsEnabled));
        }

        ManagedBlockedApps.Clear();
        foreach (var appRule in _settings.Current.Connections.BlockedApps.OrderByDescending(a => a.AddedAtUtc))
        {
            ManagedBlockedApps.Add(new BlockedAppItemViewModel(appRule.ExecutablePath, appRule.ProcessName, appRule.Note, appRule.AddedAtUtc, appRule.IsEnabled));
        }

        ManagedNotes.Clear();
        foreach (var (ip, note) in _settings.Current.Connections.IpNotes.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            ManagedNotes.Add(new IpNoteItemViewModel(ip, note));
        }
    }

    private void UpdateThreatFeedSummary()
    {
        ThreatIndicatorCount = _threatIntel.GetStatus().IndicatorCount;
        OnPropertyChanged(nameof(ThreatFeedSummaryText));
    }

    private bool FilterConnection(object obj)
    {
        if (obj is not ConnectionRowViewModel row)
        {
            return false;
        }

        if (HideLanConnections && row.IsLan)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchQuery))
        {
            return true;
        }

        var q = SearchQuery.Trim();
        return row.RemoteIp.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.Domain.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.PortText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.ProtocolLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.Organization.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.TrustBadgeText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || (!string.IsNullOrEmpty(row.ExecutablePath) && row.ExecutablePath.Contains(q, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrEmpty(row.ThreatLabel) && row.ThreatLabel.Contains(q, StringComparison.OrdinalIgnoreCase))
            || row.Note.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.StatusText.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void RefreshFilterSafe()
    {
        if (IsEditingCell || (ConnectionsView is IEditableCollectionView editable && (editable.IsEditingItem || editable.IsAddingNew)))
        {
            _pendingFilterRefresh = true;
            return;
        }

        ConnectionsView.Refresh();
    }

    private void PruneHistoryIfNeeded()
    {
        if (Connections.Count <= MaxTrackedRows)
        {
            return;
        }

        var overflow = Connections.Count - MaxTrackedRows;
        var victims = Connections
            .OrderBy(r => r.Status == ConnectionDisplayStatus.Closed ? 0 : 1)
            .ThenBy(r => r.LastSeen)
            .Take(overflow)
            .ToList();

        foreach (var row in victims)
        {
            _rowsByKey.Remove(row.Key);
            Connections.Remove(row);
        }
    }

    private ProtectedIpContext GetProtectedIpContext()
    {
        if (_cachedProtectedContext is not null && (DateTimeOffset.UtcNow - _protectedContextBuiltAt).TotalSeconds < 10)
        {
            return _cachedProtectedContext;
        }

        var current = _settings.Current;
        _cachedProtectedContext = ProtectedIpContext.Build(
            _networkInfo.GetSnapshot(),
            _resolverLibrary.GetAll(),
            current.Dns,
            current.Bypass,
            _reverseCache);
        _protectedContextBuiltAt = DateTimeOffset.UtcNow;
        return _cachedProtectedContext;
    }

    private async Task RefreshFirewallStatusAsync()
    {
        try
        {
            var fwStatus = await _firewall.GetStatusAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = fwStatus.IsWindowsFirewallEnabled;
                RequiresElevationHint = fwStatus.RequiresElevation;
                IsLockdownActive = fwStatus.IsLockdownActive;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not query Windows Firewall status.");
        }
    }

    private void OnEnrichmentReady(object? sender, IpEnrichmentInfo info)
    {
        _ = RunOnUiAsync(() =>
        {
            if (_disposed)
            {
                return;
            }

            foreach (var row in Connections)
            {
                if (!string.Equals(row.RemoteIp, info.Ip, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(row.Domain) && !string.IsNullOrWhiteSpace(info.ReverseDns))
                {
                    row.Domain = info.ReverseDns;
                }

                var updatedOrg = ResolveDisplayOrg(info.Ip, row.Domain);
                if (!string.IsNullOrWhiteSpace(updatedOrg))
                {
                    row.Organization = updatedOrg;
                }
            }
        });
    }

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
