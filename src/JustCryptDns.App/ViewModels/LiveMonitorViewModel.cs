using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.App.Services;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Diagnostics;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.Routing;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed partial class LiveMonitorViewModel : PageViewModel
{
    public const int MaxLocalQueryBuffer = 5000;

    private readonly INetworkDiagnosticsService _diagnostics;
    private readonly IDnsFailoverService _failover;
    private readonly IDnsEngine _dnsEngine;
    private readonly IServiceClient? _serviceClient;
    private readonly ISettingsService? _settings;
    private readonly IDnsFilteringService? _filtering;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly List<LiveQueryMonitorEntry> _allQueries = new(MaxLocalQueryBuffer);
    private DispatcherTimer? _servicePollTimer;
    private bool _isServicePollInFlight;
    private long _lastSyncedSequenceId;
    private QueryAnalyticsSnapshot _latestAnalytics = new()
    {
        SessionStartedUtc = DateTimeOffset.UtcNow,
        TopQueried = [],
        TopBlocked = [],
        TopFailed = [],
    };

    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private DnsEngineState _engineState = DnsEngineState.Stopped;
    [ObservableProperty] private string _activeResolverName = "—";
    [ObservableProperty] private long _totalQueries;
    [ObservableProperty] private long _blockedQueries;
    [ObservableProperty] private long _failedQueriesCount;
    [ObservableProperty] private int _uniqueDomainsCount;
    [ObservableProperty] private string _queriesPerMinuteText = "0/m";
    [ObservableProperty] private string _cacheHitRatioText = "0%";
    [ObservableProperty] private string _lastLatencyText = "—";
    [ObservableProperty] private string _filteredCountSummary = "0 / 0";

    // Inner sub-tab state: 0 = Detailed Query Log, 1 = Top Domains & Spam Detector, 2 = Failover History
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsLogTabActive))]
    [NotifyPropertyChangedFor(nameof(IsAnalyticsTabActive))]
    [NotifyPropertyChangedFor(nameof(IsFailoverTabActive))]
    private int _activeTabIndex;

    // Detailed Query Log filters
    [ObservableProperty] private string _searchQuery = string.Empty;
    [ObservableProperty] private string _selectedOutcomeFilter = "All";
    [ObservableProperty] private string _selectedRecordTypeFilter = "All";
    [ObservableProperty] private bool _onlySlowQueries;

    // Top Domains & Spam Detector category: TopQueried | TopBlocked | TopFailed
    [ObservableProperty] private string _selectedAnalyticsCategory = "TopQueried";

    // Query Inspector & 1-click actions
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelectedQuery))]
    private LiveQueryMonitorEntry? _selectedQuery;

    [ObservableProperty] private string _inspectorRewriteTarget = "127.0.0.1";
    [ObservableProperty] private string _inspectorTargetResolverId = BuiltInResolvers.DefaultResolverId;
    [ObservableProperty] private string? _actionFeedback;

    public LiveMonitorViewModel(
        INetworkDiagnosticsService diagnostics,
        IDnsFailoverService failover,
        IDnsEngine dnsEngine,
        IServiceClient? serviceClient = null,
        ISettingsService? settings = null,
        IDnsFilteringService? filtering = null,
        IBypassEngineService? bypassEngine = null,
        IResolverLibraryService? resolverLibrary = null)
        : base("Nav_Monitor", "Page_Monitor_Subtitle")
    {
        _diagnostics = diagnostics;
        _failover = failover;
        _dnsEngine = dnsEngine;
        _serviceClient = serviceClient;
        _settings = settings;
        _filtering = filtering;
        _bypassEngine = bypassEngine;
        _resolverLibrary = resolverLibrary;

        _isPaused = _diagnostics.IsMonitorPaused;
        RefreshAvailableResolvers();
        RefreshAll();
    }

    public ObservableCollection<LiveQueryMonitorEntry> QueryEntries { get; } = [];

    public ObservableCollection<DomainQueryAggregate> DisplayedDomainAggregates { get; } = [];

    public ObservableCollection<FailoverEventEntry> FailoverEvents { get; } = [];

    public ObservableCollection<DnsResolverEndpoint> AvailableResolvers { get; } = [];

    public IReadOnlyList<string> OutcomeFilters { get; } =
        ["All", "Blocked", "Allowed", "Cached", "Routed", "Rewritten", "Failed", "Stale", "Canary"];

    public IReadOnlyList<string> RecordTypeFilters { get; } =
        ["All", "A", "AAAA", "HTTPS", "CNAME", "TXT", "MX", "PTR", "SRV", "NS", "SOA"];

    public bool IsLogTabActive => ActiveTabIndex == 0;

    public bool IsAnalyticsTabActive => ActiveTabIndex == 1;

    public bool IsFailoverTabActive => ActiveTabIndex == 2;

    public bool HasSelectedQuery => SelectedQuery is not null;

    public override void OnNavigatedTo()
    {
        _diagnostics.QueryObserved += OnQueryObserved;
        _failover.FailoverOccurred += OnFailoverOccurred;
        _dnsEngine.StateChanged += OnEngineStateChanged;
        if (_serviceClient is not null)
        {
            _serviceClient.StateChanged -= OnServiceClientStateChanged;
            _serviceClient.StateChanged += OnServiceClientStateChanged;
        }

        RefreshAvailableResolvers();
        RefreshAll();
        StartServicePolling();
    }

    public override void OnNavigatedFrom()
    {
        StopServicePolling();
        if (_serviceClient is not null)
        {
            _serviceClient.StateChanged -= OnServiceClientStateChanged;
        }

        _diagnostics.QueryObserved -= OnQueryObserved;
        _failover.FailoverOccurred -= OnFailoverOccurred;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            StopServicePolling();
            if (_serviceClient is not null)
            {
                _serviceClient.StateChanged -= OnServiceClientStateChanged;
            }

            _diagnostics.QueryObserved -= OnQueryObserved;
            _failover.FailoverOccurred -= OnFailoverOccurred;
            _dnsEngine.StateChanged -= OnEngineStateChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnIsPausedChanged(bool value) => _diagnostics.IsMonitorPaused = value;

    partial void OnSearchQueryChanged(string value) => RebuildFilteredQueries();

    partial void OnSelectedOutcomeFilterChanged(string value) => RebuildFilteredQueries();

    partial void OnSelectedRecordTypeFilterChanged(string value) => RebuildFilteredQueries();

    partial void OnOnlySlowQueriesChanged(bool value) => RebuildFilteredQueries();

    partial void OnSelectedAnalyticsCategoryChanged(string value) => RebuildDisplayedAnalytics();

    [RelayCommand]
    private void SelectTab(string tabIndexText)
    {
        if (int.TryParse(tabIndexText, out var idx))
        {
            ActiveTabIndex = Math.Clamp(idx, 0, 2);
            if (ActiveTabIndex == 1 && _serviceClient?.ConnectionState != ServiceConnectionState.Connected)
            {
                ApplyAnalyticsSnapshot(_diagnostics.GetQueryAnalyticsSnapshot(50));
            }
        }
    }

    [RelayCommand]
    private void SelectOutcomeFilter(string outcome)
    {
        SelectedOutcomeFilter = string.IsNullOrWhiteSpace(outcome) ? "All" : outcome;
    }

    [RelayCommand]
    private void SelectAnalyticsCategory(string category)
    {
        SelectedAnalyticsCategory = string.IsNullOrWhiteSpace(category) ? "TopQueried" : category;
    }

    [RelayCommand]
    private void ResetFilters()
    {
        SearchQuery = string.Empty;
        SelectedOutcomeFilter = "All";
        SelectedRecordTypeFilter = "All";
        OnlySlowQueries = false;
    }

    [RelayCommand]
    private void FilterByDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        SearchQuery = domain.Trim();
        SelectedOutcomeFilter = "All";
        SelectedRecordTypeFilter = "All";
        OnlySlowQueries = false;
        ActiveTabIndex = 0;
    }

    [RelayCommand]
    private void ClearMonitor()
    {
        _diagnostics.ClearMonitorEntries();
        _allQueries.Clear();
        _lastSyncedSequenceId = 0;
        QueryEntries.Clear();
        SelectedQuery = null;
        ApplyAnalyticsSnapshot(new QueryAnalyticsSnapshot
        {
            SessionStartedUtc = DateTimeOffset.UtcNow,
            TopQueried = [],
            TopBlocked = [],
            TopFailed = [],
        });
        UpdateFilteredCountSummary();

        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearDiagnosticMonitors));
        }

        ActionFeedback = LocalizationManager.Instance["Monitor_Action_Cleared"];
    }

    [RelayCommand]
    private void ClearFailoverHistory()
    {
        _failover.ClearHistory();
        FailoverEvents.Clear();
    }

    private async Task<bool> TryUpdateSettingsAsync(Action<AppSettings> mutate)
    {
        if (_settings is null)
        {
            return false;
        }

        try
        {
            await _settings.UpdateAsync(mutate).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or InvalidOperationException)
        {
            SetFeedbackOnUi(ex.Message);
            return false;
        }
    }

    [RelayCommand]
    private async Task BlockDomainAsync(string? domain)
    {
        var target = NormalizeActionDomain(domain ?? SelectedQuery?.Domain);
        if (target is null)
        {
            return;
        }

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Filtering.IsFilteringEnabled = true;
            if (!s.Filtering.CustomBlockedDomains.Contains(target, StringComparer.OrdinalIgnoreCase))
            {
                s.Filtering.CustomBlockedDomains.Add(target);
            }

            s.Filtering.Allowlist.RemoveAll(a => string.Equals(a.Domain, target, StringComparison.OrdinalIgnoreCase));
        }).ConfigureAwait(false))
        {
            return;
        }

        await SyncFilteringMutationAsync().ConfigureAwait(false);
        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Blocked"], target));
    }

    [RelayCommand]
    private async Task AllowDomainAsync(string? domain)
    {
        var target = NormalizeActionDomain(domain ?? SelectedQuery?.Domain);
        if (target is null)
        {
            return;
        }

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Filtering.CustomBlockedDomains.RemoveAll(d => string.Equals(d, target, StringComparison.OrdinalIgnoreCase));
            s.Filtering.Allowlist.RemoveAll(a => string.Equals(a.Domain, target, StringComparison.OrdinalIgnoreCase));
            s.Filtering.Allowlist.Add(new DnsAllowlistEntry
            {
                Domain = target,
                Note = "Allowed from Query Explorer",
            });
        }).ConfigureAwait(false))
        {
            return;
        }

        await SyncFilteringMutationAsync().ConfigureAwait(false);
        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Allowed"], target));
    }

    [RelayCommand]
    private async Task AllowDomainTemp30MinAsync(string? domain)
    {
        var target = NormalizeActionDomain(domain ?? SelectedQuery?.Domain);
        if (target is null)
        {
            return;
        }

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Filtering.Allowlist.RemoveAll(a => string.Equals(a.Domain, target, StringComparison.OrdinalIgnoreCase));
            s.Filtering.Allowlist.Add(new DnsAllowlistEntry
            {
                Domain = target,
                Note = "30m exception from Query Explorer",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30),
            });
        }).ConfigureAwait(false))
        {
            return;
        }

        await SyncFilteringMutationAsync().ConfigureAwait(false);
        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Allowed30m"], target));
    }

    [RelayCommand]
    private async Task CreateLocalRewriteAsync()
    {
        var targetDomain = NormalizeActionDomain(SelectedQuery?.Domain);
        var rewriteTarget = InspectorRewriteTarget?.Trim();
        if (targetDomain is null || string.IsNullOrWhiteSpace(rewriteTarget))
        {
            return;
        }

        var recordType = IPAddress.TryParse(rewriteTarget, out var parsedIp)
            ? (parsedIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? LocalDnsRewriteRecordType.AAAA
                : LocalDnsRewriteRecordType.A)
            : LocalDnsRewriteRecordType.CNAME;

        var rule = new LocalDnsRewriteRule
        {
            Id = $"rw-{Guid.NewGuid():N}"[..16],
            Pattern = targetDomain,
            MatchKind = RoutingMatchKind.Exact,
            RecordType = recordType,
            TargetValue = rewriteTarget,
            TtlSeconds = 60,
            IsEnabled = true,
        };

        var validation = LocalDnsRewriteValidator.Validate(rule);
        if (!validation.IsValid)
        {
            ActionFeedback = validation.ErrorMessage ?? "Invalid rewrite target.";
            return;
        }

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Routing.LocalRewrites.RemoveAll(r =>
                string.Equals(r.Pattern, targetDomain, StringComparison.OrdinalIgnoreCase)
                && r.RecordType == recordType);
            s.Routing.LocalRewrites.Add(rule);
        }).ConfigureAwait(false))
        {
            return;
        }

        await SyncConfigToEngineAndServiceAsync().ConfigureAwait(false);
        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Rewritten"], targetDomain, rewriteTarget));
    }

    [RelayCommand]
    private async Task RouteDomainToResolverAsync()
    {
        var targetDomain = NormalizeActionDomain(SelectedQuery?.Domain);
        var resolverId = InspectorTargetResolverId?.Trim();
        if (targetDomain is null || string.IsNullOrWhiteSpace(resolverId))
        {
            return;
        }

        var resolverName = AvailableResolvers.FirstOrDefault(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase))?.Name ?? resolverId;

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Routing.IsRoutingEnabled = true;
            s.Routing.Rules ??= [];
            var activeProfileId = s.Routing.ActiveProfileId;
            s.Routing.Rules.RemoveAll(r =>
                string.Equals(r.ProfileId, activeProfileId, StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.Pattern, targetDomain, StringComparison.OrdinalIgnoreCase));
            s.Routing.Rules.Add(new DnsRoutingRule
            {
                Id = $"rt-{Guid.NewGuid():N}"[..16],
                ProfileId = activeProfileId,
                Name = $"Route {targetDomain}",
                Pattern = targetDomain,
                MatchKind = RoutingMatchKind.DomainSuffix,
                ResolverId = resolverId,
            });
        }).ConfigureAwait(false))
        {
            return;
        }

        await SyncConfigToEngineAndServiceAsync().ConfigureAwait(false);
        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Routed"], targetDomain, resolverName));
    }

    [RelayCommand]
    private async Task AddDomainToDpiBypassAsync(string? domain)
    {
        var targetDomain = NormalizeActionDomain(domain ?? SelectedQuery?.Domain);
        if (targetDomain is null)
        {
            return;
        }

        if (!await TryUpdateSettingsAsync(s =>
        {
            s.Bypass.Rules ??= [];
            if (!s.Bypass.Rules.Any(r => string.Equals(r.Pattern, targetDomain, StringComparison.OrdinalIgnoreCase)))
            {
                s.Bypass.Rules.Add(new BypassRule
                {
                    Id = $"bp-{Guid.NewGuid():N}"[..16],
                    Name = targetDomain,
                    Pattern = targetDomain,
                    MatchKind = RoutingMatchKind.DomainSuffix,
                    Mode = BypassMode.AutoHybrid,
                    Category = "Custom",
                    Enabled = true,
                });
            }
        }).ConfigureAwait(false))
        {
            return;
        }

        if (_settings is not null)
        {
            await _settings.FlushAsync().ConfigureAwait(false);
        }
        if (_bypassEngine is not null && _bypassEngine.GetStats().State is BypassEngineState.Running or BypassEngineState.Degraded)
        {
            try
            {
                await _bypassEngine.RestartAsync().ConfigureAwait(false);
            }
            catch
            {
                // Ignore soft restart failures.
            }
        }

        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration)).ConfigureAwait(false);
        }

        SetFeedbackOnUi(string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_BypassAdded"], targetDomain));
    }

    [RelayCommand]
    private void CopyDomain(string? domain)
    {
        var target = (domain ?? SelectedQuery?.Domain)?.Trim();
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        try
        {
            Clipboard.SetText(target);
            ActionFeedback = string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Copied"], target);
        }
        catch
        {
            // Clipboard locked by another process.
        }
    }

    [RelayCommand]
    private void ExportCsv()
    {
        var isAnalytics = ActiveTabIndex == 1;
        var dialog = new SaveFileDialog
        {
            Title = LocalizationManager.Instance["Monitor_ExportCsv"],
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = isAnalytics
                ? $"justcryptdns-domains-{DateTime.Now:yyyyMMdd-HHmmss}.csv"
                : $"justcryptdns-queries-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };

        if (dialog.ShowDialog() != true)
        {
            return;
        }

        try
        {
            var csv = isAnalytics
                ? CsvExportHelper.SerializeDomainAnalytics(DisplayedDomainAggregates)
                : CsvExportHelper.SerializeQueries(QueryEntries);
            File.WriteAllText(dialog.FileName, csv, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
            var count = isAnalytics ? DisplayedDomainAggregates.Count : QueryEntries.Count;
            ActionFeedback = string.Format(CultureInfo.CurrentCulture, LocalizationManager.Instance["Monitor_Action_Exported"], count, Path.GetFileName(dialog.FileName));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ActionFeedback = ex.Message;
        }
    }

    public void RefreshAll()
    {
        ApplyEngineStats(_dnsEngine.GetStats());

        _allQueries.Clear();
        var entries = _diagnostics.GetMonitorEntries();
        foreach (var entry in entries.Take(MaxLocalQueryBuffer))
        {
            _allQueries.Add(entry);
            if (entry.SequenceId > _lastSyncedSequenceId)
            {
                _lastSyncedSequenceId = entry.SequenceId;
            }
        }

        RebuildFilteredQueries();
        ApplyAnalyticsSnapshot(_diagnostics.GetQueryAnalyticsSnapshot(50));

        FailoverEvents.Clear();
        foreach (var ev in _failover.GetFailoverHistory())
        {
            FailoverEvents.Add(ev);
        }
    }

    private void RefreshAvailableResolvers()
    {
        if (_resolverLibrary is null)
        {
            return;
        }

        AvailableResolvers.Clear();
        foreach (var r in _resolverLibrary.GetEnabled())
        {
            AvailableResolvers.Add(r);
        }

        if (AvailableResolvers.Count > 0 && !AvailableResolvers.Any(r => string.Equals(r.Id, InspectorTargetResolverId, StringComparison.OrdinalIgnoreCase)))
        {
            InspectorTargetResolverId = AvailableResolvers[0].Id;
        }
    }

    private async Task SyncFilteringMutationAsync()
    {
        if (_settings is not null)
        {
            await _settings.FlushAsync().ConfigureAwait(false);
        }

        if (_filtering is not null)
        {
            try
            {
                _filtering.ReloadBlocklistsFromDisk();
            }
            catch
            {
                // Soft fallback.
            }
        }

        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration)).ConfigureAwait(false);
            _ = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadFilteringBlocklists)).ConfigureAwait(false);
        }
    }

    private async Task SyncConfigToEngineAndServiceAsync()
    {
        if (_settings is not null)
        {
            await _settings.FlushAsync().ConfigureAwait(false);
        }

        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration)).ConfigureAwait(false);
        }
    }

    private void SetFeedbackOnUi(string message)
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ActionFeedback = message);
        }
        else
        {
            ActionFeedback = message;
        }
    }

    private static string? NormalizeActionDomain(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var norm = RoutingMatcher.NormalizeDomain(raw);
        return string.IsNullOrWhiteSpace(norm) ? null : norm;
    }

    private void ApplyEngineStats(DnsEngineRuntimeStats stats)
    {
        EngineState = stats.State;
        ActiveResolverName = stats.ActiveResolverName;
        TotalQueries = stats.TotalQueries;
        BlockedQueries = stats.BlockedQueries;
        CacheHitRatioText = string.Create(CultureInfo.InvariantCulture, $"{stats.CacheHitRatioPercent:0.#}%");
        LastLatencyText = stats.LastLatencyMs is { } ms
            ? string.Create(CultureInfo.InvariantCulture, $"{ms:0.#} ms")
            : "—";
    }

    private void ApplyAnalyticsSnapshot(QueryAnalyticsSnapshot snapshot)
    {
        _latestAnalytics = snapshot;
        UniqueDomainsCount = snapshot.UniqueDomainCount;
        FailedQueriesCount = snapshot.TotalFailedQueries;
        QueriesPerMinuteText = string.Create(CultureInfo.InvariantCulture, $"{snapshot.CurrentQueriesPerMinute:0}/m");
        if (snapshot.TotalObservedQueries > TotalQueries)
        {
            TotalQueries = snapshot.TotalObservedQueries;
        }

        RebuildDisplayedAnalytics();
    }

    private void RebuildDisplayedAnalytics()
    {
        IReadOnlyList<DomainQueryAggregate> source = SelectedAnalyticsCategory switch
        {
            "TopBlocked" => _latestAnalytics.TopBlocked,
            "TopFailed" => _latestAnalytics.TopFailed,
            _ => _latestAnalytics.TopQueried,
        };

        DisplayedDomainAggregates.Clear();
        foreach (var item in source)
        {
            DisplayedDomainAggregates.Add(item);
        }
    }

    private bool MatchesCurrentFilter(LiveQueryMonitorEntry entry)
    {
        if (!string.Equals(SelectedOutcomeFilter, "All", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(entry.Outcome, SelectedOutcomeFilter, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(SelectedRecordTypeFilter, "All", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(entry.RecordType, SelectedRecordTypeFilter, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (OnlySlowQueries && (!entry.LatencyMs.HasValue || entry.LatencyMs.Value < 100.0))
        {
            return false;
        }

        var search = SearchQuery?.Trim();
        if (!string.IsNullOrEmpty(search))
        {
            var matched = entry.Domain.Contains(search, StringComparison.OrdinalIgnoreCase)
                || entry.ResolverName.Contains(search, StringComparison.OrdinalIgnoreCase)
                || (entry.AnswerSummary?.Contains(search, StringComparison.OrdinalIgnoreCase) == true)
                || (entry.MatchedRule?.Contains(search, StringComparison.OrdinalIgnoreCase) == true)
                || (entry.ResponseCode?.Contains(search, StringComparison.OrdinalIgnoreCase) == true);
            if (!matched)
            {
                return false;
            }
        }

        return true;
    }

    private void RebuildFilteredQueries()
    {
        QueryEntries.Clear();
        foreach (var entry in _allQueries)
        {
            if (MatchesCurrentFilter(entry))
            {
                QueryEntries.Add(entry);
            }
        }

        UpdateFilteredCountSummary();
    }

    private void UpdateFilteredCountSummary()
    {
        FilteredCountSummary = string.Create(CultureInfo.InvariantCulture, $"{QueryEntries.Count:N0} / {_allQueries.Count:N0}");
    }

    private void OnQueryObserved(object? sender, LiveQueryMonitorEntry entry)
    {
        void Add()
        {
            _allQueries.Insert(0, entry);
            if (entry.SequenceId > _lastSyncedSequenceId)
            {
                _lastSyncedSequenceId = entry.SequenceId;
            }

            while (_allQueries.Count > MaxLocalQueryBuffer)
            {
                _allQueries.RemoveAt(_allQueries.Count - 1);
            }

            if (MatchesCurrentFilter(entry))
            {
                QueryEntries.Insert(0, entry);
                while (QueryEntries.Count > MaxLocalQueryBuffer)
                {
                    QueryEntries.RemoveAt(QueryEntries.Count - 1);
                }
            }

            UpdateFilteredCountSummary();
            if (ActiveTabIndex == 1 || _allQueries.Count % 10 == 0)
            {
                ApplyAnalyticsSnapshot(_diagnostics.GetQueryAnalyticsSnapshot(50));
            }
        }

        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Add);
        }
        else
        {
            Add();
        }
    }

    private void OnFailoverOccurred(object? sender, FailoverEventEntry ev)
    {
        void Add()
        {
            FailoverEvents.Insert(0, ev);
            while (FailoverEvents.Count > 100)
            {
                FailoverEvents.RemoveAt(FailoverEvents.Count - 1);
            }
        }

        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Add);
        }
        else
        {
            Add();
        }
    }

    private void OnEngineStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() => ApplyEngineStats(stats));
        }
        else
        {
            ApplyEngineStats(stats);
        }
    }

    private void OnServiceClientStateChanged(object? sender, EventArgs e)
    {
        void Sync()
        {
            if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
            {
                StartServicePolling();
            }
            else
            {
                StopServicePolling();
            }
        }

        if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(Sync);
        }
        else
        {
            Sync();
        }
    }

    private void StartServicePolling()
    {
        if (_serviceClient?.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        _ = PollServiceStateAsync();
        if (_servicePollTimer is null && Application.Current?.Dispatcher is { } dispatcher)
        {
            _servicePollTimer = new DispatcherTimer(
                TimeSpan.FromSeconds(1.5),
                DispatcherPriority.Background,
                OnServicePollTick,
                dispatcher);
        }

        _servicePollTimer?.Start();
    }

    private void StopServicePolling()
    {
        if (_servicePollTimer is not null)
        {
            _servicePollTimer.Stop();
            _servicePollTimer.Tick -= OnServicePollTick;
            _servicePollTimer = null;
        }
    }

    private void OnServicePollTick(object? sender, EventArgs e) => _ = PollServiceStateAsync();

    private async Task PollServiceStateAsync()
    {
        if (_isServicePollInFlight || _serviceClient?.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        _isServicePollInFlight = true;
        try
        {
            if (_dnsEngine is HybridDnsEngineProxy hybridDns)
            {
                await hybridDns.RefreshFromServiceAsync().ConfigureAwait(false);
            }

            List<LiveQueryMonitorEntry>? deltaQueries = null;
            QueryAnalyticsSnapshot? analytics = null;
            if (!IsPaused)
            {
                var after = _lastSyncedSequenceId;
                var limit = after == 0 ? 1500 : 1000;
                var queriesRes = await _serviceClient
                    .SendAsync(new IpcRequest(IpcRequestKind.GetLiveQueriesSnapshot, StringValue: $"after={after}&limit={limit}"))
                    .ConfigureAwait(false);
                if (queriesRes is { Success: true, Message: not null })
                {
                    deltaQueries = JsonSerializer.Deserialize<List<LiveQueryMonitorEntry>>(queriesRes.Message, SettingsJson.Options);
                }

                var analyticsRes = await _serviceClient
                    .SendAsync(new IpcRequest(IpcRequestKind.GetQueryAnalyticsSnapshot, StringValue: "50"))
                    .ConfigureAwait(false);
                if (analyticsRes is { Success: true, Message: not null })
                {
                    analytics = JsonSerializer.Deserialize<QueryAnalyticsSnapshot>(analyticsRes.Message, SettingsJson.Options);
                }
            }

            List<FailoverEventEntry>? failovers = null;
            var failoverRes = await _serviceClient
                .SendAsync(new IpcRequest(IpcRequestKind.GetFailoverEventsSnapshot))
                .ConfigureAwait(false);
            if (failoverRes is { Success: true, Message: not null })
            {
                failovers = JsonSerializer.Deserialize<List<FailoverEventEntry>>(failoverRes.Message, SettingsJson.Options);
            }

            void ApplyToUi()
            {
                ApplyEngineStats(_dnsEngine.GetStats());

                if (deltaQueries is { Count: > 0 })
                {
                    // deltaQueries is newest-first; insert oldest-to-newest at index 0 to preserve chronological newest-first order.
                    for (var i = deltaQueries.Count - 1; i >= 0; i--)
                    {
                        var item = deltaQueries[i];
                        if (item.SequenceId > 0 && item.SequenceId <= _lastSyncedSequenceId)
                        {
                            continue;
                        }

                        _allQueries.Insert(0, item);
                        if (item.SequenceId > _lastSyncedSequenceId)
                        {
                            _lastSyncedSequenceId = item.SequenceId;
                        }

                        if (MatchesCurrentFilter(item))
                        {
                            QueryEntries.Insert(0, item);
                        }
                    }

                    while (_allQueries.Count > MaxLocalQueryBuffer)
                    {
                        _allQueries.RemoveAt(_allQueries.Count - 1);
                    }

                    while (QueryEntries.Count > MaxLocalQueryBuffer)
                    {
                        QueryEntries.RemoveAt(QueryEntries.Count - 1);
                    }

                    UpdateFilteredCountSummary();
                }

                if (analytics is not null)
                {
                    ApplyAnalyticsSnapshot(analytics);
                }

                if (failovers is not null)
                {
                    FailoverEvents.Clear();
                    foreach (var ev in failovers)
                    {
                        FailoverEvents.Add(ev);
                    }
                }
            }

            if (Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
            {
                await dispatcher.InvokeAsync(ApplyToUi);
            }
            else
            {
                ApplyToUi();
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or JsonException or ObjectDisposedException or InvalidOperationException)
        {
            // Ignore transient IPC polling errors.
        }
        finally
        {
            _isServicePollInFlight = false;
        }
    }
}
