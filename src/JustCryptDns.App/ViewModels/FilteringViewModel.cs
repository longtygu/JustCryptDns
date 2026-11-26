using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed class BlocklistItemViewModel
{
    public BlocklistItemViewModel(DnsBlocklistSource source)
    {
        Source = source;
    }

    public DnsBlocklistSource Source { get; }

    public string Id => Source.Id;

    public string Name => Source.Name;

    public string CategoryKey => $"BlockCat_{Source.Category}";

    public int DomainCount => Source.DomainCount;

    public bool IsEnabled => Source.IsEnabled;

    public bool HasRemoteUrl => !string.IsNullOrWhiteSpace(Source.SourceUrl);

    public string LastUpdatedText => Source.LastUpdatedAt is { } ts
        ? ts.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.CurrentCulture)
        : "Seed / Offline";
}

public sealed partial class FilteringViewModel : PageViewModel
{
    private readonly IDnsFilteringService _filtering;
    private readonly IDnsCacheService _cache;
    private readonly ISettingsService? _settings;
    private readonly IServiceClient? _serviceClient;
    private bool _loading;
    private bool _isShellSuspended;
    private bool _needsRefreshOnResume;

    [ObservableProperty] private bool _isFilteringEnabled = true;
    [ObservableProperty] private int _totalBlockedDomains;
    [ObservableProperty] private long _blockedQueryCount;
    [ObservableProperty] private string _newAllowDomain = string.Empty;
    [ObservableProperty] private bool _isTemporaryException;
    [ObservableProperty] private string _newBlockedDomain = string.Empty;
    [ObservableProperty] private string _inspectDomainInput = "ad.doubleclick.net";
    [ObservableProperty] private string? _lastInspectSummary;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _statusMessage;
    [ObservableProperty] private string? _errorMessage;

    // Cache stats & batch-2 knobs
    [ObservableProperty] private bool _isCacheEnabled = true;
    [ObservableProperty] private bool _enableServeStale = true;
    [ObservableProperty] private bool _enablePrefetch = true;
    [ObservableProperty] private int _cacheCurrentEntries;
    [ObservableProperty] private int _cacheMaxEntries = 4096;
    [ObservableProperty] private long _cacheHits;
    [ObservableProperty] private long _cacheMisses;
    [ObservableProperty] private long _cachePositiveEntries;
    [ObservableProperty] private long _cacheNegativeEntries;
    [ObservableProperty] private long _cacheStaleHits;
    [ObservableProperty] private long _cachePrefetchCount;
    [ObservableProperty] private string _cacheHitRatioText = "0%";

    public FilteringViewModel(
        IDnsFilteringService filtering,
        IDnsCacheService cache,
        ISettingsService? settings = null,
        IServiceClient? serviceClient = null)
        : base("Nav_Filtering", "Page_Filtering_Subtitle")
    {
        _filtering = filtering;
        _cache = cache;
        _settings = settings;
        _serviceClient = serviceClient;

        RefreshAll();
    }

    public ObservableCollection<BlocklistItemViewModel> Blocklists { get; } = [];

    public ObservableCollection<DnsAllowlistEntry> AllowlistEntries { get; } = [];

    public ObservableCollection<string> CustomBlockedDomains { get; } = [];

    public ObservableCollection<FilterLogEntry> RecentLogs { get; } = [];

    public override void OnNavigatedTo()
    {
        _filtering.FilteringChanged -= OnFilteringChanged;
        _filtering.FilteringChanged += OnFilteringChanged;
        _filtering.DecisionLogged -= OnDecisionLogged;
        _filtering.DecisionLogged += OnDecisionLogged;
        _cache.StatsChanged -= OnCacheStatsChanged;
        _cache.StatsChanged += OnCacheStatsChanged;
        if (!_isShellSuspended)
        {
            RefreshAll();
            _needsRefreshOnResume = false;
            _ = SyncServiceStatsAsync();
        }
    }

    public override void OnShellSuspended()
    {
        _isShellSuspended = true;
    }

    public override void OnShellResumed()
    {
        _isShellSuspended = false;
        if (_needsRefreshOnResume)
        {
            _needsRefreshOnResume = false;
            RefreshAll();
            _ = SyncServiceStatsAsync();
        }
    }

    public override void OnNavigatedFrom()
    {
        _filtering.FilteringChanged -= OnFilteringChanged;
        _filtering.DecisionLogged -= OnDecisionLogged;
        _cache.StatsChanged -= OnCacheStatsChanged;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _filtering.FilteringChanged -= OnFilteringChanged;
            _filtering.DecisionLogged -= OnDecisionLogged;
            _cache.StatsChanged -= OnCacheStatsChanged;
        }

        base.Dispose(disposing);
    }

    partial void OnIsFilteringEnabledChanged(bool value)
    {
        if (!_loading)
        {
            _ = _filtering.SetFilteringEnabledAsync(value);
        }
    }

    partial void OnIsCacheEnabledChanged(bool value)
    {
        if (!_loading)
        {
            _ = _cache.SetEnabledAsync(value);
        }
    }

    partial void OnEnableServeStaleChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings?.UpdateAsync(s => s.Cache.EnableServeStale = value);
        }
    }

    partial void OnEnablePrefetchChanged(bool value)
    {
        if (!_loading)
        {
            _ = _settings?.UpdateAsync(s => s.Cache.EnablePrefetch = value);
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ToggleListEnabledAsync(BlocklistItemViewModel? item)
    {
        if (item is null)
        {
            return;
        }

        await _filtering.SetBlocklistEnabledAsync(item.Id, !item.IsEnabled);
        await NotifyServiceFilteringChangedAsync();
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task UpdateSingleListAsync(BlocklistItemViewModel? item)
    {
        if (item is null || !item.HasRemoteUrl)
        {
            return;
        }

        IsBusy = true;
        try
        {
            var (ok, count, err) = await _filtering.UpdateBlocklistAsync(item.Id);
            if (ok)
            {
                await NotifyServiceFilteringChangedAsync();
                ErrorMessage = null;
                StatusMessage = LocalizationManager.Instance.Format("Filtering_Msg_ListUpdated", item.Name, count);
                RefreshAll();
            }
            else
            {
                ErrorMessage = $"{item.Name}: {err}";
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task UpdateAllListsAsync()
    {
        IsBusy = true;
        try
        {
            var (updated, total) = await _filtering.UpdateAllEnabledBlocklistsAsync();
            await NotifyServiceFilteringChangedAsync();
            ErrorMessage = null;
            StatusMessage = LocalizationManager.Instance.Format("Filtering_Msg_AllUpdated", updated, total);
            RefreshAll();
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task ImportHostsFileAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Hosts / Domain List (*.txt;hosts)|*.txt;hosts|All Files (*.*)|*.*",
        };

        if (dialog.ShowDialog() == true)
        {
            var content = await File.ReadAllTextAsync(dialog.FileName);
            var (ok, count, err) = await _filtering.ImportHostsTextAsync(content, Path.GetFileNameWithoutExtension(dialog.FileName));
            if (ok)
            {
                await NotifyServiceFilteringChangedAsync();
                ErrorMessage = null;
                StatusMessage = LocalizationManager.Instance.Format("Filtering_Msg_HostsImported", count);
                RefreshAll();
            }
            else
            {
                ErrorMessage = err;
            }
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddAllowDomainAsync()
    {
        if (string.IsNullOrWhiteSpace(NewAllowDomain))
        {
            return;
        }

        TimeSpan? duration = IsTemporaryException ? TimeSpan.FromMinutes(30) : null;
        var ok = await _filtering.AddAllowlistEntryAsync(NewAllowDomain, IsTemporaryException ? "30m temp" : "User allowlist", duration);
        if (ok)
        {
            NewAllowDomain = string.Empty;
            RefreshAll();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveAllowDomainAsync(DnsAllowlistEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        await _filtering.RemoveAllowlistEntryAsync(entry.Domain);
        RefreshAll();
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task AddBlockedDomainAsync()
    {
        if (string.IsNullOrWhiteSpace(NewBlockedDomain))
        {
            return;
        }

        var norm = RoutingMatcher.NormalizeDomain(NewBlockedDomain);
        if (EssentialWindowsDomains.IsProtected(norm))
        {
            ErrorMessage = LocalizationManager.Instance.Format("Filtering_Err_ProtectedDomain", norm);
            return;
        }

        if (await _filtering.AddCustomBlockedDomainAsync(norm))
        {
            NewBlockedDomain = string.Empty;
            ErrorMessage = null;
            RefreshAll();
        }
    }

    [RelayCommand(AllowConcurrentExecutions = false)]
    private async Task RemoveBlockedDomainAsync(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        await _filtering.RemoveCustomBlockedDomainAsync(domain);
        RefreshAll();
    }

    [RelayCommand]
    private void InspectDomain()
    {
        if (string.IsNullOrWhiteSpace(InspectDomainInput))
        {
            return;
        }

        var decision = _filtering.EvaluateDomain(InspectDomainInput, recordStats: false);
        LastInspectSummary = $"{decision.Action}: {decision.Reason}";
    }

    [RelayCommand]
    private void ClearCache()
    {
        _cache.Clear();
        ApplyCacheStats(_cache.GetStats());
        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = ClearServiceCacheAsync();
        }

        StatusMessage = LocalizationManager.Instance["Filtering_Msg_CacheCleared"];
    }

    [RelayCommand]
    private void ClearLogs()
    {
        _filtering.ClearLogs();
        RefreshLogs();
        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            _ = _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearDiagnosticMonitors));
        }
    }

    private async Task ClearServiceCacheAsync()
    {
        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearDnsCache)).ConfigureAwait(false);
            await SyncServiceStatsAsync().ConfigureAwait(false);
        }
    }

    private async Task NotifyServiceFilteringChangedAsync()
    {
        if (_serviceClient?.ConnectionState == ServiceConnectionState.Connected)
        {
            if (_settings is not null)
            {
                await _settings.FlushAsync().ConfigureAwait(false);
            }

            await _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ReloadFilteringBlocklists)).ConfigureAwait(false);
            await SyncServiceStatsAsync().ConfigureAwait(false);
        }
    }

    private async Task SyncServiceStatsAsync()
    {
        if (_serviceClient?.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        try
        {
            var res = await _serviceClient
                .SendAsync(new IpcRequest(IpcRequestKind.GetFilterAndCacheStats))
                .ConfigureAwait(false);
            if (res is not { Success: true, Message: not null })
            {
                return;
            }

            var snap = JsonSerializer.Deserialize<ServiceFilterAndCacheSnapshot>(res.Message, SettingsJson.Options);
            if (snap is null)
            {
                return;
            }

            void Apply()
            {
                if (snap.CacheStats is not null)
                {
                    ApplyCacheStats(snap.CacheStats);
                }

                BlockedQueryCount = snap.BlockedQueryCount;
                if (snap.TotalBlockedDomains > 0)
                {
                    TotalBlockedDomains = snap.TotalBlockedDomains;
                }

                if (snap.RecentFilterLogs is { Count: > 0 })
                {
                    RecentLogs.Clear();
                    foreach (var entry in snap.RecentFilterLogs)
                    {
                        RecentLogs.Add(entry);
                    }
                }
            }

            if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
            {
                await dispatcher.InvokeAsync(Apply);
            }
            else
            {
                Apply();
            }
        }
        catch
        {
        }
    }

    public void RefreshAll()
    {
        _loading = true;
        try
        {
            IsFilteringEnabled = _filtering.IsFilteringEnabled;
            TotalBlockedDomains = _filtering.TotalBlockedDomains;
            BlockedQueryCount = _filtering.BlockedQueryCount;

            Blocklists.Clear();
            foreach (var list in _filtering.GetBlocklists())
            {
                Blocklists.Add(new BlocklistItemViewModel(list));
            }

            AllowlistEntries.Clear();
            foreach (var a in _filtering.GetAllowlist())
            {
                AllowlistEntries.Add(a);
            }

            CustomBlockedDomains.Clear();
            foreach (var d in _filtering.GetCustomBlockedDomains())
            {
                CustomBlockedDomains.Add(d);
            }

            EnableServeStale = _settings?.Current.Cache.EnableServeStale ?? true;
            EnablePrefetch = _settings?.Current.Cache.EnablePrefetch ?? true;

            ApplyCacheStats(_cache.GetStats());
            RefreshLogs();
        }
        finally
        {
            _loading = false;
        }
    }

    private void ApplyCacheStats(DnsCacheStats stats)
    {
        _loading = true;
        IsCacheEnabled = stats.IsEnabled;
        _loading = false;

        CacheCurrentEntries = stats.CurrentEntries;
        CacheMaxEntries = stats.MaxEntries;
        CacheHits = stats.CacheHits;
        CacheMisses = stats.CacheMisses;
        CachePositiveEntries = stats.PositiveEntries;
        CacheNegativeEntries = stats.NegativeEntries;
        CacheStaleHits = stats.StaleHits;
        CachePrefetchCount = stats.PrefetchCount;
        CacheHitRatioText = string.Create(CultureInfo.InvariantCulture, $"{stats.HitRatioPercent:0.#}%");
    }

    private void RefreshLogs()
    {
        RecentLogs.Clear();
        foreach (var entry in _filtering.GetRecentLogs())
        {
            RecentLogs.Add(entry);
        }
    }

    private void OnFilteringChanged(object? sender, EventArgs e)
    {
        if (_isShellSuspended)
        {
            _needsRefreshOnResume = true;
            return;
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() =>
            {
                if (_isShellSuspended)
                {
                    _needsRefreshOnResume = true;
                    return;
                }

                RefreshAll();
            });
        }
        else
        {
            RefreshAll();
        }
    }

    private void OnDecisionLogged(object? sender, FilterLogEntry e)
    {
        if (_isShellSuspended)
        {
            _needsRefreshOnResume = true;
            return;
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() =>
            {
                if (_isShellSuspended)
                {
                    _needsRefreshOnResume = true;
                    return;
                }

                BlockedQueryCount = _filtering.BlockedQueryCount;
                RefreshLogs();
            });
        }
        else
        {
            BlockedQueryCount = _filtering.BlockedQueryCount;
            RefreshLogs();
        }
    }

    private void OnCacheStatsChanged(object? sender, DnsCacheStats stats)
    {
        if (_isShellSuspended)
        {
            _needsRefreshOnResume = true;
            return;
        }

        if (System.Windows.Application.Current?.Dispatcher is { } dispatcher && !dispatcher.CheckAccess())
        {
            dispatcher.BeginInvoke(() =>
            {
                if (_isShellSuspended)
                {
                    _needsRefreshOnResume = true;
                    return;
                }

                ApplyCacheStats(stats);
            });
        }
        else
        {
            ApplyCacheStats(stats);
        }
    }
}
