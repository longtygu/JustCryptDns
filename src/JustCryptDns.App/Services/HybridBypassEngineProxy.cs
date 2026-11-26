using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Network.Bypass;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

/// <summary>
/// Unified <see cref="IBypassEngineService"/> adapter that delegates the local smart proxy and PAC server
/// to <c>JustCryptDnsService</c> via IPC when connected, while keeping interactive-user <c>HKCU</c>
/// WinINet Auto-PAC synchronization inside the desktop UI process.
/// </summary>
public sealed class HybridBypassEngineProxy : IBypassEngineService
{
    private readonly BypassEngineService _local;
    private readonly IServiceClient _serviceClient;
    private readonly IWindowsProxyManager _windowsProxy;
    private readonly ISettingsService _settings;
    private readonly ILogger<HybridBypassEngineProxy> _logger;
    private readonly SemaphoreSlim _proxySyncGate = new(1, 1);

    private BypassRuntimeStats? _cachedServiceStats;
    private IReadOnlyList<BypassConnectionEvent> _cachedServiceEvents = [];
    private volatile bool _userProxyAppliedForService;
    private string? _lastAppliedPacUrl;
    private string? _lastAppliedProxyServer;
    private string? _lastAppliedBypassList;
    private WindowsProxyMode? _lastAppliedProxyMode;
    private int _disposed;

    public HybridBypassEngineProxy(
        BypassEngineService local,
        IServiceClient serviceClient,
        IWindowsProxyManager windowsProxy,
        ISettingsService settings,
        ILogger<HybridBypassEngineProxy> logger)
    {
        _local = local;
        _serviceClient = serviceClient;
        _windowsProxy = windowsProxy;
        _settings = settings;
        _logger = logger;

        _local.StateChanged += OnLocalStateChanged;
        _local.ConnectionProcessed += OnLocalConnectionProcessed;
        _serviceClient.StateChanged += OnServiceClientStateChanged;
    }

    public bool IsDelegatingToService => _serviceClient.ConnectionState == ServiceConnectionState.Connected;

    public event EventHandler<BypassRuntimeStats>? StateChanged;

    public event EventHandler<BypassConnectionEvent>? ConnectionProcessed;

    public BypassRuntimeStats GetStats()
    {
        if (!IsDelegatingToService)
        {
            return _local.GetStats();
        }

        var baseStats = Volatile.Read(ref _cachedServiceStats)
            ?? BuildFallbackStatsFromSnapshot(_serviceClient.LastStatus, _local.GetStats());

        return baseStats with
        {
            WindowsProxyApplied = _userProxyAppliedForService || _windowsProxy.HasActiveBackup(),
        };
    }

    public Task<BypassRuntimeStats?> RefreshFromServiceAsync(CancellationToken cancellationToken = default) =>
        RefreshFromServiceAsync(includeEvents: false, cancellationToken);

    public async Task<BypassRuntimeStats?> RefreshFromServiceAsync(
        bool includeEvents,
        CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return null;
        }

        var statsResponse = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.GetBypassDetailedStats), cancellationToken)
            .ConfigureAwait(false);
        if (statsResponse is null)
        {
            return null;
        }

        BypassRuntimeStats? parsedStats = null;
        if (!string.IsNullOrWhiteSpace(statsResponse.Message))
        {
            try
            {
                parsedStats = JsonSerializer.Deserialize<BypassRuntimeStats>(statsResponse.Message, SettingsJson.Options);
            }
            catch (JsonException ex)
            {
                _logger.LogDebug(ex, "Could not deserialize detailed bypass engine stats from service.");
            }
        }

        if (includeEvents)
        {
            var eventsResponse = await _serviceClient
                .SendAsync(new IpcRequest(IpcRequestKind.GetBypassEventsSnapshot), cancellationToken)
                .ConfigureAwait(false);
            if (eventsResponse is { Success: true, Message: not null })
            {
                try
                {
                    var parsedEvents = JsonSerializer.Deserialize<List<BypassConnectionEvent>>(eventsResponse.Message, SettingsJson.Options);
                    if (parsedEvents is not null)
                    {
                        Volatile.Write(ref _cachedServiceEvents, parsedEvents);
                    }
                }
                catch (JsonException ex)
                {
                    _logger.LogDebug(ex, "Could not deserialize bypass events snapshot from service.");
                }
            }
        }

        var resolved = parsedStats ?? BuildFallbackStatsFromSnapshot(statsResponse.Status, _local.GetStats());
        var previous = Interlocked.Exchange(ref _cachedServiceStats, resolved);
        await EnsureUserProxySynchronizedAsync(cancellationToken).ConfigureAwait(false);

        var merged = GetStats();
        if (!Equals(previous, resolved))
        {
            StateChanged?.Invoke(this, merged);
        }

        return merged;
    }

    public async Task EnsureUserProxySynchronizedAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService || !_windowsProxy.CanModifyCurrentUserProxy || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        await _proxySyncGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var changed = false;
        try
        {
            var stats = Volatile.Read(ref _cachedServiceStats)
                ?? BuildFallbackStatsFromSnapshot(_serviceClient.LastStatus, _local.GetStats());
            var bypass = _settings.Current.Bypass;
            var serviceRunning = stats.State is BypassEngineState.Running or BypassEngineState.Degraded;
            var shouldApply = serviceRunning
                && bypass.ApplyWindowsProxyAutomatically
                && bypass.WindowsProxyMode != WindowsProxyMode.ManualOnly;

            if (shouldApply)
            {
                if (bypass.WindowsProxyMode == WindowsProxyMode.AutoPac)
                {
                    if (!_userProxyAppliedForService
                        || _lastAppliedProxyMode != WindowsProxyMode.AutoPac
                        || !string.Equals(_lastAppliedPacUrl, stats.PacUrl, StringComparison.Ordinal)
                        || !_windowsProxy.HasActiveBackup())
                    {
                        var res = await _windowsProxy.ApplyPacProxyAsync(stats.PacUrl, cancellationToken).ConfigureAwait(false);
                        if (res.Success)
                        {
                            _userProxyAppliedForService = true;
                            _lastAppliedPacUrl = stats.PacUrl;
                            _lastAppliedProxyServer = null;
                            _lastAppliedBypassList = null;
                            _lastAppliedProxyMode = WindowsProxyMode.AutoPac;
                            changed = true;
                        }
                    }
                }
                else
                {
                    var bypassList = string.Join(
                        ';',
                        BuiltInBypassRules.DefaultDirectExclusions.Concat(bypass.DirectExclusionDomains ?? []));
                    if (!_userProxyAppliedForService
                        || _lastAppliedProxyMode != bypass.WindowsProxyMode
                        || !string.Equals(_lastAppliedProxyServer, stats.ProxyEndpoint, StringComparison.Ordinal)
                        || !string.Equals(_lastAppliedBypassList, bypassList, StringComparison.Ordinal)
                        || !_windowsProxy.HasActiveBackup())
                    {
                        var res = await _windowsProxy
                            .ApplyManualProxyAsync(stats.ProxyEndpoint, bypassList, cancellationToken)
                            .ConfigureAwait(false);
                        if (res.Success)
                        {
                            _userProxyAppliedForService = true;
                            _lastAppliedPacUrl = null;
                            _lastAppliedProxyServer = stats.ProxyEndpoint;
                            _lastAppliedBypassList = bypassList;
                            _lastAppliedProxyMode = bypass.WindowsProxyMode;
                            changed = true;
                        }
                    }
                }
            }
            else if (_userProxyAppliedForService
                || (_windowsProxy.HasActiveBackup() && stats.State == BypassEngineState.Stopped))
            {
                var res = await _windowsProxy.RestoreOriginalProxyAsync(cancellationToken).ConfigureAwait(false);
                if (res.Success)
                {
                    _userProxyAppliedForService = false;
                    _lastAppliedPacUrl = null;
                    _lastAppliedProxyServer = null;
                    _lastAppliedBypassList = null;
                    _lastAppliedProxyMode = null;
                    changed = true;
                }
            }
        }
        finally
        {
            _proxySyncGate.Release();
        }

        if (changed)
        {
            StateChanged?.Invoke(this, GetStats());
        }
    }

    public async Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.StartAsync(cancellationToken).ConfigureAwait(false);
        }

        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken)
            .ConfigureAwait(false);

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.SetBypassEnabled, BoolValue: true), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            await _local.StopAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.SetBypassEnabled, BoolValue: false), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            return await _local.RestartAsync(cancellationToken).ConfigureAwait(false);
        }

        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken)
            .ConfigureAwait(false);

        var response = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.RestartBypassEngine), cancellationToken)
            .ConfigureAwait(false);

        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
        return response is null
            ? (false, "Background service did not respond.")
            : (response.Success, response.Message);
    }

    public BypassMode ResolveModeForHost(string host) => _local.ResolveModeForHost(host);

    public string GeneratePacScript() => _local.GeneratePacScript();

    public IReadOnlyList<BypassConnectionEvent> GetRecentEvents() =>
        IsDelegatingToService ? Volatile.Read(ref _cachedServiceEvents) : _local.GetRecentEvents();

    public void ClearRecentEvents()
    {
        Volatile.Write(ref _cachedServiceEvents, []);
        _local.ClearRecentEvents();
        if (IsDelegatingToService)
        {
            _ = _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearBypassEvents));
        }
    }

    public Task<BypassTestResult> TestDomainBypassAsync(string host, CancellationToken cancellationToken = default) =>
        _local.TestDomainBypassAsync(host, cancellationToken);

    public Task<(bool Available, string Summary)> DetectCloudflareWarpAsync(CancellationToken cancellationToken = default) =>
        _local.DetectCloudflareWarpAsync(cancellationToken);

    public Task<(bool Success, double LatencyMs, string Summary)> TestUpstreamTunnelAsync(CancellationToken cancellationToken = default) =>
        _local.TestUpstreamTunnelAsync(cancellationToken);

    public IReadOnlyList<BypassRule> GetRules() => _local.GetRules();

    public async Task<(bool Success, BypassRule? Rule, string? Error)> SaveRuleAsync(
        BypassRule rule,
        CancellationToken cancellationToken = default)
    {
        var result = await _local.SaveRuleAsync(rule, cancellationToken).ConfigureAwait(false);
        if (result.Success && IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    public async Task<bool> DeleteRuleAsync(string ruleId, CancellationToken cancellationToken = default)
    {
        var removed = await _local.DeleteRuleAsync(ruleId, cancellationToken).ConfigureAwait(false);
        if (removed && IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }

        return removed;
    }

    public async Task SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken cancellationToken = default)
    {
        await _local.SetRuleEnabledAsync(ruleId, enabled, cancellationToken).ConfigureAwait(false);
        if (IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task ResetBuiltInRulesAsync(CancellationToken cancellationToken = default)
    {
        await _local.ResetBuiltInRulesAsync(cancellationToken).ConfigureAwait(false);
        if (IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public IReadOnlyList<string> GetDirectExclusions() => _local.GetDirectExclusions();

    public async Task<(bool Success, string? Error)> AddDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default)
    {
        var result = await _local.AddDirectExclusionAsync(pattern, cancellationToken).ConfigureAwait(false);
        if (result.Success && IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    public async Task<bool> RemoveDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default)
    {
        var removed = await _local.RemoveDirectExclusionAsync(pattern, cancellationToken).ConfigureAwait(false);
        if (removed && IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }

        return removed;
    }

    public IReadOnlyList<LearnedHostEntry> GetLearnedHosts() => _local.GetLearnedHosts();

    public void ClearLearnedHosts()
    {
        _local.ClearLearnedHosts();
        if (IsDelegatingToService)
        {
            _ = _serviceClient.SendAsync(new IpcRequest(IpcRequestKind.ClearLearnedHosts));
        }
    }

    public async Task<(bool Success, string? Error)> PromoteLearnedHostAsync(
        string host,
        LearnedHostStrategy strategy,
        CancellationToken cancellationToken = default)
    {
        var result = await _local.PromoteLearnedHostAsync(host, strategy, cancellationToken).ConfigureAwait(false);
        if (result.Success && IsDelegatingToService)
        {
            await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    public async Task RefreshSystemPacAsync(CancellationToken cancellationToken = default)
    {
        if (!IsDelegatingToService)
        {
            await _local.RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        await SyncConfigurationWithServiceAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task<IReadOnlyList<BypassTestResult>> TestMultipleDomainsAsync(
        IEnumerable<string> hosts,
        CancellationToken cancellationToken = default) =>
        _local.TestMultipleDomainsAsync(hosts, cancellationToken);

    /// <summary>Stops only the in-process fallback proxy if it was somehow started.</summary>
    public async Task StopLocalFallbackOnlyAsync(CancellationToken cancellationToken = default)
    {
        if (_local.GetStats().State != BypassEngineState.Stopped)
        {
            await _local.StopAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _local.StateChanged -= OnLocalStateChanged;
        _local.ConnectionProcessed -= OnLocalConnectionProcessed;
        _serviceClient.StateChanged -= OnServiceClientStateChanged;
        await _local.DisposeAsync().ConfigureAwait(false);
        _proxySyncGate.Dispose();
    }

    private async Task SyncConfigurationWithServiceAsync(CancellationToken cancellationToken)
    {
        await _settings.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = await _serviceClient
            .SendAsync(new IpcRequest(IpcRequestKind.ReloadConfiguration), cancellationToken)
            .ConfigureAwait(false);
        await RefreshFromServiceAsync(cancellationToken).ConfigureAwait(false);
    }

    private void OnLocalStateChanged(object? sender, BypassRuntimeStats stats)
    {
        if (!IsDelegatingToService)
        {
            StateChanged?.Invoke(this, stats);
        }
    }

    private void OnLocalConnectionProcessed(object? sender, BypassConnectionEvent ev)
    {
        if (!IsDelegatingToService)
        {
            ConnectionProcessed?.Invoke(this, ev);
        }
    }

    private void OnServiceClientStateChanged(object? sender, EventArgs e)
    {
        if (!IsDelegatingToService)
        {
            Volatile.Write(ref _cachedServiceStats, null);
        }

        StateChanged?.Invoke(this, GetStats());
    }

    private static BypassRuntimeStats BuildFallbackStatsFromSnapshot(
        ServiceStatusSnapshot? snap,
        BypassRuntimeStats localFallback)
    {
        if (snap is null)
        {
            return localFallback;
        }

        var endpoint = string.IsNullOrWhiteSpace(snap.BypassEndpoint)
            ? localFallback.ProxyEndpoint
            : snap.BypassEndpoint;

        return localFallback with
        {
            State = snap.IsBypassRunning ? BypassEngineState.Running : BypassEngineState.Stopped,
            ProxyEndpoint = endpoint,
            PacUrl = string.IsNullOrWhiteSpace(snap.BypassPacUrl) ? localFallback.PacUrl : snap.BypassPacUrl,
            BoundProxyPort = snap.BoundProxyPort > 0 ? snap.BoundProxyPort : localFallback.BoundProxyPort,
            BoundPacPort = snap.BoundPacPort > 0 ? snap.BoundPacPort : localFallback.BoundPacPort,
            DpiBypassedConnections = snap.DpiBypassedConnections,
        };
    }
}
