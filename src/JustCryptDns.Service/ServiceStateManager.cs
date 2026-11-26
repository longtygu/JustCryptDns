using System.Net;
using System.Reflection;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.Proxy;
using JustCryptDns.Infrastructure.Logging;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Service;

/// <summary>
/// Maintains the live state of the independent background service, drives <see cref="IDnsEngine"/>,
/// <see cref="IGamingEngineService"/>, and <see cref="IBypassEngineService"/>, and handles local IPC requests.
/// </summary>
public sealed class ServiceStateManager : IServiceIpcHandler
{
    private readonly ISettingsService _settings;
    private readonly IDnsEngine _dnsEngine;
    private readonly IWindowsDnsManager _windowsDns;
    private readonly IGamingEngineService? _gamingEngine;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly IWindowsFirewallManager? _firewallManager;
    private readonly IDnsReverseLookupCache? _reverseLookupCache;
    private readonly INetworkInfoService? _networkInfo;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly INetworkDiagnosticsService? _diagnostics;
    private readonly IDnsFailoverService? _failover;
    private readonly IDnsFilteringService? _filtering;
    private readonly IDnsCacheService? _cache;
    private readonly IDnsCryptProxyManager? _dnsCryptManager;
    private readonly ILogger<ServiceStateManager> _logger;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly string _version;
    private readonly object _sync = new();

    private bool _gamingModeEnabled;

    public ServiceStateManager(
        ISettingsService settings,
        IDnsEngine dnsEngine,
        IWindowsDnsManager windowsDns,
        ILogger<ServiceStateManager> logger,
        IGamingEngineService? gamingEngine = null,
        IBypassEngineService? bypassEngine = null,
        IWindowsFirewallManager? firewallManager = null,
        IDnsReverseLookupCache? reverseLookupCache = null,
        INetworkInfoService? networkInfo = null,
        IResolverLibraryService? resolverLibrary = null,
        INetworkDiagnosticsService? diagnostics = null,
        IDnsFailoverService? failover = null,
        IDnsFilteringService? filtering = null,
        IDnsCacheService? cache = null,
        IDnsCryptProxyManager? dnsCryptManager = null)
    {
        _settings = settings;
        _dnsEngine = dnsEngine;
        _windowsDns = windowsDns;
        _logger = logger;
        _gamingEngine = gamingEngine;
        _bypassEngine = bypassEngine;
        _firewallManager = firewallManager;
        _reverseLookupCache = reverseLookupCache;
        _networkInfo = networkInfo;
        _resolverLibrary = resolverLibrary;
        _diagnostics = diagnostics;
        _failover = failover;
        _filtering = filtering;
        _cache = cache;
        _dnsCryptManager = dnsCryptManager;
        _version = typeof(ServiceStateManager).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "1.8.6";
    }

    public async Task InitializeFromSettingsAsync(CancellationToken cancellationToken = default)
    {
        var current = _settings.Current;
        lock (_sync)
        {
            _gamingModeEnabled = current.General.EnableGamingModeOnStartup || (_gamingEngine?.IsGamingModeEnabled ?? false);
        }

        if (current.General.EnableGamingModeOnStartup && _gamingEngine is not null)
        {
            await _gamingEngine.SetGamingModeAsync(true, cancellationToken).ConfigureAwait(false);
        }

        // Crash recovery check: if an adapter backup was left active from an unclean shutdown, restore it first.
        await _windowsDns.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "Service initialized from settings (autoStartDns={AutoStart}, autoBypass={AutoBypass}, leakGuard={LeakGuard}, gamingOnStartup={Gaming})",
            current.General.AutoStartDnsEngine,
            current.Bypass.IsBypassEnabled && current.Bypass.AutoStartWithDnsEngine,
            current.Connections.EnableDnsLeakGuard,
            current.General.EnableGamingModeOnStartup);

        if (current.General.AutoStartDnsEngine)
        {
            var dns = current.Dns;
            if (string.Equals(dns.ListenAddress, DnsSettings.DefaultListenAddress, StringComparison.OrdinalIgnoreCase)
                && dns.ListenPort == DnsSettings.DefaultListenPort
                && PortConflictDetector.CheckConflict(IPAddress.Loopback, 53) is not null
                && PortConflictDetector.FindAvailableLoopbackForPort53(IPAddress.Loopback) is { } altIp)
            {
                _logger.LogInformation("Service startup: Port 53 on 127.0.0.1 is busy; auto-selecting alternate loopback {AltIp}:53.", altIp);
                await _settings.UpdateAsync(s =>
                {
                    s.Dns.ListenAddress = altIp;
                    s.Dns.EnableIpv6 = false;
                    s.Dns.ConfigureWindowsAdapter = true;
                }, cancellationToken).ConfigureAwait(false);
                current = _settings.Current;
            }

            var (ok, err) = await _dnsEngine.StartAsync(cancellationToken).ConfigureAwait(false);
            if (!ok)
            {
                _logger.LogWarning("Auto-start DNS engine did not succeed: {Error}", err);
            }
            else
            {
                if (current.Bypass.IsBypassEnabled && current.Bypass.AutoStartWithDnsEngine && _bypassEngine is not null)
                {
                    var (bypassOk, bypassErr) = await _bypassEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                    if (!bypassOk)
                    {
                        _logger.LogWarning("Auto-start Bypass engine did not succeed: {Error}", bypassErr);
                    }
                }

                await ReapplySecurityShieldOnStartupAsync(current, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task ReapplySecurityShieldOnStartupAsync(AppSettings current, CancellationToken cancellationToken)
    {
        var conn = current.Connections;
        if (_firewallManager is null || !conn.EnableDnsLeakGuard)
        {
            return;
        }

        try
        {
            var allowedIps = BuildAllowedResolverIps();
            var protectedContext = ProtectedIpContext.Build(
                _networkInfo?.GetSnapshot(),
                _resolverLibrary?.GetAll(),
                current.Dns,
                current.Bypass,
                _reverseLookupCache);
            var payload = new FirewallSyncRequestPayload(
                conn.BlockedRules,
                conn.BlockedApps,
                EnableDnsLeakGuard: true,
                EnableEmergencyLockdown: false,
                AllowedDnsResolverIps: allowedIps);
            var result = await _firewallManager.SyncSecurityPoliciesAsync(payload, protectedContext, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation(
                "Startup Security Shield sync (LeakGuard=true): success={Success}, message={Message}",
                result.Success,
                result.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Startup Security Shield auto-sync failed safely.");
        }
    }

    private List<string> BuildAllowedResolverIps()
    {
        var ips = new List<string>();
        if (_resolverLibrary is not null)
        {
            foreach (var r in new[] { _resolverLibrary.GetPrimaryResolver(), _resolverLibrary.GetSecondaryResolver() })
            {
                if (!string.IsNullOrWhiteSpace(r.PrimaryIp)) ips.Add(r.PrimaryIp);
                if (!string.IsNullOrWhiteSpace(r.SecondaryIp)) ips.Add(r.SecondaryIp);
                if (!string.IsNullOrWhiteSpace(r.PrimaryIpv6)) ips.Add(r.PrimaryIpv6);
            }
        }

        return ips;
    }

    public ServiceStatusSnapshot GetSnapshot() =>
        BuildSnapshot(_dnsEngine.GetStats(), _bypassEngine?.GetStats());

    private ServiceStatusSnapshot BuildSnapshot(DnsEngineRuntimeStats stats, BypassRuntimeStats? bypassStats)
    {
        bool gaming;
        lock (_sync)
        {
            gaming = _gamingEngine?.IsGamingModeEnabled ?? _gamingModeEnabled;
        }

        return new ServiceStatusSnapshot
        {
            ServiceVersion = _version,
            StartedAt = _startedAt,
            EngineState = stats.State,
            IsEngineImplemented = true,
            IsEngineEnabled = stats.State is DnsEngineState.Running or DnsEngineState.Degraded or DnsEngineState.Starting,
            IsGamingModeEnabled = gaming,
            ActiveResolverId = stats.ActiveResolverId,
            ActiveResolverName = stats.ActiveResolverName,
            ActiveProtocol = stats.ActiveProtocol.ToString(),
            ListenEndpoint = stats.ListenEndpoint,
            TotalQueries = stats.TotalQueries,
            LastLatencyMs = stats.LastLatencyMs,
            HasAdapterBackup = stats.HasAdapterBackup,
            LastError = stats.LastError,
            IsBypassRunning = bypassStats?.State is BypassEngineState.Running or BypassEngineState.Degraded,
            BypassEndpoint = bypassStats?.ProxyEndpoint,
            DpiBypassedConnections = bypassStats?.DpiBypassedConnections ?? 0,
            BypassPacUrl = bypassStats?.PacUrl,
            BoundProxyPort = bypassStats?.BoundProxyPort ?? 0,
            BoundPacPort = bypassStats?.BoundPacPort ?? 0,
            BlockedQueries = stats.BlockedQueries,
            CacheHits = stats.CacheHits,
            CacheHitRatioPercent = stats.CacheHitRatioPercent,
            RewrittenQueries = stats.RewrittenQueries,
            StaleCacheHits = stats.StaleCacheHits,
            PrefetchCount = stats.PrefetchCount,
            ActiveVpnAdapterName = stats.ActiveVpnAdapterName,
            IsCaptivePortalPaused = stats.IsCaptivePortalPaused,
            BlockedQueriesPerMinute = _diagnostics?.GetBlockedQueriesPerMinute() ?? 0,
        };
    }

    public async Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        switch (request.Kind)
        {
            case IpcRequestKind.GetStatus:
                return new IpcResponse(Success: true, Status: GetSnapshot());

            case IpcRequestKind.SetEngineEnabled:
            {
                var enable = request.BoolValue ?? true;
                if (enable)
                {
                    var (ok, err) = await _dnsEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                    return new IpcResponse(ok, GetSnapshot(), ok ? null : "EngineStartFailed", err);
                }

                await _dnsEngine.StopAsync(cancellationToken).ConfigureAwait(false);
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.RestartEngine:
            {
                var (ok, err) = await _dnsEngine.RestartAsync(cancellationToken).ConfigureAwait(false);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "EngineRestartFailed", err);
            }

            case IpcRequestKind.ReloadConfiguration:
            {
                await _settings.ReloadFromDiskAsync(cancellationToken).ConfigureAwait(false);
                LoggingSetup.SetLevel(_settings.Current.Performance.LogLevel);
                _filtering?.ReloadBlocklistsFromDisk();

                if (!string.IsNullOrWhiteSpace(request.StringValue))
                {
                    var (ok, err) = await _dnsEngine.SwitchResolverAsync(request.StringValue, cancellationToken).ConfigureAwait(false);
                    return new IpcResponse(ok, GetSnapshot(), ok ? null : "SwitchResolverFailed", err);
                }

                var configuredResolverId = _settings.Current.Dns.ActiveResolverId;
                var currentStats = _dnsEngine.GetStats();
                if (!string.IsNullOrWhiteSpace(configuredResolverId)
                    && !string.Equals(configuredResolverId, currentStats.ActiveResolverId, StringComparison.OrdinalIgnoreCase))
                {
                    _ = await _dnsEngine.SwitchResolverAsync(configuredResolverId, cancellationToken).ConfigureAwait(false);
                }

                if (_bypassEngine is not null
                    && _bypassEngine.GetStats().State is BypassEngineState.Running or BypassEngineState.Degraded)
                {
                    await _bypassEngine.RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
                }

                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.SetGamingMode:
            {
                var enableGaming = request.BoolValue ?? false;
                var ok = true;
                string? err = null;
                if (_gamingEngine is not null)
                {
                    (ok, err) = await _gamingEngine.SetGamingModeAsync(enableGaming, cancellationToken).ConfigureAwait(false);
                }

                if (ok)
                {
                    lock (_sync)
                    {
                        _gamingModeEnabled = enableGaming;
                    }
                }

                _logger.LogInformation("IPC SetGamingMode({Enabled}) -> ok={Ok}.", enableGaming, ok);
                return new IpcResponse(Success: ok, Status: GetSnapshot(), ErrorCode: ok ? null : "SetGamingModeFailed", Message: err);
            }

            case IpcRequestKind.SetBypassEnabled:
            {
                if (_bypassEngine is null)
                {
                    return new IpcResponse(Success: false, Status: GetSnapshot(), ErrorCode: "BypassUnavailable", Message: "Bypass engine is not registered.");
                }

                var enable = request.BoolValue ?? true;
                if (enable)
                {
                    var (ok, err) = await _bypassEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                    return new IpcResponse(ok, GetSnapshot(), ok ? null : "BypassStartFailed", err);
                }

                await _bypassEngine.StopAsync(cancellationToken).ConfigureAwait(false);
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.RestoreOriginalDns:
            {
                var result = await _windowsDns.RestoreOriginalDnsAsync(null, cancellationToken).ConfigureAwait(false);
                return new IpcResponse(
                    Success: result.Success,
                    Status: GetSnapshot(),
                    ErrorCode: result.Success ? null : "RestoreFailed",
                    Message: result.ErrorMessage);
            }

            case IpcRequestKind.SyncFirewallBlocklist:
            {
                if (_firewallManager is null)
                {
                    return new IpcResponse(false, GetSnapshot(), "FirewallUnavailable", "Windows Firewall manager is not registered.");
                }

                FirewallSyncRequestPayload? payload = null;
                if (!string.IsNullOrWhiteSpace(request.StringValue))
                {
                    payload = JsonSerializer.Deserialize<FirewallSyncRequestPayload>(request.StringValue, SettingsJson.Options);
                }

                payload ??= new FirewallSyncRequestPayload([]);
                if (payload.EnableDnsLeakGuard && (payload.AllowedDnsResolverIps is null || payload.AllowedDnsResolverIps.Count == 0))
                {
                    var ips = new List<string>();
                    if (_resolverLibrary is not null)
                    {
                        foreach (var r in new[] { _resolverLibrary.GetPrimaryResolver(), _resolverLibrary.GetSecondaryResolver() })
                        {
                            if (!string.IsNullOrWhiteSpace(r.PrimaryIp)) ips.Add(r.PrimaryIp);
                            if (!string.IsNullOrWhiteSpace(r.SecondaryIp)) ips.Add(r.SecondaryIp);
                            if (!string.IsNullOrWhiteSpace(r.PrimaryIpv6)) ips.Add(r.PrimaryIpv6);
                        }
                    }

                    payload = payload with { AllowedDnsResolverIps = ips };
                }

                var protectedContext = ProtectedIpContext.Build(
                    _networkInfo?.GetSnapshot(),
                    _resolverLibrary?.GetAll(),
                    _settings.Current.Dns,
                    _settings.Current.Bypass,
                    _reverseLookupCache);
                var result = await _firewallManager.SyncSecurityPoliciesAsync(payload, protectedContext, cancellationToken).ConfigureAwait(false);
                var json = JsonSerializer.Serialize(result, SettingsJson.Options);
                return new IpcResponse(
                    Success: result.Success,
                    Status: GetSnapshot(),
                    ErrorCode: result.Success ? null : "FirewallSyncFailed",
                    Message: json);
            }

            case IpcRequestKind.ClearFirewallBlocklist:
            {
                if (_firewallManager is null)
                {
                    return new IpcResponse(false, GetSnapshot(), "FirewallUnavailable", "Windows Firewall manager is not registered.");
                }

                var transientOnly = request.BoolValue == true;
                var result = transientOnly
                    ? await _firewallManager.ClearLockdownAndLeakGuardAsync(cancellationToken).ConfigureAwait(false)
                    : await _firewallManager.ClearAllManagedRulesAsync(cancellationToken).ConfigureAwait(false);
                var json = JsonSerializer.Serialize(result, SettingsJson.Options);
                return new IpcResponse(
                    Success: result.Success,
                    Status: GetSnapshot(),
                    ErrorCode: result.Success ? null : "FirewallClearFailed",
                    Message: json);
            }

            case IpcRequestKind.GetFirewallBlocklistStatus:
            {
                if (_firewallManager is null)
                {
                    return new IpcResponse(false, GetSnapshot(), "FirewallUnavailable", "Windows Firewall manager is not registered.");
                }

                var fwStatus = await _firewallManager.GetStatusAsync(cancellationToken).ConfigureAwait(false);
                var json = JsonSerializer.Serialize(fwStatus, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetReverseDnsSnapshot:
            {
                var snapshot = _reverseLookupCache?.GetSnapshot(600) ?? [];
                var json = JsonSerializer.Serialize(snapshot, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetEngineDetailedStats:
            {
                var stats = _dnsEngine.GetStats();
                var json = JsonSerializer.Serialize(stats, SettingsJson.Options);
                return new IpcResponse(true, BuildSnapshot(stats, _bypassEngine?.GetStats()), Message: json);
            }

            case IpcRequestKind.GetBypassDetailedStats:
            {
                var stats = _bypassEngine?.GetStats() ?? new BypassRuntimeStats();
                var json = JsonSerializer.Serialize(stats, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetBypassEventsSnapshot:
            {
                var events = _bypassEngine?.GetRecentEvents().Take(200).ToList() ?? [];
                var json = JsonSerializer.Serialize(events, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.RestartBypassEngine:
            {
                if (_bypassEngine is null)
                {
                    return new IpcResponse(false, GetSnapshot(), "BypassUnavailable", "Bypass engine is not registered.");
                }

                var (ok, err) = await _bypassEngine.RestartAsync(cancellationToken).ConfigureAwait(false);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "BypassRestartFailed", err);
            }

            case IpcRequestKind.ProbeActiveResolver:
            {
                var probe = await _dnsEngine.ProbeActiveResolverAsync(cancellationToken).ConfigureAwait(false);
                var json = JsonSerializer.Serialize(probe, SettingsJson.Options);
                return new IpcResponse(probe.Success, GetSnapshot(), probe.Success ? null : "ProbeFailed", json);
            }

            case IpcRequestKind.TestLocalProxy:
            {
                var (ok, latencyMs, summary) = await _dnsEngine.TestLocalProxyAsync(cancellationToken).ConfigureAwait(false);
                var json = JsonSerializer.Serialize(new LocalProxyTestResult(ok, latencyMs, summary), SettingsJson.Options);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "LocalProxyTestFailed", json);
            }

            case IpcRequestKind.GetLiveQueriesSnapshot:
            {
                long afterSeq = 0;
                int limit = 1000;
                if (!string.IsNullOrWhiteSpace(request.StringValue))
                {
                    foreach (var part in request.StringValue.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        var eq = part.IndexOf('=');
                        if (eq <= 0) continue;
                        var key = part[..eq];
                        var val = part[(eq + 1)..];
                        if (string.Equals(key, "after", StringComparison.OrdinalIgnoreCase) && long.TryParse(val, out var parsedAfter) && parsedAfter >= 0)
                        {
                            afterSeq = parsedAfter;
                        }
                        else if (string.Equals(key, "limit", StringComparison.OrdinalIgnoreCase) && int.TryParse(val, out var parsedLimit))
                        {
                            limit = Math.Clamp(parsedLimit, 1, 5000);
                        }
                    }
                }

                var entries = _diagnostics?.GetMonitorEntriesSince(afterSeq, limit) ?? [];
                var json = JsonSerializer.Serialize(entries, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetQueryAnalyticsSnapshot:
            {
                var topN = 50;
                if (!string.IsNullOrWhiteSpace(request.StringValue) && int.TryParse(request.StringValue, out var parsedTop))
                {
                    topN = Math.Clamp(parsedTop, 1, 200);
                }

                var analytics = _diagnostics?.GetQueryAnalyticsSnapshot(topN) ?? new QueryAnalyticsSnapshot
                {
                    SessionStartedUtc = _startedAt,
                    TopQueried = [],
                    TopBlocked = [],
                    TopFailed = [],
                };
                var json = JsonSerializer.Serialize(analytics, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetFailoverEventsSnapshot:
            {
                var events = _failover?.GetFailoverHistory().Take(100).ToList() ?? [];
                var json = JsonSerializer.Serialize(events, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.PauseCaptivePortal:
            {
                var seconds = 300;
                if (int.TryParse(request.StringValue, out var parsed) && parsed >= 30)
                {
                    seconds = Math.Clamp(parsed, 30, 3600);
                }

                var (ok, err) = await _dnsEngine
                    .PauseForCaptivePortalAsync(TimeSpan.FromSeconds(seconds), cancellationToken)
                    .ConfigureAwait(false);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "CaptivePauseFailed", err);
            }

            case IpcRequestKind.ResumeCaptivePortal:
            {
                var (ok, err) = await _dnsEngine.ResumeFromCaptivePortalAsync(cancellationToken).ConfigureAwait(false);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "CaptiveResumeFailed", err);
            }

            case IpcRequestKind.ClearDnsCache:
            {
                _cache?.Clear();
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.GetFilterAndCacheStats:
            {
                var payload = new ServiceFilterAndCacheSnapshot(
                    _cache?.GetStats(),
                    _filtering?.BlockedQueryCount ?? 0,
                    _filtering?.TotalBlockedDomains ?? 0,
                    _filtering?.GetRecentLogs().Take(100).ToList() ?? []);
                var json = JsonSerializer.Serialize(payload, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.ReloadFilteringBlocklists:
            {
                await _settings.ReloadFromDiskAsync(cancellationToken).ConfigureAwait(false);
                _filtering?.ReloadBlocklistsFromDisk();
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.GetLearnedHosts:
            {
                var hosts = _bypassEngine?.GetLearnedHosts() ?? [];
                var json = JsonSerializer.Serialize(hosts, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.ClearLearnedHosts:
            {
                _bypassEngine?.ClearLearnedHosts();
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.ClearBypassEvents:
            {
                _bypassEngine?.ClearRecentEvents();
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.ClearDiagnosticMonitors:
            {
                _diagnostics?.ClearMonitorEntries();
                _filtering?.ClearLogs();
                return new IpcResponse(true, GetSnapshot());
            }

            case IpcRequestKind.InstallOrUpdateDnsCrypt:
            {
                if (_dnsCryptManager is null)
                {
                    return new IpcResponse(false, GetSnapshot(), "DnsCryptUnavailable", "DNSCrypt manager is not registered in service.");
                }

                var (ok, ver, err) = await _dnsCryptManager.InstallOrUpdateAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
                return new IpcResponse(ok, GetSnapshot(), ok ? null : "DnsCryptInstallFailed", ok ? ver : err);
            }

            default:
                return new IpcResponse(
                    Success: false,
                    Status: GetSnapshot(),
                    ErrorCode: "UnknownRequest",
                    Message: $"Unsupported request kind {request.Kind}.");
        }
    }
}
