using System.Reflection;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
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
        IDnsFailoverService? failover = null)
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
        _version = typeof(ServiceStateManager).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "1.6.0";
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

    public ServiceStatusSnapshot GetSnapshot()
    {
        var stats = _dnsEngine.GetStats();
        var bypassStats = _bypassEngine?.GetStats();
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
                if (!string.IsNullOrWhiteSpace(request.StringValue))
                {
                    var (ok, err) = await _dnsEngine.SwitchResolverAsync(request.StringValue, cancellationToken).ConfigureAwait(false);
                    return new IpcResponse(ok, GetSnapshot(), ok ? null : "SwitchResolverFailed", err);
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
                return new IpcResponse(true, GetSnapshot(), Message: json);
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
                var entries = _diagnostics?.GetMonitorEntries().Take(200).ToList() ?? [];
                var json = JsonSerializer.Serialize(entries, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
            }

            case IpcRequestKind.GetFailoverEventsSnapshot:
            {
                var events = _failover?.GetFailoverHistory().Take(100).ToList() ?? [];
                var json = JsonSerializer.Serialize(events, SettingsJson.Options);
                return new IpcResponse(true, GetSnapshot(), Message: json);
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
