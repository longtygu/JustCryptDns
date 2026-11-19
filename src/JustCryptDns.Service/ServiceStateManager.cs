using System.Reflection;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
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
        IBypassEngineService? bypassEngine = null)
    {
        _settings = settings;
        _dnsEngine = dnsEngine;
        _windowsDns = windowsDns;
        _logger = logger;
        _gamingEngine = gamingEngine;
        _bypassEngine = bypassEngine;
        _version = typeof(ServiceStateManager).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "1.1.0";
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
            "Service initialized from settings (autoStartDns={AutoStart}, autoBypass={AutoBypass}, gamingOnStartup={Gaming})",
            current.General.AutoStartDnsEngine,
            current.Bypass.IsBypassEnabled && current.Bypass.AutoStartWithDnsEngine,
            current.General.EnableGamingModeOnStartup);

        if (current.General.AutoStartDnsEngine)
        {
            var (ok, err) = await _dnsEngine.StartAsync(cancellationToken).ConfigureAwait(false);
            if (!ok)
            {
                _logger.LogWarning("Auto-start DNS engine did not succeed: {Error}", err);
            }
            else if (current.Bypass.IsBypassEnabled && current.Bypass.AutoStartWithDnsEngine && _bypassEngine is not null)
            {
                var (bypassOk, bypassErr) = await _bypassEngine.StartAsync(cancellationToken).ConfigureAwait(false);
                if (!bypassOk)
                {
                    _logger.LogWarning("Auto-start Bypass engine did not succeed: {Error}", bypassErr);
                }
            }
        }
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
                if (!string.IsNullOrWhiteSpace(request.StringValue))
                {
                    var (ok, err) = await _dnsEngine.SwitchResolverAsync(request.StringValue, cancellationToken).ConfigureAwait(false);
                    return new IpcResponse(ok, GetSnapshot(), ok ? null : "SwitchResolverFailed", err);
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

            default:
                return new IpcResponse(
                    Success: false,
                    Status: GetSnapshot(),
                    ErrorCode: "UnknownRequest",
                    Message: $"Unsupported request kind {request.Kind}.");
        }
    }
}
