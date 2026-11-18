using System.Reflection;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Service;

/// <summary>
/// Maintains the live state of the independent background service, drives <see cref="IDnsEngine"/>,
/// and handles local IPC requests from the UI or CLI.
/// </summary>
public sealed class ServiceStateManager : IServiceIpcHandler
{
    private readonly ISettingsService _settings;
    private readonly IDnsEngine _dnsEngine;
    private readonly IWindowsDnsManager _windowsDns;
    private readonly ILogger<ServiceStateManager> _logger;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly string _version;
    private readonly object _sync = new();

    private bool _gamingModeEnabled;

    public ServiceStateManager(
        ISettingsService settings,
        IDnsEngine dnsEngine,
        IWindowsDnsManager windowsDns,
        ILogger<ServiceStateManager> logger)
    {
        _settings = settings;
        _dnsEngine = dnsEngine;
        _windowsDns = windowsDns;
        _logger = logger;
        _version = typeof(ServiceStateManager).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.1.0";
    }

    public async Task InitializeFromSettingsAsync(CancellationToken cancellationToken = default)
    {
        var current = _settings.Current;
        lock (_sync)
        {
            _gamingModeEnabled = current.General.EnableGamingModeOnStartup;
        }

        // Crash recovery check: if an adapter backup was left active from an unclean shutdown, restore it first.
        await _windowsDns.RecoverAfterCrashIfNeededAsync(proxyIsRunning: false, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation(
            "Service initialized from settings (autoStartDns={AutoStart}, gamingOnStartup={Gaming})",
            current.General.AutoStartDnsEngine,
            current.General.EnableGamingModeOnStartup);

        if (current.General.AutoStartDnsEngine)
        {
            var (ok, err) = await _dnsEngine.StartAsync(cancellationToken).ConfigureAwait(false);
            if (!ok)
            {
                _logger.LogWarning("Auto-start DNS engine did not succeed: {Error}", err);
            }
        }
    }

    public ServiceStatusSnapshot GetSnapshot()
    {
        var stats = _dnsEngine.GetStats();
        bool gaming;
        lock (_sync)
        {
            gaming = _gamingModeEnabled;
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
                lock (_sync)
                {
                    _gamingModeEnabled = enableGaming;
                }

                _logger.LogInformation("IPC SetGamingMode({Enabled}) applied.", enableGaming);
                return new IpcResponse(Success: true, Status: GetSnapshot());
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
