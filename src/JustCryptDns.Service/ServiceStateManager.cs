using System.Reflection;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Ipc;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Service;

/// <summary>
/// Maintains the live state of the independent background service and handles local IPC requests.
/// In Phase 3 the service host and IPC are operational while the DNS engine is honestly reported as Phase 4.
/// </summary>
public sealed class ServiceStateManager : IServiceIpcHandler
{
    private readonly ISettingsStore _settingsStore;
    private readonly ILogger<ServiceStateManager> _logger;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
    private readonly string _version;
    private readonly object _sync = new();

    private bool _gamingModeEnabled;

    public ServiceStateManager(ISettingsStore settingsStore, ILogger<ServiceStateManager> logger)
    {
        _settingsStore = settingsStore;
        _logger = logger;
        _version = typeof(ServiceStateManager).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.1.0";
    }

    public void InitializeFromSettings()
    {
        var loaded = _settingsStore.Load();
        lock (_sync)
        {
            _gamingModeEnabled = loaded.Settings.General.EnableGamingModeOnStartup;
        }

        _logger.LogInformation(
            "Service initialized from settings (outcome={Outcome}, autoStartDns={AutoStart}, gamingOnStartup={Gaming})",
            loaded.Outcome,
            loaded.Settings.General.AutoStartDnsEngine,
            loaded.Settings.General.EnableGamingModeOnStartup);
    }

    public ServiceStatusSnapshot GetSnapshot()
    {
        lock (_sync)
        {
            return new ServiceStatusSnapshot
            {
                ServiceVersion = _version,
                StartedAt = _startedAt,
                EngineState = DnsEngineState.NotImplemented,
                IsEngineImplemented = false,
                IsEngineEnabled = false,
                IsGamingModeEnabled = _gamingModeEnabled,
                ActiveResolverName = null,
                ActiveProtocol = null,
                LastError = null,
            };
        }
    }

    public Task<IpcResponse> HandleAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        switch (request.Kind)
        {
            case IpcRequestKind.GetStatus:
                return Task.FromResult(new IpcResponse(Success: true, Status: GetSnapshot()));

            case IpcRequestKind.SetEngineEnabled:
                _logger.LogInformation("IPC SetEngineEnabled({Enabled}) requested; engine is Phase 4.", request.BoolValue);
                return Task.FromResult(new IpcResponse(
                    Success: false,
                    Status: GetSnapshot(),
                    ErrorCode: "EngineNotImplemented",
                    Message: "The DNS engine is scheduled for Phase 4."));

            case IpcRequestKind.SetGamingMode:
                var enableGaming = request.BoolValue ?? false;
                lock (_sync)
                {
                    _gamingModeEnabled = enableGaming;
                }

                _logger.LogInformation("IPC SetGamingMode({Enabled}) applied.", enableGaming);
                return Task.FromResult(new IpcResponse(Success: true, Status: GetSnapshot()));

            case IpcRequestKind.RestoreOriginalDns:
                _logger.LogInformation("IPC RestoreOriginalDns requested; no adapter changes have been made by JustCryptDns.");
                return Task.FromResult(new IpcResponse(
                    Success: true,
                    Status: GetSnapshot(),
                    Message: "No adapter DNS changes were applied by JustCryptDns."));

            default:
                return Task.FromResult(new IpcResponse(
                    Success: false,
                    Status: GetSnapshot(),
                    ErrorCode: "UnknownRequest",
                    Message: $"Unsupported request kind {request.Kind}."));
        }
    }
}
