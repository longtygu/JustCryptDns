using JustCryptDns.Core.Interfaces;
using JustCryptDns.Infrastructure.Ipc;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Service;

/// <summary>
/// Long-running Windows Service worker that hosts the Named Pipe IPC endpoint and manages the DNS engine lifecycle.
/// </summary>
public sealed class DnsBackgroundWorker : BackgroundService
{
    private readonly ServiceStateManager _state;
    private readonly IDnsEngine _dnsEngine;
    private readonly IBypassEngineService? _bypassEngine;
    private readonly IWindowsFirewallManager? _firewallManager;
    private readonly NamedPipeIpcServer _ipcServer;
    private readonly ILogger<DnsBackgroundWorker> _logger;

    public DnsBackgroundWorker(
        ServiceStateManager state,
        IDnsEngine dnsEngine,
        NamedPipeIpcServer ipcServer,
        ILogger<DnsBackgroundWorker> logger,
        IBypassEngineService? bypassEngine = null,
        IWindowsFirewallManager? firewallManager = null)
    {
        _state = state;
        _dnsEngine = dnsEngine;
        _ipcServer = ipcServer;
        _logger = logger;
        _bypassEngine = bypassEngine;
        _firewallManager = firewallManager;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("JustCryptDns background service starting.");
        _ipcServer.Start();
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _state.InitializeFromSettingsAsync(stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Service initialization encountered an unexpected error.");
        }

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal service stop.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("JustCryptDns background service stopping.");
        try
        {
            await _ipcServer.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error while stopping IPC server.");
        }

        if (_bypassEngine is not null)
        {
            try
            {
                await _bypassEngine.StopAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error while stopping Bypass engine.");
            }
        }

        if (_firewallManager is not null)
        {
            try
            {
                await _firewallManager.ClearLockdownAndLeakGuardAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error while clearing transient firewall rules.");
            }
        }

        try
        {
            await _dnsEngine.StopAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error while stopping DNS engine.");
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
