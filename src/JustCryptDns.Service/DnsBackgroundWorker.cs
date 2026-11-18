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
    private readonly NamedPipeIpcServer _ipcServer;
    private readonly ILogger<DnsBackgroundWorker> _logger;

    public DnsBackgroundWorker(
        ServiceStateManager state,
        IDnsEngine dnsEngine,
        NamedPipeIpcServer ipcServer,
        ILogger<DnsBackgroundWorker> logger)
    {
        _state = state;
        _dnsEngine = dnsEngine;
        _ipcServer = ipcServer;
        _logger = logger;
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("JustCryptDns background service starting.");
        _ipcServer.Start();
        await _state.InitializeFromSettingsAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
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
        await _ipcServer.DisposeAsync().ConfigureAwait(false);
        await _dnsEngine.StopAsync(cancellationToken).ConfigureAwait(false);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
