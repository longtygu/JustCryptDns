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
    private readonly NamedPipeIpcServer _ipcServer;
    private readonly ILogger<DnsBackgroundWorker> _logger;

    public DnsBackgroundWorker(
        ServiceStateManager state,
        NamedPipeIpcServer ipcServer,
        ILogger<DnsBackgroundWorker> logger)
    {
        _state = state;
        _ipcServer = ipcServer;
        _logger = logger;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("JustCryptDns background service starting.");
        _state.InitializeFromSettings();
        _ipcServer.Start();
        return base.StartAsync(cancellationToken);
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
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
