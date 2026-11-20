using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

/// <summary>
/// Coordinates IP/CIDR blocklist synchronization with Windows Firewall via the elevated background service IPC,
/// falling back cleanly to local COM firewall management when the service is offline or running standalone.
/// </summary>
public sealed class FirewallBlocklistCoordinator : IFirewallBlocklistCoordinator
{
    private readonly IServiceClient _serviceClient;
    private readonly IWindowsFirewallManager _localFirewall;
    private readonly INetworkInfoService _networkInfo;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly ISettingsService _settings;
    private readonly IDnsReverseLookupCache _reverseCache;
    private readonly ILogger<FirewallBlocklistCoordinator> _logger;

    public FirewallBlocklistCoordinator(
        IServiceClient serviceClient,
        IWindowsFirewallManager localFirewall,
        INetworkInfoService networkInfo,
        IResolverLibraryService resolverLibrary,
        ISettingsService settings,
        IDnsReverseLookupCache reverseCache,
        ILogger<FirewallBlocklistCoordinator> logger)
    {
        _serviceClient = serviceClient;
        _localFirewall = localFirewall;
        _networkInfo = networkInfo;
        _resolverLibrary = resolverLibrary;
        _settings = settings;
        _reverseCache = reverseCache;
        _logger = logger;
    }

    public async Task<FirewallSyncResult> SyncAsync(IReadOnlyList<BlockedIpRule> rules, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var payloadJson = JsonSerializer.Serialize(new FirewallSyncRequestPayload(rules), SettingsJson.Options);
        if (System.Text.Encoding.UTF8.GetByteCount(payloadJson) <= IpcConstants.MaxMessageBytes - 4096)
        {
            if (_serviceClient.ConnectionState != ServiceConnectionState.Connected)
            {
                await _serviceClient.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
            }

            if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
            {
                var ipcResponse = await _serviceClient.SendAsync(
                    new IpcRequest(IpcRequestKind.SyncFirewallBlocklist, StringValue: payloadJson),
                    cancellationToken).ConfigureAwait(false);
                if (ipcResponse is not null && !string.IsNullOrWhiteSpace(ipcResponse.Message))
                {
                    try
                    {
                        var parsed = JsonSerializer.Deserialize<FirewallSyncResult>(ipcResponse.Message, SettingsJson.Options);
                        if (parsed is not null)
                        {
                            return parsed;
                        }
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogDebug(ex, "Could not deserialize IPC firewall sync response; falling back to IPC message.");
                        return new FirewallSyncResult(ipcResponse.Success, 0, 0, 0, true, false, ipcResponse.Message);
                    }
                }
            }
        }
        else
        {
            return new FirewallSyncResult(false, 0, 0, 0, true, false, "Blocklist payload exceeds IPC frame limit.");
        }

        var context = await Task.Run(BuildProtectedContext, cancellationToken).ConfigureAwait(false);
        return await _localFirewall.SyncRulesAsync(rules, context, cancellationToken).ConfigureAwait(false);
    }

    public async Task<FirewallSyncResult> ClearAllAsync(CancellationToken cancellationToken = default)
    {
        if (_serviceClient.ConnectionState != ServiceConnectionState.Connected)
        {
            await _serviceClient.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        }

        if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
        {
            var ipcResponse = await _serviceClient.SendAsync(
                new IpcRequest(IpcRequestKind.ClearFirewallBlocklist),
                cancellationToken).ConfigureAwait(false);
            if (ipcResponse is not null && !string.IsNullOrWhiteSpace(ipcResponse.Message))
            {
                try
                {
                    var parsed = JsonSerializer.Deserialize<FirewallSyncResult>(ipcResponse.Message, SettingsJson.Options);
                    if (parsed is not null)
                    {
                        return parsed;
                    }
                }
                catch (JsonException)
                {
                    return new FirewallSyncResult(ipcResponse.Success, 0, 0, 0, true, false, ipcResponse.Message);
                }
            }
        }

        return await _localFirewall.ClearAllManagedRulesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
        {
            var ipcResponse = await _serviceClient.SendAsync(
                new IpcRequest(IpcRequestKind.GetFirewallBlocklistStatus),
                cancellationToken).ConfigureAwait(false);
            if (ipcResponse is not null && ipcResponse.Success && !string.IsNullOrWhiteSpace(ipcResponse.Message))
            {
                try
                {
                    var parsed = JsonSerializer.Deserialize<FirewallStatusSnapshot>(ipcResponse.Message, SettingsJson.Options);
                    if (parsed is not null)
                    {
                        return parsed;
                    }
                }
                catch (JsonException)
                {
                    // Fall back to local read-only query.
                }
            }
        }

        return await _localFirewall.GetStatusAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task PullReverseDnsFromServiceIfConnectedAsync(CancellationToken cancellationToken = default)
    {
        if (_serviceClient.ConnectionState != ServiceConnectionState.Connected)
        {
            return;
        }

        var response = await _serviceClient.SendAsync(
            new IpcRequest(IpcRequestKind.GetReverseDnsSnapshot),
            cancellationToken).ConfigureAwait(false);
        if (response is { Success: true, Message.Length: > 2 })
        {
            try
            {
                var entries = JsonSerializer.Deserialize<List<ReverseDnsMapping>>(response.Message, SettingsJson.Options);
                if (entries is { Count: > 0 })
                {
                    _reverseCache.ImportSnapshot(entries);
                }
            }
            catch (JsonException ex)
            {
                _logger.LogDebug(ex, "Failed to parse reverse DNS snapshot from service.");
            }
        }
    }

    private ProtectedIpContext BuildProtectedContext()
    {
        var current = _settings.Current;
        return ProtectedIpContext.Build(
            _networkInfo.GetSnapshot(),
            _resolverLibrary.GetAll(),
            current.Dns,
            current.Bypass,
            _reverseCache);
    }
}
