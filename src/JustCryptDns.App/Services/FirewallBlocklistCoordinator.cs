using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.App.Services;

/// <summary>
/// Coordinates IP/CIDR, Per-App, DNS Leak Guard, and Emergency Lockdown policies with Windows Firewall
/// via the elevated background service IPC, falling back cleanly to local COM management when standalone.
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

    public Task<FirewallSyncResult> SyncAsync(IReadOnlyList<BlockedIpRule> rules, CancellationToken cancellationToken = default)
    {
        var conn = _settings.Current.Connections;
        return SyncSecurityAsync(
            new FirewallSyncRequestPayload(
                rules,
                conn.BlockedApps,
                conn.EnableDnsLeakGuard,
                EnableEmergencyLockdown: false),
            cancellationToken);
    }

    public async Task<FirewallSyncResult> SyncSecurityAsync(
        FirewallSyncRequestPayload payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var enrichedPayload = EnrichAllowedResolverIps(payload);
        var payloadJson = JsonSerializer.Serialize(enrichedPayload, SettingsJson.Options);
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
            return new FirewallSyncResult(false, 0, 0, 0, true, false, "Security policy payload exceeds IPC frame limit.");
        }

        var context = await Task.Run(BuildProtectedContext, cancellationToken).ConfigureAwait(false);
        return await _localFirewall.SyncSecurityPoliciesAsync(enrichedPayload, context, cancellationToken).ConfigureAwait(false);
    }

    public Task<FirewallSyncResult> ClearLockdownAndLeakGuardAsync(CancellationToken cancellationToken = default) =>
        ClearCoreAsync(transientOnly: true, cancellationToken);

    public Task<FirewallSyncResult> ClearAllAsync(CancellationToken cancellationToken = default) =>
        ClearCoreAsync(transientOnly: false, cancellationToken);

    private async Task<FirewallSyncResult> ClearCoreAsync(bool transientOnly, CancellationToken cancellationToken)
    {
        if (_serviceClient.ConnectionState != ServiceConnectionState.Connected)
        {
            await _serviceClient.RefreshStatusAsync(cancellationToken).ConfigureAwait(false);
        }

        if (_serviceClient.ConnectionState == ServiceConnectionState.Connected)
        {
            var ipcResponse = await _serviceClient.SendAsync(
                new IpcRequest(IpcRequestKind.ClearFirewallBlocklist, BoolValue: transientOnly),
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

        return transientOnly
            ? await _localFirewall.ClearLockdownAndLeakGuardAsync(cancellationToken).ConfigureAwait(false)
            : await _localFirewall.ClearAllManagedRulesAsync(cancellationToken).ConfigureAwait(false);
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

    private FirewallSyncRequestPayload EnrichAllowedResolverIps(FirewallSyncRequestPayload payload)
    {
        if (!payload.EnableDnsLeakGuard || (payload.AllowedDnsResolverIps is { Count: > 0 }))
        {
            return payload;
        }

        var resolverIps = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAddIp(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }

            if (System.Net.IPAddress.TryParse(raw.Trim(), out var ip) && seen.Add(ip.ToString()))
            {
                resolverIps.Add(ip.ToString());
            }
        }

        var primary = _resolverLibrary.GetPrimaryResolver();
        var secondary = _resolverLibrary.GetSecondaryResolver();
        foreach (var resolver in new[] { primary, secondary })
        {
            TryAddIp(resolver.PrimaryIp);
            TryAddIp(resolver.SecondaryIp);
            TryAddIp(resolver.PrimaryIpv6);
        }

        // Also keep currently cached resolved hosts of active DoH/DoT resolvers reachable.
        foreach (var resolver in new[] { primary, secondary })
        {
            if (Uri.TryCreate(resolver.Endpoint, UriKind.Absolute, out var uri))
            {
                foreach (var cachedIp in _reverseCache.GetIpsForDomain(uri.Host).Take(2))
                {
                    TryAddIp(cachedIp);
                }
            }
            else if (!string.IsNullOrWhiteSpace(resolver.Endpoint))
            {
                foreach (var cachedIp in _reverseCache.GetIpsForDomain(resolver.Endpoint).Take(2))
                {
                    TryAddIp(cachedIp);
                }
            }
        }

        return payload with { AllowedDnsResolverIps = resolverIps };
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
