using System.Net;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Bounded, TTL-aware in-memory <c>IP -> Domain</c> and <c>Domain -> IPs</c> cache fed by the DNS proxy.
/// </summary>
public interface IDnsReverseLookupCache
{
    int Count { get; }

    void Record(IPAddress ip, string domain, uint ttlSeconds);

    void RecordFromDnsPacket(string queryDomain, IReadOnlyList<(IPAddress Ip, uint TtlSeconds)> answers);

    bool TryResolve(string? ip, out string domain);

    IReadOnlyList<string> GetIpsForDomain(string? domain);

    IReadOnlyList<ReverseDnsMapping> GetSnapshot(int maxItems = 800);

    void ImportSnapshot(IEnumerable<ReverseDnsMapping> mappings);

    void Clear();
}

/// <summary>
/// Enumerates live TCP/UDP sockets with owning PID and process name using OS-native APIs.
/// </summary>
public interface IConnectionMonitorService
{
    IReadOnlyList<RawSocketConnection> CaptureSnapshot();
}

/// <summary>
/// Optional, rate-limited background IP enrichment (rDNS + ipinfo.io). Disabled by default.
/// </summary>
public interface IIpEnrichmentService : IDisposable
{
    event EventHandler<IpEnrichmentInfo>? EnrichmentReady;

    bool TryGetCached(string ip, out IpEnrichmentInfo info);

    void EnqueueLookup(string ip);

    void Pause();

    void Resume();
}

/// <summary>
/// Manages Windows Firewall block rules scoped exclusively to JustCryptDns (<see cref="RuleGroup"/>).
/// </summary>
public interface IWindowsFirewallManager
{
    const string RuleGroup = "JustCryptDns_IPBlock";
    const string RuleNamePrefix = "JustCryptDns_IPBlock_";

    Task<FirewallSyncResult> SyncRulesAsync(
        IReadOnlyList<BlockedIpRule> rules,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> ClearAllManagedRulesAsync(CancellationToken cancellationToken = default);

    Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Routes Windows Firewall operations through the elevated background service IPC when available,
/// falling back gracefully to local management if running elevated or offline.
/// </summary>
public interface IFirewallBlocklistCoordinator
{
    Task<FirewallSyncResult> SyncAsync(IReadOnlyList<BlockedIpRule> rules, CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> ClearAllAsync(CancellationToken cancellationToken = default);

    Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default);

    Task PullReverseDnsFromServiceIfConnectedAsync(CancellationToken cancellationToken = default);
}
