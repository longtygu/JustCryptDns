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
    const string AppRuleGroup = "JustCryptDns_AppBlock";
    const string AppRuleNamePrefix = "JustCryptDns_AppBlock_";
    const string DnsLeakRuleGroup = "JustCryptDns_DnsLeakGuard";
    const string DnsLeakRuleNamePrefix = "JustCryptDns_DnsLeakGuard_";
    const string LockdownRuleGroup = "JustCryptDns_Lockdown";
    const string LockdownRuleNamePrefix = "JustCryptDns_Lockdown_";

    Task<FirewallSyncResult> SyncRulesAsync(
        IReadOnlyList<BlockedIpRule> rules,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> SyncSecurityPoliciesAsync(
        FirewallSyncRequestPayload payload,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> ClearLockdownAndLeakGuardAsync(CancellationToken cancellationToken = default);

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

    Task<FirewallSyncResult> SyncSecurityAsync(FirewallSyncRequestPayload payload, CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> ClearLockdownAndLeakGuardAsync(CancellationToken cancellationToken = default);

    Task<FirewallSyncResult> ClearAllAsync(CancellationToken cancellationToken = default);

    Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default);

    Task PullReverseDnsFromServiceIfConnectedAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Evaluates Authenticode signatures, execution directory risk, and system binary masquerading offline.
/// </summary>
public interface IProcessTrustInspector
{
    ProcessTrustInfo Inspect(string? executablePath, string? processName = null);
}

/// <summary>
/// Matches remote IPs/CIDRs against local/cached Threat Intelligence feeds (Abuse.ch Feodo, Spamhaus DROP)
/// while always sparing protected system and DNS resolver addresses.
/// </summary>
public interface IThreatIntelligenceService
{
    ThreatIntelStatus GetStatus();

    bool TryMatch(string? ipText, ProtectedIpContext? protectedContext, out ThreatIntelMatch match);

    Task<ThreatIntelStatus> RefreshFeedsAsync(CancellationToken cancellationToken = default);
}
