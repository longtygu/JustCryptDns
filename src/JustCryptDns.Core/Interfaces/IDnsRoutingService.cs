using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Manages domain-based DNS routing profiles, prioritized rules, rule testing, and routing logs (Part 4).
/// </summary>
public interface IDnsRoutingService
{
    event EventHandler? RoutingChanged;

    event EventHandler<RoutingLogEntry>? LogAdded;

    bool IsRoutingEnabled { get; }

    Task SetRoutingEnabledAsync(bool enabled, CancellationToken cancellationToken = default);

    IReadOnlyList<DnsRoutingProfile> GetProfiles();

    DnsRoutingProfile GetActiveProfile();

    Task SetActiveProfileAsync(string profileId, CancellationToken cancellationToken = default);

    Task SetProfileFallbackResolverAsync(string profileId, string resolverId, CancellationToken cancellationToken = default);

    Task<(bool Success, DnsRoutingProfile? Profile, string? Error)> AddCustomProfileAsync(
        string name,
        string description,
        string fallbackResolverId,
        CancellationToken cancellationToken = default);

    Task<bool> RemoveCustomProfileAsync(string profileId, CancellationToken cancellationToken = default);

    IReadOnlyList<DnsRoutingRule> GetRulesForProfile(string profileId);

    IReadOnlyList<DnsRoutingRule> GetAllRules();

    Task<(bool Success, DnsRoutingRule? Rule, string? Error)> AddOrUpdateRuleAsync(
        DnsRoutingRule rule,
        CancellationToken cancellationToken = default);

    Task<bool> RemoveRuleAsync(string ruleId, CancellationToken cancellationToken = default);

    Task SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken cancellationToken = default);

    RoutingDecision ResolveForDomain(string domain, string? profileIdOverride = null);

    void RecordRoutingLog(RoutingDecision decision, string queryType, double? latencyMs);

    IReadOnlyList<RoutingLogEntry> GetRecentLogs();

    void ClearLogs();

    IReadOnlyList<LocalDnsRewriteRule> GetLocalRewrites() => [];

    Task<(bool Success, LocalDnsRewriteRule? Rule, string? Error)> AddOrUpdateLocalRewriteAsync(
        LocalDnsRewriteRule rule,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<(bool, LocalDnsRewriteRule?, string?)>((false, null, "Not implemented."));

    Task<bool> RemoveLocalRewriteAsync(string rewriteId, CancellationToken cancellationToken = default) =>
        Task.FromResult(false);

    Task SetLocalRewriteEnabledAsync(string rewriteId, bool enabled, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;

    LocalDnsRewriteRule? FindMatchingRewrite(string domain, string recordType) => null;
}
