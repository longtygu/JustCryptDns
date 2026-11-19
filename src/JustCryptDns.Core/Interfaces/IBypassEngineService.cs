using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

public interface IBypassEngineService : IAsyncDisposable
{
    event EventHandler<BypassRuntimeStats>? StateChanged;

    event EventHandler<BypassConnectionEvent>? ConnectionProcessed;

    BypassRuntimeStats GetStats();

    Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default);

    BypassMode ResolveModeForHost(string host);

    string GeneratePacScript();

    IReadOnlyList<BypassConnectionEvent> GetRecentEvents();

    void ClearRecentEvents();

    Task<BypassTestResult> TestDomainBypassAsync(string host, CancellationToken cancellationToken = default);

    Task<(bool Available, string Summary)> DetectCloudflareWarpAsync(CancellationToken cancellationToken = default);

    Task<(bool Success, double LatencyMs, string Summary)> TestUpstreamTunnelAsync(CancellationToken cancellationToken = default);

    IReadOnlyList<BypassRule> GetRules();

    Task<(bool Success, BypassRule? Rule, string? Error)> SaveRuleAsync(
        BypassRule rule,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteRuleAsync(string ruleId, CancellationToken cancellationToken = default);

    Task SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken cancellationToken = default);

    Task ResetBuiltInRulesAsync(CancellationToken cancellationToken = default);

    IReadOnlyList<string> GetDirectExclusions();

    Task<(bool Success, string? Error)> AddDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default);

    Task<bool> RemoveDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default);

    IReadOnlyList<LearnedHostEntry> GetLearnedHosts();

    void ClearLearnedHosts();

    Task<(bool Success, string? Error)> PromoteLearnedHostAsync(
        string host,
        LearnedHostStrategy strategy,
        CancellationToken cancellationToken = default);

    Task RefreshSystemPacAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<BypassTestResult>> TestMultipleDomainsAsync(
        IEnumerable<string> hosts,
        CancellationToken cancellationToken = default);
}
