using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Manages DNS blocklists (Advertising, Tracking, Malware, Phishing, Telemetry, Custom),
/// allowlist, temporary exceptions, hosts-file imports, and filtering decision inspection (Part 7).
/// </summary>
public interface IDnsFilteringService
{
    event EventHandler? FilteringChanged;

    event EventHandler<FilterLogEntry>? DecisionLogged;

    bool IsFilteringEnabled { get; }

    long BlockedQueryCount { get; }

    int TotalBlockedDomains { get; }

    Task SetFilteringEnabledAsync(bool enabled, CancellationToken cancellationToken = default);

    IReadOnlyList<DnsBlocklistSource> GetBlocklists();

    IReadOnlyList<string> GetCustomBlockedDomains();

    IReadOnlyList<DnsAllowlistEntry> GetAllowlist();

    Task SetBlocklistEnabledAsync(string listId, bool enabled, CancellationToken cancellationToken = default);

    Task<(bool Success, int DomainCount, string? Error)> UpdateBlocklistAsync(
        string listId,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default);

    Task<(int UpdatedLists, int TotalDomains)> UpdateAllEnabledBlocklistsAsync(
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default);

    Task<(bool Success, int ImportedCount, string? Error)> ImportHostsTextAsync(
        string hostsContent,
        string? listName = null,
        CancellationToken cancellationToken = default);

    Task<bool> AddCustomBlockedDomainAsync(string domain, CancellationToken cancellationToken = default);

    Task<bool> RemoveCustomBlockedDomainAsync(string domain, CancellationToken cancellationToken = default);

    Task<bool> AddAllowlistEntryAsync(string domain, string note, TimeSpan? temporaryDuration = null, CancellationToken cancellationToken = default);

    Task<bool> RemoveAllowlistEntryAsync(string domain, CancellationToken cancellationToken = default);

    FilterDecision EvaluateDomain(string domain, bool recordStats = false);

    IReadOnlyList<FilterLogEntry> GetRecentLogs();

    void ClearLogs();
}
