using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Network diagnostics & live query monitor service (Part 9):
/// A/AAAA/CNAME/MX/TXT/NS lookup, DNSSEC test, DoH & DNSCrypt connectivity tests,
/// resolver comparison, DNS leak test, propagation test, and bounded live query stream.
/// </summary>
public interface INetworkDiagnosticsService
{
    event EventHandler<LiveQueryMonitorEntry>? QueryObserved;

    bool IsMonitorPaused { get; set; }

    IReadOnlyList<LiveQueryMonitorEntry> GetMonitorEntries();

    void RecordMonitorEntry(LiveQueryMonitorEntry entry);

    void ClearMonitorEntries();

    Task<DnsLookupReport> LookupAsync(
        string domain,
        string recordType,
        string? resolverId = null,
        CancellationToken cancellationToken = default);

    Task<DnssecTestReport> TestDnssecAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default);

    Task<(bool Success, double LatencyMs, string Summary)> TestDohConnectivityAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default);

    Task<(bool Success, double LatencyMs, string Summary)> TestDnsCryptConnectivityAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ResolverComparisonEntry>> CompareResolversAsync(
        string domain,
        string recordType = "A",
        CancellationToken cancellationToken = default);

    Task<DnsLeakTestReport> RunDnsLeakTestAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ResolverComparisonEntry>> CheckPropagationAsync(
        string domain,
        string recordType = "A",
        CancellationToken cancellationToken = default);
}
