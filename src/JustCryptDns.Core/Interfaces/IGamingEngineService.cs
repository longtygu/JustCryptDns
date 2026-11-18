using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Gaming Low Latency Engine (Part 5): multi-domain repeated resolver benchmarking,
/// Smart Resolver Selection (Lowest Latency, Balanced, Maximum Reliability),
/// gaming platform profiles, and Gaming Mode with session pinning.
/// </summary>
public interface IGamingEngineService
{
    event EventHandler? GamingStateChanged;

    event EventHandler<IReadOnlyList<ResolverBenchmarkResult>>? BenchmarkCompleted;

    bool IsGamingModeEnabled { get; }

    bool IsSessionPinned { get; }

    GamingSelectionProfile SelectionProfile { get; }

    string? ManualOverrideResolverId { get; }

    GamingPlatformProfile GetActiveGamingProfile();

    IReadOnlyList<GamingPlatformProfile> GetGamingProfiles();

    IReadOnlyList<ResolverBenchmarkResult> GetLastBenchmarkResults();

    DnsResolverEndpoint GetSelectedGamingResolver();

    Task SetSelectionProfileAsync(GamingSelectionProfile profile, CancellationToken cancellationToken = default);

    Task SetManualOverrideResolverAsync(string? resolverId, CancellationToken cancellationToken = default);

    Task SetActiveGamingProfileAsync(string profileId, CancellationToken cancellationToken = default);

    Task<(bool Success, GamingPlatformProfile? Profile, string? Error)> AddCustomGamingProfileAsync(
        string name,
        IReadOnlyList<string> domains,
        string? preferredResolverId = null,
        CancellationToken cancellationToken = default);

    Task<bool> RemoveCustomGamingProfileAsync(string profileId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ResolverBenchmarkResult>> RunBenchmarkAsync(
        int roundsPerDomain = 2,
        IProgress<(int Completed, int Total, string CurrentResolver)>? progress = null,
        CancellationToken cancellationToken = default);

    ResolverBenchmarkResult? SelectBestBenchmarkResult(
        IReadOnlyList<ResolverBenchmarkResult> results,
        GamingSelectionProfile profile);

    Task<(bool Success, string? Error)> SetGamingModeAsync(bool enabled, CancellationToken cancellationToken = default);
}
