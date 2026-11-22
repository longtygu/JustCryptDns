using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Gaming;

public sealed class GamingEngineService : IGamingEngineService, IDisposable
{
    private readonly ISettingsService _settings;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly IDnsRoutingService _routing;
    private readonly IDnsCacheService _cache;
    private readonly IDnsEngine _dnsEngine;
    private readonly ILogger<GamingEngineService> _logger;
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _upstreams;
    private readonly DohDnsUpstream _defaultDoh;
    private readonly DotDnsUpstream _defaultDot;
    private readonly object _resultsLock = new();
    private List<ResolverBenchmarkResult> _lastResults = [];
    private string? _pinnedResolverId;
    private bool _disposed;

    public GamingEngineService(
        ISettingsService settings,
        IResolverLibraryService resolverLibrary,
        IDnsRoutingService routing,
        IDnsCacheService cache,
        IDnsEngine dnsEngine,
        ILogger<GamingEngineService> logger,
        IEnumerable<IDnsUpstreamClient>? customUpstreams = null)
    {
        _settings = settings;
        _resolverLibrary = resolverLibrary;
        _routing = routing;
        _cache = cache;
        _dnsEngine = dnsEngine;
        _logger = logger;

        _defaultDoh = new DohDnsUpstream();
        _defaultDot = new DotDnsUpstream();
        var defaultClients = new IDnsUpstreamClient[]
        {
            _defaultDoh,
            _defaultDot,
            new UdpTcpDnsUpstream(),
        };

        var list = customUpstreams?.ToList();
        IEnumerable<IDnsUpstreamClient> active = list is { Count: > 0 } ? list : defaultClients;
        _upstreams = active.ToDictionary(u => u.Protocol);

        _dnsEngine.StateChanged += OnEngineStateChanged;
    }

    public event EventHandler? GamingStateChanged;

    public event EventHandler<IReadOnlyList<ResolverBenchmarkResult>>? BenchmarkCompleted;

    public bool IsGamingModeEnabled => _settings.Current.Gaming.IsGamingModeEnabled;

    public bool IsSessionPinned => IsGamingModeEnabled && !string.IsNullOrWhiteSpace(_pinnedResolverId);

    public GamingSelectionProfile SelectionProfile => _settings.Current.Gaming.SelectionProfile;

    public string? ManualOverrideResolverId => _settings.Current.Gaming.ManualOverrideResolverId;

    public IReadOnlyList<GamingPlatformProfile> GetGamingProfiles()
    {
        var custom = _settings.Current.Gaming.CustomGamingProfiles;
        var list = new List<GamingPlatformProfile>(BuiltInGamingProfiles.All.Count + custom.Count);
        list.AddRange(BuiltInGamingProfiles.All);
        foreach (var c in custom)
        {
            list.Add(c with { IsBuiltIn = false });
        }

        return list;
    }

    public GamingPlatformProfile GetActiveGamingProfile()
    {
        var id = _settings.Current.Gaming.ActiveGamingProfileId;
        var all = GetGamingProfiles();
        return all.FirstOrDefault(p => string.Equals(p.Id, id, StringComparison.OrdinalIgnoreCase)) ?? all[0];
    }

    public IReadOnlyList<ResolverBenchmarkResult> GetLastBenchmarkResults()
    {
        lock (_resultsLock)
        {
            return _lastResults.ToList();
        }
    }

    public DnsResolverEndpoint GetSelectedGamingResolver()
    {
        if (IsSessionPinned && !string.IsNullOrWhiteSpace(_pinnedResolverId))
        {
            return _resolverLibrary.GetByIdOrDefault(_pinnedResolverId);
        }

        var manualId = _settings.Current.Gaming.ManualOverrideResolverId;
        if (!string.IsNullOrWhiteSpace(manualId))
        {
            return _resolverLibrary.GetByIdOrDefault(manualId);
        }

        var profile = GetActiveGamingProfile();
        if (!string.IsNullOrWhiteSpace(profile.PreferredResolverId))
        {
            return _resolverLibrary.GetByIdOrDefault(profile.PreferredResolverId);
        }

        var results = GetLastBenchmarkResults();
        if (results.Count > 0)
        {
            var best = SelectBestBenchmarkResult(results, SelectionProfile);
            if (best is not null)
            {
                return _resolverLibrary.GetByIdOrDefault(best.ResolverId);
            }
        }

        return _resolverLibrary.GetPrimaryResolver();
    }

    public async Task SetSelectionProfileAsync(GamingSelectionProfile profile, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s => s.Gaming.SelectionProfile = profile, cancellationToken).ConfigureAwait(false);
        RaiseGamingStateChanged();
    }

    public async Task SetManualOverrideResolverAsync(string? resolverId, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(
            s => s.Gaming.ManualOverrideResolverId = string.IsNullOrWhiteSpace(resolverId) ? null : resolverId.Trim(),
            cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(resolverId) && IsGamingModeEnabled)
        {
            _pinnedResolverId = resolverId.Trim();
            await _dnsEngine.SwitchResolverAsync(_pinnedResolverId, cancellationToken).ConfigureAwait(false);
        }

        RaiseGamingStateChanged();
    }

    public async Task SetActiveGamingProfileAsync(string profileId, CancellationToken cancellationToken = default)
    {
        var match = GetGamingProfiles().FirstOrDefault(p => string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            return;
        }

        await _settings.UpdateAsync(s => s.Gaming.ActiveGamingProfileId = match.Id, cancellationToken).ConfigureAwait(false);
        if (IsGamingModeEnabled)
        {
            await ApplyGamingRoutingRulesAsync(match, GetSelectedGamingResolver(), cancellationToken).ConfigureAwait(false);
        }

        RaiseGamingStateChanged();
    }

    public async Task<(bool Success, GamingPlatformProfile? Profile, string? Error)> AddCustomGamingProfileAsync(
        string name,
        IReadOnlyList<string> domains,
        string? preferredResolverId = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return (false, null, "Gaming profile name is required.");
        }

        var cleanDomains = (domains ?? [])
            .Select(RoutingMatcher.NormalizeDomain)
            .Where(d => !string.IsNullOrEmpty(d) && d.Contains('.'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (cleanDomains.Count == 0)
        {
            return (false, null, "At least one valid gaming domain is required.");
        }

        var id = $"gaming-custom-{Guid.NewGuid().ToString("N")[..6]}";
        var profile = new GamingPlatformProfile
        {
            Id = id,
            Name = name.Trim(),
            Domains = cleanDomains,
            PreferredResolverId = string.IsNullOrWhiteSpace(preferredResolverId) ? null : preferredResolverId.Trim(),
            IsBuiltIn = false,
        };

        await _settings.UpdateAsync(s =>
        {
            s.Gaming.CustomGamingProfiles.Add(profile);
            s.Gaming.ActiveGamingProfileId = profile.Id;
        }, cancellationToken).ConfigureAwait(false);

        RaiseGamingStateChanged();
        return (true, profile, null);
    }

    public async Task<bool> RemoveCustomGamingProfileAsync(string profileId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profileId))
        {
            return false;
        }

        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            var count = s.Gaming.CustomGamingProfiles.RemoveAll(p => string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));
            if (count > 0)
            {
                removed = true;
                if (string.Equals(s.Gaming.ActiveGamingProfileId, profileId, StringComparison.OrdinalIgnoreCase))
                {
                    s.Gaming.ActiveGamingProfileId = BuiltInGamingProfiles.GeneralGamingId;
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseGamingStateChanged();
        }

        return removed;
    }

    public Task<IReadOnlyList<ResolverBenchmarkResult>> RunBenchmarkAsync(
        int roundsPerDomain = 2,
        IProgress<(int Completed, int Total, string CurrentResolver)>? progress = null,
        CancellationToken cancellationToken = default) =>
        RunBenchmarkCoreAsync(roundsPerDomain, progress, detailedProgress: null, cancellationToken);

    public Task<IReadOnlyList<ResolverBenchmarkResult>> RunBenchmarkAsync(
        int roundsPerDomain,
        IProgress<GamingBenchmarkProgress>? detailedProgress,
        CancellationToken cancellationToken = default) =>
        RunBenchmarkCoreAsync(roundsPerDomain, legacyProgress: null, detailedProgress, cancellationToken);

    private async Task<IReadOnlyList<ResolverBenchmarkResult>> RunBenchmarkCoreAsync(
        int roundsPerDomain,
        IProgress<(int Completed, int Total, string CurrentResolver)>? legacyProgress,
        IProgress<GamingBenchmarkProgress>? detailedProgress,
        CancellationToken cancellationToken)
    {
        roundsPerDomain = Math.Clamp(roundsPerDomain, 2, 10);
        var activeProfile = GetActiveGamingProfile();
        var domains = activeProfile.Domains.Count >= 3
            ? activeProfile.Domains.Take(5).ToList()
            : BuiltInGamingProfiles.DefaultBenchmarkDomains.Take(5).ToList();

        var candidates = _resolverLibrary.GetEnabled()
            .Where(r => _upstreams.ContainsKey(r.Protocol))
            .ToList();

        var totalResolvers = candidates.Count;
        var totalQueriesTarget = totalResolvers * domains.Count * roundsPerDomain;
        var results = new List<ResolverBenchmarkResult>(totalResolvers);
        var resultsLock = new object();
        var perQueryTimeout = TimeSpan.FromMilliseconds(Math.Clamp(_settings.Current.Dns.QueryTimeoutMs, 1000, 2200));
        var hardDeadline = perQueryTimeout + TimeSpan.FromMilliseconds(400);
        var completedResolvers = 0;
        var completedQueries = 0;
        var cancelled = false;

        using var throttle = new SemaphoreSlim(3, 3);
        var tasks = candidates.Select(async resolver =>
        {
            var acquired = false;
            try
            {
                await throttle.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;
                cancellationToken.ThrowIfCancellationRequested();

                var snapshotDone = Volatile.Read(ref completedResolvers);
                legacyProgress?.Report((snapshotDone, totalResolvers, resolver.Name));
                detailedProgress?.Report(new GamingBenchmarkProgress(
                    GamingBenchmarkProgressStage.ResolverStarted,
                    resolver.Id,
                    resolver.Name,
                    resolver.Protocol,
                    domains[0],
                    1,
                    roundsPerDomain,
                    snapshotDone,
                    totalResolvers,
                    Volatile.Read(ref completedQueries),
                    totalQueriesTarget,
                    true,
                    false,
                    0,
                    0,
                    0,
                    null,
                    DateTimeOffset.Now));

                var upstream = _upstreams[resolver.Protocol];
                var latencies = new List<double>(domains.Count * roundsPerDomain);
                var resolverTotalQueries = 0;
                var successQueries = 0;
                var timeoutQueries = 0;

                for (var round = 0; round < roundsPerDomain; round++)
                {
                    foreach (var domain in domains)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        resolverTotalQueries++;
                        DnsQueryResult outcome;
                        try
                        {
                            var query = DnsPacket.CreateQuery(domain, DnsRecordType.A);
                            outcome = await upstream
                                .QueryAsync(query, resolver, perQueryTimeout, cancellationToken)
                                .WaitAsync(hardDeadline, cancellationToken)
                                .ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            throw;
                        }
                        catch (TimeoutException)
                        {
                            outcome = new DnsQueryResult(false, [], perQueryTimeout.TotalMilliseconds, resolver.Id, resolver.Protocol, "Timed out");
                        }
                        catch (Exception ex)
                        {
                            outcome = new DnsQueryResult(false, [], 0, resolver.Id, resolver.Protocol, ex.Message);
                        }

                        var timedOut = !outcome.Success && outcome.Error is not null &&
                                       (outcome.Error.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                                        outcome.Error.Contains("timeout", StringComparison.OrdinalIgnoreCase));
                        if (outcome.Success)
                        {
                            successQueries++;
                            latencies.Add(outcome.LatencyMs);
                        }
                        else if (timedOut)
                        {
                            timeoutQueries++;
                        }

                        var doneQueriesNow = Interlocked.Increment(ref completedQueries);
                        detailedProgress?.Report(new GamingBenchmarkProgress(
                            GamingBenchmarkProgressStage.DomainProbed,
                            resolver.Id,
                            resolver.Name,
                            resolver.Protocol,
                            domain,
                            round + 1,
                            roundsPerDomain,
                            Volatile.Read(ref completedResolvers),
                            totalResolvers,
                            doneQueriesNow,
                            totalQueriesTarget,
                            outcome.Success,
                            timedOut,
                            outcome.LatencyMs,
                            0,
                            0,
                            outcome.Error,
                            DateTimeOffset.Now));
                    }
                }

                var metric = BuildBenchmarkMetric(resolver, resolverTotalQueries, successQueries, timeoutQueries, latencies);
                lock (resultsLock)
                {
                    results.Add(metric);
                }

                var doneResolversNow = Interlocked.Increment(ref completedResolvers);
                legacyProgress?.Report((doneResolversNow, totalResolvers, resolver.Name));
                detailedProgress?.Report(new GamingBenchmarkProgress(
                    GamingBenchmarkProgressStage.ResolverCompleted,
                    resolver.Id,
                    resolver.Name,
                    resolver.Protocol,
                    string.Join(", ", domains.Take(2)),
                    roundsPerDomain,
                    roundsPerDomain,
                    doneResolversNow,
                    totalResolvers,
                    Volatile.Read(ref completedQueries),
                    totalQueriesTarget,
                    metric.SuccessfulQueries > 0,
                    metric.TimeoutQueries == metric.TotalQueries,
                    metric.AverageLatencyMs,
                    metric.AverageLatencyMs,
                    metric.ReliabilityScore,
                    metric.SuccessfulQueries == 0 ? "All probes failed" : null,
                    DateTimeOffset.Now));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
            }
            finally
            {
                if (acquired)
                {
                    throttle.Release();
                }
            }
        }).ToList();

        await Task.WhenAll(tasks).ConfigureAwait(false);

        if (cancelled)
        {
            detailedProgress?.Report(new GamingBenchmarkProgress(
                GamingBenchmarkProgressStage.Cancelled,
                string.Empty,
                string.Empty,
                DnsProtocol.DnsOverHttps,
                string.Empty,
                roundsPerDomain,
                roundsPerDomain,
                completedResolvers,
                totalResolvers,
                completedQueries,
                totalQueriesTarget,
                false,
                false,
                0,
                0,
                0,
                "Cancelled",
                DateTimeOffset.Now));
        }

        var ordered = results
            .OrderByDescending(r => r.SuccessfulQueries > 0)
            .ThenBy(r => r.AverageLatencyMs)
            .ToList();

        if (ordered.Count > 0)
        {
            lock (_resultsLock)
            {
                _lastResults = ordered;
            }

            BenchmarkCompleted?.Invoke(this, ordered);
        }

        RaiseGamingStateChanged();
        return ordered;
    }

    public ResolverBenchmarkResult? SelectBestBenchmarkResult(
        IReadOnlyList<ResolverBenchmarkResult> results,
        GamingSelectionProfile profile)
    {
        if (results is null || results.Count == 0)
        {
            return null;
        }

        var viable = results.Where(r => r.SuccessfulQueries > 0).ToList();
        if (viable.Count == 0)
        {
            return null;
        }

        switch (profile)
        {
            case GamingSelectionProfile.LowestLatency:
                var lowLatencyPool = viable.Where(r => r.SuccessRatePercent >= 80.0).ToList();
                if (lowLatencyPool.Count == 0)
                {
                    lowLatencyPool = viable;
                }

                return lowLatencyPool
                    .OrderBy(r => (r.AverageLatencyMs * 0.65) + (r.P95LatencyMs * 0.35))
                    .First();

            case GamingSelectionProfile.Balanced:
                var balancedPool = viable.Where(r => r.SuccessRatePercent >= 90.0).ToList();
                if (balancedPool.Count == 0)
                {
                    balancedPool = viable;
                }

                return balancedPool
                    .OrderByDescending(r => (r.ReliabilityScore * 1.4) - (r.AverageLatencyMs * 0.35) - (r.P95LatencyMs * 0.15))
                    .First();

            case GamingSelectionProfile.MaximumReliability:
            default:
                return viable
                    .OrderByDescending(r => r.SuccessRatePercent)
                    .ThenBy(r => r.TimeoutRatePercent)
                    .ThenByDescending(r => r.ReliabilityScore)
                    .ThenBy(r => r.P95LatencyMs)
                    .First();
        }
    }

    public async Task<(bool Success, string? Error)> SetGamingModeAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s => s.Gaming.IsGamingModeEnabled = enabled, cancellationToken).ConfigureAwait(false);
        if (!enabled)
        {
            _pinnedResolverId = null;
            _logger.LogInformation("Gaming Mode disabled; session resolver unpinned.");
            RaiseGamingStateChanged();
            return (true, null);
        }

        var chosen = GetSelectedGamingResolver();
        _pinnedResolverId = chosen.Id;

        // 1. Ensure DNS cache is warm/enabled
        if (!_cache.IsEnabled)
        {
            await _cache.SetEnabledAsync(true, cancellationToken).ConfigureAwait(false);
        }

        // 2. Activate gaming domain routing rules
        var gamingProfile = GetActiveGamingProfile();
        await ApplyGamingRoutingRulesAsync(gamingProfile, chosen, cancellationToken).ConfigureAwait(false);

        // 3. Switch active resolver once at session start (and pin it during the session)
        var (ok, err) = await _dnsEngine.SwitchResolverAsync(chosen.Id, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Gaming Mode enabled with pinned resolver {Resolver} ({Profile})", chosen.Name, gamingProfile.Name);
        RaiseGamingStateChanged();
        return (ok, err);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dnsEngine.StateChanged -= OnEngineStateChanged;
        _defaultDoh.Dispose();
        _defaultDot.Dispose();
    }

    private static ResolverBenchmarkResult BuildBenchmarkMetric(
        DnsResolverEndpoint resolver,
        int totalQueries,
        int successQueries,
        int timeoutQueries,
        List<double> latencies)
    {
        double avg = 9999.0;
        double min = 9999.0;
        double max = 9999.0;
        double p95 = 9999.0;
        double jitter = 0.0;

        if (latencies.Count > 0)
        {
            var sorted = latencies.OrderBy(x => x).ToList();
            avg = Math.Round(sorted.Average(), 1);
            min = Math.Round(sorted[0], 1);
            max = Math.Round(sorted[^1], 1);
            var p95Index = Math.Clamp((int)Math.Ceiling(sorted.Count * 0.95) - 1, 0, sorted.Count - 1);
            p95 = Math.Round(sorted[p95Index], 1);

            var mean = sorted.Average();
            var variance = sorted.Sum(x => (x - mean) * (x - mean)) / sorted.Count;
            jitter = Math.Round(Math.Sqrt(variance), 1);
        }

        var successRate = totalQueries > 0 ? Math.Round(successQueries * 100.0 / totalQueries, 1) : 0.0;
        var timeoutRate = totalQueries > 0 ? Math.Round(timeoutQueries * 100.0 / totalQueries, 1) : 0.0;

        double reliability = 0.0;
        if (successQueries > 0)
        {
            var successComponent = (successRate / 100.0) * 70.0;
            var stabilityComponent = (1.0 - Math.Clamp(jitter / 120.0, 0.0, 1.0)) * 15.0;
            var speedComponent = (1.0 - Math.Clamp(avg / 400.0, 0.0, 1.0)) * 15.0;
            reliability = Math.Round(successComponent + stabilityComponent + speedComponent, 1);
        }

        return new ResolverBenchmarkResult
        {
            ResolverId = resolver.Id,
            ResolverName = resolver.Name,
            Provider = resolver.Provider,
            Protocol = resolver.Protocol,
            TotalQueries = totalQueries,
            SuccessfulQueries = successQueries,
            TimeoutQueries = timeoutQueries,
            AverageLatencyMs = avg,
            MinLatencyMs = min,
            MaxLatencyMs = max,
            P95LatencyMs = p95,
            JitterMs = jitter,
            SuccessRatePercent = successRate,
            TimeoutRatePercent = timeoutRate,
            ReliabilityScore = reliability,
            MeasuredAt = DateTimeOffset.UtcNow,
        };
    }

    private async Task ApplyGamingRoutingRulesAsync(
        GamingPlatformProfile gamingProfile,
        DnsResolverEndpoint resolver,
        CancellationToken cancellationToken)
    {
        await _routing.SetRoutingEnabledAsync(true, cancellationToken).ConfigureAwait(false);
        await _routing.SetActiveProfileAsync(BuiltInRoutingProfiles.GamingProfileId, cancellationToken).ConfigureAwait(false);
        await _routing.SetProfileFallbackResolverAsync(BuiltInRoutingProfiles.GamingProfileId, resolver.Id, cancellationToken).ConfigureAwait(false);

        foreach (var domain in gamingProfile.Domains)
        {
            await _routing.AddOrUpdateRuleAsync(new DnsRoutingRule
            {
                Id = $"gaming-auto-{domain.Replace('.', '-')}",
                ProfileId = BuiltInRoutingProfiles.GamingProfileId,
                Name = $"{gamingProfile.Name} ({domain})",
                Pattern = domain,
                MatchKind = RoutingMatchKind.DomainSuffix,
                ResolverId = resolver.Id,
                Priority = 5,
                IsEnabled = true,
            }, cancellationToken).ConfigureAwait(false);
        }
    }

    private void OnEngineStateChanged(object? sender, DnsEngineRuntimeStats stats)
    {
        // Automatic recovery during Gaming Mode if the pinned resolver becomes Degraded
        if (IsGamingModeEnabled && stats.State == DnsEngineState.Degraded)
        {
            var fallback = _resolverLibrary.GetSecondaryResolver();
            if (!string.Equals(fallback.Id, stats.ActiveResolverId, StringComparison.OrdinalIgnoreCase))
            {
                _pinnedResolverId = fallback.Id;
                _logger.LogWarning("Gaming Mode detected degraded resolver; recovering to secondary {Resolver}", fallback.Name);
                _ = _dnsEngine.SwitchResolverAsync(fallback.Id);
            }
        }
    }

    private void RaiseGamingStateChanged() => GamingStateChanged?.Invoke(this, EventArgs.Empty);
}
