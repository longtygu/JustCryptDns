using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;

namespace JustCryptDns.Network.Diagnostics;

public sealed class NetworkDiagnosticsService : INetworkDiagnosticsService, IDisposable
{
    public const int MaxMonitorEntries = 3000;
    public const int MaxTrackedDomains = 4096;

    private readonly ISettingsService _settings;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly INetworkInfoService _networkInfo;
    private readonly IBrowserPolicyInspector? _browserPolicy;
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _upstreams;
    private readonly DohDnsUpstream? _defaultDoh;
    private readonly DotDnsUpstream? _defaultDot;
    private readonly LinkedList<LiveQueryMonitorEntry> _monitorEntries = new();
    private readonly Dictionary<string, DomainAggregateState> _domainStats = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTimeOffset> _globalQueryWindow = new();
    private readonly Queue<DateTimeOffset> _globalBlockedWindow = new();
    private readonly object _monitorLock = new();
    private DateTimeOffset _sessionStartedUtc = DateTimeOffset.UtcNow;
    private long _nextSequenceId;
    private long _totalObservedQueries;
    private long _totalBlockedQueries;
    private long _totalCachedQueries;
    private long _totalFailedQueries;
    private bool _disposed;

    private sealed class DomainAggregateState
    {
        public string Domain { get; init; } = string.Empty;
        public long TotalCount;
        public long BlockedCount;
        public long CachedCount;
        public long FailedCount;
        public long RoutedCount;
        public long RewrittenCount;
        public double LatencySumMs;
        public long LatencySamples;
        public string LastOutcome = string.Empty;
        public string LastResolverName = string.Empty;
        public string? LastAnswerSummary;
        public DateTimeOffset LastSeenUtc;
        public readonly Queue<DateTimeOffset> RecentWindow = new();
        public readonly Queue<DateTimeOffset> RecentBlockedWindow = new();
    }

    public NetworkDiagnosticsService(
        ISettingsService settings,
        IResolverLibraryService resolverLibrary,
        INetworkInfoService networkInfo,
        IEnumerable<IDnsUpstreamClient>? customUpstreams = null,
        IBrowserPolicyInspector? browserPolicy = null)
    {
        _settings = settings;
        _resolverLibrary = resolverLibrary;
        _networkInfo = networkInfo;
        _browserPolicy = browserPolicy;

        var list = customUpstreams?.ToList();
        if (list is { Count: > 0 })
        {
            _upstreams = list.ToDictionary(u => u.Protocol);
        }
        else
        {
            _defaultDoh = new DohDnsUpstream();
            _defaultDot = new DotDnsUpstream();
            var defaultClients = new IDnsUpstreamClient[]
            {
                _defaultDoh,
                _defaultDot,
                new UdpTcpDnsUpstream(),
            };
            _upstreams = defaultClients.ToDictionary(u => u.Protocol);
        }
    }

    public event EventHandler<LiveQueryMonitorEntry>? QueryObserved;

    public bool IsMonitorPaused { get; set; }

    public IReadOnlyList<LiveQueryMonitorEntry> GetMonitorEntries()
    {
        lock (_monitorLock)
        {
            return _monitorEntries.ToList();
        }
    }

    public IReadOnlyList<LiveQueryMonitorEntry> GetMonitorEntriesSince(long afterSequenceId, int maxCount = 1000)
    {
        var limit = Math.Clamp(maxCount, 1, 5000);
        lock (_monitorLock)
        {
            var result = new List<LiveQueryMonitorEntry>(Math.Min(limit, _monitorEntries.Count));
            foreach (var item in _monitorEntries)
            {
                if (item.SequenceId <= afterSequenceId)
                {
                    break;
                }

                result.Add(item);
                if (result.Count >= limit)
                {
                    break;
                }
            }

            return result;
        }
    }

    public double GetBlockedQueriesPerMinute()
    {
        var cutoff = DateTimeOffset.UtcNow.AddSeconds(-60);
        lock (_monitorLock)
        {
            PruneWindow(_globalBlockedWindow, cutoff);
            return _globalBlockedWindow.Count;
        }
    }

    public QueryAnalyticsSnapshot GetQueryAnalyticsSnapshot(int topN = 50)
    {
        var limit = Math.Clamp(topN, 1, 200);
        var nowUtc = DateTimeOffset.UtcNow;
        var cutoff = nowUtc.AddSeconds(-60);

        lock (_monitorLock)
        {
            PruneWindow(_globalQueryWindow, cutoff);
            PruneWindow(_globalBlockedWindow, cutoff);

            var all = new List<DomainQueryAggregate>(_domainStats.Count);
            foreach (var state in _domainStats.Values)
            {
                PruneWindow(state.RecentWindow, cutoff);
                PruneWindow(state.RecentBlockedWindow, cutoff);

                var qpm = (double)state.RecentWindow.Count;
                var blockedPerMin = state.RecentBlockedWindow.Count;
                var isHighFreq = qpm >= 20 || blockedPerMin >= 10;

                all.Add(new DomainQueryAggregate
                {
                    Domain = state.Domain,
                    TotalCount = state.TotalCount,
                    BlockedCount = state.BlockedCount,
                    CachedCount = state.CachedCount,
                    FailedCount = state.FailedCount,
                    RoutedCount = state.RoutedCount,
                    RewrittenCount = state.RewrittenCount,
                    AverageLatencyMs = state.LatencySamples > 0
                        ? Math.Round(state.LatencySumMs / state.LatencySamples, 1)
                        : 0.0,
                    QueriesPerMinute = qpm,
                    IsHighFrequency = isHighFreq,
                    LastOutcome = state.LastOutcome,
                    LastResolverName = state.LastResolverName,
                    LastAnswerSummary = state.LastAnswerSummary,
                    LastSeenUtc = state.LastSeenUtc,
                });
            }

            return new QueryAnalyticsSnapshot
            {
                SessionStartedUtc = _sessionStartedUtc,
                TotalObservedQueries = _totalObservedQueries,
                TotalBlockedQueries = _totalBlockedQueries,
                TotalCachedQueries = _totalCachedQueries,
                TotalFailedQueries = _totalFailedQueries,
                UniqueDomainCount = _domainStats.Count,
                CurrentQueriesPerMinute = _globalQueryWindow.Count,
                BlockedQueriesPerMinute = _globalBlockedWindow.Count,
                TopQueried = all
                    .OrderByDescending(a => a.TotalCount)
                    .ThenByDescending(a => a.LastSeenUtc)
                    .Take(limit)
                    .ToList(),
                TopBlocked = all
                    .Where(a => a.BlockedCount > 0)
                    .OrderByDescending(a => a.BlockedCount)
                    .ThenByDescending(a => a.QueriesPerMinute)
                    .Take(limit)
                    .ToList(),
                TopFailed = all
                    .Where(a => a.FailedCount > 0)
                    .OrderByDescending(a => a.FailedCount)
                    .ThenByDescending(a => a.LastSeenUtc)
                    .Take(limit)
                    .ToList(),
            };
        }
    }

    public void RecordMonitorEntry(LiveQueryMonitorEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (IsMonitorPaused)
        {
            return;
        }

        var seq = Interlocked.Increment(ref _nextSequenceId);
        var stamped = entry.SequenceId > 0 ? entry : entry with { SequenceId = seq };
        var maxEntries = _settings.Current.Performance.GetMonitorBufferLimit();
        var nowUtc = stamped.Timestamp.ToUniversalTime();
        var cutoff = nowUtc.AddSeconds(-60);

        lock (_monitorLock)
        {
            _monitorEntries.AddFirst(stamped);
            while (_monitorEntries.Count > maxEntries)
            {
                _monitorEntries.RemoveLast();
            }

            _totalObservedQueries++;
            _globalQueryWindow.Enqueue(nowUtc);
            PruneWindow(_globalQueryWindow, cutoff);

            var isBlocked = string.Equals(stamped.Outcome, "Blocked", StringComparison.OrdinalIgnoreCase);
            var isCached = string.Equals(stamped.Outcome, "Cached", StringComparison.OrdinalIgnoreCase)
                || string.Equals(stamped.Outcome, "Stale", StringComparison.OrdinalIgnoreCase);
            var isFailed = string.Equals(stamped.Outcome, "Failed", StringComparison.OrdinalIgnoreCase);
            var isRouted = string.Equals(stamped.Outcome, "Routed", StringComparison.OrdinalIgnoreCase);
            var isRewritten = string.Equals(stamped.Outcome, "Rewritten", StringComparison.OrdinalIgnoreCase);

            if (isBlocked)
            {
                _totalBlockedQueries++;
                _globalBlockedWindow.Enqueue(nowUtc);
                PruneWindow(_globalBlockedWindow, cutoff);
            }
            else if (isCached)
            {
                _totalCachedQueries++;
            }
            else if (isFailed)
            {
                _totalFailedQueries++;
            }

            var normDomain = string.IsNullOrWhiteSpace(stamped.Domain) ? "unknown" : stamped.Domain.Trim().TrimEnd('.').ToLowerInvariant();
            if (!_domainStats.TryGetValue(normDomain, out var state))
            {
                if (_domainStats.Count >= MaxTrackedDomains)
                {
                    EvictColdestDomainLocked();
                }

                state = new DomainAggregateState { Domain = normDomain };
                _domainStats[normDomain] = state;
            }

            state.TotalCount++;
            if (isBlocked) state.BlockedCount++;
            if (isCached) state.CachedCount++;
            if (isFailed) state.FailedCount++;
            if (isRouted) state.RoutedCount++;
            if (isRewritten) state.RewrittenCount++;
            if (stamped.LatencyMs.HasValue)
            {
                state.LatencySumMs += stamped.LatencyMs.Value;
                state.LatencySamples++;
            }

            state.LastOutcome = stamped.Outcome;
            state.LastResolverName = stamped.ResolverName;
            state.LastAnswerSummary = stamped.AnswerSummary;
            state.LastSeenUtc = nowUtc;
            state.RecentWindow.Enqueue(nowUtc);
            PruneWindow(state.RecentWindow, cutoff);
            if (isBlocked)
            {
                state.RecentBlockedWindow.Enqueue(nowUtc);
                PruneWindow(state.RecentBlockedWindow, cutoff);
            }
        }

        QueryObserved?.Invoke(this, stamped);
    }

    public void ClearMonitorEntries()
    {
        lock (_monitorLock)
        {
            _monitorEntries.Clear();
            _domainStats.Clear();
            _globalQueryWindow.Clear();
            _globalBlockedWindow.Clear();
            _totalObservedQueries = 0;
            _totalBlockedQueries = 0;
            _totalCachedQueries = 0;
            _totalFailedQueries = 0;
            _sessionStartedUtc = DateTimeOffset.UtcNow;
        }
    }

    private void EvictColdestDomainLocked()
    {
        var batchCount = Math.Max(1, MaxTrackedDomains / 10);
        if (_domainStats.Count <= batchCount)
        {
            _domainStats.Clear();
            return;
        }

        foreach (var victimKey in _domainStats
            .OrderBy(kvp => kvp.Value.TotalCount)
            .ThenBy(kvp => kvp.Value.LastSeenUtc)
            .Take(batchCount)
            .Select(kvp => kvp.Key)
            .ToList())
        {
            _domainStats.Remove(victimKey);
        }
    }

    private static void PruneWindow(Queue<DateTimeOffset> queue, DateTimeOffset cutoff)
    {
        while (queue.Count > 0 && queue.Peek() < cutoff)
        {
            queue.Dequeue();
        }
    }

    public async Task<DnsLookupReport> LookupAsync(
        string domain,
        string recordType,
        string? resolverId = null,
        CancellationToken cancellationToken = default)
    {
        var normDomain = RoutingMatcher.NormalizeDomain(domain);
        if (string.IsNullOrEmpty(normDomain))
        {
            normDomain = "example.com";
        }

        if (!Enum.TryParse<DnsRecordType>(recordType, ignoreCase: true, out var qType))
        {
            qType = DnsRecordType.A;
        }

        var resolver = string.IsNullOrWhiteSpace(resolverId)
            ? _resolverLibrary.GetPrimaryResolver()
            : _resolverLibrary.GetByIdOrDefault(resolverId);

        if (!_upstreams.TryGetValue(resolver.Protocol, out var upstream))
        {
            return new DnsLookupReport
            {
                Domain = normDomain,
                RecordType = qType.ToString(),
                ResolverName = resolver.Name,
                Protocol = resolver.Protocol,
                Success = false,
                ResponseCode = "UNAVAILABLE",
                LatencyMs = 0,
                AuthenticDataBit = false,
                Records = [],
                ErrorMessage = $"Direct lookup client not available for {resolver.Protocol}.",
            };
        }

        var timeoutMs = Math.Clamp(_settings.Current.Dns.QueryTimeoutMs, 800, 5000);
        var timeout = TimeSpan.FromMilliseconds(timeoutMs);
        DnsQueryResult result;
        try
        {
            var query = DnsPacket.CreateQuery(normDomain, qType, dnssecOk: true);
            result = await upstream
                .QueryAsync(query, resolver, timeout, cancellationToken)
                .WaitAsync(timeout + TimeSpan.FromMilliseconds(400), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            result = new DnsQueryResult(false, [], timeoutMs, resolver.Id, resolver.Protocol, $"Timed out after {timeoutMs} ms");
        }
        catch (Exception ex)
        {
            result = new DnsQueryResult(false, [], 0, resolver.Id, resolver.Protocol, ex.Message);
        }

        if (!result.Success || !DnsPacket.TryParse(result.ResponseBytes, out var parsed) || parsed is null)
        {
            return new DnsLookupReport
            {
                Domain = normDomain,
                RecordType = qType.ToString(),
                ResolverName = resolver.Name,
                Protocol = resolver.Protocol,
                Success = false,
                ResponseCode = "ERROR",
                LatencyMs = Math.Round(result.LatencyMs, 1),
                AuthenticDataBit = false,
                Records = [],
                ErrorMessage = result.Error ?? "Malformed DNS response.",
            };
        }

        var items = parsed.Answers
            .Select(a => new DnsLookupRecordItem(a.Name, a.Type.ToString(), a.Ttl, a.DataSummary))
            .ToList();

        RecordMonitorEntry(new LiveQueryMonitorEntry
        {
            Timestamp = DateTimeOffset.Now,
            Domain = normDomain,
            RecordType = qType.ToString(),
            Outcome = "Diagnostic",
            ResolverName = resolver.Name,
            Protocol = resolver.Protocol,
            LatencyMs = Math.Round(result.LatencyMs, 1),
        });

        return new DnsLookupReport
        {
            Domain = normDomain,
            RecordType = qType.ToString(),
            ResolverName = resolver.Name,
            Protocol = resolver.Protocol,
            Success = true,
            ResponseCode = parsed.Header.ResponseCode.ToString(),
            LatencyMs = Math.Round(result.LatencyMs, 1),
            AuthenticDataBit = parsed.Header.IsAuthenticData,
            Records = items,
        };
    }

    public async Task<DnssecTestReport> TestDnssecAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default)
    {
        var resolver = string.IsNullOrWhiteSpace(resolverId)
            ? _resolverLibrary.GetPrimaryResolver()
            : _resolverLibrary.GetByIdOrDefault(resolverId);

        var signedLookup = await LookupAsync("cloudflare.com", "A", resolver.Id, cancellationToken).ConfigureAwait(false);
        var adVerified = signedLookup.Success && (signedLookup.AuthenticDataBit || resolver.SupportsDnssec);

        var summary = adVerified
            ? $"External test passed: '{resolver.Name}' resolved DNSSEC-signed domain 'cloudflare.com' ({signedLookup.LatencyMs:0.#} ms, AD={signedLookup.AuthenticDataBit})."
            : $"External test failed or unverified on '{resolver.Name}': {signedLookup.ErrorMessage ?? signedLookup.ResponseCode}.";

        return new DnssecTestReport
        {
            ResolverName = resolver.Name,
            SupportsDnssecValidation = resolver.SupportsDnssec,
            SignedDomainVerified = adVerified,
            LatencyMs = signedLookup.LatencyMs,
            Summary = summary,
        };
    }

    public async Task<(bool Success, double LatencyMs, string Summary)> TestDohConnectivityAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default)
    {
        var resolver = string.IsNullOrWhiteSpace(resolverId)
            ? _resolverLibrary.GetAll().FirstOrDefault(r => r.Protocol == DnsProtocol.DnsOverHttps) ?? _resolverLibrary.GetPrimaryResolver()
            : _resolverLibrary.GetByIdOrDefault(resolverId);

        var report = await LookupAsync("example.com", "A", resolver.Id, cancellationToken).ConfigureAwait(false);
        var summary = report.Success
            ? $"External DoH connectivity verified with {resolver.Name} ({resolver.Endpoint}) in {report.LatencyMs:0.#} ms."
            : $"External DoH connectivity failed for {resolver.Name}: {report.ErrorMessage ?? report.ResponseCode}.";
        return (report.Success, report.LatencyMs, summary);
    }

    public async Task<(bool Success, double LatencyMs, string Summary)> TestDnsCryptConnectivityAsync(
        string? resolverId = null,
        CancellationToken cancellationToken = default)
    {
        var resolver = string.IsNullOrWhiteSpace(resolverId)
            ? _resolverLibrary.GetAll().FirstOrDefault(r => r.Protocol == DnsProtocol.DnsCrypt) ?? BuiltInResolvers.GetByIdOrDefault("quad9-dnscrypt")
            : _resolverLibrary.GetByIdOrDefault(resolverId);

        if (!ResolverValidator.TryValidateDnsCryptStamp(resolver.Endpoint, out var stampError))
        {
            return (false, 0, $"DNSCrypt stamp validation failed: {stampError}");
        }

        if (_upstreams.TryGetValue(DnsProtocol.DnsCrypt, out var cryptUpstream))
        {
            var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
            var res = await cryptUpstream.QueryAsync(query, resolver, TimeSpan.FromMilliseconds(2500), cancellationToken).ConfigureAwait(false);
            var msg = res.Success
                ? $"DNSCrypt query verified via {resolver.Name} in {res.LatencyMs:0.#} ms."
                : $"DNSCrypt query failed on {resolver.Name}: {res.Error}.";
            return (res.Success, Math.Round(res.LatencyMs, 1), msg);
        }

        if (!IPAddress.TryParse(resolver.PrimaryIp, out var ip))
        {
            return (false, 0, $"Invalid DNSCrypt bootstrap IP '{resolver.PrimaryIp}'.");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(2500));
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily);
            await tcp.ConnectAsync(ip, resolver.Port, cts.Token).ConfigureAwait(false);
            sw.Stop();
            var ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
            return (true, ms, $"External DNSCrypt endpoint {resolver.Name} ({ip}:{resolver.Port}) is reachable ({ms:0.#} ms) and stamp is valid.");
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), $"External DNSCrypt endpoint {resolver.Name} unreachable: {ex.Message}");
        }
    }

    public Task<IReadOnlyList<ResolverComparisonEntry>> CompareResolversAsync(
        string domain,
        string recordType = "A",
        CancellationToken cancellationToken = default) =>
        CompareResolversAsync(domain, recordType, progress: null, cancellationToken);

    public async Task<IReadOnlyList<ResolverComparisonEntry>> CompareResolversAsync(
        string domain,
        string recordType,
        IProgress<DiagnosticStepProgress>? progress,
        CancellationToken cancellationToken = default)
    {
        var candidates = _resolverLibrary.GetEnabled()
            .Where(r => _upstreams.ContainsKey(r.Protocol))
            .Take(8)
            .ToList();

        return await QueryMultipleResolversCoreAsync(DiagnosticTestCategory.Compare, candidates, domain, recordType, progress, cancellationToken).ConfigureAwait(false);
    }

    public Task<IReadOnlyList<ResolverComparisonEntry>> CheckPropagationAsync(
        string domain,
        string recordType = "A",
        CancellationToken cancellationToken = default) =>
        CheckPropagationAsync(domain, recordType, progress: null, cancellationToken);

    public async Task<IReadOnlyList<ResolverComparisonEntry>> CheckPropagationAsync(
        string domain,
        string recordType,
        IProgress<DiagnosticStepProgress>? progress,
        CancellationToken cancellationToken = default)
    {
        string[] globalIds =
        [
            "cloudflare-doh",
            "google-doh",
            "quad9-doh",
            "opendns-doh",
            "adguard-doh",
            "controld-unfiltered-doh",
            "mullvad-doh",
            "dns0-zero-doh",
        ];

        var candidates = globalIds
            .Select(_resolverLibrary.GetByIdOrDefault)
            .DistinctBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
            .Where(r => _upstreams.ContainsKey(r.Protocol))
            .ToList();

        return await QueryMultipleResolversCoreAsync(DiagnosticTestCategory.Propagation, candidates, domain, recordType, progress, cancellationToken).ConfigureAwait(false);
    }

    public Task<DnsLeakTestReport> RunDnsLeakTestAsync(CancellationToken cancellationToken = default)
    {
        var snapshot = _networkInfo.GetSnapshot();
        var dns = _settings.Current.Dns;
        var listenEndpoint = $"{dns.ListenAddress}:{dns.ListenPort}";
        var primaryResolver = _resolverLibrary.GetByIdOrDefault(dns.ActiveResolverId);

        var adapterDns = snapshot.PrimaryAdapter?.DnsServers.Select(ip => ip.ToString()).ToList() ?? [];
        var allLoopback = adapterDns.Count > 0 && adapterDns.All(ip => IPAddress.TryParse(ip, out var parsed) && IPAddress.IsLoopback(parsed));

        var isLeak = !allLoopback || !primaryResolver.IsEncrypted;

        string summary;
        if (!allLoopback)
        {
            summary = $"Potential DNS leak detected: Windows adapter DNS ({string.Join(", ", adapterDns)}) includes non-loopback servers that may bypass the local proxy ({listenEndpoint}).";
        }
        else if (!primaryResolver.IsEncrypted)
        {
            summary = $"Unencrypted upstream: Windows adapter routes to local proxy ({listenEndpoint}), but active resolver '{primaryResolver.Name}' uses plain UDP/TCP.";
        }
        else
        {
            summary = $"No local DNS leak detected: Windows adapter points exclusively to local proxy ({string.Join(", ", adapterDns)}), and queries are encrypted via {primaryResolver.Name} ({primaryResolver.Protocol}).";
        }

        return Task.FromResult(new DnsLeakTestReport
        {
            IsLeakDetected = isLeak,
            IsAdapterUsingLocalProxy = allLoopback,
            AdapterDnsServers = adapterDns,
            ActiveEncryptedResolver = primaryResolver.Name,
            ActiveProtocol = primaryResolver.Protocol,
            Summary = summary,
        });
    }

    public Task<BrowserDohCheckReport> CheckBrowserDohBypassAsync(CancellationToken cancellationToken = default)
    {
        var dns = _settings.Current.Dns;
        var canaryBlocked = dns.BlockFirefoxDohCanary;
        var snapshot = _networkInfo.GetSnapshot();
        var adapterDns = snapshot.PrimaryAdapter?.DnsServers ?? [];
        var adapterLoopback = adapterDns.Count > 0 && adapterDns.All(IPAddress.IsLoopback);

        var policies = _browserPolicy?.InspectConfiguredBrowserDohPolicies() ?? [];
        var policyDetected = policies.Count > 0;
        var findings = new List<string>
        {
            canaryBlocked
                ? "Firefox DoH Canary Guard enabled (use-application-dns.net -> NXDOMAIN)."
                : "Warning: Firefox DoH Canary Guard is disabled; Firefox may bypass local filtering.",
            adapterLoopback
                ? $"Windows primary adapter DNS routes to local proxy ({string.Join(", ", adapterDns)})."
                : "Warning: Primary adapter DNS is not pointing exclusively to loopback local proxy.",
        };

        if (policyDetected)
        {
            findings.AddRange(policies);
        }
        else
        {
            findings.Add("No Chrome, Edge, or Firefox Group Policy DoH overrides found in registry.");
        }

        var summary = canaryBlocked && adapterLoopback && !policyDetected
            ? "Browser DoH audit OK: Firefox canary blocked, adapter on local proxy, no forced browser DoH policy."
            : policyDetected
                ? $"Browser DoH policy detected ({policies.Count}): enterprise/registry browser DoH settings may bypass local DNS filtering."
                : "Browser DoH bypass risk detected: ensure local adapter routes to loopback proxy and Firefox Canary Guard is enabled.";

        return Task.FromResult(new BrowserDohCheckReport
        {
            FirefoxCanaryBlocked = canaryBlocked,
            AdapterPointsToLocalProxy = adapterLoopback,
            BrowserPolicyDetected = policyDetected,
            BrowserPolicyDetail = policyDetected ? string.Join("; ", policies) : null,
            Findings = findings,
            Summary = summary,
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _defaultDoh?.Dispose();
        _defaultDot?.Dispose();
    }

    private async Task<IReadOnlyList<ResolverComparisonEntry>> QueryMultipleResolversCoreAsync(
        DiagnosticTestCategory category,
        List<DnsResolverEndpoint> resolvers,
        string domain,
        string recordType,
        IProgress<DiagnosticStepProgress>? progress,
        CancellationToken cancellationToken)
    {
        var total = resolvers.Count;
        var completed = 0;
        var bag = new List<ResolverComparisonEntry>(total);
        var bagLock = new object();
        using var throttle = new SemaphoreSlim(6, 6);

        var tasks = resolvers.Select(async r =>
        {
            var acquired = false;
            try
            {
                await throttle.WaitAsync(cancellationToken).ConfigureAwait(false);
                acquired = true;
                cancellationToken.ThrowIfCancellationRequested();

                progress?.Report(new DiagnosticStepProgress(
                    category,
                    "Probing",
                    $"{r.Name} ({r.Protocol})",
                    DiagnosticStepOutcome.Running,
                    null,
                    $"Querying {domain} ({recordType})...",
                    Volatile.Read(ref completed),
                    total,
                    DateTimeOffset.Now));

                var report = await LookupAsync(domain, recordType, r.Id, cancellationToken).ConfigureAwait(false);
                var primaryAnswer = report.Records.Count > 0
                    ? string.Join(", ", report.Records.Select(x => x.Value).Take(2))
                    : (report.ErrorMessage ?? report.ResponseCode);

                var entry = new ResolverComparisonEntry(
                    r.Name,
                    r.Provider,
                    r.Protocol,
                    report.Success,
                    report.LatencyMs,
                    report.ResponseCode,
                    primaryAnswer);

                lock (bagLock)
                {
                    bag.Add(entry);
                }

                var doneNow = Interlocked.Increment(ref completed);
                progress?.Report(new DiagnosticStepProgress(
                    category,
                    r.Provider,
                    $"{r.Name} ({r.Protocol})",
                    report.Success ? DiagnosticStepOutcome.Pass : DiagnosticStepOutcome.Fail,
                    report.LatencyMs,
                    report.Success ? $"{report.ResponseCode}: {primaryAnswer}" : (report.ErrorMessage ?? report.ResponseCode),
                    doneNow,
                    total,
                    DateTimeOffset.Now));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Partial results returned to caller when cancelled.
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

        return bag
            .OrderByDescending(x => x.Success)
            .ThenBy(x => x.LatencyMs)
            .ToList();
    }
}
