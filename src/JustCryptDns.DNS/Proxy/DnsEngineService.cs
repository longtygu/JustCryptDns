using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Ipc;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DnsCrypt;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.DNS.Proxy;

/// <summary>
/// Full lifecycle manager for the JustCryptDns core engine (Part 2):
/// local proxy, protocol dispatch (DoH, DoT, DNSCrypt, UDP/TCP), port conflict and loop prevention,
/// health monitoring, automatic recovery, and Windows adapter DNS safety integration.
/// </summary>
public sealed class DnsEngineService : IDnsEngine
{
    private readonly ISettingsService _settings;
    private readonly IDnsCryptProxyManager _dnsCryptManager;
    private readonly IWindowsDnsManager _windowsDns;
    private readonly ILogger<DnsEngineService> _logger;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly IDnsRoutingService? _routingService;
    private readonly IDnsFilteringService? _filteringService;
    private readonly IDnsCacheService? _cacheService;
    private readonly IDnsFailoverService? _failoverService;
    private readonly INetworkDiagnosticsService? _diagnosticsService;
    private readonly INetworkInfoService? _networkInfo;
    private readonly IDnsReverseLookupCache? _reverseLookupCache;
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _upstreams;
    private readonly DohDnsUpstream _defaultDoh;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);

    private LocalDnsProxy? _proxy;
    private DnsEngineState _state = DnsEngineState.Stopped;
    private DnsResolverEndpoint _activeResolver;
    private string _listenEndpoint;
    private long _totalQueries;
    private long _successfulQueries;
    private long _failedQueries;
    private long _consecutiveFailures;
    private double? _lastLatencyMs;
    private string? _lastError;
    private PortConflictInfo? _portConflict;
    private bool _disposed;

    public DnsEngineService(
        ISettingsService settings,
        IDnsCryptProxyManager dnsCryptManager,
        IWindowsDnsManager windowsDns,
        ILogger<DnsEngineService> logger,
        IEnumerable<IDnsUpstreamClient>? customUpstreams = null,
        IResolverLibraryService? resolverLibrary = null,
        IDnsRoutingService? routingService = null,
        IDnsFilteringService? filteringService = null,
        IDnsCacheService? cacheService = null,
        IDnsFailoverService? failoverService = null,
        INetworkDiagnosticsService? diagnosticsService = null,
        INetworkInfoService? networkInfo = null,
        IDnsReverseLookupCache? reverseLookupCache = null)
    {
        _settings = settings;
        _dnsCryptManager = dnsCryptManager;
        _windowsDns = windowsDns;
        _logger = logger;
        _resolverLibrary = resolverLibrary;
        _routingService = routingService;
        _filteringService = filteringService;
        _cacheService = cacheService;
        _failoverService = failoverService;
        _diagnosticsService = diagnosticsService;
        _networkInfo = networkInfo;
        _reverseLookupCache = reverseLookupCache;

        _defaultDoh = new DohDnsUpstream();
        var defaultClients = new IDnsUpstreamClient[]
        {
            _defaultDoh,
            new DotDnsUpstream(),
            new UdpTcpDnsUpstream(),
            new DnsCryptUpstream(_dnsCryptManager, () => _settings.Current.Dns.DnsCryptInternalPort),
        };

        var list = customUpstreams?.ToList();
        IEnumerable<IDnsUpstreamClient> active = list is { Count: > 0 } ? list : defaultClients;
        _upstreams = active.ToDictionary(u => u.Protocol);
        var dns = _settings.Current.Dns;
        _activeResolver = ResolveEndpoint(dns.ActiveResolverId);
        _listenEndpoint = $"{dns.ListenAddress}:{dns.ListenPort}";
    }

    public event EventHandler<DnsEngineRuntimeStats>? StateChanged;

    public DnsEngineRuntimeStats GetStats()
    {
        var dns = _settings.Current.Dns;
        var resolver = ResolveEndpoint(dns.ActiveResolverId);
        var cacheStats = _cacheService?.GetStats();
        var boundPort = _proxy is { BoundPort: > 0 } ? _proxy.BoundPort : dns.ListenPort;

        var trafficStatus = SystemTrafficStatus.Stopped;
        string? port53Owner = null;
        string? port53Service = null;
        string? suggestedLoopback = null;
        if (_state is DnsEngineState.Running or DnsEngineState.Degraded)
        {
            if (boundPort != 53)
            {
                trafficStatus = SystemTrafficStatus.NonStandardPort;
                var (procName, pid, svcName) = PortConflictDetector.TryFindPortOwnerDetails(53);
                if (procName is not null && pid.HasValue)
                {
                    port53Owner = $"{procName} (PID {pid.Value})";
                }

                port53Service = svcName;
                suggestedLoopback = PortConflictDetector.FindAvailableLoopbackForPort53(IPAddress.Loopback);
            }
            else if (_networkInfo is not null)
            {
                var snap = _networkInfo.GetSnapshot();
                var adapterDns = snap.PrimaryAdapter?.DnsServers;
                var listenIp = IPAddress.TryParse(dns.ListenAddress, out var parsedListen)
                    ? parsedListen
                    : IPAddress.Loopback;
                var matchesOurProxy = adapterDns is { Count: > 0 }
                    && adapterDns.Any(ip => ip.Equals(listenIp) || (dns.EnableIpv6 && ip.Equals(IPAddress.IPv6Loopback)));
                trafficStatus = matchesOurProxy
                    ? SystemTrafficStatus.InterceptingSystemTraffic
                    : SystemTrafficStatus.AdapterNotConfigured;
            }
            else
            {
                trafficStatus = SystemTrafficStatus.InterceptingSystemTraffic;
            }
        }

        return new DnsEngineRuntimeStats
        {
            State = _state,
            ActiveResolverId = resolver.Id,
            ActiveResolverName = resolver.Name,
            ActiveProtocol = resolver.Protocol,
            ListenEndpoint = $"{dns.ListenAddress}:{boundPort}",
            BoundPort = boundPort,
            TrafficStatus = trafficStatus,
            Port53OwnerDescription = port53Owner,
            Port53ServiceName = port53Service,
            SuggestedLoopbackIp = suggestedLoopback,
            TotalQueries = Interlocked.Read(ref _totalQueries),
            SuccessfulQueries = Interlocked.Read(ref _successfulQueries),
            FailedQueries = Interlocked.Read(ref _failedQueries),
            BlockedQueries = _filteringService?.BlockedQueryCount ?? 0,
            CacheHits = cacheStats?.CacheHits ?? 0,
            CacheHitRatioPercent = cacheStats?.HitRatioPercent ?? 0.0,
            LastLatencyMs = _lastLatencyMs,
            LastError = _lastError,
            PortConflict = _portConflict,
            DnsCryptVersion = _dnsCryptManager.InstalledVersion,
            HasAdapterBackup = _windowsDns.HasActiveBackup(),
        };
    }

    public async Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_state is DnsEngineState.Running or DnsEngineState.Degraded)
            {
                return (true, null);
            }

            SetState(DnsEngineState.Starting, error: null, conflict: null);

            var dns = _settings.Current.Dns;
            _activeResolver = ResolveEndpoint(dns.ActiveResolverId);
            if (!IPAddress.TryParse(dns.ListenAddress, out var listenIp))
            {
                listenIp = IPAddress.Loopback;
            }

            if (DnsLoopGuard.WouldLoop(_activeResolver, listenIp, dns.ListenPort))
            {
                var loopMsg = $"DNS loop prevented: resolver '{_activeResolver.Name}' points back to local listener {listenIp}:{dns.ListenPort}.";
                SetState(DnsEngineState.Stopped, loopMsg, null);
                return (false, loopMsg);
            }

            if (dns.ListenPort != 0)
            {
                var conflict = PortConflictDetector.CheckConflict(listenIp, dns.ListenPort);
                if (conflict is not null)
                {
                    SetState(DnsEngineState.Stopped, conflict.Message, conflict);
                    return (false, conflict.Message);
                }
            }

            if (_activeResolver.Protocol == DnsProtocol.DnsCrypt)
            {
                var (cryptOk, cryptErr) = await _dnsCryptManager.EnsureRunningAsync(
                    _activeResolver,
                    dns.DnsCryptInternalPort,
                    cancellationToken).ConfigureAwait(false);
                if (!cryptOk)
                {
                    SetState(DnsEngineState.Stopped, cryptErr, null);
                    return (false, cryptErr);
                }
            }

            var proxy = new LocalDnsProxy(listenIp, dns.ListenPort, dns.EnableIpv6, HandleClientQueryAsync, _logger);
            try
            {
                proxy.Start();
            }
            catch (SocketException ex)
            {
                await proxy.DisposeAsync().ConfigureAwait(false);
                var conflict = new PortConflictInfo(
                    true,
                    $"{listenIp}:{dns.ListenPort}",
                    "UDP/TCP",
                    PortConflictDetector.FindAvailablePort(listenIp),
                    $"Could not bind {listenIp}:{dns.ListenPort}: {ex.Message}");
                SetState(DnsEngineState.Stopped, conflict.Message, conflict);
                return (false, conflict.Message);
            }

            _proxy = proxy;
            _listenEndpoint = $"{listenIp}:{proxy.BoundPort}";
            Interlocked.Exchange(ref _consecutiveFailures, 0);

            if (dns.ConfigureWindowsAdapter)
            {
                var adapterResult = await _windowsDns.ApplyLocalProxyDnsAsync(
                    dns.TargetAdapterId,
                    listenIp.ToString(),
                    dns.EnableIpv6 ? "::1" : null,
                    async ct =>
                    {
                        var probe = await ProbeActiveResolverAsync(ct).ConfigureAwait(false);
                        return probe.Success;
                    },
                    cancellationToken).ConfigureAwait(false);

                if (!adapterResult.Success)
                {
                    await StopCoreAsync().ConfigureAwait(false);
                    SetState(DnsEngineState.Stopped, adapterResult.ErrorMessage, null);
                    return (false, adapterResult.ErrorMessage);
                }
            }

            SetState(DnsEngineState.Running, error: null, conflict: null);
            _logger.LogInformation("DNS engine started on {Endpoint} using {Resolver} ({Protocol})", _listenEndpoint, _activeResolver.Name, _activeResolver.Protocol);
            return (true, null);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_state == DnsEngineState.Stopped)
            {
                if (_windowsDns.HasActiveBackup())
                {
                    await _windowsDns.RestoreOriginalDnsAsync(_settings.Current.Dns.TargetAdapterId, cancellationToken).ConfigureAwait(false);
                }

                return;
            }

            SetState(DnsEngineState.Stopping, _lastError, _portConflict);
            await StopCoreAsync().ConfigureAwait(false);
            if (_windowsDns.HasActiveBackup())
            {
                await _windowsDns.RestoreOriginalDnsAsync(_settings.Current.Dns.TargetAdapterId, cancellationToken).ConfigureAwait(false);
            }

            SetState(DnsEngineState.Stopped, error: null, conflict: null);
            _logger.LogInformation("DNS engine stopped.");
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task<(bool Success, string? Error)> RestartAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync(cancellationToken).ConfigureAwait(false);
        return await StartAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<(bool Success, string? Error)> SwitchResolverAsync(string resolverId, CancellationToken cancellationToken = default)
    {
        var resolver = ResolveEndpoint(resolverId);
        var validation = ResolverValidator.Validate(resolver);
        if (!validation.IsValid)
        {
            return (false, validation.ErrorMessage);
        }

        await _settings.UpdateAsync(s => s.Dns.ActiveResolverId = resolver.Id, cancellationToken).ConfigureAwait(false);
        _activeResolver = resolver;

        if (_state is DnsEngineState.Running or DnsEngineState.Degraded)
        {
            if (resolver.Protocol == DnsProtocol.DnsCrypt)
            {
                var (ok, err) = await _dnsCryptManager.EnsureRunningAsync(
                    resolver,
                    _settings.Current.Dns.DnsCryptInternalPort,
                    cancellationToken).ConfigureAwait(false);
                if (!ok)
                {
                    SetState(DnsEngineState.Degraded, err, null);
                    return (false, err);
                }
            }
            else
            {
                await _dnsCryptManager.StopAsync(cancellationToken).ConfigureAwait(false);
            }

            SetState(DnsEngineState.Running, error: null, conflict: null);
        }
        else
        {
            RaiseStateChanged();
        }

        return (true, null);
    }

    public async Task<DnsQueryResult> ProbeActiveResolverAsync(CancellationToken cancellationToken = default)
    {
        var resolver = ResolveEndpoint(_settings.Current.Dns.ActiveResolverId);
        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
        var timeout = TimeSpan.FromMilliseconds(_settings.Current.Dns.QueryTimeoutMs);

        if (!_upstreams.TryGetValue(resolver.Protocol, out var upstream))
        {
            return new DnsQueryResult(false, [], 0, resolver.Id, resolver.Protocol, $"No upstream registered for {resolver.Protocol}.");
        }

        var result = await upstream.QueryAsync(query, resolver, timeout, cancellationToken).ConfigureAwait(false);
        RecordQueryOutcome(result);
        _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
        {
            Timestamp = DateTimeOffset.Now,
            Domain = "example.com",
            RecordType = "A",
            Outcome = result.Success ? "Probe" : "Failed",
            ResolverName = resolver.Name,
            Protocol = resolver.Protocol,
            LatencyMs = result.Success ? Math.Round(result.LatencyMs, 1) : null,
        });
        _logger.LogInformation(
            "Resolver probe to {Resolver} ({Protocol}): success={Success}, latency={Latency:0.0} ms, error={Error}",
            resolver.Name,
            resolver.Protocol,
            result.Success,
            result.LatencyMs,
            result.Error);
        return result;
    }

    public async Task<(bool Success, double LatencyMs, string Summary)> TestLocalProxyAsync(CancellationToken cancellationToken = default)
    {
        if (_proxy is not { BoundPort: > 0 } proxy)
        {
            return (false, 0, "Local DNS proxy is not running.");
        }

        var listenIp = IPAddress.TryParse(_settings.Current.Dns.ListenAddress, out var parsedIp)
            ? parsedIp
            : IPAddress.Loopback;
        var endpoint = new IPEndPoint(listenIp, proxy.BoundPort);

        using var udp = new UdpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(_settings.Current.Dns.QueryTimeoutMs, 4000)));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            // 1. Query cloudflare.com (tests routing + upstream + cache store)
            var q1 = DnsPacket.CreateQuery("cloudflare.com", DnsRecordType.A);
            await udp.SendAsync(q1, endpoint, cts.Token).ConfigureAwait(false);
            var r1 = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            sw.Stop();
            var firstMs = Math.Round(sw.Elapsed.TotalMilliseconds, 1);

            // 2. Query cloudflare.com again (tests TTL cache hit!)
            var q2 = DnsPacket.CreateQuery("cloudflare.com", DnsRecordType.A);
            await udp.SendAsync(q2, endpoint, cts.Token).ConfigureAwait(false);
            _ = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);

            // 3. Query a known ad domain (tests filtering -> NXDOMAIN)
            var q3 = DnsPacket.CreateQuery("ad.doubleclick.net", DnsRecordType.A);
            await udp.SendAsync(q3, endpoint, cts.Token).ConfigureAwait(false);
            var r3 = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
            var blocked = DnsPacket.TryParse(r3.Buffer, out var p3) && p3?.Header.ResponseCode == DnsResponseCode.NxDomain;

            var ok = DnsPacket.TryParse(r1.Buffer, out var p1) && p1?.Header.ResponseCode == DnsResponseCode.NoError;
            var summary = ok
                ? $"Local proxy {endpoint} OK ({firstMs:0.#} ms) — tested lookup, TTL cache hit, and ad filter ({(blocked ? "blocked" : "allowed")})."
                : $"Local proxy {endpoint} responded with {p1?.Header.ResponseCode.ToString() ?? "ERROR"}.";
            return (ok, firstMs, summary);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), $"Local proxy test on {endpoint} failed: {ex.Message}");
        }
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(
        string host,
        bool includeIpv6 = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return [];
        }

        var normalized = host.Trim().TrimEnd('.');
        if (IPAddress.TryParse(normalized, out var literal))
        {
            return [literal];
        }

        var results = new List<IPAddress>();
        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(_settings.Current.Dns.QueryTimeoutMs, 1000, 3000));

        await ResolveRecordAddressesAsync(normalized, DnsRecordType.A, timeout, results, cancellationToken).ConfigureAwait(false);
        if (includeIpv6)
        {
            await ResolveRecordAddressesAsync(normalized, DnsRecordType.AAAA, timeout, results, cancellationToken).ConfigureAwait(false);
        }

        if (results.Count > 0)
        {
            return results;
        }

        try
        {
            var osAddresses = await Dns.GetHostAddressesAsync(normalized, cancellationToken).ConfigureAwait(false);
            foreach (var addr in osAddresses)
            {
                if (!includeIpv6 && addr.AddressFamily != AddressFamily.InterNetwork)
                {
                    continue;
                }

                results.Add(addr);
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ArgumentException)
        {
            _logger.LogDebug(ex, "OS DNS fallback failed for host {Host}.", normalized);
        }

        return results;
    }

    private async Task ResolveRecordAddressesAsync(
        string host,
        DnsRecordType recordType,
        TimeSpan timeout,
        List<IPAddress> destination,
        CancellationToken cancellationToken)
    {
        byte[] queryWire;
        try
        {
            queryWire = DnsPacket.CreateQuery(host, recordType);
        }
        catch (ArgumentException)
        {
            return;
        }

        byte[]? responseWire = null;
        if (_cacheService is { IsEnabled: true }
            && _cacheService.TryGetResponse(queryWire, out var cachedBytes))
        {
            responseWire = cachedBytes;
        }
        else
        {
            var resolver = _routingService is { IsRoutingEnabled: true }
                ? ResolveEndpoint(_routingService.ResolveForDomain(host).ResolverId)
                : ResolveEndpoint(_settings.Current.Dns.ActiveResolverId);

            if (_upstreams.TryGetValue(resolver.Protocol, out var upstream))
            {
                try
                {
                    DnsQueryResult queryResult;
                    if (_failoverService is { IsAutoFailoverEnabled: true })
                    {
                        queryResult = await _failoverService.QueryWithResilienceAsync(
                            queryWire,
                            resolver,
                            async (candidate, ct) =>
                            {
                                if (!_upstreams.TryGetValue(candidate.Protocol, out var candUpstream))
                                {
                                    return new DnsQueryResult(false, [], 0, candidate.Id, candidate.Protocol, $"No upstream for {candidate.Protocol}.");
                                }

                                return await candUpstream.QueryAsync(queryWire, candidate, timeout, ct).ConfigureAwait(false);
                            },
                            cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        queryResult = await upstream.QueryAsync(queryWire, resolver, timeout, cancellationToken).ConfigureAwait(false);
                    }

                    if (queryResult.Success && queryResult.ResponseBytes.Length >= DnsPacket.HeaderSize)
                    {
                        responseWire = queryResult.ResponseBytes;
                        _cacheService?.StoreResponse(queryWire, responseWire);
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Encrypted DNS lookup failed for {Host} ({Type}).", host, recordType);
                }
            }
        }

        if (responseWire is null || !DnsPacket.TryParse(responseWire, out var packet) || packet is null)
        {
            return;
        }

        foreach (var answer in packet.Answers)
        {
            if (answer.Type is DnsRecordType.A or DnsRecordType.AAAA
                && IPAddress.TryParse(answer.DataSummary, out var anyIp))
            {
                _reverseLookupCache?.Record(anyIp, host, answer.Ttl);
            }

            if (answer.Type == recordType
                && IPAddress.TryParse(answer.DataSummary, out var ip)
                && !destination.Contains(ip))
            {
                destination.Add(ip);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        _disposed = true;
        _defaultDoh.Dispose();
        _lifecycleGate.Dispose();
    }

    private async Task<byte[]> HandleClientQueryAsync(ReadOnlyMemory<byte> queryWire, CancellationToken cancellationToken)
    {
        var hasParsed = DnsPacket.TryParse(queryWire.Span, out var parsed)
            && parsed is { PrimaryQuestionName.Length: > 0 };

        var qDomain = hasParsed ? parsed!.PrimaryQuestionName! : "unknown";
        var queryType = hasParsed ? parsed!.PrimaryQuestionType.ToString() : "A";

        // 1. DNS Filtering (Blocklists & Allowlist)
        if (hasParsed && _filteringService is not null)
        {
            var filterDecision = _filteringService.EvaluateDomain(qDomain, recordStats: true);
            if (filterDecision.IsBlocked)
            {
                Interlocked.Increment(ref _totalQueries);
                _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
                {
                    Timestamp = DateTimeOffset.Now,
                    Domain = qDomain,
                    RecordType = queryType,
                    Outcome = "Blocked",
                    ResolverName = filterDecision.MatchedRuleOrListName ?? "Filter",
                    Protocol = _activeResolver.Protocol,
                    LatencyMs = 0.0,
                });
                RaiseStateChanged();
                return DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NxDomain);
            }
        }

        // 2. TTL-aware DNS Cache lookup
        if (_cacheService is { IsEnabled: true }
            && _cacheService.TryGetResponse(queryWire.Span, out var cachedBytes))
        {
            if (hasParsed)
            {
                RecordReverseDnsFromResponse(qDomain, cachedBytes);
            }

            Interlocked.Increment(ref _totalQueries);
            Interlocked.Increment(ref _successfulQueries);
            _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = DateTimeOffset.Now,
                Domain = qDomain,
                RecordType = queryType,
                Outcome = "Cached",
                ResolverName = "TTL Cache",
                Protocol = _activeResolver.Protocol,
                LatencyMs = 0.1,
            });
            RaiseStateChanged();
            return cachedBytes;
        }

        // 3. Smart DNS Routing
        var resolver = _activeResolver;
        RoutingDecision? decision = null;

        if (hasParsed && _routingService is { IsRoutingEnabled: true })
        {
            decision = _routingService.ResolveForDomain(qDomain);
            resolver = ResolveEndpoint(decision.ResolverId);
        }

        if (!_upstreams.TryGetValue(resolver.Protocol, out var upstream))
        {
            return DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.ServFail);
        }

        var timeout = TimeSpan.FromMilliseconds(_settings.Current.Dns.QueryTimeoutMs);
        DnsQueryResult result;
        if (_failoverService is { IsAutoFailoverEnabled: true })
        {
            result = await _failoverService.QueryWithResilienceAsync(
                queryWire,
                resolver,
                async (candidate, ct) =>
                {
                    if (!_upstreams.TryGetValue(candidate.Protocol, out var candUpstream))
                    {
                        return new DnsQueryResult(false, [], 0, candidate.Id, candidate.Protocol, $"No upstream for {candidate.Protocol}.");
                    }

                    return await candUpstream.QueryAsync(queryWire, candidate, timeout, ct).ConfigureAwait(false);
                },
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            result = await upstream.QueryAsync(queryWire, resolver, timeout, cancellationToken).ConfigureAwait(false);
        }

        RecordQueryOutcome(result);

        if (decision is not null && _routingService is not null)
        {
            _routingService.RecordRoutingLog(decision, queryType, result.Success ? result.LatencyMs : null);
        }

        _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
        {
            Timestamp = DateTimeOffset.Now,
            Domain = qDomain,
            RecordType = queryType,
            Outcome = result.Success ? (decision is { IsFallback: false } ? "Routed" : "Allowed") : "Failed",
            ResolverName = resolver.Name,
            Protocol = resolver.Protocol,
            LatencyMs = result.Success ? Math.Round(result.LatencyMs, 1) : null,
        });

        if (result.Success && result.ResponseBytes.Length >= DnsPacket.HeaderSize)
        {
            if (hasParsed)
            {
                RecordReverseDnsFromResponse(qDomain, result.ResponseBytes);
            }

            _cacheService?.StoreResponse(queryWire.Span, result.ResponseBytes);
            return result.ResponseBytes;
        }

        return DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.ServFail);
    }

    private void RecordReverseDnsFromResponse(string queryDomain, ReadOnlySpan<byte> responseWire)
    {
        if (_reverseLookupCache is null || string.IsNullOrWhiteSpace(queryDomain))
        {
            return;
        }

        if (!DnsPacket.TryParse(responseWire, out var responsePacket) || responsePacket is null)
        {
            return;
        }

        foreach (var answer in responsePacket.Answers)
        {
            if (answer.Type is DnsRecordType.A or DnsRecordType.AAAA
                && IPAddress.TryParse(answer.DataSummary, out var ip))
            {
                _reverseLookupCache.Record(ip, queryDomain, answer.Ttl);
            }
        }
    }

    private void RecordQueryOutcome(DnsQueryResult result)
    {
        Interlocked.Increment(ref _totalQueries);
        if (result.Success)
        {
            Interlocked.Increment(ref _successfulQueries);
            Interlocked.Exchange(ref _consecutiveFailures, 0);
            _lastLatencyMs = Math.Round(result.LatencyMs, 1);
            if (_state == DnsEngineState.Degraded)
            {
                SetState(DnsEngineState.Running, error: null, conflict: null);
            }
            else
            {
                RaiseStateChanged();
            }
        }
        else
        {
            Interlocked.Increment(ref _failedQueries);
            var failures = Interlocked.Increment(ref _consecutiveFailures);
            _lastError = result.Error;
            if (_state == DnsEngineState.Running && failures >= 3)
            {
                SetState(DnsEngineState.Degraded, result.Error, null);
            }
            else
            {
                RaiseStateChanged();
            }
        }
    }

    private async Task StopCoreAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync().ConfigureAwait(false);
            _proxy = null;
        }

        await _dnsCryptManager.StopAsync().ConfigureAwait(false);
    }

    private void SetState(DnsEngineState state, string? error, PortConflictInfo? conflict)
    {
        _state = state;
        _lastError = error;
        _portConflict = conflict;
        RaiseStateChanged();
    }

    private DnsResolverEndpoint ResolveEndpoint(string? resolverId) =>
        _resolverLibrary is not null
            ? _resolverLibrary.GetByIdOrDefault(resolverId)
            : BuiltInResolvers.GetByIdOrDefault(resolverId);

    private void RaiseStateChanged() => StateChanged?.Invoke(this, GetStats());
}
