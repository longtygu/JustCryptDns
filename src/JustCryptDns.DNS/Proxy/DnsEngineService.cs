using System.Collections.Concurrent;
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
    private readonly DotDnsUpstream _defaultDot;
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private readonly ConcurrentDictionary<string, byte> _inFlightPrefetches = new(StringComparer.OrdinalIgnoreCase);

    private LocalDnsProxy? _proxy;
    private DnsEngineState _state = DnsEngineState.Stopped;
    private DnsResolverEndpoint _activeResolver;
    private string _listenEndpoint;
    private long _totalQueries;
    private long _successfulQueries;
    private long _failedQueries;
    private long _rewrittenQueries;
    private long _consecutiveFailures;
    private double? _lastLatencyMs;
    private string? _lastError;
    private PortConflictInfo? _portConflict;
    private string? _lastAppliedAdapterId;
    private string? _activeVpnAdapterName;
    private bool _isCaptivePortalDetected;
    private bool _isCaptivePortalPaused;
    private DateTimeOffset? _captivePortalPauseUntilUtc;
    private int _networkAdaptGeneration;
    private int _captiveResumeGeneration;
    private bool _networkSubscribed;
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
        _defaultDot = new DotDnsUpstream();
        var defaultClients = new IDnsUpstreamClient[]
        {
            _defaultDoh,
            _defaultDot,
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
        IReadOnlyList<string>? leakingIpv6Dns = null;
        var isIpv6LoopbackBound = _proxy?.IsIpv6Bound == true;
        if (_state is DnsEngineState.Running or DnsEngineState.Degraded)
        {
            if (boundPort != 53)
            {
                trafficStatus = SystemTrafficStatus.NonStandardPort;
                (port53Owner, port53Service) = ReadPort53ConflictOwner();
                suggestedLoopback = PortConflictDetector.FindAvailableLoopbackForPort53(IPAddress.Loopback);
            }
            else if (!string.IsNullOrWhiteSpace(_activeVpnAdapterName))
            {
                trafficStatus = SystemTrafficStatus.DeferredToVpn;
            }
            else if (_isCaptivePortalPaused || _isCaptivePortalDetected)
            {
                trafficStatus = SystemTrafficStatus.CaptivePortalDetected;
            }
            else if (_networkInfo is not null)
            {
                var snap = _networkInfo.GetSnapshot();
                var listenIp = IPAddress.TryParse(dns.ListenAddress, out var parsedListen)
                    ? parsedListen
                    : IPAddress.Loopback;
                (trafficStatus, leakingIpv6Dns) = EvaluateAdapterTrafficStatus(
                    snap.PrimaryAdapter?.DnsServers,
                    listenIp,
                    dns.EnableIpv6 || isIpv6LoopbackBound);

                if (trafficStatus == SystemTrafficStatus.Ipv6DnsLeakDetected)
                {
                    (port53Owner, port53Service) = ReadPort53ConflictOwner();
                }
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
            LeakingIpv6DnsServers = leakingIpv6Dns,
            IsIpv6LoopbackBound = _proxy?.IsIpv6Bound == true,
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
            ActiveVpnAdapterName = _activeVpnAdapterName,
            IsCaptivePortalPaused = _isCaptivePortalPaused,
            CaptivePortalPauseUntilUtc = _captivePortalPauseUntilUtc,
            RewrittenQueries = Interlocked.Read(ref _rewrittenQueries),
            StaleCacheHits = cacheStats?.StaleHits ?? 0,
            PrefetchCount = cacheStats?.PrefetchCount ?? 0,
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

            var autoBindIpv6IfFree = dns.ConfigureWindowsAdapter && dns.ListenPort == DnsSettings.DefaultListenPort;
            var proxy = new LocalDnsProxy(listenIp, dns.ListenPort, dns.EnableIpv6, HandleClientQueryAsync, _logger, autoBindIpv6IfFree);
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
            _activeVpnAdapterName = null;
            _isCaptivePortalDetected = false;
            _isCaptivePortalPaused = false;
            _captivePortalPauseUntilUtc = null;
            _lastAppliedAdapterId = null;

            var initialSnap = _networkInfo?.GetSnapshot();
            if (dns.ConfigureWindowsAdapter)
            {
                if (dns.AutoAdaptNetworkChanges
                    && dns.AutoDeferToVpn
                    && NetworkAdaptationEvaluator.DetectActiveVpnAdapter(initialSnap) is { } vpnAdapter)
                {
                    _activeVpnAdapterName = vpnAdapter.Name;
                    _logger.LogInformation("Active VPN adapter detected ({Vpn}); deferring adapter DNS configuration safely.", vpnAdapter.Name);
                }
                else
                {
                    var adapterResult = await _windowsDns.ApplyLocalProxyDnsAsync(
                        dns.TargetAdapterId,
                        listenIp.ToString(),
                        proxy.IsIpv6Bound ? "::1" : null,
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

                    _lastAppliedAdapterId = initialSnap?.PrimaryAdapter?.Id;
                }
            }

            if (_networkInfo is not null && !_networkSubscribed)
            {
                _networkInfo.NetworkChanged += OnNetworkChanged;
                _networkSubscribed = true;
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
        CancellationToken cancellationToken,
        int rewriteDepth = 0)
    {
        if (rewriteDepth <= 3
            && _routingService?.FindMatchingRewrite(host, recordType.ToString()) is { } directRewrite)
        {
            if (directRewrite.RecordType is LocalDnsRewriteRecordType.A or LocalDnsRewriteRecordType.AAAA
                && IPAddress.TryParse(directRewrite.TargetValue, out var rewrittenIp)
                && !destination.Contains(rewrittenIp))
            {
                _reverseLookupCache?.Record(rewrittenIp, host, (uint)Math.Max(1, directRewrite.TtlSeconds));
                destination.Add(rewrittenIp);
                return;
            }
        }

        if (rewriteDepth <= 3
            && recordType == DnsRecordType.A
            && _routingService?.FindMatchingRewrite(host, nameof(LocalDnsRewriteRecordType.CNAME)) is { } cnameRewrite)
        {
            await ResolveRecordAddressesAsync(
                cnameRewrite.TargetValue,
                recordType,
                timeout,
                destination,
                cancellationToken,
                rewriteDepth + 1).ConfigureAwait(false);
            if (destination.Count > 0)
            {
                return;
            }
        }

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
            && _cacheService.TryGetResponse(queryWire, out var cachedBytes, out _))
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

            if (responseWire is null
                && _cacheService is { IsEnabled: true }
                && _cacheService.TryGetStaleResponse(queryWire, out var staleBytes))
            {
                responseWire = staleBytes;
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

    public async Task<(bool Success, string? Error)> PauseForCaptivePortalAsync(
        TimeSpan duration,
        CancellationToken cancellationToken = default)
    {
        var effectiveDuration = duration > TimeSpan.Zero ? duration : TimeSpan.FromMinutes(5);
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_windowsDns.HasActiveBackup())
            {
                var restore = await _windowsDns.RestoreOriginalDnsAsync(
                    _settings.Current.Dns.TargetAdapterId,
                    cancellationToken).ConfigureAwait(false);
                if (!restore.Success)
                {
                    return (false, restore.ErrorMessage);
                }
            }

            _isCaptivePortalPaused = true;
            _captivePortalPauseUntilUtc = DateTimeOffset.UtcNow.Add(effectiveDuration);
            _lastAppliedAdapterId = null;
            RaiseStateChanged();

            var gen = Interlocked.Increment(ref _captiveResumeGeneration);
            _ = AutoResumeAfterCaptivePauseAsync(effectiveDuration, gen);
            _logger.LogInformation("Paused adapter DNS protection for {Minutes:0.#} min to allow captive portal sign-in.", effectiveDuration.TotalMinutes);
            return (true, null);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task<(bool Success, string? Error)> ResumeFromCaptivePortalAsync(
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _captiveResumeGeneration);
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _isCaptivePortalPaused = false;
            _captivePortalPauseUntilUtc = null;
            _isCaptivePortalDetected = false;

            var dns = _settings.Current.Dns;
            if (_state is DnsEngineState.Running or DnsEngineState.Degraded
                && _proxy is { BoundPort: > 0 } proxy
                && dns.ConfigureWindowsAdapter)
            {
                var snap = _networkInfo?.GetSnapshot();
                if (dns.AutoAdaptNetworkChanges
                    && dns.AutoDeferToVpn
                    && NetworkAdaptationEvaluator.DetectActiveVpnAdapter(snap) is { } vpnAdapter)
                {
                    _activeVpnAdapterName = vpnAdapter.Name;
                    RaiseStateChanged();
                    return (true, null);
                }

                var listenIp = IPAddress.TryParse(dns.ListenAddress, out var parsed) ? parsed : IPAddress.Loopback;
                var result = await _windowsDns.ApplyLocalProxyDnsAsync(
                    dns.TargetAdapterId,
                    listenIp.ToString(),
                    proxy.IsIpv6Bound ? "::1" : null,
                    async ct =>
                    {
                        var probe = await ProbeActiveResolverAsync(ct).ConfigureAwait(false);
                        return probe.Success;
                    },
                    cancellationToken).ConfigureAwait(false);

                if (!result.Success)
                {
                    RaiseStateChanged();
                    return (false, result.ErrorMessage);
                }

                _lastAppliedAdapterId = snap?.PrimaryAdapter?.Id;
            }

            RaiseStateChanged();
            _logger.LogInformation("Resumed adapter DNS protection after captive portal pause.");
            return (true, null);
        }
        finally
        {
            _lifecycleGate.Release();
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
        _defaultDot.Dispose();
        _lifecycleGate.Dispose();
    }

    private async Task<byte[]> HandleClientQueryAsync(ReadOnlyMemory<byte> queryWire, CancellationToken cancellationToken)
    {
        var hasParsed = DnsPacket.TryParse(queryWire.Span, out var parsed)
            && parsed is { PrimaryQuestionName.Length: > 0 };

        var qDomain = hasParsed ? parsed!.PrimaryQuestionName! : "unknown";
        var queryType = hasParsed ? parsed!.PrimaryQuestionType.ToString() : "A";

        // 0A. Firefox DoH Canary Guard (RFC-recommended NXDOMAIN prevents silent bypass of local filtering/routing)
        if (hasParsed
            && _settings.Current.Dns.BlockFirefoxDohCanary
            && string.Equals(RoutingMatcher.NormalizeDomain(qDomain), "use-application-dns.net", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _totalQueries);
            _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = DateTimeOffset.Now,
                Domain = qDomain,
                RecordType = queryType,
                Outcome = "Canary",
                ResolverName = "Firefox DoH Guard",
                Protocol = _activeResolver.Protocol,
                LatencyMs = 0.0,
            });
            RaiseStateChanged();
            return DnsPacket.CreateErrorResponse(queryWire.Span, DnsResponseCode.NxDomain);
        }

        // 0B. Local DNS Rewrite rules (custom LAN/dev A/AAAA/CNAME overrides)
        if (hasParsed
            && _routingService?.FindMatchingRewrite(qDomain, queryType) is { } rewriteRule)
        {
            var rewriteWire = DnsPacket.CreateLocalRewriteResponse(
                queryWire.Span,
                rewriteRule.RecordType,
                rewriteRule.TargetValue,
                (uint)Math.Max(1, rewriteRule.TtlSeconds));
            if (rewriteWire.Length >= DnsPacket.HeaderSize)
            {
                RecordReverseDnsFromResponse(qDomain, rewriteWire);
                Interlocked.Increment(ref _totalQueries);
                Interlocked.Increment(ref _successfulQueries);
                Interlocked.Increment(ref _rewrittenQueries);
                _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
                {
                    Timestamp = DateTimeOffset.Now,
                    Domain = qDomain,
                    RecordType = queryType,
                    Outcome = "Rewritten",
                    ResolverName = $"Local Rewrite ({rewriteRule.TargetValue})",
                    Protocol = _activeResolver.Protocol,
                    LatencyMs = 0.0,
                });
                RaiseStateChanged();
                return rewriteWire;
            }
        }

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

        // 2. TTL-aware DNS Cache lookup (+ near-expiry background prefetch)
        if (_cacheService is { IsEnabled: true }
            && _cacheService.TryGetResponse(queryWire.Span, out var cachedBytes, out var shouldPrefetch))
        {
            if (hasParsed)
            {
                RecordReverseDnsFromResponse(qDomain, cachedBytes);
            }

            if (shouldPrefetch && hasParsed)
            {
                SchedulePrefetch(qDomain, queryType, queryWire.ToArray());
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
            if (_cacheService is { IsEnabled: true }
                && _cacheService.TryGetStaleResponse(queryWire.Span, out var staleBytes))
            {
                if (hasParsed)
                {
                    RecordReverseDnsFromResponse(qDomain, staleBytes);
                }

                _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
                {
                    Timestamp = DateTimeOffset.Now,
                    Domain = qDomain,
                    RecordType = queryType,
                    Outcome = "Stale",
                    ResolverName = "Serve-Stale Cache",
                    Protocol = _activeResolver.Protocol,
                    LatencyMs = 0.1,
                });
                RaiseStateChanged();
                return staleBytes;
            }

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

        if ((!result.Success || result.ResponseBytes.Length < DnsPacket.HeaderSize)
            && _cacheService is { IsEnabled: true }
            && _cacheService.TryGetStaleResponse(queryWire.Span, out var staleFallback))
        {
            if (hasParsed)
            {
                RecordReverseDnsFromResponse(qDomain, staleFallback);
            }

            Interlocked.Increment(ref _totalQueries);
            Interlocked.Increment(ref _successfulQueries);
            _diagnosticsService?.RecordMonitorEntry(new LiveQueryMonitorEntry
            {
                Timestamp = DateTimeOffset.Now,
                Domain = qDomain,
                RecordType = queryType,
                Outcome = "Stale",
                ResolverName = $"Serve-Stale ({resolver.Name})",
                Protocol = resolver.Protocol,
                LatencyMs = 0.1,
            });
            RaiseStateChanged();
            return staleFallback;
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
        Interlocked.Increment(ref _networkAdaptGeneration);
        Interlocked.Increment(ref _captiveResumeGeneration);

        if (_networkInfo is not null && _networkSubscribed)
        {
            _networkInfo.NetworkChanged -= OnNetworkChanged;
            _networkSubscribed = false;
        }

        _activeVpnAdapterName = null;
        _isCaptivePortalDetected = false;
        _isCaptivePortalPaused = false;
        _captivePortalPauseUntilUtc = null;
        _lastAppliedAdapterId = null;

        if (_proxy is not null)
        {
            await _proxy.DisposeAsync().ConfigureAwait(false);
            _proxy = null;
        }

        await _dnsCryptManager.StopAsync().ConfigureAwait(false);
    }

    private void SchedulePrefetch(string domain, string queryType, byte[] queryWire)
    {
        if (_disposed
            || _cacheService is not { IsEnabled: true }
            || _state is not (DnsEngineState.Running or DnsEngineState.Degraded))
        {
            return;
        }

        var key = $"{domain}|{queryType}";
        if (!_inFlightPrefetches.TryAdd(key, 0))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                if (_disposed || _state is not (DnsEngineState.Running or DnsEngineState.Degraded))
                {
                    return;
                }

                var resolver = _activeResolver;
                if (_routingService is { IsRoutingEnabled: true })
                {
                    var decision = _routingService.ResolveForDomain(domain);
                    resolver = ResolveEndpoint(decision.ResolverId);
                }

                if (!_upstreams.TryGetValue(resolver.Protocol, out var upstream))
                {
                    return;
                }

                var timeout = TimeSpan.FromMilliseconds(_settings.Current.Dns.QueryTimeoutMs);
                using var cts = new CancellationTokenSource(timeout);
                var result = await upstream.QueryAsync(queryWire, resolver, timeout, cts.Token).ConfigureAwait(false);
                if (result.Success && result.ResponseBytes.Length >= DnsPacket.HeaderSize)
                {
                    RecordReverseDnsFromResponse(domain, result.ResponseBytes);
                    _cacheService?.StoreResponse(queryWire, result.ResponseBytes);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException or IOException)
            {
                _logger.LogDebug(ex, "Background DNS cache prefetch failed for {Domain} ({Type}).", domain, queryType);
            }
            finally
            {
                _inFlightPrefetches.TryRemove(key, out _);
            }
        });
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        var generation = Interlocked.Increment(ref _networkAdaptGeneration);
        if (_disposed
            || _state is not (DnsEngineState.Running or DnsEngineState.Degraded)
            || !_settings.Current.Dns.AutoAdaptNetworkChanges)
        {
            return;
        }

        _ = DebounceEvaluateNetworkAdaptationAsync(generation);
    }

    private async Task DebounceEvaluateNetworkAdaptationAsync(int generation)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(1500)).ConfigureAwait(false);
            if (_disposed || Volatile.Read(ref _networkAdaptGeneration) != generation)
            {
                return;
            }

            var snapshot = _networkInfo?.GetSnapshot();
            if (snapshot is null)
            {
                return;
            }

            await EvaluateNetworkAdaptationAsync(snapshot, generation).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "Network adaptation debounce evaluation aborted.");
        }
    }

    private async Task EvaluateNetworkAdaptationAsync(NetworkSnapshot snapshot, int generation)
    {
        var dns = _settings.Current.Dns;
        if (!dns.AutoAdaptNetworkChanges || !dns.ConfigureWindowsAdapter)
        {
            return;
        }

        var vpnAdapter = dns.AutoDeferToVpn
            ? NetworkAdaptationEvaluator.DetectActiveVpnAdapter(snapshot)
            : null;

        bool captivePortalDetected = false;
        if (vpnAdapter is null && snapshot.PrimaryAdapter is { IsUp: true })
        {
            captivePortalDetected = await NetworkAdaptationEvaluator.CheckCaptivePortalAsync().ConfigureAwait(false);
        }

        await _lifecycleGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed
                || Volatile.Read(ref _networkAdaptGeneration) != generation
                || _state is not (DnsEngineState.Running or DnsEngineState.Degraded)
                || _proxy is not { BoundPort: > 0 } proxy)
            {
                return;
            }

            if (vpnAdapter is not null)
            {
                _activeVpnAdapterName = vpnAdapter.Name;
                _isCaptivePortalDetected = false;
                if (_windowsDns.HasActiveBackup())
                {
                    await _windowsDns.RestoreOriginalDnsAsync(dns.TargetAdapterId).ConfigureAwait(false);
                }

                _lastAppliedAdapterId = null;
                RaiseStateChanged();
                _logger.LogInformation("Deferred local adapter DNS because active VPN tunnel was detected ({Vpn}).", vpnAdapter.Name);
                return;
            }

            if (!string.IsNullOrWhiteSpace(_activeVpnAdapterName))
            {
                _activeVpnAdapterName = null;
            }

            _isCaptivePortalDetected = captivePortalDetected;
            if (captivePortalDetected || _isCaptivePortalPaused)
            {
                RaiseStateChanged();
                return;
            }

            var primary = snapshot.PrimaryAdapter;
            if (primary is not { IsUp: true })
            {
                RaiseStateChanged();
                return;
            }

            var listenIp = IPAddress.TryParse(dns.ListenAddress, out var parsed) ? parsed : IPAddress.Loopback;
            var (status, _) = EvaluateAdapterTrafficStatus(
                primary.DnsServers,
                listenIp,
                dns.EnableIpv6 || proxy.IsIpv6Bound);

            if (!string.Equals(_lastAppliedAdapterId, primary.Id, StringComparison.OrdinalIgnoreCase)
                || status == SystemTrafficStatus.AdapterNotConfigured)
            {
                var applyResult = await _windowsDns.ApplyLocalProxyDnsAsync(
                    dns.TargetAdapterId,
                    listenIp.ToString(),
                    proxy.IsIpv6Bound ? "::1" : null,
                    async ct =>
                    {
                        var probe = await ProbeActiveResolverAsync(ct).ConfigureAwait(false);
                        return probe.Success;
                    }).ConfigureAwait(false);

                if (applyResult.Success)
                {
                    _lastAppliedAdapterId = primary.Id;
                }
            }

            RaiseStateChanged();
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    private async Task AutoResumeAfterCaptivePauseAsync(TimeSpan delay, int generation)
    {
        try
        {
            await Task.Delay(delay).ConfigureAwait(false);
            if (_disposed
                || Volatile.Read(ref _captiveResumeGeneration) != generation
                || _state is not (DnsEngineState.Running or DnsEngineState.Degraded))
            {
                return;
            }

            await ResumeFromCaptivePortalAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "Captive portal auto-resume aborted.");
        }
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

    public static bool IsExternalIpv6Dns(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);
        if (ip.AddressFamily != AddressFamily.InterNetworkV6 || IPAddress.IsLoopback(ip))
        {
            return false;
        }

        // Ignore Windows default site-local DNS placeholder addresses (fec0:0:0:ffff::1..3).
        Span<byte> bytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(bytes, out _))
        {
            return false;
        }

        var isWindowsSiteLocalPlaceholder = bytes[0] == 0xFE
            && bytes[1] == 0xC0
            && bytes[2] == 0x00 && bytes[3] == 0x00 && bytes[4] == 0x00 && bytes[5] == 0x00
            && bytes[6] == 0xFF && bytes[7] == 0xFF;
        return !isWindowsSiteLocalPlaceholder;
    }

    public static (SystemTrafficStatus Status, IReadOnlyList<string>? LeakingIpv6) EvaluateAdapterTrafficStatus(
        IReadOnlyList<IPAddress>? adapterDns,
        IPAddress listenIp,
        bool allowIpv6Loopback)
    {
        ArgumentNullException.ThrowIfNull(listenIp);
        var matchesOurProxy = adapterDns is { Count: > 0 }
            && adapterDns.Any(ip => ip.Equals(listenIp) || (allowIpv6Loopback && ip.Equals(IPAddress.IPv6Loopback)));

        if (!matchesOurProxy)
        {
            return (SystemTrafficStatus.AdapterNotConfigured, null);
        }

        var extV6 = adapterDns!
            .Where(IsExternalIpv6Dns)
            .Select(ip => ip.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return extV6.Count > 0
            ? (SystemTrafficStatus.Ipv6DnsLeakDetected, extV6)
            : (SystemTrafficStatus.InterceptingSystemTraffic, null);
    }

    private static (string? OwnerDescription, string? ServiceName) ReadPort53ConflictOwner()
    {
        var (procName, pid, svcName) = PortConflictDetector.TryFindPortOwnerDetails(53, excludeSelf: true);
        var owner = procName is not null && pid.HasValue ? $"{procName} (PID {pid.Value})" : null;
        return (owner, svcName);
    }
}
