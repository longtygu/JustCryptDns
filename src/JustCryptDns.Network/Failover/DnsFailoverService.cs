using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Resolver;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Failover;

public sealed class DnsFailoverService : IDnsFailoverService, IDisposable
{
    public const int MaxHistoryEntries = 100;

    private readonly ISettingsService _settings;
    private readonly IResolverLibraryService _resolverLibrary;
    private readonly INetworkInfoService? _networkInfo;
    private readonly ILogger<DnsFailoverService> _logger;
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _upstreams;
    private readonly DohDnsUpstream _defaultDoh;
    private readonly ConcurrentDictionary<string, int> _consecutiveFailures = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<FailoverEventEntry> _history = new();
    private readonly object _historyLock = new();
    private bool _disposed;

    public DnsFailoverService(
        ISettingsService settings,
        IResolverLibraryService resolverLibrary,
        ILogger<DnsFailoverService> logger,
        INetworkInfoService? networkInfo = null,
        IEnumerable<IDnsUpstreamClient>? customUpstreams = null)
    {
        _settings = settings;
        _resolverLibrary = resolverLibrary;
        _logger = logger;
        _networkInfo = networkInfo;

        _defaultDoh = new DohDnsUpstream();
        var defaultClients = new IDnsUpstreamClient[]
        {
            _defaultDoh,
            new DotDnsUpstream(),
            new UdpTcpDnsUpstream(),
        };

        var list = customUpstreams?.ToList();
        IEnumerable<IDnsUpstreamClient> active = list is { Count: > 0 } ? list : defaultClients;
        _upstreams = active.ToDictionary(u => u.Protocol);
    }

    public event EventHandler<FailoverEventEntry>? FailoverOccurred;

    public bool IsAutoFailoverEnabled => _settings.Current.Resilience.EnableAutoFailover;

    public FailoverPolicy CurrentPolicy => _settings.Current.Resilience.Policy;

    public NetworkRestrictionReport? LastRestrictionReport { get; private set; }

    public IReadOnlyList<DnsResolverEndpoint> GetFailoverChain(DnsResolverEndpoint startingResolver)
    {
        ArgumentNullException.ThrowIfNull(startingResolver);

        var policy = CurrentPolicy;
        var primary = _resolverLibrary.GetPrimaryResolver();
        var secondary = _resolverLibrary.GetSecondaryResolver();
        var enabled = _resolverLibrary.GetEnabled();

        var chain = new List<DnsResolverEndpoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddIfAllowed(DnsResolverEndpoint r)
        {
            if (!r.IsEnabled || !seen.Add(r.Id))
            {
                return;
            }

            if (policy == FailoverPolicy.EncryptedOnly && !r.IsEncrypted && !string.Equals(r.Id, startingResolver.Id, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            chain.Add(r);
        }

        AddIfAllowed(startingResolver);
        AddIfAllowed(primary);
        AddIfAllowed(secondary);

        if (policy == FailoverPolicy.PrimaryAndSecondaryOnly)
        {
            return chain;
        }

        // Add remaining encrypted resolvers
        foreach (var r in enabled.Where(x => x.IsEncrypted))
        {
            AddIfAllowed(r);
        }

        if (policy == FailoverPolicy.EncryptedThenPlainFallback)
        {
            foreach (var r in enabled.Where(x => !x.IsEncrypted))
            {
                AddIfAllowed(r);
            }
        }

        return chain;
    }

    public IReadOnlyList<FailoverEventEntry> GetFailoverHistory()
    {
        lock (_historyLock)
        {
            return _history.ToList();
        }
    }

    public DnsFailureCategory ClassifyFailure(DnsResolverEndpoint resolver, string? errorMessage)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        var msg = errorMessage ?? string.Empty;

        if (msg.Contains("timed out", StringComparison.OrdinalIgnoreCase)
            || msg.Contains("timeout", StringComparison.OrdinalIgnoreCase))
        {
            return DnsFailureCategory.ResolverTimeout;
        }

        return resolver.Protocol switch
        {
            DnsProtocol.DnsOverHttps => DnsFailureCategory.DohEndpointFailure,
            DnsProtocol.DnsOverTls => DnsFailureCategory.DotTlsHandshakeFailure,
            DnsProtocol.DnsCrypt => DnsFailureCategory.DnsCryptHandshakeFailure,
            DnsProtocol.UdpTcp => msg.Contains("TCP", StringComparison.OrdinalIgnoreCase)
                ? DnsFailureCategory.Tcp53BlockedOrUnreachable
                : DnsFailureCategory.Udp53BlockedOrUnreachable,
            _ => DnsFailureCategory.ResolverTimeout,
        };
    }

    public async Task<DnsQueryResult> QueryWithResilienceAsync(
        ReadOnlyMemory<byte> queryWire,
        DnsResolverEndpoint preferredResolver,
        Func<DnsResolverEndpoint, CancellationToken, Task<DnsQueryResult>> queryExecutor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(preferredResolver);
        ArgumentNullException.ThrowIfNull(queryExecutor);

        var resilience = _settings.Current.Resilience;
        var maxAttemptsPerResolver = Math.Max(1, resilience.MaxRetriesPerQuery + 1);
        var retryDelay = TimeSpan.FromMilliseconds(resilience.RetryDelayMs);

        var candidates = IsAutoFailoverEnabled
            ? GetFailoverChain(preferredResolver)
            : [preferredResolver];

        DnsQueryResult? lastFailure = null;
        DnsFailureCategory firstFailureCat = DnsFailureCategory.None;

        for (var cIdx = 0; cIdx < candidates.Count; cIdx++)
        {
            var candidate = candidates[cIdx];
            for (var attempt = 1; attempt <= maxAttemptsPerResolver; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await queryExecutor(candidate, cancellationToken).ConfigureAwait(false);
                if (result.Success)
                {
                    _consecutiveFailures.TryRemove(candidate.Id, out _);
                    if (cIdx > 0)
                    {
                        RecordFailoverEvent(preferredResolver, candidate, firstFailureCat, lastFailure?.Error);
                    }

                    return result;
                }

                lastFailure = result;
                var cat = ClassifyFailure(candidate, result.Error);
                if (firstFailureCat == DnsFailureCategory.None)
                {
                    firstFailureCat = cat;
                }

                var failCount = _consecutiveFailures.AddOrUpdate(candidate.Id, 1, (_, prev) => prev + 1);
                if (attempt < maxAttemptsPerResolver && retryDelay > TimeSpan.Zero)
                {
                    await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
                }
                else if (failCount >= resilience.FailureThresholdBeforeSwitch)
                {
                    break;
                }
            }
        }

        return lastFailure ?? new DnsQueryResult(false, [], 0, preferredResolver.Id, preferredResolver.Protocol, "All failover candidates failed.");
    }

    public async Task<NetworkRestrictionReport> DiagnoseNetworkRestrictionsAsync(
        CancellationToken cancellationToken = default)
    {
        var timeout = TimeSpan.FromMilliseconds(Math.Min(_settings.Current.Dns.QueryTimeoutMs, 2500));
        var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
        var issues = new List<DnsFailureCategory>();

        // 1. Check IPv4 and IPv6 local adapter status
        var ipv4Ok = true;
        var ipv6Ok = false;
        if (_networkInfo is not null)
        {
            var snap = _networkInfo.GetSnapshot();
            ipv4Ok = snap.PrimaryAdapter is { IPv4Addresses.Count: > 0 };
            ipv6Ok = snap.PrimaryAdapter is { HasGlobalIPv6: true };
        }

        if (!ipv4Ok)
        {
            issues.Add(DnsFailureCategory.Ipv4ConnectivityProblem);
        }

        if (!ipv6Ok)
        {
            issues.Add(DnsFailureCategory.Ipv6ConnectivityProblem);
        }

        // 2. Probe UDP/53
        var udpResolver = _resolverLibrary.GetByIdOrDefault("cloudflare-udp");
        var udp53Ok = false;
        if (_upstreams.TryGetValue(DnsProtocol.UdpTcp, out var udpUpstream))
        {
            var r = await udpUpstream.QueryAsync(query, udpResolver, timeout, cancellationToken).ConfigureAwait(false);
            udp53Ok = r.Success;
        }

        if (!udp53Ok)
        {
            issues.Add(DnsFailureCategory.Udp53BlockedOrUnreachable);
        }

        // 3. Probe TCP/53
        var tcp53Ok = await ProbeTcpPortAsync(udpResolver.PrimaryIp, 53, timeout, cancellationToken).ConfigureAwait(false);
        if (!tcp53Ok)
        {
            issues.Add(DnsFailureCategory.Tcp53BlockedOrUnreachable);
        }

        // 4. Probe DoH/443
        var dohResolver = _resolverLibrary.GetByIdOrDefault("cloudflare-doh");
        var doh443Ok = false;
        if (_upstreams.TryGetValue(DnsProtocol.DnsOverHttps, out var dohUpstream))
        {
            var r = await dohUpstream.QueryAsync(query, dohResolver, timeout, cancellationToken).ConfigureAwait(false);
            doh443Ok = r.Success;
        }

        if (!doh443Ok)
        {
            issues.Add(DnsFailureCategory.DohEndpointFailure);
        }

        // 5. Probe DoT/853
        var dotResolver = _resolverLibrary.GetByIdOrDefault("cloudflare-dot");
        var dot853Ok = false;
        if (_upstreams.TryGetValue(DnsProtocol.DnsOverTls, out var dotUpstream))
        {
            var r = await dotUpstream.QueryAsync(query, dotResolver, timeout, cancellationToken).ConfigureAwait(false);
            dot853Ok = r.Success;
        }

        if (!dot853Ok)
        {
            issues.Add(DnsFailureCategory.DotTlsHandshakeFailure);
        }

        // 6. Probe DNSCrypt endpoint
        var cryptResolver = _resolverLibrary.GetByIdOrDefault("quad9-dnscrypt");
        var cryptOk = _upstreams.TryGetValue(DnsProtocol.DnsCrypt, out var cryptUpstream)
            ? (await cryptUpstream.QueryAsync(query, cryptResolver, timeout, cancellationToken).ConfigureAwait(false)).Success
            : await ProbeTcpPortAsync(cryptResolver.PrimaryIp, cryptResolver.Port, timeout, cancellationToken).ConfigureAwait(false);

        if (!cryptOk)
        {
            issues.Add(DnsFailureCategory.DnsCryptHandshakeFailure);
        }

        var summary = issues.Count == 0 || (issues.Count == 1 && issues[0] == DnsFailureCategory.Ipv6ConnectivityProblem)
            ? "All encrypted and standard DNS transports (DoH, DoT, DNSCrypt, UDP/53, TCP/53) are reachable."
            : $"Detected {issues.Count} transport or connectivity issue(s): {string.Join(", ", issues)}.";

        var report = new NetworkRestrictionReport
        {
            TestedAt = DateTimeOffset.UtcNow,
            Udp53Reachable = udp53Ok,
            Tcp53Reachable = tcp53Ok,
            Doh443Reachable = doh443Ok,
            Dot853Reachable = dot853Ok,
            DnsCryptReachable = cryptOk,
            Ipv4Available = ipv4Ok,
            Ipv6Available = ipv6Ok,
            DetectedIssues = issues,
            Summary = summary,
        };

        LastRestrictionReport = report;
        return report;
    }

    public void ClearHistory()
    {
        lock (_historyLock)
        {
            _history.Clear();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _defaultDoh.Dispose();
    }

    private void RecordFailoverEvent(
        DnsResolverEndpoint failed,
        DnsResolverEndpoint activated,
        DnsFailureCategory category,
        string? error)
    {
        var entry = new FailoverEventEntry
        {
            Timestamp = DateTimeOffset.Now,
            FailedResolverId = failed.Id,
            FailedResolverName = failed.Name,
            FailedProtocol = failed.Protocol,
            ActivatedResolverId = activated.Id,
            ActivatedResolverName = activated.Name,
            ActivatedProtocol = activated.Protocol,
            FailureCategory = category,
            Reason = error ?? category.ToString(),
        };

        lock (_historyLock)
        {
            _history.AddFirst(entry);
            while (_history.Count > MaxHistoryEntries)
            {
                _history.RemoveLast();
            }
        }

        _logger.LogWarning(
            "DNS failover: {Failed} ({FailedProto}) -> {Activated} ({ActivatedProto}) due to {Category}",
            failed.Name,
            failed.Protocol,
            activated.Name,
            activated.Protocol,
            category);
        FailoverOccurred?.Invoke(this, entry);
    }

    private static async Task<bool> ProbeTcpPortAsync(
        string ipString,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(ipString, out var ip))
        {
            return false;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily);
            await tcp.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
