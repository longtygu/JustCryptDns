using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Bypass;

/// <summary>
/// Full lifecycle manager for JustCryptDns's Pure-C# DPI Bypass + Split-Tunnel Proxy + Auto-PAC subsystem.
/// </summary>
public sealed class BypassEngineService : IBypassEngineService
{
    private const int MaxEvents = 300;

    private readonly ISettingsService _settings;
    private readonly IWindowsProxyManager _windowsProxy;
    private readonly IDnsEngine _dnsEngine;
    private readonly ILogger<BypassEngineService> _logger;
    private readonly BypassRuleMatcher _matcher = new();
    private readonly UpstreamTunnelConnector _connector;
    private readonly ConcurrentQueue<BypassConnectionEvent> _events = new();
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);

    private LocalSmartBypassProxy? _proxy;
    private LocalPacHttpServer? _pacServer;
    private BypassEngineState _state = BypassEngineState.Stopped;
    private bool _windowsProxyApplied;
    private string? _lastError;
    private long _totalConnections;
    private long _dpiBypassedConnections;
    private long _tunneledConnections;
    private long _directConnections;
    private long _failedConnections;
    private long _autoFallbackCount;
    private long _selfHealedDirectCount;
    private long _escalatedDpiCount;
    private int _pacRevision = 1;
    private bool _hasStartedOnce;
    private bool _disposed;

    public BypassEngineService(
        ISettingsService settings,
        IWindowsProxyManager windowsProxy,
        IDnsEngine dnsEngine,
        ILogger<BypassEngineService> logger)
    {
        _settings = settings;
        _windowsProxy = windowsProxy;
        _dnsEngine = dnsEngine;
        _logger = logger;
        _connector = new UpstreamTunnelConnector(dnsEngine);
    }

    public event EventHandler<BypassRuntimeStats>? StateChanged;

    public event EventHandler<BypassConnectionEvent>? ConnectionProcessed;

    public BypassRuntimeStats GetStats()
    {
        var bypass = _settings.Current.Bypass;
        var listenIp = ParseListenIp(bypass.ListenAddress);
        var proxyPort = _proxy is { BoundPort: > 0 } ? _proxy.BoundPort : bypass.ProxyPort;
        var pacPort = _pacServer is { BoundPort: > 0 } ? _pacServer.BoundPort : bypass.PacPort;
        var upstreamConfigured = bypass.Upstream.Enabled && bypass.Upstream.Kind != UpstreamTunnelKind.None;

        return new BypassRuntimeStats
        {
            State = _state,
            ProxyEndpoint = $"{listenIp}:{proxyPort}",
            PacUrl = BuildVersionedPacUrl(listenIp, pacPort),
            BoundProxyPort = proxyPort,
            BoundPacPort = pacPort,
            WindowsProxyApplied = _windowsProxyApplied,
            ActiveWindowsProxyMode = bypass.WindowsProxyMode,
            TotalConnections = Interlocked.Read(ref _totalConnections),
            DpiBypassedConnections = Interlocked.Read(ref _dpiBypassedConnections),
            TunneledConnections = Interlocked.Read(ref _tunneledConnections),
            DirectConnections = Interlocked.Read(ref _directConnections),
            FailedConnections = Interlocked.Read(ref _failedConnections),
            AutoFallbackCount = Interlocked.Read(ref _autoFallbackCount),
            ActiveTunnels = _proxy?.ActiveTunnels ?? 0,
            UpstreamConfigured = upstreamConfigured,
            UpstreamSummary = upstreamConfigured
                ? $"{bypass.Upstream.Kind} ({bypass.Upstream.Host}:{bypass.Upstream.Port})"
                : "Disabled",
            LastError = _lastError,
            HasProxyBackup = _windowsProxy.HasActiveBackup(),
            CoverageMode = bypass.CoverageMode,
            LearnedHostCount = _matcher.ActiveLearnedHostCount,
            SelfHealedDirectCount = Interlocked.Read(ref _selfHealedDirectCount),
            EscalatedDpiCount = Interlocked.Read(ref _escalatedDpiCount),
        };
    }

    private string BuildVersionedPacUrl(IPAddress listenIp, int pacPort) =>
        $"http://{listenIp}:{pacPort}/proxy.pac?v={Volatile.Read(ref _pacRevision)}";

    public async Task<(bool Success, string? Error)> StartAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_state is BypassEngineState.Running or BypassEngineState.Degraded)
            {
                return (true, null);
            }

            SetState(BypassEngineState.Starting, null);
            var bypass = _settings.Current.Bypass;
            var listenIp = ParseListenIp(bypass.ListenAddress);

            var (pacServer, pacError) = await StartListenerWithFallbackAsync(
                "local PAC server",
                listenIp,
                bypass.PacPort,
                avoidPort: bypass.ProxyPort,
                port => new LocalPacHttpServer(listenIp, port, GeneratePacScript, _logger),
                server => server.Start()).ConfigureAwait(false);

            if (pacServer is null)
            {
                _logger.LogError("Bypass start failed: {Error}", pacError);
                SetState(BypassEngineState.Stopped, pacError);
                return (false, pacError);
            }

            var (proxy, proxyError) = await StartListenerWithFallbackAsync(
                "DPI bypass proxy",
                listenIp,
                bypass.ProxyPort,
                avoidPort: pacServer.BoundPort,
                port => new LocalSmartBypassProxy(
                    listenIp,
                    port,
                    () => pacServer.BoundPort,
                    () => _settings.Current.Bypass,
                    () => _settings.Current.Dns.EnableIpv6,
                    _matcher,
                    _connector,
                    RecordConnectionEvent,
                    _logger),
                server => server.Start()).ConfigureAwait(false);

            if (proxy is null)
            {
                await pacServer.DisposeAsync().ConfigureAwait(false);
                _logger.LogError("Bypass start failed: {Error}", proxyError);
                SetState(BypassEngineState.Stopped, proxyError);
                return (false, proxyError);
            }

            _pacServer = pacServer;
            _proxy = proxy;
            _windowsProxyApplied = false;
            if (_hasStartedOnce)
            {
                Interlocked.Increment(ref _pacRevision);
            }
            else
            {
                _hasStartedOnce = true;
            }

            string? warning = null;
            var pacUrl = BuildVersionedPacUrl(listenIp, pacServer.BoundPort);
            if (bypass.ApplyWindowsProxyAutomatically && bypass.WindowsProxyMode != WindowsProxyMode.ManualOnly)
            {
                WindowsProxyOperationResult proxyResult;
                if (bypass.WindowsProxyMode == WindowsProxyMode.AutoPac)
                {
                    proxyResult = await _windowsProxy.ApplyPacProxyAsync(pacUrl, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    var bypassList = string.Join(';', BuiltInBypassRules.DefaultDirectExclusions.Concat(bypass.DirectExclusionDomains ?? []));
                    proxyResult = await _windowsProxy.ApplyManualProxyAsync($"{listenIp}:{proxy.BoundPort}", bypassList, cancellationToken).ConfigureAwait(false);
                }

                if (proxyResult.Success)
                {
                    _windowsProxyApplied = true;
                }
                else
                {
                    warning = proxyResult.ErrorMessage;
                    _logger.LogWarning("Bypass proxy started, but Windows proxy registration returned: {Warning}", warning);
                }
            }

            SetState(warning is null ? BypassEngineState.Running : BypassEngineState.Degraded, warning);
            _logger.LogInformation(
                "Bypass engine started (proxy={Proxy}, pac={Pac}, coverage={Coverage}, winProxy={Applied}).",
                $"{listenIp}:{proxy.BoundPort}",
                pacUrl,
                bypass.CoverageMode,
                _windowsProxyApplied);
            return (true, warning);
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
            if (_state == BypassEngineState.Stopped && _proxy is null && _pacServer is null)
            {
                if (_windowsProxyApplied || _windowsProxy.HasActiveBackup())
                {
                    await _windowsProxy.RestoreOriginalProxyAsync(cancellationToken).ConfigureAwait(false);
                    _windowsProxyApplied = false;
                }

                return;
            }

            SetState(BypassEngineState.Stopping, _lastError);
            await StopCoreAsync().ConfigureAwait(false);

            if (_windowsProxyApplied || _windowsProxy.HasActiveBackup())
            {
                await _windowsProxy.RestoreOriginalProxyAsync(cancellationToken).ConfigureAwait(false);
            }

            _windowsProxyApplied = false;
            SetState(BypassEngineState.Stopped, null);
            _logger.LogInformation("Bypass engine stopped.");
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

    public BypassMode ResolveModeForHost(string host) => _matcher.Evaluate(host, _settings.Current.Bypass);

    public string GeneratePacScript()
    {
        var bypass = _settings.Current.Bypass;
        var activePort = _proxy is { BoundPort: > 0 } ? _proxy.BoundPort : bypass.ProxyPort;
        return PacScriptGenerator.Generate(bypass, activePort);
    }

    public IReadOnlyList<BypassConnectionEvent> GetRecentEvents() => _events.ToArray();

    public void ClearRecentEvents()
    {
        while (_events.TryDequeue(out _))
        {
        }
    }

    public async Task<BypassTestResult> TestDomainBypassAsync(string host, CancellationToken cancellationToken = default)
    {
        var cleanHost = BypassRuleMatcher.NormalizeHost(host);
        if (string.IsNullOrWhiteSpace(cleanHost))
        {
            return new BypassTestResult
            {
                Host = host ?? string.Empty,
                RecommendedMode = BypassMode.AutoHybrid,
                Summary = "Enter a valid hostname (e.g. store.steampowered.com).",
            };
        }

        var allowIpv6 = _settings.Current.Dns.EnableIpv6;
        var ips = await _connector.ResolveTargetIpsAsync(cleanHost, _settings.Current.Bypass.ResolveTargetViaLocalDns, allowIpv6, cancellationToken).ConfigureAwait(false);
        var primaryIp = ips.Count > 0 ? ips[0] : null;
        if (primaryIp is null)
        {
            return new BypassTestResult
            {
                Host = cleanHost,
                RecommendedMode = BypassMode.AutoHybrid,
                Summary = $"DNS resolution failed for {cleanHost}.",
            };
        }

        var bypass = _settings.Current.Bypass;

        // 1. Direct HTTPS probe (explicitly bypassing any system proxy)
        var (directOk, directMs, _, directErr) = await ProbeHttpsDirectAsync(cleanHost, primaryIp, cancellationToken).ConfigureAwait(false);

        // 2. TLS Record Fragmentation DPI bypass probe
        var (dpiOk, dpiMs, dpiCode, dpiErr) = await ProbeHttpsWithTlsFragmentationAsync(
            cleanHost,
            primaryIp,
            bypass.FragmentationStrategy,
            bypass.FragmentSizeBytes,
            cancellationToken).ConfigureAwait(false);

        // 3. Optional Upstream Tunnel probe
        bool tunnelOk = false;
        double? tunnelMs = null;
        string? tunnelErr = null;
        if (bypass.Upstream.Enabled && bypass.Upstream.Kind != UpstreamTunnelKind.None)
        {
            (tunnelOk, tunnelMs, tunnelErr) = await ProbeHttpsViaUpstreamAsync(cleanHost, bypass.Upstream, cancellationToken).ConfigureAwait(false);
        }

        BypassMode recommended;
        string summary;
        if (directOk)
        {
            recommended = BypassMode.Direct;
            summary = $"{cleanHost} ({primaryIp}) is accessible directly ({directMs:0.#} ms). No bypass required.";
        }
        else if (dpiOk)
        {
            recommended = BypassMode.AutoHybrid;
            summary = $"Direct HTTPS blocked/timed out ({directErr}), but TLS Fragmentation succeeded (HTTP {dpiCode} in {dpiMs:0.#} ms)! Recommend AutoHybrid / DPI Fragment.";
        }
        else if (tunnelOk)
        {
            recommended = BypassMode.UpstreamTunnel;
            summary = $"Direct & DPI blocked; upstream tunnel ({bypass.Upstream.Kind}) succeeded in {tunnelMs:0.#} ms. Recommend Upstream Tunnel.";
        }
        else
        {
            recommended = BypassMode.AutoHybrid;
            summary = bypass.Upstream.Enabled
                ? $"Direct ({directErr}), DPI ({dpiErr}), and Tunnel ({tunnelErr}) all failed."
                : $"Direct ({directErr}) and DPI ({dpiErr}) failed. Enable Tier 2 Split-Tunnel upstream (e.g. Cloudflare WARP) if this host is IP/geo-blocked.";
        }

        return new BypassTestResult
        {
            Host = cleanHost,
            ResolvedIp = primaryIp.ToString(),
            DirectSucceeded = directOk,
            DirectLatencyMs = directMs,
            DirectError = directErr,
            DpiBypassSucceeded = dpiOk,
            DpiBypassLatencyMs = dpiMs,
            DpiBypassStatusCode = dpiCode,
            DpiBypassError = dpiErr,
            TunnelSucceeded = tunnelOk,
            TunnelLatencyMs = tunnelMs,
            TunnelError = tunnelErr,
            RecommendedMode = recommended,
            Summary = summary,
        };
    }

    public Task<(bool Available, string Summary)> DetectCloudflareWarpAsync(CancellationToken cancellationToken = default) =>
        UpstreamTunnelConnector.DetectCloudflareWarpAsync(cancellationToken);

    public Task<(bool Success, double LatencyMs, string Summary)> TestUpstreamTunnelAsync(CancellationToken cancellationToken = default) =>
        UpstreamTunnelConnector.TestUpstreamAsync(_settings.Current.Bypass.Upstream, cancellationToken);

    public IReadOnlyList<BypassRule> GetRules() =>
        _settings.Current.Bypass.Rules ?? [];

    public async Task<(bool Success, BypassRule? Rule, string? Error)> SaveRuleAsync(
        BypassRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            return (false, null, "Rule name is required.");
        }

        if (!RoutingMatcher.IsValidPattern(rule.Pattern, rule.MatchKind, out var patternError))
        {
            return (false, null, patternError);
        }

        var normalized = rule with
        {
            Id = string.IsNullOrWhiteSpace(rule.Id) ? $"custom-{Guid.NewGuid():N}" : rule.Id.Trim(),
            Name = rule.Name.Trim(),
            Pattern = RoutingMatcher.NormalizeDomain(rule.Pattern),
            Category = string.IsNullOrWhiteSpace(rule.Category) ? "Custom" : rule.Category.Trim(),
        };

        await _settings.UpdateAsync(s =>
        {
            s.Bypass.Rules ??= BuiltInBypassRules.CreateDefaultRules().ToList();
            var idx = s.Bypass.Rules.FindIndex(r => string.Equals(r.Id, normalized.Id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Bypass.Rules[idx] = normalized;
            }
            else
            {
                s.Bypass.Rules.Insert(0, normalized);
            }
        }, cancellationToken).ConfigureAwait(false);

        _matcher.ClearHints();
        await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
        return (true, normalized, null);
    }

    public async Task<bool> DeleteRuleAsync(string ruleId, CancellationToken cancellationToken = default)
    {
        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            if (s.Bypass.Rules is null)
            {
                return;
            }

            var target = s.Bypass.Rules.FirstOrDefault(r => string.Equals(r.Id, ruleId, StringComparison.OrdinalIgnoreCase));
            if (target is { IsBuiltIn: false })
            {
                s.Bypass.Rules.Remove(target);
                removed = true;
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            _matcher.ClearHints();
            await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
        }

        return removed;
    }

    public async Task SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s =>
        {
            if (s.Bypass.Rules is null)
            {
                return;
            }

            var idx = s.Bypass.Rules.FindIndex(r => string.Equals(r.Id, ruleId, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Bypass.Rules[idx] = s.Bypass.Rules[idx] with { Enabled = enabled };
            }
        }, cancellationToken).ConfigureAwait(false);

        _matcher.ClearHints();
        await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task ResetBuiltInRulesAsync(CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s =>
        {
            var custom = (s.Bypass.Rules ?? []).Where(r => !r.IsBuiltIn).ToList();
            s.Bypass.Rules = [.. BuiltInBypassRules.CreateDefaultRules(), .. custom];
        }, cancellationToken).ConfigureAwait(false);

        _matcher.ClearHints();
        await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
    }

    public IReadOnlyList<string> GetDirectExclusions() =>
        _settings.Current.Bypass.DirectExclusionDomains ?? [];

    public async Task<(bool Success, string? Error)> AddDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default)
    {
        var normalized = RoutingMatcher.NormalizeDomain(pattern);
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Contains(' ') || normalized.Contains('/') || normalized.Contains(':'))
        {
            return (false, "Enter a valid domain or wildcard pattern (e.g. bank.vn or *.corp.local).");
        }

        await _settings.UpdateAsync(s =>
        {
            s.Bypass.DirectExclusionDomains ??= [];
            if (!s.Bypass.DirectExclusionDomains.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                s.Bypass.DirectExclusionDomains.Add(normalized);
            }
        }, cancellationToken).ConfigureAwait(false);

        _matcher.ClearHints();
        await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
        return (true, null);
    }

    public async Task<bool> RemoveDirectExclusionAsync(
        string pattern,
        CancellationToken cancellationToken = default)
    {
        var normalized = RoutingMatcher.NormalizeDomain(pattern);
        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            if (s.Bypass.DirectExclusionDomains is null)
            {
                return;
            }

            removed = s.Bypass.DirectExclusionDomains.RemoveAll(d => string.Equals(d, normalized, StringComparison.OrdinalIgnoreCase)) > 0;
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            _matcher.ClearHints();
            await RefreshSystemPacAsync(cancellationToken).ConfigureAwait(false);
        }

        return removed;
    }

    public IReadOnlyList<LearnedHostEntry> GetLearnedHosts() => _matcher.GetLearnedHosts();

    public void ClearLearnedHosts()
    {
        _matcher.ClearHints();
        RaiseStateChanged();
    }

    public async Task<(bool Success, string? Error)> PromoteLearnedHostAsync(
        string host,
        LearnedHostStrategy strategy,
        CancellationToken cancellationToken = default)
    {
        var clean = BypassRuleMatcher.NormalizeHost(host);
        if (string.IsNullOrWhiteSpace(clean))
        {
            return (false, "Invalid hostname.");
        }

        if (strategy == LearnedHostStrategy.Direct)
        {
            return await AddDirectExclusionAsync(clean, cancellationToken).ConfigureAwait(false);
        }

        var mode = strategy == LearnedHostStrategy.UpstreamTunnel
            ? BypassMode.UpstreamTunnel
            : BypassMode.DpiFragment;

        var (ok, _, err) = await SaveRuleAsync(new BypassRule
        {
            Id = $"promoted-{clean}",
            Name = clean,
            Pattern = clean,
            MatchKind = RoutingMatchKind.Exact,
            Mode = mode,
            Category = "Promoted",
            Enabled = true,
            IsBuiltIn = false,
        }, cancellationToken).ConfigureAwait(false);
        return (ok, err);
    }

    public async Task RefreshSystemPacAsync(CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _pacRevision);
        var bypass = _settings.Current.Bypass;
        if (_state is BypassEngineState.Running or BypassEngineState.Degraded
            && _pacServer is { BoundPort: > 0 } pacServer
            && bypass.ApplyWindowsProxyAutomatically
            && bypass.WindowsProxyMode == WindowsProxyMode.AutoPac)
        {
            var listenIp = ParseListenIp(bypass.ListenAddress);
            var url = BuildVersionedPacUrl(listenIp, pacServer.BoundPort);
            var res = await _windowsProxy.ApplyPacProxyAsync(url, cancellationToken).ConfigureAwait(false);
            _windowsProxyApplied = res.Success;
        }

        RaiseStateChanged();
    }

    public async Task<IReadOnlyList<BypassTestResult>> TestMultipleDomainsAsync(
        IEnumerable<string> hosts,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(hosts);
        var distinct = hosts
            .Select(BypassRuleMatcher.NormalizeHost)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        using var throttler = new SemaphoreSlim(4, 4);
        var tasks = distinct.Select(async h =>
        {
            await throttler.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await TestDomainBypassAsync(h, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                throttler.Release();
            }
        });

        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static async Task<(bool Ok, double LatencyMs, int? StatusCode, string? Error)> ProbeHttpsDirectAsync(
        string host,
        IPAddress ip,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(3000);
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(ip, 443, cts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token).ConfigureAwait(false);
            var code = await SendHeadRequestAsync(ssl, host, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Round(sw.Elapsed.TotalMilliseconds, 1), code, null);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), null, ex.Message);
        }
    }

    private static async Task<(bool Ok, double LatencyMs, int? StatusCode, string? Error)> ProbeHttpsWithTlsFragmentationAsync(
        string host,
        IPAddress ip,
        TlsFragmentationStrategy strategy,
        int chunkSize,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(4500);
        try
        {
            using var tcp = new TcpClient(ip.AddressFamily) { NoDelay = true };
            await tcp.ConnectAsync(ip, 443, cts.Token).ConfigureAwait(false);
            using var fragStream = new FragmentingHandshakeStream(tcp.GetStream(), strategy, chunkSize);
            using var ssl = new SslStream(fragStream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token).ConfigureAwait(false);
            var code = await SendHeadRequestAsync(ssl, host, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Round(sw.Elapsed.TotalMilliseconds, 1), code, null);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), null, ex.Message);
        }
    }

    private static async Task<(bool Ok, double? LatencyMs, string? Error)> ProbeHttpsViaUpstreamAsync(
        string host,
        UpstreamTunnelSettings upstream,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(5000);
        try
        {
            using var tcp = await UpstreamTunnelConnector.ConnectViaUpstreamAsync(host, 443, upstream, 4500, cts.Token).ConfigureAwait(false);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token).ConfigureAwait(false);
            _ = await SendHeadRequestAsync(ssl, host, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, Math.Round(sw.Elapsed.TotalMilliseconds, 1), null);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            sw.Stop();
            return (false, Math.Round(sw.Elapsed.TotalMilliseconds, 1), ex.Message);
        }
    }

    private static async Task<int> SendHeadRequestAsync(SslStream ssl, string host, CancellationToken ct)
    {
        var req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: JustCryptDns/1.1\r\nConnection: close\r\n\r\n");
        await ssl.WriteAsync(req, ct).ConfigureAwait(false);
        await ssl.FlushAsync(ct).ConfigureAwait(false);

        var buf = new byte[128];
        var read = await ssl.ReadAsync(buf, ct).ConfigureAwait(false);
        var statusLine = Encoding.ASCII.GetString(buf, 0, read);
        var parts = statusLine.Split(' ', 3);
        return parts.Length >= 2 && int.TryParse(parts[1], out var code) ? code : 200;
    }

    private sealed class FragmentingHandshakeStream(
        Stream inner,
        TlsFragmentationStrategy strategy,
        int chunkSize) : Stream
    {
        private bool _fragmented;

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_fragmented && TlsClientHelloFragmenter.IsTlsClientHelloHeader(buffer.Span))
            {
                _fragmented = true;
                var records = TlsClientHelloFragmenter.BuildFragmentedTlsRecords(buffer.Span, strategy, chunkSize);
                foreach (var record in records)
                {
                    await inner.WriteAsync(record, cancellationToken).ConfigureAwait(false);
                    await inner.FlushAsync(cancellationToken).ConfigureAwait(false);
                }

                return;
            }

            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
    }

    private void RecordConnectionEvent(
        BypassActionKind action,
        string host,
        int port,
        string clientProtocol,
        string strategyUsed,
        double latencyMs,
        string? error)
    {
        Interlocked.Increment(ref _totalConnections);
        switch (action)
        {
            case BypassActionKind.DpiFragmented:
                Interlocked.Increment(ref _dpiBypassedConnections);
                break;
            case BypassActionKind.EscalatedDpi16B:
                Interlocked.Increment(ref _dpiBypassedConnections);
                Interlocked.Increment(ref _escalatedDpiCount);
                break;
            case BypassActionKind.SelfHealedDirect:
                Interlocked.Increment(ref _directConnections);
                Interlocked.Increment(ref _selfHealedDirectCount);
                break;
            case BypassActionKind.UpstreamTunneled:
                Interlocked.Increment(ref _tunneledConnections);
                break;
            case BypassActionKind.AutoFallbackTunnel:
                Interlocked.Increment(ref _tunneledConnections);
                Interlocked.Increment(ref _autoFallbackCount);
                break;
            case BypassActionKind.DirectPassthrough:
                Interlocked.Increment(ref _directConnections);
                break;
            case BypassActionKind.Failed:
                Interlocked.Increment(ref _failedConnections);
                break;
        }

        var entry = new BypassConnectionEvent
        {
            Timestamp = DateTimeOffset.Now,
            Host = host,
            Port = port,
            ClientProtocol = clientProtocol,
            Action = action,
            StrategyUsed = strategyUsed,
            LatencyMs = Math.Round(latencyMs, 1),
            Error = error,
        };

        _events.Enqueue(entry);
        while (_events.Count > MaxEvents && _events.TryDequeue(out _))
        {
        }

        ConnectionProcessed?.Invoke(this, entry);
        RaiseStateChanged();
    }

    private static IPAddress ParseListenIp(string? address) =>
        IPAddress.TryParse(address, out var parsed) && IPAddress.IsLoopback(parsed)
            ? parsed
            : IPAddress.Loopback;

    private async Task<(T? Listener, string? Error)> StartListenerWithFallbackAsync<T>(
        string roleName,
        IPAddress listenIp,
        int requestedPort,
        int avoidPort,
        Func<int, T> factory,
        Action<T> startAction)
        where T : class, IAsyncDisposable
    {
        var candidates = new List<int> { requestedPort };
        if (requestedPort > 0)
        {
            for (var offset = 1; offset <= 20; offset++)
            {
                var candidate = requestedPort + offset;
                if (candidate is > 1024 and <= 65534 && candidate != avoidPort)
                {
                    candidates.Add(candidate);
                }
            }

            candidates.Add(0);
        }

        SocketException? lastSocketError = null;
        for (var i = 0; i < candidates.Count; i++)
        {
            var port = candidates[i];
            var server = factory(port);
            try
            {
                startAction(server);
                if (i > 0)
                {
                    _logger.LogWarning(
                        "Configured {Role} port {RequestedPort} on {Ip} was unavailable ({Reason}); rebound cleanly to {ActualPort}.",
                        roleName,
                        requestedPort,
                        listenIp,
                        lastSocketError?.SocketErrorCode,
                        port == 0 ? "ephemeral" : port);
                }

                return (server, null);
            }
            catch (SocketException ex)
            {
                lastSocketError = ex;
                await server.DisposeAsync().ConfigureAwait(false);
                if (ex.SocketErrorCode is not (SocketError.AddressAlreadyInUse or SocketError.AccessDenied)
                    || i == candidates.Count - 1)
                {
                    return (null, $"Could not start {roleName} on {listenIp}:{requestedPort}: {ex.Message}");
                }
            }
        }

        return (null, $"Could not start {roleName} on {listenIp}:{requestedPort}: {lastSocketError?.Message}");
    }

    private async Task StopCoreAsync()
    {
        if (_proxy is not null)
        {
            await _proxy.DisposeAsync().ConfigureAwait(false);
            _proxy = null;
        }

        if (_pacServer is not null)
        {
            await _pacServer.DisposeAsync().ConfigureAwait(false);
            _pacServer = null;
        }
    }

    private void SetState(BypassEngineState state, string? error)
    {
        _state = state;
        _lastError = error;
        RaiseStateChanged();
    }

    private void RaiseStateChanged() => StateChanged?.Invoke(this, GetStats());

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        _disposed = true;
        _lifecycleGate.Dispose();
    }
}
