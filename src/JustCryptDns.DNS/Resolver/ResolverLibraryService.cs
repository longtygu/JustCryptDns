using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.DNS.DNSOverHTTPS;
using JustCryptDns.DNS.DNSOverTLS;
using JustCryptDns.DNS.Wire;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.DNS.Resolver;

public sealed class ResolverLibraryService : IResolverLibraryService, IDisposable
{
    private readonly ISettingsService _settings;
    private readonly ILogger<ResolverLibraryService> _logger;
    private readonly Dictionary<DnsProtocol, IDnsUpstreamClient> _upstreams;
    private readonly DohDnsUpstream _defaultDoh;
    private readonly ConcurrentDictionary<string, ResolverHealthStatus> _health = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public ResolverLibraryService(
        ISettingsService settings,
        ILogger<ResolverLibraryService> logger,
        IEnumerable<IDnsUpstreamClient>? customUpstreams = null)
    {
        _settings = settings;
        _logger = logger;

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

    public event EventHandler? LibraryChanged;

    public event EventHandler<ResolverHealthStatus>? HealthUpdated;

    public IReadOnlyList<DnsResolverEndpoint> GetAll()
    {
        var dns = _settings.Current.Dns;
        var disabled = dns.DisabledResolverIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var groupOverrides = dns.ResolverGroupOverrides;

        var result = new List<DnsResolverEndpoint>(BuiltInResolvers.All.Count + dns.CustomResolvers.Count);
        foreach (var builtIn in BuiltInResolvers.All)
        {
            var group = groupOverrides.TryGetValue(builtIn.Id, out var customGroup) && !string.IsNullOrWhiteSpace(customGroup)
                ? customGroup
                : builtIn.GroupName;
            result.Add(builtIn with
            {
                IsEnabled = !disabled.Contains(builtIn.Id),
                GroupName = group,
                IsCustom = false,
            });
        }

        foreach (var custom in dns.CustomResolvers)
        {
            var group = groupOverrides.TryGetValue(custom.Id, out var customGroup) && !string.IsNullOrWhiteSpace(customGroup)
                ? customGroup
                : (string.IsNullOrWhiteSpace(custom.GroupName) ? ResolverGroups.General : custom.GroupName);
            result.Add(custom with
            {
                IsEnabled = !disabled.Contains(custom.Id) && custom.IsEnabled,
                GroupName = group,
                IsCustom = true,
            });
        }

        return result;
    }

    public IReadOnlyList<DnsResolverEndpoint> GetEnabled() =>
        GetAll().Where(r => r.IsEnabled).ToList();

    public DnsResolverEndpoint GetByIdOrDefault(string? resolverId)
    {
        var all = GetAll();
        if (!string.IsNullOrWhiteSpace(resolverId))
        {
            var match = all.FirstOrDefault(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match;
            }
        }

        return all.FirstOrDefault(r => r.IsEnabled) ?? all[0];
    }

    public DnsResolverEndpoint GetPrimaryResolver() =>
        GetByIdOrDefault(_settings.Current.Dns.ActiveResolverId);

    public DnsResolverEndpoint GetSecondaryResolver() =>
        GetByIdOrDefault(_settings.Current.Dns.SecondaryResolverId);

    public IReadOnlyList<string> GetGroups()
    {
        var groups = new List<string>(ResolverGroups.BuiltIn);
        foreach (var g in _settings.Current.Dns.CustomGroups)
        {
            if (!string.IsNullOrWhiteSpace(g) && !groups.Contains(g, StringComparer.OrdinalIgnoreCase))
            {
                groups.Add(g.Trim());
            }
        }

        foreach (var r in GetAll())
        {
            if (!string.IsNullOrWhiteSpace(r.GroupName) && !groups.Contains(r.GroupName, StringComparer.OrdinalIgnoreCase))
            {
                groups.Add(r.GroupName.Trim());
            }
        }

        return groups;
    }

    public ResolverHealthStatus GetHealth(string resolverId)
    {
        if (_health.TryGetValue(resolverId, out var status))
        {
            return status;
        }

        return new ResolverHealthStatus { ResolverId = resolverId };
    }

    public IReadOnlyDictionary<string, ResolverHealthStatus> GetAllHealth() =>
        new Dictionary<string, ResolverHealthStatus>(_health, StringComparer.OrdinalIgnoreCase);

    public async Task<(bool Success, DnsResolverEndpoint? Resolver, ResolverValidationResult Validation)> AddCustomResolverAsync(
        DnsResolverEndpoint resolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        var id = string.IsNullOrWhiteSpace(resolver.Id)
            ? GenerateResolverId(resolver.Provider, resolver.Name, resolver.Protocol)
            : resolver.Id.Trim();

        var existingIds = GetAll().Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (existingIds.Contains(id))
        {
            id = $"{id}-{Guid.NewGuid().ToString("N")[..6]}";
        }

        var normalized = NormalizeResolver(resolver, id, isCustom: true);
        var validation = ResolverValidator.Validate(normalized);
        if (!validation.IsValid)
        {
            return (false, null, validation);
        }

        await _settings.UpdateAsync(s =>
        {
            s.Dns.CustomResolvers.Add(normalized);
            if (!ResolverGroups.BuiltIn.Contains(normalized.GroupName, StringComparer.OrdinalIgnoreCase)
                && !s.Dns.CustomGroups.Contains(normalized.GroupName, StringComparer.OrdinalIgnoreCase))
            {
                s.Dns.CustomGroups.Add(normalized.GroupName);
            }
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Added custom resolver {Name} ({Id}, {Protocol})", normalized.Name, normalized.Id, normalized.Protocol);
        RaiseLibraryChanged();
        return (true, normalized, validation);
    }

    public async Task<(bool Success, DnsResolverEndpoint? Resolver, ResolverValidationResult Validation)> UpdateResolverAsync(
        DnsResolverEndpoint resolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        var existing = GetAll().FirstOrDefault(r => string.Equals(r.Id, resolver.Id, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            return (false, null, new ResolverValidationResult(false, "Resolvers_Err_NotFound", "Resolver not found."));
        }

        if (!existing.IsCustom)
        {
            // Built-in resolvers only allow group and enabled state updates.
            await SetResolverGroupAsync(existing.Id, resolver.GroupName, cancellationToken).ConfigureAwait(false);
            await SetResolverEnabledAsync(existing.Id, resolver.IsEnabled, cancellationToken).ConfigureAwait(false);
            var updatedBuiltIn = GetByIdOrDefault(existing.Id);
            return (true, updatedBuiltIn, new ResolverValidationResult(true));
        }

        var normalized = NormalizeResolver(resolver, existing.Id, isCustom: true);
        var validation = ResolverValidator.Validate(normalized);
        if (!validation.IsValid)
        {
            return (false, null, validation);
        }

        await _settings.UpdateAsync(s =>
        {
            var idx = s.Dns.CustomResolvers.FindIndex(r => string.Equals(r.Id, existing.Id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Dns.CustomResolvers[idx] = normalized;
            }

            if (normalized.IsEnabled)
            {
                s.Dns.DisabledResolverIds.RemoveAll(x => string.Equals(x, existing.Id, StringComparison.OrdinalIgnoreCase));
            }
            else if (!s.Dns.DisabledResolverIds.Contains(existing.Id, StringComparer.OrdinalIgnoreCase))
            {
                s.Dns.DisabledResolverIds.Add(existing.Id);
            }
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Updated custom resolver {Name} ({Id})", normalized.Name, normalized.Id);
        RaiseLibraryChanged();
        return (true, normalized, validation);
    }

    public async Task<bool> RemoveCustomResolverAsync(string resolverId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(resolverId))
        {
            return false;
        }

        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            var count = s.Dns.CustomResolvers.RemoveAll(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
            if (count > 0)
            {
                removed = true;
                s.Dns.DisabledResolverIds.RemoveAll(id => string.Equals(id, resolverId, StringComparison.OrdinalIgnoreCase));
                s.Dns.ResolverGroupOverrides.Remove(resolverId);

                if (string.Equals(s.Dns.ActiveResolverId, resolverId, StringComparison.OrdinalIgnoreCase))
                {
                    s.Dns.ActiveResolverId = BuiltInResolvers.DefaultResolverId;
                }

                if (string.Equals(s.Dns.SecondaryResolverId, resolverId, StringComparison.OrdinalIgnoreCase))
                {
                    s.Dns.SecondaryResolverId = BuiltInResolvers.DefaultSecondaryResolverId;
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            _health.TryRemove(resolverId, out _);
            _logger.LogInformation("Removed custom resolver {Id}", resolverId);
            RaiseLibraryChanged();
        }

        return removed;
    }

    public async Task SetResolverEnabledAsync(string resolverId, bool enabled, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(resolverId))
        {
            return;
        }

        await _settings.UpdateAsync(s =>
        {
            s.Dns.DisabledResolverIds.RemoveAll(x => string.Equals(x, resolverId, StringComparison.OrdinalIgnoreCase));
            if (!enabled)
            {
                s.Dns.DisabledResolverIds.Add(resolverId);
            }

            var idx = s.Dns.CustomResolvers.FindIndex(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Dns.CustomResolvers[idx] = s.Dns.CustomResolvers[idx] with { IsEnabled = enabled };
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseLibraryChanged();
    }

    public async Task SetResolverGroupAsync(string resolverId, string groupName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(resolverId) || string.IsNullOrWhiteSpace(groupName))
        {
            return;
        }

        var trimmed = groupName.Trim();
        await _settings.UpdateAsync(s =>
        {
            s.Dns.ResolverGroupOverrides[resolverId] = trimmed;
            var idx = s.Dns.CustomResolvers.FindIndex(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Dns.CustomResolvers[idx] = s.Dns.CustomResolvers[idx] with { GroupName = trimmed };
            }

            if (!ResolverGroups.BuiltIn.Contains(trimmed, StringComparer.OrdinalIgnoreCase)
                && !s.Dns.CustomGroups.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
            {
                s.Dns.CustomGroups.Add(trimmed);
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseLibraryChanged();
    }

    public async Task AddGroupAsync(string groupName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(groupName))
        {
            return;
        }

        var trimmed = groupName.Trim();
        await _settings.UpdateAsync(s =>
        {
            if (!ResolverGroups.BuiltIn.Contains(trimmed, StringComparer.OrdinalIgnoreCase)
                && !s.Dns.CustomGroups.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
            {
                s.Dns.CustomGroups.Add(trimmed);
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseLibraryChanged();
    }

    public async Task<(bool Success, string? Error)> SetPrimaryResolverAsync(string resolverId, CancellationToken cancellationToken = default)
    {
        var resolver = GetAll().FirstOrDefault(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
        if (resolver is null)
        {
            return (false, "Resolver not found.");
        }

        if (!resolver.IsEnabled)
        {
            return (false, $"Resolver '{resolver.Name}' is disabled. Enable it before setting as primary.");
        }

        var validation = ResolverValidator.Validate(resolver);
        if (!validation.IsValid)
        {
            return (false, validation.ErrorMessage);
        }

        await _settings.UpdateAsync(s => s.Dns.ActiveResolverId = resolver.Id, cancellationToken).ConfigureAwait(false);
        RaiseLibraryChanged();
        return (true, null);
    }

    public async Task<(bool Success, string? Error)> SetSecondaryResolverAsync(string resolverId, CancellationToken cancellationToken = default)
    {
        var resolver = GetAll().FirstOrDefault(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
        if (resolver is null)
        {
            return (false, "Resolver not found.");
        }

        if (!resolver.IsEnabled)
        {
            return (false, $"Resolver '{resolver.Name}' is disabled. Enable it before setting as secondary.");
        }

        var validation = ResolverValidator.Validate(resolver);
        if (!validation.IsValid)
        {
            return (false, validation.ErrorMessage);
        }

        await _settings.UpdateAsync(s => s.Dns.SecondaryResolverId = resolver.Id, cancellationToken).ConfigureAwait(false);
        RaiseLibraryChanged();
        return (true, null);
    }

    public async Task<ResolverHealthStatus> CheckHealthAsync(string resolverId, CancellationToken cancellationToken = default)
    {
        var resolver = GetAll().FirstOrDefault(r => string.Equals(r.Id, resolverId, StringComparison.OrdinalIgnoreCase));
        if (resolver is null)
        {
            return new ResolverHealthStatus
            {
                ResolverId = resolverId,
                IsAvailable = false,
                LastCheckedAt = DateTimeOffset.UtcNow,
                LastError = "Resolver not found.",
            };
        }

        var validation = ResolverValidator.Validate(resolver);
        if (!validation.IsValid)
        {
            var invalidStatus = UpdateHealthEntry(resolver.Id, false, null, validation.ErrorMessage);
            HealthUpdated?.Invoke(this, invalidStatus);
            return invalidStatus;
        }

        var timeout = TimeSpan.FromMilliseconds(_settings.Current.Dns.QueryTimeoutMs);
        bool ok;
        double? latencyMs;
        string? error;

        if (_upstreams.TryGetValue(resolver.Protocol, out var upstream))
        {
            var query = DnsPacket.CreateQuery("example.com", DnsRecordType.A);
            var result = await upstream.QueryAsync(query, resolver, timeout, cancellationToken).ConfigureAwait(false);
            ok = result.Success;
            latencyMs = result.Success ? Math.Round(result.LatencyMs, 1) : null;
            error = result.Error;
        }
        else if (resolver.Protocol == DnsProtocol.DnsCrypt)
        {
            // When no live dnscrypt-proxy child is bound to this stamp yet, verify stamp validity + TCP reachability of PrimaryIp:Port.
            var (tcpOk, tcpMs, tcpErr) = await ProbeTcpEndpointAsync(resolver.PrimaryIp, resolver.Port, timeout, cancellationToken).ConfigureAwait(false);
            ok = tcpOk;
            latencyMs = tcpOk ? Math.Round(tcpMs, 1) : null;
            error = tcpErr;
        }
        else
        {
            ok = false;
            latencyMs = null;
            error = $"Unsupported protocol {resolver.Protocol}.";
        }

        var status = UpdateHealthEntry(resolver.Id, ok, latencyMs, error);
        HealthUpdated?.Invoke(this, status);
        return status;
    }

    public async Task<IReadOnlyList<ResolverHealthStatus>> CheckAllEnabledHealthAsync(CancellationToken cancellationToken = default)
    {
        var enabled = GetEnabled();
        using var gate = new SemaphoreSlim(6, 6);
        var tasks = enabled.Select(async r =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await CheckHealthAsync(r.Id, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        });

        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public string ExportProfileJson()
    {
        var dns = _settings.Current.Dns;
        var doc = new ResolverProfileExportDocument
        {
            FormatVersion = 1,
            ExportedAt = DateTimeOffset.UtcNow,
            PrimaryResolverId = dns.ActiveResolverId,
            SecondaryResolverId = dns.SecondaryResolverId,
            CustomResolvers = dns.CustomResolvers.ToList(),
            DisabledResolverIds = dns.DisabledResolverIds.ToList(),
            GroupOverrides = new Dictionary<string, string>(dns.ResolverGroupOverrides, StringComparer.OrdinalIgnoreCase),
            CustomGroups = dns.CustomGroups.ToList(),
        };

        return JsonSerializer.Serialize(doc, SettingsJson.Options);
    }

    public async Task<(bool Success, int ImportedCount, string? Error)> ImportProfileJsonAsync(
        string json,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return (false, 0, "Profile JSON is empty.");
        }

        ResolverProfileExportDocument? doc;
        try
        {
            doc = JsonSerializer.Deserialize<ResolverProfileExportDocument>(json, SettingsJson.Options);
        }
        catch (JsonException ex)
        {
            return (false, 0, $"Invalid resolver profile JSON: {ex.Message}");
        }

        if (doc is null)
        {
            return (false, 0, "Profile document could not be parsed.");
        }

        var validCustom = new List<DnsResolverEndpoint>();
        if (doc.CustomResolvers is not null)
        {
            foreach (var r in doc.CustomResolvers)
            {
                if (r is null)
                {
                    continue;
                }

                var id = string.IsNullOrWhiteSpace(r.Id)
                    ? GenerateResolverId(r.Provider, r.Name, r.Protocol)
                    : r.Id.Trim();
                var normalized = NormalizeResolver(r, id, isCustom: true);
                var validation = ResolverValidator.Validate(normalized);
                if (!validation.IsValid)
                {
                    return (false, 0, $"Invalid resolver '{r.Name}': {validation.ErrorMessage}");
                }

                validCustom.Add(normalized);
            }
        }

        var importedCount = 0;
        await _settings.UpdateAsync(s =>
        {
            foreach (var custom in validCustom)
            {
                if (BuiltInResolvers.All.Any(b => string.Equals(b.Id, custom.Id, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                var existingIdx = s.Dns.CustomResolvers.FindIndex(x => string.Equals(x.Id, custom.Id, StringComparison.OrdinalIgnoreCase));
                if (existingIdx >= 0)
                {
                    s.Dns.CustomResolvers[existingIdx] = custom;
                }
                else
                {
                    s.Dns.CustomResolvers.Add(custom);
                }

                importedCount++;
            }

            if (doc.CustomGroups is not null)
            {
                foreach (var g in doc.CustomGroups)
                {
                    if (!string.IsNullOrWhiteSpace(g)
                        && !ResolverGroups.BuiltIn.Contains(g, StringComparer.OrdinalIgnoreCase)
                        && !s.Dns.CustomGroups.Contains(g, StringComparer.OrdinalIgnoreCase))
                    {
                        s.Dns.CustomGroups.Add(g.Trim());
                    }
                }
            }

            if (doc.GroupOverrides is not null)
            {
                foreach (var (k, v) in doc.GroupOverrides)
                {
                    if (!string.IsNullOrWhiteSpace(k) && !string.IsNullOrWhiteSpace(v))
                    {
                        s.Dns.ResolverGroupOverrides[k] = v.Trim();
                    }
                }
            }

            if (doc.DisabledResolverIds is not null)
            {
                s.Dns.DisabledResolverIds = doc.DisabledResolverIds
                    .Where(id => !string.IsNullOrWhiteSpace(id))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
            }

            if (!string.IsNullOrWhiteSpace(doc.PrimaryResolverId))
            {
                s.Dns.ActiveResolverId = doc.PrimaryResolverId;
            }

            if (!string.IsNullOrWhiteSpace(doc.SecondaryResolverId))
            {
                s.Dns.SecondaryResolverId = doc.SecondaryResolverId;
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseLibraryChanged();
        return (true, importedCount, null);
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

    private static DnsResolverEndpoint NormalizeResolver(DnsResolverEndpoint resolver, string id, bool isCustom)
    {
        var port = resolver.Port;
        if (port <= 0)
        {
            port = resolver.Protocol switch
            {
                DnsProtocol.DnsOverTls => 853,
                DnsProtocol.UdpTcp => 53,
                _ => 443,
            };
        }

        return resolver with
        {
            Id = id,
            Name = resolver.Name?.Trim() ?? string.Empty,
            Provider = resolver.Provider?.Trim() ?? string.Empty,
            Endpoint = resolver.Endpoint?.Trim() ?? string.Empty,
            PrimaryIp = resolver.PrimaryIp?.Trim() ?? string.Empty,
            SecondaryIp = string.IsNullOrWhiteSpace(resolver.SecondaryIp) ? null : resolver.SecondaryIp.Trim(),
            PrimaryIpv6 = string.IsNullOrWhiteSpace(resolver.PrimaryIpv6) ? null : resolver.PrimaryIpv6.Trim(),
            Port = port,
            GroupName = string.IsNullOrWhiteSpace(resolver.GroupName) ? ResolverGroups.General : resolver.GroupName.Trim(),
            IsCustom = isCustom,
        };
    }

    private static string GenerateResolverId(string? provider, string? name, DnsProtocol protocol)
    {
        var raw = $"{provider}-{name}-{protocol}".ToLowerInvariant();
        var chars = raw.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        var slug = string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
        return string.IsNullOrWhiteSpace(slug) ? $"custom-{Guid.NewGuid().ToString("N")[..8]}" : slug;
    }

    private ResolverHealthStatus UpdateHealthEntry(string resolverId, bool success, double? latencyMs, string? error)
    {
        return _health.AddOrUpdate(
            resolverId,
            _ =>
            {
                var total = 1;
                var succ = success ? 1 : 0;
                return new ResolverHealthStatus
                {
                    ResolverId = resolverId,
                    IsAvailable = success,
                    LastLatencyMs = latencyMs,
                    ReliabilityScore = ComputeReliability(total, succ, latencyMs),
                    TotalProbes = total,
                    SuccessfulProbes = succ,
                    LastCheckedAt = DateTimeOffset.UtcNow,
                    LastError = success ? null : error,
                };
            },
            (_, prev) =>
            {
                var total = prev.TotalProbes + 1;
                var succ = prev.SuccessfulProbes + (success ? 1 : 0);
                var effLatency = latencyMs ?? prev.LastLatencyMs;
                return new ResolverHealthStatus
                {
                    ResolverId = resolverId,
                    IsAvailable = success,
                    LastLatencyMs = effLatency,
                    ReliabilityScore = ComputeReliability(total, succ, effLatency),
                    TotalProbes = total,
                    SuccessfulProbes = succ,
                    LastCheckedAt = DateTimeOffset.UtcNow,
                    LastError = success ? null : error,
                };
            });
    }

    private static double ComputeReliability(int totalProbes, int successfulProbes, double? latencyMs)
    {
        if (totalProbes <= 0 || successfulProbes <= 0)
        {
            return 0.0;
        }

        var successRatio = (double)successfulProbes / totalProbes;
        var latencyFactor = latencyMs is { } ms
            ? Math.Clamp(1.0 - (ms / 1500.0), 0.1, 1.0)
            : 0.5;
        return Math.Round((successRatio * 85.0) + (latencyFactor * 15.0), 1);
    }

    private static async Task<(bool Success, double LatencyMs, string? Error)> ProbeTcpEndpointAsync(
        string ipAddress,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(ipAddress, out var ip))
        {
            return (false, 0, $"Invalid IP address '{ipAddress}'.");
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var sw = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(ip.AddressFamily);
            await client.ConnectAsync(ip, port, cts.Token).ConfigureAwait(false);
            sw.Stop();
            return (true, sw.Elapsed.TotalMilliseconds, null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            sw.Stop();
            return (false, sw.Elapsed.TotalMilliseconds, $"Connection to {ip}:{port} timed out.");
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, sw.Elapsed.TotalMilliseconds, ex.Message);
        }
    }

    private void RaiseLibraryChanged() => LibraryChanged?.Invoke(this, EventArgs.Empty);
}
