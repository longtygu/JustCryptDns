using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.DNS.Routing;

public sealed class DnsRoutingService : IDnsRoutingService
{
    public const int MaxLogEntries = 200;

    private readonly ISettingsService _settings;
    private readonly IResolverLibraryService? _resolverLibrary;
    private readonly ILogger<DnsRoutingService> _logger;
    private readonly LinkedList<RoutingLogEntry> _logs = new();
    private readonly object _logLock = new();

    public DnsRoutingService(
        ISettingsService settings,
        ILogger<DnsRoutingService> logger,
        IResolverLibraryService? resolverLibrary = null)
    {
        _settings = settings;
        _logger = logger;
        _resolverLibrary = resolverLibrary;
    }

    public event EventHandler? RoutingChanged;

    public event EventHandler<RoutingLogEntry>? LogAdded;

    public bool IsRoutingEnabled => _settings.Current.Routing.IsRoutingEnabled;

    public async Task SetRoutingEnabledAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s => s.Routing.IsRoutingEnabled = enabled, cancellationToken).ConfigureAwait(false);
        RaiseRoutingChanged();
    }

    public IReadOnlyList<DnsRoutingProfile> GetProfiles()
    {
        var routing = _settings.Current.Routing;
        var overrides = routing.ProfileFallbackOverrides;
        var list = new List<DnsRoutingProfile>(BuiltInRoutingProfiles.All.Count + routing.CustomProfiles.Count);

        foreach (var builtIn in BuiltInRoutingProfiles.All)
        {
            var fallback = overrides.TryGetValue(builtIn.Id, out var customFallback) && !string.IsNullOrWhiteSpace(customFallback)
                ? customFallback
                : builtIn.FallbackResolverId;
            list.Add(builtIn with { FallbackResolverId = fallback, IsBuiltIn = true });
        }

        foreach (var custom in routing.CustomProfiles)
        {
            var fallback = overrides.TryGetValue(custom.Id, out var customFallback) && !string.IsNullOrWhiteSpace(customFallback)
                ? customFallback
                : custom.FallbackResolverId;
            list.Add(custom with { FallbackResolverId = fallback, IsBuiltIn = false });
        }

        return list;
    }

    public DnsRoutingProfile GetActiveProfile()
    {
        var activeId = _settings.Current.Routing.ActiveProfileId;
        var profiles = GetProfiles();
        return profiles.FirstOrDefault(p => string.Equals(p.Id, activeId, StringComparison.OrdinalIgnoreCase)) ?? profiles[0];
    }

    public async Task SetActiveProfileAsync(string profileId, CancellationToken cancellationToken = default)
    {
        var match = GetProfiles().FirstOrDefault(p => string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            return;
        }

        await _settings.UpdateAsync(s => s.Routing.ActiveProfileId = match.Id, cancellationToken).ConfigureAwait(false);
        _logger.LogInformation("Activated routing profile {ProfileName} ({ProfileId})", match.Name, match.Id);
        RaiseRoutingChanged();
    }

    public async Task SetProfileFallbackResolverAsync(string profileId, string resolverId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profileId) || string.IsNullOrWhiteSpace(resolverId))
        {
            return;
        }

        var resolver = ResolveEndpoint(resolverId);
        await _settings.UpdateAsync(s =>
        {
            s.Routing.ProfileFallbackOverrides[profileId] = resolver.Id;
            var idx = s.Routing.CustomProfiles.FindIndex(p => string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Routing.CustomProfiles[idx] = s.Routing.CustomProfiles[idx] with { FallbackResolverId = resolver.Id };
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseRoutingChanged();
    }

    public async Task<(bool Success, DnsRoutingProfile? Profile, string? Error)> AddCustomProfileAsync(
        string name,
        string description,
        string fallbackResolverId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return (false, null, "Profile name is required.");
        }

        var trimmed = name.Trim();
        var id = GenerateSlug("profile", trimmed);
        var existingIds = GetProfiles().Select(p => p.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (existingIds.Contains(id))
        {
            id = $"{id}-{Guid.NewGuid().ToString("N")[..6]}";
        }

        var fallback = ResolveEndpoint(fallbackResolverId);
        var profile = new DnsRoutingProfile
        {
            Id = id,
            Name = trimmed,
            Description = description?.Trim() ?? string.Empty,
            FallbackResolverId = fallback.Id,
            IsBuiltIn = false,
        };

        await _settings.UpdateAsync(s =>
        {
            s.Routing.CustomProfiles.Add(profile);
            s.Routing.ActiveProfileId = profile.Id;
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Added custom routing profile {Name} ({Id})", profile.Name, profile.Id);
        RaiseRoutingChanged();
        return (true, profile, null);
    }

    public async Task<bool> RemoveCustomProfileAsync(string profileId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(profileId))
        {
            return false;
        }

        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            var count = s.Routing.CustomProfiles.RemoveAll(p => string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));
            if (count > 0)
            {
                removed = true;
                s.Routing.ProfileFallbackOverrides.Remove(profileId);
                s.Routing.Rules?.RemoveAll(r => string.Equals(r.ProfileId, profileId, StringComparison.OrdinalIgnoreCase));
                if (string.Equals(s.Routing.ActiveProfileId, profileId, StringComparison.OrdinalIgnoreCase))
                {
                    s.Routing.ActiveProfileId = BuiltInRoutingProfiles.GamingProfileId;
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseRoutingChanged();
        }

        return removed;
    }

    public IReadOnlyList<DnsRoutingRule> GetAllRules() =>
        (_settings.Current.Routing.Rules ?? BuiltInRoutingProfiles.CreateDefaultRules())
        .OrderBy(r => r.Priority)
        .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
        .ToList();

    public IReadOnlyList<DnsRoutingRule> GetRulesForProfile(string profileId) =>
        GetAllRules()
        .Where(r => string.Equals(r.ProfileId, profileId, StringComparison.OrdinalIgnoreCase))
        .OrderBy(r => r.Priority)
        .ThenBy(r => r.MatchKind)
        .ThenByDescending(r => r.Pattern.Length)
        .ToList();

    public async Task<(bool Success, DnsRoutingRule? Rule, string? Error)> AddOrUpdateRuleAsync(
        DnsRoutingRule rule,
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

        var id = string.IsNullOrWhiteSpace(rule.Id)
            ? GenerateSlug("rule", $"{rule.ProfileId}-{rule.Name}-{Guid.NewGuid().ToString("N")[..6]}")
            : rule.Id.Trim();

        var resolver = ResolveEndpoint(rule.ResolverId);
        var normalized = rule with
        {
            Id = id,
            ProfileId = string.IsNullOrWhiteSpace(rule.ProfileId) ? GetActiveProfile().Id : rule.ProfileId.Trim(),
            Name = rule.Name.Trim(),
            Pattern = RoutingMatcher.NormalizeDomain(rule.Pattern),
            ResolverId = resolver.Id,
            Priority = Math.Clamp(rule.Priority, 1, 9999),
        };

        await _settings.UpdateAsync(s =>
        {
            s.Routing.Rules ??= BuiltInRoutingProfiles.CreateDefaultRules().ToList();
            var idx = s.Routing.Rules.FindIndex(r => string.Equals(r.Id, normalized.Id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Routing.Rules[idx] = normalized;
            }
            else
            {
                s.Routing.Rules.Add(normalized);
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseRoutingChanged();
        return (true, normalized, null);
    }

    public async Task<bool> RemoveRuleAsync(string ruleId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return false;
        }

        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            if (s.Routing.Rules is not null)
            {
                removed = s.Routing.Rules.RemoveAll(r => string.Equals(r.Id, ruleId, StringComparison.OrdinalIgnoreCase)) > 0;
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseRoutingChanged();
        }

        return removed;
    }

    public async Task SetRuleEnabledAsync(string ruleId, bool enabled, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return;
        }

        await _settings.UpdateAsync(s =>
        {
            if (s.Routing.Rules is not null)
            {
                var idx = s.Routing.Rules.FindIndex(r => string.Equals(r.Id, ruleId, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    s.Routing.Rules[idx] = s.Routing.Rules[idx] with { IsEnabled = enabled };
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseRoutingChanged();
    }

    public RoutingDecision ResolveForDomain(string domain, string? profileIdOverride = null)
    {
        var normalizedDomain = RoutingMatcher.NormalizeDomain(domain);
        var profile = string.IsNullOrWhiteSpace(profileIdOverride)
            ? GetActiveProfile()
            : GetProfiles().FirstOrDefault(p => string.Equals(p.Id, profileIdOverride, StringComparison.OrdinalIgnoreCase)) ?? GetActiveProfile();

        var rules = GetRulesForProfile(profile.Id);
        foreach (var rule in rules)
        {
            if (!rule.IsEnabled)
            {
                continue;
            }

            if (RoutingMatcher.IsMatch(normalizedDomain, rule.Pattern, rule.MatchKind))
            {
                var targetResolver = ResolveEndpoint(rule.ResolverId);
                if (targetResolver.IsEnabled)
                {
                    return new RoutingDecision
                    {
                        Domain = normalizedDomain,
                        ProfileId = profile.Id,
                        MatchedRuleId = rule.Id,
                        MatchedRuleName = rule.Name,
                        MatchedPattern = rule.Pattern,
                        MatchKind = rule.MatchKind,
                        ResolverId = targetResolver.Id,
                        ResolverName = targetResolver.Name,
                        Protocol = targetResolver.Protocol,
                        IsFallback = false,
                    };
                }
            }
        }

        var fallbackResolver = ResolveEndpoint(profile.FallbackResolverId);
        if (!fallbackResolver.IsEnabled)
        {
            fallbackResolver = ResolveEndpoint(_settings.Current.Dns.ActiveResolverId);
        }

        return new RoutingDecision
        {
            Domain = normalizedDomain,
            ProfileId = profile.Id,
            MatchedRuleId = null,
            MatchedRuleName = null,
            MatchedPattern = null,
            MatchKind = null,
            ResolverId = fallbackResolver.Id,
            ResolverName = fallbackResolver.Name,
            Protocol = fallbackResolver.Protocol,
            IsFallback = true,
        };
    }

    public void RecordRoutingLog(RoutingDecision decision, string queryType, double? latencyMs)
    {
        ArgumentNullException.ThrowIfNull(decision);

        var entry = new RoutingLogEntry
        {
            Timestamp = DateTimeOffset.Now,
            Domain = decision.Domain,
            QueryType = string.IsNullOrWhiteSpace(queryType) ? "A" : queryType,
            MatchedRuleName = decision.IsFallback ? "Fallback" : (decision.MatchedRuleName ?? "Rule"),
            ResolverName = decision.ResolverName,
            Protocol = decision.Protocol,
            LatencyMs = latencyMs.HasValue ? Math.Round(latencyMs.Value, 1) : null,
            IsFallback = decision.IsFallback,
        };

        lock (_logLock)
        {
            _logs.AddFirst(entry);
            while (_logs.Count > MaxLogEntries)
            {
                _logs.RemoveLast();
            }
        }

        LogAdded?.Invoke(this, entry);
    }

    public IReadOnlyList<RoutingLogEntry> GetRecentLogs()
    {
        lock (_logLock)
        {
            return _logs.ToList();
        }
    }

    public void ClearLogs()
    {
        lock (_logLock)
        {
            _logs.Clear();
        }

        RaiseRoutingChanged();
    }

    public IReadOnlyList<LocalDnsRewriteRule> GetLocalRewrites() =>
        (_settings.Current.Routing.LocalRewrites ?? [])
        .OrderBy(r => r.MatchKind)
        .ThenByDescending(r => r.Pattern.Length)
        .ThenBy(r => r.Pattern, StringComparer.OrdinalIgnoreCase)
        .ToList();

    public async Task<(bool Success, LocalDnsRewriteRule? Rule, string? Error)> AddOrUpdateLocalRewriteAsync(
        LocalDnsRewriteRule rule,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var normalized = rule with
        {
            Id = string.IsNullOrWhiteSpace(rule.Id)
                ? GenerateSlug("rewrite", $"{rule.Pattern}-{rule.RecordType}-{Guid.NewGuid().ToString("N")[..6]}")
                : rule.Id.Trim(),
            Pattern = RoutingMatcher.NormalizeDomain(rule.Pattern),
            TargetValue = (rule.TargetValue ?? string.Empty).Trim(),
            TtlSeconds = Math.Clamp(rule.TtlSeconds, 1, 86400),
            Note = (rule.Note ?? string.Empty).Trim(),
        };

        var (valid, validationError) = LocalDnsRewriteValidator.Validate(normalized);
        if (!valid)
        {
            return (false, null, validationError);
        }

        if (normalized.RecordType == LocalDnsRewriteRecordType.CNAME)
        {
            normalized = normalized with { TargetValue = RoutingMatcher.NormalizeDomain(normalized.TargetValue) };
        }

        await _settings.UpdateAsync(s =>
        {
            s.Routing.LocalRewrites ??= [];
            var idx = s.Routing.LocalRewrites.FindIndex(r => string.Equals(r.Id, normalized.Id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Routing.LocalRewrites[idx] = normalized;
            }
            else
            {
                s.Routing.LocalRewrites.Add(normalized);
            }
        }, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Saved local DNS rewrite {Pattern} ({Type} -> {Target}).", normalized.Pattern, normalized.RecordType, normalized.TargetValue);
        RaiseRoutingChanged();
        return (true, normalized, null);
    }

    public async Task<bool> RemoveLocalRewriteAsync(string rewriteId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rewriteId))
        {
            return false;
        }

        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            if (s.Routing.LocalRewrites is not null)
            {
                removed = s.Routing.LocalRewrites.RemoveAll(r => string.Equals(r.Id, rewriteId, StringComparison.OrdinalIgnoreCase)) > 0;
            }
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseRoutingChanged();
        }

        return removed;
    }

    public async Task SetLocalRewriteEnabledAsync(string rewriteId, bool enabled, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rewriteId))
        {
            return;
        }

        await _settings.UpdateAsync(s =>
        {
            if (s.Routing.LocalRewrites is not null)
            {
                var idx = s.Routing.LocalRewrites.FindIndex(r => string.Equals(r.Id, rewriteId, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    s.Routing.LocalRewrites[idx] = s.Routing.LocalRewrites[idx] with { IsEnabled = enabled };
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseRoutingChanged();
    }

    public LocalDnsRewriteRule? FindMatchingRewrite(string domain, string recordType)
    {
        var normalized = RoutingMatcher.NormalizeDomain(domain);
        if (string.IsNullOrEmpty(normalized)
            || !Enum.TryParse<LocalDnsRewriteRecordType>(recordType, ignoreCase: true, out var targetType))
        {
            return null;
        }

        foreach (var rule in GetLocalRewrites())
        {
            if (!rule.IsEnabled || rule.RecordType != targetType)
            {
                continue;
            }

            if (RoutingMatcher.IsMatch(normalized, rule.Pattern, rule.MatchKind))
            {
                return rule;
            }
        }

        return null;
    }

    private DnsResolverEndpoint ResolveEndpoint(string? resolverId) =>
        _resolverLibrary is not null
            ? _resolverLibrary.GetByIdOrDefault(resolverId)
            : BuiltInResolvers.GetByIdOrDefault(resolverId);

    private static string GenerateSlug(string prefix, string text)
    {
        var raw = $"{prefix}-{text}".ToLowerInvariant();
        var chars = raw.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        var slug = string.Join('-', new string(chars).Split('-', StringSplitOptions.RemoveEmptyEntries));
        return string.IsNullOrWhiteSpace(slug) ? $"{prefix}-{Guid.NewGuid().ToString("N")[..8]}" : slug;
    }

    private void RaiseRoutingChanged() => RoutingChanged?.Invoke(this, EventArgs.Empty);
}
