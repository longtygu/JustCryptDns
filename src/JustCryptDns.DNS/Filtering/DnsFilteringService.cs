using System.Collections.Concurrent;
using System.Net;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.DNS.Filtering;

public static class HostsFileParser
{
    private static readonly HashSet<string> IgnoredHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-localnet",
        "ip6-mcastprefix",
        "ip6-allnodes",
        "ip6-allrouters",
        "ip6-allhosts",
        "0.0.0.0",
    };

    public static (bool IsValid, HashSet<string> Domains, string? Error) ParseAndValidate(string content)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(content))
        {
            return (false, domains, "Downloaded or imported list is empty.");
        }

        var trimmedStart = content.AsSpan().TrimStart();
        if (trimmedStart.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
            || trimmedStart.StartsWith("<html", StringComparison.OrdinalIgnoreCase))
        {
            return (false, domains, "Content appears to be an HTML document rather than a domain or hosts list.");
        }

        using var reader = new StringReader(content);
        string? rawLine;
        while ((rawLine = reader.ReadLine()) is not null)
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!'))
            {
                continue;
            }

            var commentIdx = line.IndexOf('#');
            if (commentIdx >= 0)
            {
                line = line[..commentIdx].Trim();
                if (line.Length == 0)
                {
                    continue;
                }
            }

            // Adblock ||domain.com^ syntax
            if (line.StartsWith("||", StringComparison.Ordinal) && line.EndsWith('^'))
            {
                var adblockDomain = RoutingMatcher.NormalizeDomain(line[2..^1]);
                if (IsValidBlockDomain(adblockDomain))
                {
                    domains.Add(adblockDomain);
                }

                continue;
            }

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 1)
            {
                var candidate = RoutingMatcher.NormalizeDomain(parts[0]);
                if (IsValidBlockDomain(candidate))
                {
                    domains.Add(candidate);
                }
            }
            else if (parts.Length >= 2 && IPAddress.TryParse(parts[0], out _))
            {
                for (var i = 1; i < parts.Length; i++)
                {
                    var candidate = RoutingMatcher.NormalizeDomain(parts[i]);
                    if (IsValidBlockDomain(candidate))
                    {
                        domains.Add(candidate);
                    }
                }
            }
        }

        if (domains.Count == 0)
        {
            return (false, domains, "No valid domains were found in the list.");
        }

        return (true, domains, null);
    }

    private static bool IsValidBlockDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253 || !domain.Contains('.'))
        {
            return false;
        }

        if (IgnoredHosts.Contains(domain) || EssentialWindowsDomains.IsProtected(domain) || IPAddress.TryParse(domain, out _))
        {
            return false;
        }

        foreach (var ch in domain)
        {
            if (!(char.IsLetterOrDigit(ch) || ch == '-' || ch == '.' || ch == '_'))
            {
                return false;
            }
        }

        return true;
    }
}

public sealed class DnsFilteringService : IDnsFilteringService
{
    public const int MaxLogEntries = 200;

    private static readonly Dictionary<string, DnsBlocklistSource> BuiltInSeedsById =
        BuiltInBlocklists.All.ToDictionary(b => b.Id, StringComparer.OrdinalIgnoreCase);

    private sealed record CompiledFilteringSnapshot(
        FilteringSettings SourceSettings,
        long BlocklistVersion,
        IReadOnlyList<(string Id, string Name, BlocklistCategory Category, HashSet<string> Domains)> EnabledBlocklists);

    private readonly ISettingsService _settings;
    private readonly IAppPaths? _paths;
    private readonly ILogger<DnsFilteringService> _logger;
    private readonly ConcurrentDictionary<string, HashSet<string>> _listDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<FilterLogEntry> _logs = new();
    private readonly object _logLock = new();
    private readonly object _snapshotLock = new();
    private CompiledFilteringSnapshot? _compiledSnapshot;
    private long _blocklistVersion;
    private long _blockedQueries;

    public DnsFilteringService(
        ISettingsService settings,
        ILogger<DnsFilteringService> logger,
        IAppPaths? paths = null)
    {
        _settings = settings;
        _logger = logger;
        _paths = paths;

        InitializeListsInMemory();
    }

    public event EventHandler? FilteringChanged;

    public event EventHandler<FilterLogEntry>? DecisionLogged;

    public bool IsFilteringEnabled => _settings.Current.Filtering.IsFilteringEnabled;

    public long BlockedQueryCount => Interlocked.Read(ref _blockedQueries);

    public int TotalBlockedDomains
    {
        get
        {
            var customCount = _settings.Current.Filtering.CustomBlockedDomains.Count;
            var enabledLists = GetBlocklists().Where(b => b.IsEnabled);
            var listCount = enabledLists.Sum(b => _listDomains.TryGetValue(b.Id, out var set) ? set.Count : b.DomainCount);
            return customCount + listCount;
        }
    }

    public async Task SetFilteringEnabledAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s => s.Filtering.IsFilteringEnabled = enabled, cancellationToken).ConfigureAwait(false);
        RaiseFilteringChanged();
    }

    public IReadOnlyList<DnsBlocklistSource> GetBlocklists()
    {
        var configured = _settings.Current.Filtering.Blocklists ?? BuiltInBlocklists.All.ToList();

        var result = new List<DnsBlocklistSource>(configured.Count);
        foreach (var item in configured)
        {
            var seedList = BuiltInSeedsById.TryGetValue(item.Id, out var seed) ? seed.SeedDomains : [];
            var count = _listDomains.TryGetValue(item.Id, out var loaded) ? loaded.Count : Math.Max(item.DomainCount, seedList.Count);
            result.Add(item with
            {
                SeedDomains = seedList,
                DomainCount = count,
            });
        }

        return result;
    }

    public IReadOnlyList<string> GetCustomBlockedDomains() =>
        _settings.Current.Filtering.CustomBlockedDomains.OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();

    public IReadOnlyList<DnsAllowlistEntry> GetAllowlist()
    {
        var now = DateTimeOffset.UtcNow;
        return _settings.Current.Filtering.Allowlist
            .Where(a => !a.IsExpired(now))
            .OrderBy(a => a.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task SetBlocklistEnabledAsync(string listId, bool enabled, CancellationToken cancellationToken = default)
    {
        await _settings.UpdateAsync(s =>
        {
            s.Filtering.Blocklists ??= BuiltInBlocklists.All.ToList();
            var idx = s.Filtering.Blocklists.FindIndex(b => string.Equals(b.Id, listId, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0)
            {
                s.Filtering.Blocklists[idx] = s.Filtering.Blocklists[idx] with { IsEnabled = enabled };
            }
        }, cancellationToken).ConfigureAwait(false);

        RaiseFilteringChanged();
    }

    public async Task<(bool Success, int DomainCount, string? Error)> UpdateBlocklistAsync(
        string listId,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        var list = GetBlocklists().FirstOrDefault(b => string.Equals(b.Id, listId, StringComparison.OrdinalIgnoreCase));
        if (list is null)
        {
            return (false, 0, "Blocklist not found.");
        }

        var disposeClient = httpClient is null;
        var client = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        try
        {
            var content = await client.GetStringAsync(list.SourceUrl, cancellationToken).ConfigureAwait(false);
            var (valid, domains, error) = HostsFileParser.ParseAndValidate(content);
            if (!valid)
            {
                return (false, 0, error);
            }

            foreach (var seed in list.SeedDomains)
            {
                domains.Add(seed);
            }

            _listDomains[list.Id] = domains;
            Interlocked.Increment(ref _blocklistVersion);
            SaveCachedBlocklistToDisk(list.Id, domains);

            var now = DateTimeOffset.UtcNow;
            await _settings.UpdateAsync(s =>
            {
                s.Filtering.Blocklists ??= BuiltInBlocklists.All.ToList();
                var idx = s.Filtering.Blocklists.FindIndex(b => string.Equals(b.Id, list.Id, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0)
                {
                    s.Filtering.Blocklists[idx] = s.Filtering.Blocklists[idx] with
                    {
                        LastUpdatedAt = now,
                        DomainCount = domains.Count,
                    };
                }
            }, cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Updated blocklist {Name} ({Count} domains)", list.Name, domains.Count);
            RaiseFilteringChanged();
            return (true, domains.Count, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to update blocklist {Name}", list.Name);
            return (false, 0, ex.Message);
        }
        finally
        {
            if (disposeClient)
            {
                client.Dispose();
            }
        }
    }

    public async Task<(int UpdatedLists, int TotalDomains)> UpdateAllEnabledBlocklistsAsync(
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        var enabled = GetBlocklists().Where(b => b.IsEnabled && !string.IsNullOrWhiteSpace(b.SourceUrl)).ToList();
        var updated = 0;
        foreach (var list in enabled)
        {
            var (ok, _, _) = await UpdateBlocklistAsync(list.Id, httpClient, cancellationToken).ConfigureAwait(false);
            if (ok)
            {
                updated++;
            }
        }

        return (updated, TotalBlockedDomains);
    }

    public async Task<(bool Success, int ImportedCount, string? Error)> ImportHostsTextAsync(
        string hostsContent,
        string? listName = null,
        CancellationToken cancellationToken = default)
    {
        var (valid, domains, error) = HostsFileParser.ParseAndValidate(hostsContent);
        if (!valid)
        {
            return (false, 0, error);
        }

        var id = $"custom-hosts-{Guid.NewGuid().ToString("N")[..6]}";
        var name = string.IsNullOrWhiteSpace(listName) ? $"Imported Hosts ({DateTime.Now:yyyy-MM-dd})" : listName.Trim();
        _listDomains[id] = domains;
        Interlocked.Increment(ref _blocklistVersion);
        SaveCachedBlocklistToDisk(id, domains);

        var source = new DnsBlocklistSource
        {
            Id = id,
            Name = name,
            Category = BlocklistCategory.Custom,
            SourceUrl = string.Empty,
            IsEnabled = true,
            IsBuiltIn = false,
            LastUpdatedAt = DateTimeOffset.UtcNow,
            DomainCount = domains.Count,
        };

        await _settings.UpdateAsync(s =>
        {
            s.Filtering.Blocklists ??= BuiltInBlocklists.All.ToList();
            s.Filtering.Blocklists.Add(source);
        }, cancellationToken).ConfigureAwait(false);

        RaiseFilteringChanged();
        return (true, domains.Count, null);
    }

    public async Task<bool> AddCustomBlockedDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var norm = RoutingMatcher.NormalizeDomain(domain);
        if (string.IsNullOrEmpty(norm) || !norm.Contains('.') || EssentialWindowsDomains.IsProtected(norm))
        {
            return false;
        }

        var added = false;
        await _settings.UpdateAsync(s =>
        {
            if (!s.Filtering.CustomBlockedDomains.Contains(norm, StringComparer.OrdinalIgnoreCase))
            {
                s.Filtering.CustomBlockedDomains.Add(norm);
                added = true;
            }
        }, cancellationToken).ConfigureAwait(false);

        if (added)
        {
            RaiseFilteringChanged();
        }

        return added;
    }

    public async Task<bool> RemoveCustomBlockedDomainAsync(string domain, CancellationToken cancellationToken = default)
    {
        var norm = RoutingMatcher.NormalizeDomain(domain);
        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            removed = s.Filtering.CustomBlockedDomains.RemoveAll(d => string.Equals(d, norm, StringComparison.OrdinalIgnoreCase)) > 0;
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseFilteringChanged();
        }

        return removed;
    }

    public async Task<bool> AddAllowlistEntryAsync(
        string domain,
        string note,
        TimeSpan? temporaryDuration = null,
        CancellationToken cancellationToken = default)
    {
        var norm = RoutingMatcher.NormalizeDomain(domain);
        if (string.IsNullOrEmpty(norm) || !norm.Contains('.'))
        {
            return false;
        }

        var entry = new DnsAllowlistEntry
        {
            Domain = norm,
            Note = note?.Trim() ?? string.Empty,
            ExpiresAt = temporaryDuration.HasValue ? DateTimeOffset.UtcNow.Add(temporaryDuration.Value) : null,
        };

        await _settings.UpdateAsync(s =>
        {
            s.Filtering.Allowlist.RemoveAll(a => string.Equals(a.Domain, norm, StringComparison.OrdinalIgnoreCase));
            s.Filtering.Allowlist.Add(entry);
        }, cancellationToken).ConfigureAwait(false);

        RaiseFilteringChanged();
        return true;
    }

    public async Task<bool> RemoveAllowlistEntryAsync(string domain, CancellationToken cancellationToken = default)
    {
        var norm = RoutingMatcher.NormalizeDomain(domain);
        var removed = false;
        await _settings.UpdateAsync(s =>
        {
            removed = s.Filtering.Allowlist.RemoveAll(a => string.Equals(a.Domain, norm, StringComparison.OrdinalIgnoreCase)) > 0;
        }, cancellationToken).ConfigureAwait(false);

        if (removed)
        {
            RaiseFilteringChanged();
        }

        return removed;
    }

    public FilterDecision EvaluateDomain(string domain, bool recordStats = false)
    {
        var norm = RoutingMatcher.NormalizeDomain(domain);
        if (string.IsNullOrEmpty(norm))
        {
            return new FilterDecision
            {
                Domain = string.Empty,
                IsBlocked = false,
                Action = FilterAction.Allowed,
                Reason = "Empty domain.",
            };
        }

        // 1. Essential Windows service protection (always allowed)
        if (EssentialWindowsDomains.IsProtected(norm))
        {
            return FinalizeDecision(new FilterDecision
            {
                Domain = norm,
                IsBlocked = false,
                Action = FilterAction.AllowedByEssentialWindowsGuard,
                MatchedRuleOrListName = "Windows Essential Services Guard",
                Reason = $"'{norm}' is a protected essential Windows service domain and is never blocked.",
            }, recordStats);
        }

        // 2. Allowlist & Temporary Exceptions
        var now = DateTimeOffset.UtcNow;
        foreach (var allow in _settings.Current.Filtering.Allowlist)
        {
            if (allow.IsExpired(now))
            {
                continue;
            }

            if (RoutingMatcher.IsMatch(norm, allow.Domain, RoutingMatchKind.DomainSuffix))
            {
                var action = allow.IsTemporary ? FilterAction.AllowedByTemporaryException : FilterAction.AllowedByUserAllowlist;
                return FinalizeDecision(new FilterDecision
                {
                    Domain = norm,
                    IsBlocked = false,
                    Action = action,
                    MatchedRuleOrListName = allow.IsTemporary ? $"Temporary Exception ({allow.Domain})" : $"Allowlist ({allow.Domain})",
                    Reason = allow.IsTemporary
                        ? $"Allowed by temporary exception for '{allow.Domain}' until {allow.ExpiresAt:HH:mm:ss}."
                        : $"Allowed by user allowlist entry '{allow.Domain}'.",
                }, recordStats);
            }
        }

        if (!IsFilteringEnabled)
        {
            return new FilterDecision
            {
                Domain = norm,
                IsBlocked = false,
                Action = FilterAction.Allowed,
                Reason = "DNS filtering is currently disabled.",
            };
        }

        // 3. Custom blocked domains
        foreach (var blocked in _settings.Current.Filtering.CustomBlockedDomains)
        {
            if (RoutingMatcher.IsMatch(norm, blocked, RoutingMatchKind.DomainSuffix))
            {
                return FinalizeDecision(new FilterDecision
                {
                    Domain = norm,
                    IsBlocked = true,
                    Action = FilterAction.BlockedByCustomRule,
                    MatchedRuleOrListName = $"Custom Block ({blocked})",
                    Category = BlocklistCategory.Custom,
                    Reason = $"Blocked by custom domain rule '{blocked}'.",
                }, recordStats);
            }
        }

        // 4. Enabled blocklists (use cached snapshot to avoid cloning lists on every DNS query)
        var snapshot = GetCompiledSnapshot();
        foreach (var (id, name, category, set) in snapshot.EnabledBlocklists)
        {
            if (MatchesDomainOrParentInSet(norm, set))
            {
                return FinalizeDecision(new FilterDecision
                {
                    Domain = norm,
                    IsBlocked = true,
                    Action = FilterAction.BlockedByBlocklist,
                    MatchedRuleOrListId = id,
                    MatchedRuleOrListName = name,
                    Category = category,
                    Reason = $"Blocked by '{name}' ({category}).",
                }, recordStats);
            }
        }

        return new FilterDecision
        {
            Domain = norm,
            IsBlocked = false,
            Action = FilterAction.Allowed,
            Reason = $"'{norm}' is not on any enabled blocklist.",
        };
    }

    public IReadOnlyList<FilterLogEntry> GetRecentLogs()
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

        RaiseFilteringChanged();
    }

    public void ReloadBlocklistsFromDisk()
    {
        InitializeListsInMemory(forceReloadFromDisk: true);
        Interlocked.Increment(ref _blocklistVersion);
        RaiseFilteringChanged();
    }

    private CompiledFilteringSnapshot GetCompiledSnapshot()
    {
        var cfg = _settings.Current.Filtering;
        var version = Interlocked.Read(ref _blocklistVersion);
        var current = Volatile.Read(ref _compiledSnapshot);
        if (current is not null
            && ReferenceEquals(current.SourceSettings, cfg)
            && current.BlocklistVersion == version)
        {
            return current;
        }

        lock (_snapshotLock)
        {
            current = _compiledSnapshot;
            version = Interlocked.Read(ref _blocklistVersion);
            if (current is not null
                && ReferenceEquals(current.SourceSettings, cfg)
                && current.BlocklistVersion == version)
            {
                return current;
            }

            var configured = cfg.Blocklists ?? BuiltInBlocklists.All.ToList();
            var enabledLists = new List<(string Id, string Name, BlocklistCategory Category, HashSet<string> Domains)>(configured.Count);
            foreach (var item in configured)
            {
                if (item.IsEnabled && _listDomains.TryGetValue(item.Id, out var set))
                {
                    enabledLists.Add((item.Id, item.Name, item.Category, set));
                }
            }

            var rebuilt = new CompiledFilteringSnapshot(cfg, version, enabledLists);
            Volatile.Write(ref _compiledSnapshot, rebuilt);
            return rebuilt;
        }
    }

    private static bool MatchesDomainOrParentInSet(string normalizedDomain, HashSet<string> domainSet)
    {
        var current = normalizedDomain;
        while (true)
        {
            if (domainSet.Contains(current))
            {
                return true;
            }

            var dot = current.IndexOf('.');
            if (dot < 0 || dot == current.Length - 1)
            {
                return false;
            }

            var remainder = current[(dot + 1)..];
            if (!remainder.Contains('.'))
            {
                return false;
            }

            current = remainder;
        }
    }

    private FilterDecision FinalizeDecision(FilterDecision decision, bool recordStats)
    {
        if (recordStats)
        {
            if (decision.IsBlocked)
            {
                Interlocked.Increment(ref _blockedQueries);
            }

            var entry = new FilterLogEntry
            {
                Timestamp = DateTimeOffset.Now,
                Domain = decision.Domain,
                IsBlocked = decision.IsBlocked,
                Action = decision.Action,
                SourceName = decision.MatchedRuleOrListName ?? "Filter",
            };

            lock (_logLock)
            {
                _logs.AddFirst(entry);
                while (_logs.Count > MaxLogEntries)
                {
                    _logs.RemoveLast();
                }
            }

            DecisionLogged?.Invoke(this, entry);
        }

        return decision;
    }

    private void InitializeListsInMemory(bool forceReloadFromDisk = false)
    {
        foreach (var builtIn in BuiltInBlocklists.All)
        {
            var set = new HashSet<string>(builtIn.SeedDomains, StringComparer.OrdinalIgnoreCase);
            LoadCachedBlocklistFromDisk(builtIn.Id, set);
            _listDomains[builtIn.Id] = set;
        }

        var configured = _settings.Current.Filtering.Blocklists;
        if (configured is not null)
        {
            foreach (var item in configured)
            {
                if (forceReloadFromDisk || !_listDomains.TryGetValue(item.Id, out var set))
                {
                    var seeds = BuiltInSeedsById.TryGetValue(item.Id, out var builtIn) ? builtIn.SeedDomains : [];
                    set = new HashSet<string>(seeds, StringComparer.OrdinalIgnoreCase);
                    LoadCachedBlocklistFromDisk(item.Id, set);
                    _listDomains[item.Id] = set;
                }
            }
        }
    }

    private bool TryGetSafeBlocklistFilePath(string listId, out string filePath)
    {
        filePath = string.Empty;
        if (_paths is null || string.IsNullOrWhiteSpace(listId))
        {
            return false;
        }

        var trimmed = Path.GetFileName(listId.Trim());
        if (string.IsNullOrWhiteSpace(trimmed)
            || !trimmed.All(c => char.IsLetterOrDigit(c) || c is '-' or '_'))
        {
            return false;
        }

        var dir = Path.Combine(_paths.DataDirectory, "blocklists");
        filePath = Path.Combine(dir, $"{trimmed}.txt");
        return true;
    }

    private void SaveCachedBlocklistToDisk(string listId, HashSet<string> domains)
    {
        if (!TryGetSafeBlocklistFilePath(listId, out var filePath))
        {
            return;
        }

        try
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllLines(filePath, domains);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not persist blocklist cache for {Id}", listId);
        }
    }

    private void LoadCachedBlocklistFromDisk(string listId, HashSet<string> target)
    {
        if (!TryGetSafeBlocklistFilePath(listId, out var file))
        {
            return;
        }

        try
        {
            if (File.Exists(file))
            {
                foreach (var line in File.ReadLines(file))
                {
                    var norm = RoutingMatcher.NormalizeDomain(line);
                    if (!string.IsNullOrEmpty(norm))
                    {
                        target.Add(norm);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not load cached blocklist {Id}", listId);
        }
    }

    private void RaiseFilteringChanged() => FilteringChanged?.Invoke(this, EventArgs.Empty);
}
