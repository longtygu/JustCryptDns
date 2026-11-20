using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using JustCryptDns.App.Localization;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.App.ViewModels;

public sealed partial class ConnectionMonitorViewModel
{
    private async void OnPollTimerTick(object? sender, EventArgs e)
    {
        if (!_isNavigatedActive || !_isWindowVisible || _disposed)
        {
            return;
        }

        await PollOnceAsync().ConfigureAwait(false);
    }

    private async Task PollOnceAsync()
    {
        if (_pollInFlight || _disposed)
        {
            return;
        }

        _pollInFlight = true;
        try
        {
            _pollCycle++;
            if ((_pollCycle % 2) == 1)
            {
                await _firewall.PullReverseDnsFromServiceIfConnectedAsync().ConfigureAwait(false);
            }

            var verifySigs = VerifyProcessSignatures;
            var checkThreats = EnableThreatIntelligence;
            var (rawList, trustByPath, threatsByIp) = await Task.Run(() =>
            {
                var snapshot = _monitor.CaptureSnapshot();
                var trustMap = new Dictionary<string, ProcessTrustInfo>(StringComparer.OrdinalIgnoreCase);
                var threatMap = new Dictionary<string, ThreatIntelMatch>(StringComparer.OrdinalIgnoreCase);
                ProtectedIpContext? protectedCtx = null;

                foreach (var raw in snapshot)
                {
                    if (verifySigs && !string.IsNullOrWhiteSpace(raw.ExecutablePath) && !trustMap.ContainsKey(raw.ExecutablePath))
                    {
                        trustMap[raw.ExecutablePath] = _trustInspector.Inspect(raw.ExecutablePath, raw.ProcessName);
                    }

                    if (checkThreats && raw.RemoteIp != "*" && !threatMap.ContainsKey(raw.RemoteIp))
                    {
                        protectedCtx ??= GetProtectedIpContext();
                        if (_threatIntel.TryMatch(raw.RemoteIp, protectedCtx, out var threat))
                        {
                            threatMap[raw.RemoteIp] = threat;
                        }
                    }
                }

                return (snapshot, trustMap, threatMap);
            }).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                if (_disposed || !_isNavigatedActive)
                {
                    return;
                }

                ApplySnapshotToUi(rawList, trustByPath, threatsByIp);
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Connection poll iteration failed cleanly.");
        }
        finally
        {
            _pollInFlight = false;
        }
    }

    private void ApplySnapshotToUi(
        IReadOnlyList<RawSocketConnection> rawList,
        Dictionary<string, ProcessTrustInfo> trustByPath,
        Dictionary<string, ThreatIntelMatch> threatsByIp)
    {
        if (IsEditingCell || (ConnectionsView is IEditableCollectionView editable && (editable.IsEditingItem || editable.IsAddingNew)))
        {
            return;
        }

        var now = DateTimeOffset.Now;
        var notes = _settings.Current.Connections.IpNotes;

        var grouped = new Dictionary<string, (RawSocketConnection Sample, int Count)>(rawList.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var raw in rawList)
        {
            var key = BuildRowKey(raw);
            if (grouped.TryGetValue(key, out var existing))
            {
                grouped[key] = (existing.Sample, existing.Count + 1);
            }
            else
            {
                grouped[key] = (raw, 1);
            }
        }

        ConnectionRowViewModel? lastNewVisible = null;
        var newlyAddedAny = false;
        string? autoBlockTarget = null;
        string? autoBlockReason = null;

        foreach (var (key, group) in grouped)
        {
            var raw = group.Sample;
            var socketCount = group.Count;
            var isUdp = raw.Protocol is ConnectionProtocol.Udp4 or ConnectionProtocol.Udp6;
            var isLan = !isUdp && CidrNetwork.IsLanOrLocalString(raw.RemoteIp);
            var status = EvaluateRowStatus(raw.RemoteIp, activeInSnapshot: true);
            var resolvedDomain = ResolveDisplayDomain(raw.RemoteIp);
            var resolvedOrg = ResolveDisplayOrg(raw.RemoteIp, resolvedDomain);
            var isAppBlocked = !string.IsNullOrWhiteSpace(raw.ExecutablePath) && _blockedAppPaths.Contains(raw.ExecutablePath);

            ProcessTrustInfo? trustInfo = null;
            if (!string.IsNullOrWhiteSpace(raw.ExecutablePath) && trustByPath.TryGetValue(raw.ExecutablePath, out var ti))
            {
                trustInfo = ti;
            }
            else if (string.Equals(raw.ProcessName, "System", StringComparison.OrdinalIgnoreCase)
                || string.Equals(raw.ProcessName, "System Idle", StringComparison.OrdinalIgnoreCase))
            {
                trustInfo = new ProcessTrustInfo(raw.ProcessName, ProcessTrustLevel.TrustedSystem, "Microsoft Windows", false, false, null);
            }

            var hasThreat = threatsByIp.TryGetValue(raw.RemoteIp, out var threatMatch);
            var threatLabel = hasThreat && threatMatch is not null ? $"{threatMatch.Source} ({threatMatch.Category})" : null;

            if (hasThreat && threatMatch is not null)
            {
                if (_alertedThreats.Add(raw.RemoteIp))
                {
                    ThreatAlertText = LocalizationManager.Instance.Format(
                        "Conn_Alert_ThreatDetected",
                        raw.ProcessName,
                        raw.RemoteIp,
                        threatMatch.Source,
                        threatMatch.Category);
                }

                if (AutoBlockDetectedThreats
                    && autoBlockTarget is null
                    && status != ConnectionDisplayStatus.BlockedIp
                    && status != ConnectionDisplayStatus.BlockedRange)
                {
                    var eval = IpBlockerGuard.Evaluate(raw.RemoteIp, GetProtectedIpContext());
                    if (eval.IsValid && !eval.IsProtectedViolation && eval.NormalizedNetwork is { } cidr)
                    {
                        autoBlockTarget = cidr.CanonicalText;
                        autoBlockReason = $"{threatMatch.Source}: {threatMatch.Category} ({raw.ProcessName})";
                    }
                }
            }

            if (!isUdp && !isLan)
            {
                if (_baselineCaptured && AlertNewUnknownProcess && !_knownExternalProcesses.Contains(raw.ProcessName))
                {
                    _knownExternalProcesses.Add(raw.ProcessName);
                    var targetLabel = string.IsNullOrEmpty(resolvedDomain)
                        ? $"{raw.RemoteIp}:{raw.RemotePort}"
                        : $"{resolvedDomain} ({raw.RemoteIp}:{raw.RemotePort})";
                    NewProcessAlertText = LocalizationManager.Instance.Format("Conn_Alert_NewProcess", raw.ProcessName, targetLabel);
                }
                else
                {
                    _knownExternalProcesses.Add(raw.ProcessName);
                }
            }

            if (_rowsByKey.TryGetValue(key, out var row))
            {
                var wasClosed = row.Status == ConnectionDisplayStatus.Closed;
                row.LastSeen = now;
                if (!string.Equals(row.ProcessName, raw.ProcessName, StringComparison.Ordinal))
                {
                    row.ProcessName = raw.ProcessName;
                }

                if (!string.IsNullOrWhiteSpace(raw.ExecutablePath)
                    && !string.Equals(row.ExecutablePath, raw.ExecutablePath, StringComparison.Ordinal))
                {
                    row.ExecutablePath = raw.ExecutablePath;
                }

                row.ConnectionCount = wasClosed
                    ? row.ConnectionCount + socketCount
                    : Math.Max(row.ConnectionCount, socketCount);

                if (!string.IsNullOrEmpty(resolvedDomain))
                {
                    row.Domain = resolvedDomain;
                }

                if (!string.IsNullOrEmpty(resolvedOrg))
                {
                    row.Organization = resolvedOrg;
                }

                if (row.Status != status)
                {
                    row.Status = status;
                }

                if (trustInfo is not null)
                {
                    row.TrustLevel = trustInfo.Level;
                    row.Publisher = trustInfo.Publisher;
                    row.RiskReason = trustInfo.RiskReason;
                }

                row.IsThreatMatch = hasThreat;
                row.ThreatLabel = threatLabel;
                row.IsAppBlocked = isAppBlocked;
            }
            else
            {
                var created = new ConnectionRowViewModel(key, (r, text) => PersistNoteForKey(GetNoteStorageKey(r), text))
                {
                    FirstSeen = now,
                    LastSeen = now,
                    ProcessId = raw.ProcessId,
                    ProcessName = raw.ProcessName,
                    ExecutablePath = raw.ExecutablePath,
                    Protocol = raw.Protocol,
                    RemoteIp = raw.RemoteIp,
                    RemotePort = raw.RemotePort,
                    ConnectionCount = socketCount,
                    Domain = resolvedDomain,
                    Organization = resolvedOrg,
                    Status = status,
                    IsLan = isLan,
                    TrustLevel = trustInfo?.Level ?? ProcessTrustLevel.Unknown,
                    Publisher = trustInfo?.Publisher,
                    RiskReason = trustInfo?.RiskReason,
                    IsThreatMatch = hasThreat,
                    ThreatLabel = threatLabel,
                    IsAppBlocked = isAppBlocked,
                };

                var noteKey = GetNoteStorageKey(created);
                if (notes.TryGetValue(noteKey, out var storedNote))
                {
                    created.SetNoteSilent(storedNote);
                }

                _rowsByKey[key] = created;
                Connections.Add(created);
                newlyAddedAny = true;

                if (FilterConnection(created))
                {
                    lastNewVisible = created;
                }
            }

            if (EnableOnlineLookup && !isUdp && !isLan && !_enrichment.TryGetCached(raw.RemoteIp, out _))
            {
                _enrichment.EnqueueLookup(raw.RemoteIp);
            }
        }

        foreach (var (key, row) in _rowsByKey)
        {
            if (!grouped.ContainsKey(key) && row.Status != ConnectionDisplayStatus.Closed)
            {
                row.Status = ConnectionDisplayStatus.Closed;
            }
        }

        _baselineCaptured = true;
        PruneHistoryIfNeeded();
        UpdateSummaryCounts();

        if (autoBlockTarget is not null)
        {
            AddBlockedTarget(autoBlockTarget, autoBlockReason, autoSyncIfRequested: true);
        }

        if (newlyAddedAny && AutoScroll && lastNewVisible is not null && !IsEditingCell)
        {
            AutoScrollRequested?.Invoke(this, lastNewVisible);
        }
    }

    private string ResolveDisplayDomain(string remoteIp)
    {
        if (remoteIp == "*")
        {
            return string.Empty;
        }

        if (_reverseCache.TryResolve(remoteIp, out var cachedDomain))
        {
            return cachedDomain;
        }

        if (_enrichment.TryGetCached(remoteIp, out var info) && !string.IsNullOrWhiteSpace(info.ReverseDns))
        {
            return info.ReverseDns;
        }

        return string.Empty;
    }

    private string ResolveDisplayOrg(string remoteIp, string? domain)
    {
        if (remoteIp == "*")
        {
            return string.Empty;
        }

        // 1. Persisted / online enrichment cache (zero network calls here)
        if (_enrichment.TryGetCached(remoteIp, out var info) && !string.IsNullOrWhiteSpace(info.Organization))
        {
            return !string.IsNullOrWhiteSpace(info.Country)
                ? $"{info.Organization} ({info.Country})"
                : info.Organization;
        }

        // 2. Instant zero-network offline IP CIDR + DNS suffix attribution
        if (OfflineOrganizationDatabase.TryResolve(remoteIp, domain, out var offline))
        {
            return !string.IsNullOrWhiteSpace(offline.CountryCode)
                ? $"{offline.Organization} ({offline.CountryCode})"
                : offline.Organization;
        }

        // 3. Fallback cached rDNS hostname if any
        if (info is not null && !string.IsNullOrWhiteSpace(info.ReverseDns))
        {
            return info.ReverseDns;
        }

        return string.Empty;
    }

    private ConnectionDisplayStatus EvaluateRowStatus(string remoteIp, bool activeInSnapshot)
    {
        if (!activeInSnapshot)
        {
            return ConnectionDisplayStatus.Closed;
        }

        if (remoteIp != "*" && IPAddress.TryParse(remoteIp, out var ip))
        {
            var matchedExact = false;
            var matchedRange = false;
            foreach (var (_, network) in _compiledRules)
            {
                if (!network.Contains(ip))
                {
                    continue;
                }

                if (network.IsSingleHost)
                {
                    matchedExact = true;
                    break;
                }

                matchedRange = true;
            }

            if (matchedExact)
            {
                return ConnectionDisplayStatus.BlockedIp;
            }

            if (matchedRange)
            {
                return ConnectionDisplayStatus.BlockedRange;
            }
        }

        return ConnectionDisplayStatus.Active;
    }

    private void RecomputeAllRowStatuses()
    {
        foreach (var row in Connections)
        {
            if (row.Status != ConnectionDisplayStatus.Closed)
            {
                row.Status = EvaluateRowStatus(row.RemoteIp, activeInSnapshot: true);
            }

            row.IsAppBlocked = !string.IsNullOrWhiteSpace(row.ExecutablePath)
                && _blockedAppPaths.Contains(row.ExecutablePath);
        }

        UpdateSummaryCounts();
    }

    private void UpdateSummaryCounts()
    {
        TotalCount = Connections.Count;
        ActiveCount = Connections.Count(r => r.Status != ConnectionDisplayStatus.Closed);
        BlockedRuleCount = _compiledRules.Count;
        BlockedAppCount = _blockedAppPaths.Count;
    }

    private void RebuildCompiledRules()
    {
        _compiledRules.Clear();
        foreach (var rule in _settings.Current.Connections.BlockedRules)
        {
            if (rule.IsEnabled && CidrNetwork.TryParse(rule.Target, out var network, out _))
            {
                _compiledRules.Add((rule, network));
            }
        }

        _blockedAppPaths.Clear();
        foreach (var appRule in _settings.Current.Connections.BlockedApps)
        {
            if (appRule.IsEnabled && !string.IsNullOrWhiteSpace(appRule.ExecutablePath))
            {
                _blockedAppPaths.Add(appRule.ExecutablePath);
            }
        }

        BlockedRuleCount = _compiledRules.Count;
        BlockedAppCount = _blockedAppPaths.Count;
    }

    private void RefreshManagedCollections()
    {
        ManagedBlockedRules.Clear();
        foreach (var rule in _settings.Current.Connections.BlockedRules.OrderByDescending(r => r.AddedAtUtc))
        {
            ManagedBlockedRules.Add(new BlockedRuleItemViewModel(rule.Target, rule.Note, rule.AddedAtUtc, rule.IsEnabled));
        }

        ManagedBlockedApps.Clear();
        foreach (var appRule in _settings.Current.Connections.BlockedApps.OrderByDescending(a => a.AddedAtUtc))
        {
            ManagedBlockedApps.Add(new BlockedAppItemViewModel(appRule.ExecutablePath, appRule.ProcessName, appRule.Note, appRule.AddedAtUtc, appRule.IsEnabled));
        }

        ManagedNotes.Clear();
        foreach (var (ip, note) in _settings.Current.Connections.IpNotes.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            ManagedNotes.Add(new IpNoteItemViewModel(ip, note));
        }
    }

    private void UpdateThreatFeedSummary()
    {
        ThreatIndicatorCount = _threatIntel.GetStatus().IndicatorCount;
        OnPropertyChanged(nameof(ThreatFeedSummaryText));
    }

    private bool FilterConnection(object obj)
    {
        if (obj is not ConnectionRowViewModel row)
        {
            return false;
        }

        if (HideLanConnections && row.IsLan)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(SearchQuery))
        {
            return true;
        }

        var q = SearchQuery.Trim();
        return row.RemoteIp.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.Domain.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.PortText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.ProtocolLabel.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.Organization.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.TrustBadgeText.Contains(q, StringComparison.OrdinalIgnoreCase)
            || (!string.IsNullOrEmpty(row.ExecutablePath) && row.ExecutablePath.Contains(q, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrEmpty(row.ThreatLabel) && row.ThreatLabel.Contains(q, StringComparison.OrdinalIgnoreCase))
            || row.Note.Contains(q, StringComparison.OrdinalIgnoreCase)
            || row.StatusText.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void RefreshFilterSafe()
    {
        if (IsEditingCell || (ConnectionsView is IEditableCollectionView editable && (editable.IsEditingItem || editable.IsAddingNew)))
        {
            _pendingFilterRefresh = true;
            return;
        }

        ConnectionsView.Refresh();
    }

    private void PruneHistoryIfNeeded()
    {
        if (Connections.Count <= MaxTrackedRows)
        {
            return;
        }

        var overflow = Connections.Count - MaxTrackedRows;
        var victims = Connections
            .OrderBy(r => r.Status == ConnectionDisplayStatus.Closed ? 0 : 1)
            .ThenBy(r => r.LastSeen)
            .Take(overflow)
            .ToList();

        foreach (var row in victims)
        {
            _rowsByKey.Remove(row.Key);
            Connections.Remove(row);
        }
    }

    private ProtectedIpContext GetProtectedIpContext()
    {
        if (_cachedProtectedContext is not null && (DateTimeOffset.UtcNow - _protectedContextBuiltAt).TotalSeconds < 10)
        {
            return _cachedProtectedContext;
        }

        var current = _settings.Current;
        _cachedProtectedContext = ProtectedIpContext.Build(
            _networkInfo.GetSnapshot(),
            _resolverLibrary.GetAll(),
            current.Dns,
            current.Bypass,
            _reverseCache);
        _protectedContextBuiltAt = DateTimeOffset.UtcNow;
        return _cachedProtectedContext;
    }

    private async Task RefreshFirewallStatusAsync()
    {
        try
        {
            var fwStatus = await _firewall.GetStatusAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = fwStatus.IsWindowsFirewallEnabled;
                RequiresElevationHint = fwStatus.RequiresElevation;
                IsLockdownActive = fwStatus.IsLockdownActive;
            }).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not query Windows Firewall status.");
        }
    }

    private void OnEnrichmentReady(object? sender, IpEnrichmentInfo info)
    {
        _ = RunOnUiAsync(() =>
        {
            if (_disposed)
            {
                return;
            }

            foreach (var row in Connections)
            {
                if (!string.Equals(row.RemoteIp, info.Ip, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(row.Domain) && !string.IsNullOrWhiteSpace(info.ReverseDns))
                {
                    row.Domain = info.ReverseDns;
                }

                var updatedOrg = ResolveDisplayOrg(info.Ip, row.Domain);
                if (!string.IsNullOrWhiteSpace(updatedOrg))
                {
                    row.Organization = updatedOrg;
                }
            }
        });
    }
}
