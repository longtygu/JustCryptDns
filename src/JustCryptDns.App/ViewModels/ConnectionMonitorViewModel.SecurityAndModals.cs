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
    [RelayCommand]
    private void BlockSelectedIp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        if (SelectedConnection.RemoteIp == "*" || !IPAddress.TryParse(SelectedConnection.RemoteIp, out _))
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_CannotBlockUdpWildcard"), isError: true);
            return;
        }

        var defaultNote = string.IsNullOrWhiteSpace(SelectedConnection.Domain)
            ? SelectedConnection.ProcessName
            : $"{SelectedConnection.Domain} ({SelectedConnection.ProcessName})";

        var protectedCtx = GetProtectedIpContext();
        var eval = IpBlockerGuard.Evaluate(SelectedConnection.RemoteIp, protectedCtx);
        if (!eval.IsValid || eval.IsProtectedViolation || eval.NormalizedNetwork is not { } cidr)
        {
            var reason = eval.Message ?? "Invalid target.";
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_ProtectedRejected", reason), isError: true);
            return;
        }

        if (eval.RequiresConfirmation)
        {
            CancelModals();
            CustomCidrInput = cidr.CanonicalText;
            CustomCidrNote = string.IsNullOrWhiteSpace(SelectedConnection.Note) ? defaultNote : SelectedConnection.Note;
            PendingRiskWarning = eval.WarningMessage;
            IsRiskConfirmed = false;
            IsBlockCidrModalOpen = true;
            NotifyModalFlagsChanged();
            return;
        }

        var noteToStore = string.IsNullOrWhiteSpace(SelectedConnection.Note) ? defaultNote : SelectedConnection.Note;
        AddBlockedTarget(cidr.CanonicalText, noteToStore);
    }

    [RelayCommand]
    private void UnblockSelectedIp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        var ip = SelectedConnection.RemoteIp;
        if (RemoveExactTarget(ip))
        {
            return;
        }

        if (IPAddress.TryParse(ip, out var parsedAddr))
        {
            var covering = _compiledRules.FirstOrDefault(r => r.Network.Contains(parsedAddr));
            if (covering.Rule is not null)
            {
                SetBanner(LocalizationManager.Instance.Format("Conn_Msg_CoveredByCidr", ip, covering.Rule.Target), isError: true);
                OpenBlockedListModal();
                return;
            }
        }

        SetBanner(LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_NoneFound", ip, ip), isError: false);
    }

    [RelayCommand]
    private void BlockSelectedApp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        var eval = AppBlockerGuard.Evaluate(SelectedConnection.ExecutablePath);
        if (!eval.IsValid || string.IsNullOrWhiteSpace(eval.NormalizedPath))
        {
            SetBanner(eval.ErrorMessage ?? "Cannot block selected process.", isError: true);
            return;
        }

        var exePath = eval.NormalizedPath;
        var procName = string.IsNullOrWhiteSpace(SelectedConnection.ProcessName)
            ? Path.GetFileName(exePath)
            : SelectedConnection.ProcessName;

        var existing = _settings.Current.Connections.BlockedApps.FirstOrDefault(a =>
            string.Equals(a.ExecutablePath, exePath, StringComparison.OrdinalIgnoreCase));
        if (existing is { IsEnabled: true })
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppAlreadyBlocked", procName), isError: false);
            return;
        }

        _settings.UpdateDeferred(s =>
        {
            if (existing is not null)
            {
                var idx = s.Connections.BlockedApps.IndexOf(existing);
                s.Connections.BlockedApps[idx] = existing with { IsEnabled = true };
            }
            else
            {
                s.Connections.BlockedApps.Add(new BlockedAppRule
                {
                    ExecutablePath = exePath,
                    ProcessName = procName,
                    Note = SelectedConnection.Note,
                    AddedAtUtc = DateTimeOffset.UtcNow,
                    IsEnabled = true,
                });
            }

            s.Connections.HasUnsyncedFirewallChanges = true;
        });

        UnsyncedCount++;
        RebuildCompiledRules();
        RefreshManagedCollections();
        RecomputeAllRowStatuses();
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppAdded", procName), isError: false);
    }

    [RelayCommand]
    private void UnblockSelectedApp()
    {
        if (SelectedConnection is null)
        {
            SetBanner(LocalizationManager.Instance.Get("Conn_Msg_NoSelection"), isError: true);
            return;
        }

        if (string.IsNullOrWhiteSpace(SelectedConnection.ExecutablePath))
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppNotBlocked", SelectedConnection.ProcessName), isError: false);
            return;
        }

        if (!RemoveBlockedAppByPath(SelectedConnection.ExecutablePath))
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppNotBlocked", SelectedConnection.ProcessName), isError: false);
        }
    }

    [RelayCommand]
    private void OpenBlockCidrModal()
    {
        CancelModals();
        CustomCidrInput = SelectedConnection is { RemoteIp.Length: > 0 } && SelectedConnection.RemoteIp != "*"
            ? SelectedConnection.RemoteIp
            : string.Empty;
        CustomCidrNote = SelectedConnection?.Domain ?? string.Empty;
        CidrValidationError = null;
        PendingRiskWarning = null;
        IsRiskConfirmed = false;
        IsBlockCidrModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void ConfirmBlockCidr()
    {
        var protectedCtx = GetProtectedIpContext();
        var eval = IpBlockerGuard.Evaluate(CustomCidrInput, protectedCtx);
        if (!eval.IsValid || eval.NormalizedNetwork is not { } cidr)
        {
            CidrValidationError = eval.IsProtectedViolation
                ? LocalizationManager.Instance.Format("Conn_Msg_ProtectedRejected", eval.Message ?? string.Empty)
                : eval.Message;
            PendingRiskWarning = null;
            return;
        }

        if (eval.RequiresConfirmation && !IsRiskConfirmed)
        {
            PendingRiskWarning = eval.WarningMessage;
            CidrValidationError = null;
            return;
        }

        AddBlockedTarget(cidr.CanonicalText, CustomCidrNote);
        CancelModals();
    }

    [RelayCommand]
    private void OpenUnblockWebsiteModal()
    {
        CancelModals();
        UnblockDomainInput = SelectedConnection?.Domain ?? string.Empty;
        UnblockWebsiteStatus = null;
        IsUnblockWebsiteModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private async Task ExecuteUnblockWebsiteAsync()
    {
        var domain = UnblockDomainInput?.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        IsBusy = true;
        try
        {
            var matchedIps = new HashSet<IPAddress>();
            foreach (var cachedIp in _reverseCache.GetIpsForDomain(domain))
            {
                if (IPAddress.TryParse(cachedIp, out var ip))
                {
                    matchedIps.Add(ip);
                }
            }

            var resolved = await _dnsEngine.ResolveHostAsync(domain, includeIpv6: true).ConfigureAwait(false);
            foreach (var ip in resolved)
            {
                matchedIps.Add(ip);
            }

            var ipStrings = matchedIps.Select(ip => ip.ToString()).ToList();
            if (matchedIps.Count == 0)
            {
                await RunOnUiAsync(() =>
                    UnblockWebsiteStatus = LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_NoneFound", domain, "—")).ConfigureAwait(false);
                return;
            }

            var removedCount = 0;
            await _settings.UpdateAsync(s =>
            {
                removedCount = s.Connections.BlockedRules.RemoveAll(rule =>
                    CidrNetwork.TryParse(rule.Target, out var net, out _)
                    && matchedIps.Any(ip => net.Contains(ip)));

                if (removedCount > 0)
                {
                    s.Connections.HasUnsyncedFirewallChanges = true;
                }
            }).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                if (removedCount > 0)
                {
                    UnsyncedCount += removedCount;
                    RebuildCompiledRules();
                    RefreshManagedCollections();
                    RecomputeAllRowStatuses();
                    var msg = LocalizationManager.Instance.Format("Conn_Modal_UnblockWeb_Removed", removedCount, domain);
                    UnblockWebsiteStatus = msg;
                    SetBanner(msg, isError: false);
                }
                else
                {
                    UnblockWebsiteStatus = LocalizationManager.Instance.Format(
                        "Conn_Modal_UnblockWeb_NoneFound",
                        domain,
                        string.Join(", ", ipStrings.Take(6)));
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void OpenBlockedListModal()
    {
        CancelModals();
        RefreshManagedCollections();
        IsBlockedListModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void OpenBlockedAppsModal()
    {
        CancelModals();
        RefreshManagedCollections();
        IsBlockedAppsModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void RemoveBlockedRule(string? target)
    {
        if (!string.IsNullOrWhiteSpace(target))
        {
            _ = RemoveExactTarget(target);
        }
    }

    [RelayCommand]
    private void ToggleBlockedRule(string? target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        var changed = false;
        _settings.UpdateDeferred(s =>
        {
            var index = s.Connections.BlockedRules.FindIndex(r =>
                string.Equals(r.Target, target, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                var current = s.Connections.BlockedRules[index];
                s.Connections.BlockedRules[index] = current with { IsEnabled = !current.IsEnabled };
                s.Connections.HasUnsyncedFirewallChanges = true;
                changed = true;
            }
        });

        if (changed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
        }
    }

    [RelayCommand]
    private void RemoveBlockedApp(string? executablePath)
    {
        if (!string.IsNullOrWhiteSpace(executablePath))
        {
            _ = RemoveBlockedAppByPath(executablePath);
        }
    }

    [RelayCommand]
    private void ToggleBlockedApp(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return;
        }

        var changed = false;
        _settings.UpdateDeferred(s =>
        {
            var index = s.Connections.BlockedApps.FindIndex(a =>
                string.Equals(a.ExecutablePath, executablePath, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                var current = s.Connections.BlockedApps[index];
                s.Connections.BlockedApps[index] = current with { IsEnabled = !current.IsEnabled };
                s.Connections.HasUnsyncedFirewallChanges = true;
                changed = true;
            }
        });

        if (changed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
        }
    }

    [RelayCommand]
    private async Task ClearAllFirewallRulesAsync()
    {
        IsBusy = true;
        try
        {
            var result = await _firewall.ClearAllAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    _settings.UpdateDeferred(s =>
                    {
                        s.Connections.BlockedRules.Clear();
                        s.Connections.BlockedApps.Clear();
                        s.Connections.EnableDnsLeakGuard = false;
                        s.Connections.HasUnsyncedFirewallChanges = false;
                    });
                    _suppressPreferencePersist = true;
                    try
                    {
                        EnableDnsLeakGuard = false;
                    }
                    finally
                    {
                        _suppressPreferencePersist = false;
                    }

                    IsLockdownActive = false;
                    UnsyncedCount = 0;
                    RebuildCompiledRules();
                    RefreshManagedCollections();
                    RecomputeAllRowStatuses();
                    SetBanner(LocalizationManager.Instance.Format("Conn_Msg_ClearedAll", result.RemovedRuleCount), isError: false);
                }
                else
                {
                    SetBanner(result.Message ?? "Failed to clear Windows Firewall rules.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private async Task ToggleEmergencyLockdownAsync()
    {
        var targetState = !IsLockdownActive;
        await ApplySecurityShieldToggleAsync(isLeakToggle: false, desiredState: targetState).ConfigureAwait(false);
    }

    [RelayCommand]
    private async Task UpdateThreatFeedsAsync()
    {
        IsBusy = true;
        try
        {
            var status = await _threatIntel.RefreshFeedsAsync().ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                UpdateThreatFeedSummary();
                if (string.IsNullOrWhiteSpace(status.LastError))
                {
                    SetBanner(
                        LocalizationManager.Instance.Format("Conn_Msg_ThreatFeedsUpdated", status.IndicatorCount, status.IpCount, status.CidrCount),
                        isError: false);
                }
                else
                {
                    SetBanner(
                        LocalizationManager.Instance.Format("Conn_Msg_ThreatFeedsFailed", status.LastError),
                        isError: status.IndicatorCount == 0);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void InspectIpAbuseIpDb()
    {
        if (SelectedConnection is not { RemoteIp.Length: > 0 } row
            || !IPAddress.TryParse(row.RemoteIp, out var ip))
        {
            return;
        }

        OpenExternalUrl($"https://www.abuseipdb.com/check/{Uri.EscapeDataString(ip.ToString())}");
    }

    [RelayCommand]
    private void InspectIpVirusTotal()
    {
        if (SelectedConnection is not { RemoteIp.Length: > 0 } row
            || !IPAddress.TryParse(row.RemoteIp, out var ip))
        {
            return;
        }

        OpenExternalUrl($"https://www.virustotal.com/gui/ip-address/{Uri.EscapeDataString(ip.ToString())}");
    }

    [RelayCommand]
    private void OpenNotesModal()
    {
        CancelModals();
        if (SelectedConnection is not null)
        {
            NoteEditorIp = GetNoteStorageKey(SelectedConnection);
            NoteEditorText = SelectedConnection.Note;
        }
        else
        {
            NoteEditorIp = string.Empty;
            NoteEditorText = string.Empty;
        }

        RefreshManagedCollections();
        IsNotesModalOpen = true;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private void SaveNoteEntry()
    {
        var key = NoteEditorIp?.Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        PersistNoteForKey(key, NoteEditorText);
        NoteEditorIp = string.Empty;
        NoteEditorText = string.Empty;
    }

    [RelayCommand]
    private void DeleteNoteEntry(string? key)
    {
        if (!string.IsNullOrWhiteSpace(key))
        {
            PersistNoteForKey(key, string.Empty);
        }
    }

    [RelayCommand]
    private void CancelModals()
    {
        IsBlockCidrModalOpen = false;
        IsUnblockWebsiteModalOpen = false;
        IsBlockedListModalOpen = false;
        IsBlockedAppsModalOpen = false;
        IsNotesModalOpen = false;
        CidrValidationError = null;
        PendingRiskWarning = null;
        UnblockWebsiteStatus = null;
        IsRiskConfirmed = false;
        NotifyModalFlagsChanged();
    }

    [RelayCommand]
    private async Task SyncBlocklistAsync()
    {
        IsBusy = true;
        try
        {
            var conn = _settings.Current.Connections;
            var payload = new FirewallSyncRequestPayload(
                conn.BlockedRules.ToList(),
                conn.BlockedApps.ToList(),
                EnableDnsLeakGuard,
                IsLockdownActive);

            var result = await _firewall.SyncSecurityAsync(payload).ConfigureAwait(false);

            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    _settings.UpdateDeferred(s => s.Connections.HasUnsyncedFirewallChanges = false);
                    UnsyncedCount = 0;

                    var msg = result.RejectedProtectedCount > 0
                        ? LocalizationManager.Instance.Format("Conn_Msg_SyncedWithRejected", result.AppliedRuleCount, result.RejectedProtectedCount)
                        : LocalizationManager.Instance.Format("Conn_Msg_Synced", result.AppliedRuleCount, result.RemovedRuleCount);
                    SetBanner(msg, isError: false);
                }
                else
                {
                    SetBanner(result.Message ?? "Failed to sync Windows Firewall.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    [RelayCommand]
    private void ExportCsv()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".csv",
            FileName = $"JustCryptDns-Connections-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }

        var rows = ConnectionsView.Cast<ConnectionRowViewModel>().ToList();
        var sb = new StringBuilder();
        sb.AppendLine("FirstSeen,LastSeen,Process,PID,Protocol,RemoteIP,Port,Count,Domain,Status,Organization,Trust,Threat,ExecutablePath,Note");
        foreach (var row in rows)
        {
            sb.Append(CsvEscape(row.FirstSeen.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
              .Append(CsvEscape(row.LastSeen.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append(',')
              .Append(CsvEscape(row.ProcessName)).Append(',')
              .Append(row.ProcessId.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(CsvEscape(row.ProtocolLabel)).Append(',')
              .Append(CsvEscape(row.RemoteIp)).Append(',')
              .Append(row.RemotePort.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(row.ConnectionCount.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(CsvEscape(row.Domain)).Append(',')
              .Append(CsvEscape(row.StatusText)).Append(',')
              .Append(CsvEscape(row.Organization)).Append(',')
              .Append(CsvEscape(row.TrustBadgeText)).Append(',')
              .Append(CsvEscape(row.ThreatLabel)).Append(',')
              .Append(CsvEscape(row.ExecutablePath)).Append(',')
              .AppendLine(CsvEscape(row.Note));
        }

        File.WriteAllText(dialog.FileName, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_Exported", rows.Count, Path.GetFileName(dialog.FileName)), isError: false);
    }

    [RelayCommand]
    private void CopySelectedIp()
    {
        if (SelectedConnection is null || string.IsNullOrWhiteSpace(SelectedConnection.RemoteIp))
        {
            return;
        }

        try
        {
            Clipboard.SetText(SelectedConnection.RemoteIp);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Clipboard copy failed cleanly.");
        }
    }

    [RelayCommand]
    private void RequestEditNote()
    {
        if (SelectedConnection is not null)
        {
            EditNoteRequested?.Invoke(this, SelectedConnection);
        }
    }

    [RelayCommand]
    private void DismissProcessAlert() => NewProcessAlertText = null;

    [RelayCommand]
    private void DismissThreatAlert() => ThreatAlertText = null;

    [RelayCommand]
    private void ClearClosedConnections()
    {
        var closedKeys = Connections
            .Where(r => r.Status == ConnectionDisplayStatus.Closed)
            .Select(r => r.Key)
            .ToList();

        foreach (var key in closedKeys)
        {
            if (_rowsByKey.TryGetValue(key, out var row))
            {
                _rowsByKey.Remove(key);
                Connections.Remove(row);
            }
        }

        UpdateSummaryCounts();
    }

    private async Task ApplySecurityShieldToggleAsync(bool isLeakToggle, bool desiredState)
    {
        IsBusy = true;
        try
        {
            var conn = _settings.Current.Connections;
            var payload = new FirewallSyncRequestPayload(
                conn.BlockedRules.ToList(),
                conn.BlockedApps.ToList(),
                isLeakToggle ? desiredState : EnableDnsLeakGuard,
                isLeakToggle ? IsLockdownActive : desiredState);

            var result = await _firewall.SyncSecurityAsync(payload).ConfigureAwait(false);
            await RunOnUiAsync(() =>
            {
                IsWindowsFirewallEnabled = result.IsWindowsFirewallEnabled;
                RequiresElevationHint = result.RequiresElevation;
                if (result.Success)
                {
                    if (!isLeakToggle)
                    {
                        IsLockdownActive = desiredState;
                        SetBanner(
                            LocalizationManager.Instance.Get(desiredState ? "Conn_Msg_LockdownEnabled" : "Conn_Msg_LockdownDisabled"),
                            isError: false);
                    }
                    else
                    {
                        SetBanner(
                            LocalizationManager.Instance.Get(desiredState ? "Conn_Msg_DnsLeakGuardEnabled" : "Conn_Msg_DnsLeakGuardDisabled"),
                            isError: false);
                    }
                }
                else
                {
                    if (isLeakToggle)
                    {
                        _suppressPreferencePersist = true;
                        try
                        {
                            EnableDnsLeakGuard = !desiredState;
                        }
                        finally
                        {
                            _suppressPreferencePersist = false;
                        }

                        _settings.UpdateDeferred(s => s.Connections.EnableDnsLeakGuard = !desiredState);
                    }

                    SetBanner(result.Message ?? "Failed to update Windows Firewall security policy.", isError: true);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            await RunOnUiAsync(() => IsBusy = false).ConfigureAwait(false);
        }
    }

    private void AddBlockedTarget(string canonicalTarget, string? note, bool autoSyncIfRequested = false)
    {
        var existing = _settings.Current.Connections.BlockedRules.FirstOrDefault(r =>
            string.Equals(r.Target, canonicalTarget, StringComparison.OrdinalIgnoreCase));

        if (existing is { IsEnabled: true })
        {
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleAlreadyBlocked", canonicalTarget), isError: false);
            return;
        }

        var trimmedNote = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        _settings.UpdateDeferred(s =>
        {
            if (existing is not null)
            {
                var idx = s.Connections.BlockedRules.IndexOf(existing);
                s.Connections.BlockedRules[idx] = existing with
                {
                    IsEnabled = true,
                    Note = trimmedNote ?? existing.Note,
                };
            }
            else
            {
                s.Connections.BlockedRules.Add(new BlockedIpRule
                {
                    Target = canonicalTarget,
                    Note = trimmedNote,
                    AddedAtUtc = DateTimeOffset.UtcNow,
                    IsEnabled = true,
                });
            }

            if (!string.IsNullOrWhiteSpace(trimmedNote))
            {
                s.Connections.IpNotes[canonicalTarget] = trimmedNote;
            }

            s.Connections.HasUnsyncedFirewallChanges = true;
        });

        UnsyncedCount++;
        RebuildCompiledRules();
        RefreshManagedCollections();
        RecomputeAllRowStatuses();
        SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleAdded", canonicalTarget), isError: false);

        if (autoSyncIfRequested)
        {
            _ = SyncBlocklistAsync();
        }
    }

    private bool RemoveExactTarget(string target)
    {
        var normalized = CidrNetwork.TryParse(target, out var cidr, out _)
            ? cidr.CanonicalText
            : target.Trim();

        var removed = false;
        _settings.UpdateDeferred(s =>
        {
            removed = s.Connections.BlockedRules.RemoveAll(r =>
                string.Equals(r.Target, normalized, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                s.Connections.HasUnsyncedFirewallChanges = true;
            }
        });

        if (removed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_RuleRemoved", normalized), isError: false);
        }

        return removed;
    }

    private bool RemoveBlockedAppByPath(string executablePath)
    {
        var fullPath = Path.GetFullPath(executablePath.Trim());
        var removed = false;
        _settings.UpdateDeferred(s =>
        {
            removed = s.Connections.BlockedApps.RemoveAll(a =>
                string.Equals(a.ExecutablePath, fullPath, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                s.Connections.HasUnsyncedFirewallChanges = true;
            }
        });

        if (removed)
        {
            UnsyncedCount++;
            RebuildCompiledRules();
            RefreshManagedCollections();
            RecomputeAllRowStatuses();
            SetBanner(LocalizationManager.Instance.Format("Conn_Msg_AppRemoved", Path.GetFileName(fullPath)), isError: false);
        }

        return removed;
    }

    private void PersistNoteForKey(string key, string note)
    {
        var trimmed = string.IsNullOrWhiteSpace(note) ? string.Empty : note.Trim();
        _settings.UpdateDeferred(s =>
        {
            if (string.IsNullOrEmpty(trimmed))
            {
                s.Connections.IpNotes.Remove(key);
            }
            else
            {
                s.Connections.IpNotes[key] = trimmed;
            }
        });

        foreach (var row in Connections)
        {
            if (string.Equals(GetNoteStorageKey(row), key, StringComparison.OrdinalIgnoreCase))
            {
                row.SetNoteSilent(trimmed);
            }
        }

        RefreshManagedCollections();
        if (!IsEditingCell)
        {
            RefreshFilterSafe();
        }
    }
}
