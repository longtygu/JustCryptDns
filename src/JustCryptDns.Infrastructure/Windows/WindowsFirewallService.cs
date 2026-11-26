using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Manages Windows Firewall COM rules (<c>HNetCfg.FwPolicy2</c>) across four strictly isolated groups:
/// <c>JustCryptDns_IPBlock</c>, <c>JustCryptDns_AppBlock</c>, <c>JustCryptDns_DnsLeakGuard</c>, and
/// <c>JustCryptDns_Lockdown</c>. Unrelated Windows Firewall rules are never modified or deleted.
/// </summary>
public sealed class WindowsFirewallService : IWindowsFirewallManager, IDisposable
{
    private const int NetFwRuleDirIn = 1;
    private const int NetFwRuleDirOut = 2;
    private const int NetFwActionBlock = 0;
    private const int NetFwIpProtocolTcp = 6;
    private const int NetFwIpProtocolUdp = 17;
    private const int NetFwIpProtocolAny = 256;
    private const int NetFwProfileAll = int.MaxValue;
    private const int AccessDeniedHResult = unchecked((int)0x80070005);

    private sealed record DesiredRuleSpec(
        string Grouping,
        string Description,
        int Direction,
        int Protocol,
        string? RemoteAddresses,
        string? RemotePorts,
        string? ApplicationName);

    private sealed record ExistingManagedRule(
        string Name,
        string? Grouping,
        string? Description,
        bool Enabled);

    private const int StatusCacheTtlMs = 30_000;

    private readonly ILogger<WindowsFirewallService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private FirewallStatusSnapshot? _cachedStatus;
    private long _cachedStatusTick;

    public WindowsFirewallService(ILogger<WindowsFirewallService> logger)
    {
        _logger = logger;
    }

    public Task<FirewallSyncResult> SyncRulesAsync(
        IReadOnlyList<BlockedIpRule> rules,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(protectedContext);
        return SyncSecurityPoliciesAsync(new FirewallSyncRequestPayload(rules), protectedContext, cancellationToken);
    }

    public async Task<FirewallSyncResult> SyncSecurityPoliciesAsync(
        FirewallSyncRequestPayload payload,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(protectedContext);

        if (!OperatingSystem.IsWindows())
        {
            return new FirewallSyncResult(false, 0, 0, 0, false, false, "Windows Firewall is only supported on Windows.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Volatile.Write(ref _cachedStatus, null);
            return await Task.Run(() => SyncSecurityPoliciesCore(payload, protectedContext, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FirewallSyncResult> ClearLockdownAndLeakGuardAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new FirewallSyncResult(false, 0, 0, 0, false, false, "Windows Firewall is only supported on Windows.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Volatile.Write(ref _cachedStatus, null);
            return await Task.Run(() => ClearMatchingGroupsCore(transientOnly: true, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FirewallSyncResult> ClearAllManagedRulesAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new FirewallSyncResult(false, 0, 0, 0, false, false, "Windows Firewall is only supported on Windows.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Volatile.Write(ref _cachedStatus, null);
            return await Task.Run(() => ClearMatchingGroupsCore(transientOnly: false, cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<FirewallStatusSnapshot> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new FirewallStatusSnapshot(0, false, false, [], "Windows Firewall is only supported on Windows.");
        }

        var cached = Volatile.Read(ref _cachedStatus);
        if (cached is not null && Environment.TickCount64 - Volatile.Read(ref _cachedStatusTick) < StatusCacheTtlMs)
        {
            return cached;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cached = Volatile.Read(ref _cachedStatus);
            if (cached is not null && Environment.TickCount64 - Volatile.Read(ref _cachedStatusTick) < StatusCacheTtlMs)
            {
                return cached;
            }

            var snapshot = await Task.Run(() => GetStatusCore(cancellationToken), cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _cachedStatusTick, Environment.TickCount64);
            Volatile.Write(ref _cachedStatus, snapshot);
            return snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    private FirewallSyncResult SyncSecurityPoliciesCore(
        FirewallSyncRequestPayload payload,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken)
    {
        object? policyObj = null;
        object? fwRulesObj = null;
        var isFirewallEnabled = true;

        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("Windows Firewall COM class HNetCfg.FwPolicy2 is not registered.");
            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule")
                ?? throw new InvalidOperationException("Windows Firewall COM class HNetCfg.FWRule is not registered.");

            policyObj = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException("Failed to instantiate HNetCfg.FwPolicy2.");
            isFirewallEnabled = ReadIsFirewallEnabled(policyType, policyObj);
            fwRulesObj = InvokeGet(policyType, policyObj, "Rules")
                ?? throw new InvalidOperationException("Failed to obtain Windows Firewall rules collection.");
            var fwRulesType = fwRulesObj.GetType();

            var rejectedTargets = new List<string>();
            var desired = new Dictionary<string, DesiredRuleSpec>(StringComparer.OrdinalIgnoreCase);

            // 1. IP & CIDR Rules
            foreach (var rule in payload.Rules)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rule is null || !rule.IsEnabled)
                {
                    continue;
                }

                var eval = IpBlockerGuard.Evaluate(rule.Target, protectedContext);
                if (!eval.IsValid || eval.IsProtectedViolation || eval.NormalizedNetwork is not { } cidr)
                {
                    rejectedTargets.Add(rule.Target);
                    _logger.LogWarning("Rejected unsafe or invalid block target {Target}: {Reason}", rule.Target, eval.Message);
                    continue;
                }

                var safeKey = BuildSafeRuleKey(cidr.CanonicalText);
                var cleanNote = string.IsNullOrWhiteSpace(rule.Note)
                    ? string.Empty
                    : rule.Note.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal).Trim();
                if (cleanNote.Length > 200)
                {
                    cleanNote = cleanNote[..200];
                }

                var noteSuffix = string.IsNullOrWhiteSpace(cleanNote) ? string.Empty : $" - {cleanNote}";
                var desc = $"Managed by JustCryptDns IP Blocker ({cidr.CanonicalText}){noteSuffix}";

                desired[$"{IWindowsFirewallManager.RuleNamePrefix}Out_{safeKey}"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.RuleGroup,
                    desc,
                    NetFwRuleDirOut,
                    NetFwIpProtocolAny,
                    cidr.FirewallRemoteAddress,
                    null,
                    null);

                desired[$"{IWindowsFirewallManager.RuleNamePrefix}In_{safeKey}"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.RuleGroup,
                    desc,
                    NetFwRuleDirIn,
                    NetFwIpProtocolAny,
                    cidr.FirewallRemoteAddress,
                    null,
                    null);
            }

            // 2. Per-App Block Rules (.exe)
            if (payload.BlockedApps is not null)
            {
                foreach (var appRule in payload.BlockedApps)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (appRule is null || !appRule.IsEnabled)
                    {
                        continue;
                    }

                    var eval = AppBlockerGuard.Evaluate(appRule.ExecutablePath);
                    if (!eval.IsValid || eval.IsProtectedSystemApp || string.IsNullOrWhiteSpace(eval.NormalizedPath))
                    {
                        rejectedTargets.Add(appRule.ProcessName);
                        _logger.LogWarning("Rejected unsafe or invalid app block target {Path}: {Reason}", appRule.ExecutablePath, eval.ErrorMessage);
                        continue;
                    }

                    var pathHash = ComputeShortHash(eval.NormalizedPath);
                    var safeName = BuildSafeRuleKey(Path.GetFileNameWithoutExtension(eval.NormalizedPath));
                    var desc = $"Managed by JustCryptDns App Blocker ({eval.NormalizedPath})";

                    desired[$"{IWindowsFirewallManager.AppRuleNamePrefix}Out_{safeName}_{pathHash}"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.AppRuleGroup,
                        desc,
                        NetFwRuleDirOut,
                        NetFwIpProtocolAny,
                        null,
                        null,
                        eval.NormalizedPath);

                    desired[$"{IWindowsFirewallManager.AppRuleNamePrefix}In_{safeName}_{pathHash}"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.AppRuleGroup,
                        desc,
                        NetFwRuleDirIn,
                        NetFwIpProtocolAny,
                        null,
                        null,
                        eval.NormalizedPath);
                }
            }

            // 3. DNS Leak Guard (Outbound Port 53/853 excluding Loopback + Active Encrypted Resolver IPs)
            if (payload.EnableDnsLeakGuard)
            {
                var v4Ranges = IpRangeComplement.BuildDnsLeakBlockRangesV4(payload.AllowedDnsResolverIps);
                var v6Ranges = IpRangeComplement.BuildDnsLeakBlockRangesV6(payload.AllowedDnsResolverIps);
                var sig = ComputeShortHash(v4Ranges + "|" + v6Ranges);
                var leakDesc = $"Managed by JustCryptDns DNS Leak Guard ({sig})";

                if (!string.IsNullOrWhiteSpace(v4Ranges))
                {
                    desired[$"{IWindowsFirewallManager.DnsLeakRuleNamePrefix}Out_Udp53_V4"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.DnsLeakRuleGroup,
                        leakDesc,
                        NetFwRuleDirOut,
                        NetFwIpProtocolUdp,
                        v4Ranges,
                        "53,853",
                        null);

                    desired[$"{IWindowsFirewallManager.DnsLeakRuleNamePrefix}Out_Tcp53_853_V4"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.DnsLeakRuleGroup,
                        leakDesc,
                        NetFwRuleDirOut,
                        NetFwIpProtocolTcp,
                        v4Ranges,
                        "53,853",
                        null);
                }

                if (!string.IsNullOrWhiteSpace(v6Ranges))
                {
                    desired[$"{IWindowsFirewallManager.DnsLeakRuleNamePrefix}Out_Udp53_V6"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.DnsLeakRuleGroup,
                        leakDesc,
                        NetFwRuleDirOut,
                        NetFwIpProtocolUdp,
                        v6Ranges,
                        "53,853",
                        null);

                    desired[$"{IWindowsFirewallManager.DnsLeakRuleNamePrefix}Out_Tcp53_853_V6"] = new DesiredRuleSpec(
                        IWindowsFirewallManager.DnsLeakRuleGroup,
                        leakDesc,
                        NetFwRuleDirOut,
                        NetFwIpProtocolTcp,
                        v6Ranges,
                        "53,853",
                        null);
                }
            }

            // 4. Emergency Lockdown (Kill Switch: blocks all public IPv4/IPv6 while sparing Loopback & LAN)
            if (payload.EnableEmergencyLockdown)
            {
                var lockV4 = IpRangeComplement.BuildLockdownBlockRangesV4();
                var lockV6 = IpRangeComplement.BuildLockdownBlockRangesV6();
                const string lockDesc = "Managed by JustCryptDns Emergency Network Lockdown";

                desired[$"{IWindowsFirewallManager.LockdownRuleNamePrefix}Out_V4"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.LockdownRuleGroup, lockDesc, NetFwRuleDirOut, NetFwIpProtocolAny, lockV4, null, null);
                desired[$"{IWindowsFirewallManager.LockdownRuleNamePrefix}In_V4"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.LockdownRuleGroup, lockDesc, NetFwRuleDirIn, NetFwIpProtocolAny, lockV4, null, null);
                desired[$"{IWindowsFirewallManager.LockdownRuleNamePrefix}Out_V6"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.LockdownRuleGroup, lockDesc, NetFwRuleDirOut, NetFwIpProtocolAny, lockV6, null, null);
                desired[$"{IWindowsFirewallManager.LockdownRuleNamePrefix}In_V6"] = new DesiredRuleSpec(
                    IWindowsFirewallManager.LockdownRuleGroup, lockDesc, NetFwRuleDirIn, NetFwIpProtocolAny, lockV6, null, null);
            }

            var existingManaged = new Dictionary<string, ExistingManagedRule>(StringComparer.OrdinalIgnoreCase);
            foreach (var ruleObj in (IEnumerable)fwRulesObj)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = InvokeGet(ruleObj.GetType(), ruleObj, "Name") as string;
                    var group = InvokeGet(ruleObj.GetType(), ruleObj, "Grouping") as string;
                    if (IsManagedRule(name, group, transientOnly: false) && !string.IsNullOrEmpty(name))
                    {
                        var enabled = Convert.ToBoolean(InvokeGet(ruleObj.GetType(), ruleObj, "Enabled") ?? false, CultureInfo.InvariantCulture);
                        var desc = InvokeGet(ruleObj.GetType(), ruleObj, "Description") as string;
                        existingManaged[name] = new ExistingManagedRule(name, group, desc, enabled);
                    }
                }
                finally
                {
                    ReleaseCom(ruleObj);
                }
            }

            var removed = 0;
            var unchanged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (existingName, existing) in existingManaged)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (desired.TryGetValue(existingName, out var want)
                    && existing.Enabled
                    && string.Equals(existing.Description, want.Description, StringComparison.Ordinal))
                {
                    unchanged.Add(existingName);
                    continue;
                }

                InvokeMethod(fwRulesType, fwRulesObj, "Remove", existingName);
                removed++;
            }

            var added = 0;
            foreach (var (desiredName, spec) in desired)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (unchanged.Contains(desiredName))
                {
                    continue;
                }

                object? newRule = null;
                try
                {
                    newRule = Activator.CreateInstance(ruleType)
                        ?? throw new InvalidOperationException("Failed to instantiate HNetCfg.FWRule.");
                    InvokeSet(ruleType, newRule, "Name", desiredName);
                    InvokeSet(ruleType, newRule, "Grouping", spec.Grouping);
                    InvokeSet(ruleType, newRule, "Description", spec.Description);
                    InvokeSet(ruleType, newRule, "Direction", spec.Direction);
                    InvokeSet(ruleType, newRule, "Action", NetFwActionBlock);
                    InvokeSet(ruleType, newRule, "Protocol", spec.Protocol);

                    if (!string.IsNullOrWhiteSpace(spec.RemotePorts))
                    {
                        InvokeSet(ruleType, newRule, "RemotePorts", spec.RemotePorts);
                    }

                    if (!string.IsNullOrWhiteSpace(spec.RemoteAddresses))
                    {
                        InvokeSet(ruleType, newRule, "RemoteAddresses", spec.RemoteAddresses);
                    }

                    if (!string.IsNullOrWhiteSpace(spec.ApplicationName))
                    {
                        InvokeSet(ruleType, newRule, "ApplicationName", spec.ApplicationName);
                    }

                    InvokeSet(ruleType, newRule, "Profiles", NetFwProfileAll);
                    InvokeSet(ruleType, newRule, "InterfaceTypes", "All");
                    InvokeSet(ruleType, newRule, "Enabled", true);

                    InvokeMethod(fwRulesType, fwRulesObj, "Add", newRule);
                    added++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "Failed to add Windows Firewall rule {RuleName}; continuing remaining rules.", desiredName);
                }
                finally
                {
                    ReleaseCom(newRule);
                }
            }

            var ipOrAppRuleCount = desired.Values.Count(v =>
                string.Equals(v.Grouping, IWindowsFirewallManager.RuleGroup, StringComparison.OrdinalIgnoreCase)
                || string.Equals(v.Grouping, IWindowsFirewallManager.AppRuleGroup, StringComparison.OrdinalIgnoreCase)) / 2;

            _logger.LogInformation(
                "Windows Firewall security sync: appliedPairs={Pairs}, leakGuard={Leak}, lockdown={Lockdown}, added={Added}, removed={Removed}, rejected={Rejected}",
                ipOrAppRuleCount, payload.EnableDnsLeakGuard, payload.EnableEmergencyLockdown, added, removed, rejectedTargets.Count);

            return new FirewallSyncResult(
                Success: true,
                AppliedRuleCount: ipOrAppRuleCount,
                RemovedRuleCount: removed,
                RejectedProtectedCount: rejectedTargets.Count,
                IsWindowsFirewallEnabled: isFirewallEnabled,
                RequiresElevation: false,
                Message: null,
                RejectedTargets: rejectedTargets.Count > 0 ? rejectedTargets : null);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            _logger.LogWarning(ex, "Windows Firewall modification requires Administrator privileges or the JustCryptDns background service.");
            return new FirewallSyncResult(
                Success: false,
                AppliedRuleCount: 0,
                RemovedRuleCount: 0,
                RejectedProtectedCount: 0,
                IsWindowsFirewallEnabled: isFirewallEnabled,
                RequiresElevation: true,
                Message: "Administrator privileges or a running JustCryptDns Windows Service are required to modify Windows Firewall rules.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Windows Firewall sync failed.");
            return new FirewallSyncResult(false, 0, 0, 0, isFirewallEnabled, false, ex.Message);
        }
        finally
        {
            ReleaseCom(fwRulesObj);
            ReleaseCom(policyObj);
        }
    }

    private FirewallSyncResult ClearMatchingGroupsCore(bool transientOnly, CancellationToken cancellationToken)
    {
        object? policyObj = null;
        object? fwRulesObj = null;
        var isFirewallEnabled = true;

        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("Windows Firewall COM class HNetCfg.FwPolicy2 is not registered.");
            policyObj = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException("Failed to instantiate HNetCfg.FwPolicy2.");
            isFirewallEnabled = ReadIsFirewallEnabled(policyType, policyObj);
            fwRulesObj = InvokeGet(policyType, policyObj, "Rules")
                ?? throw new InvalidOperationException("Failed to obtain Windows Firewall rules collection.");
            var fwRulesType = fwRulesObj.GetType();

            var toDelete = new List<string>();
            foreach (var ruleObj in (IEnumerable)fwRulesObj)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = InvokeGet(ruleObj.GetType(), ruleObj, "Name") as string;
                    var group = InvokeGet(ruleObj.GetType(), ruleObj, "Grouping") as string;
                    if (IsManagedRule(name, group, transientOnly) && !string.IsNullOrEmpty(name))
                    {
                        toDelete.Add(name);
                    }
                }
                finally
                {
                    ReleaseCom(ruleObj);
                }
            }

            foreach (var name in toDelete)
            {
                cancellationToken.ThrowIfCancellationRequested();
                InvokeMethod(fwRulesType, fwRulesObj, "Remove", name);
            }

            _logger.LogInformation("Cleared {Count} JustCryptDns firewall rules (transientOnly={TransientOnly}).", toDelete.Count, transientOnly);
            return new FirewallSyncResult(true, 0, toDelete.Count, 0, isFirewallEnabled, false, null);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            return new FirewallSyncResult(
                false, 0, 0, 0, isFirewallEnabled, true,
                "Administrator privileges or a running JustCryptDns Windows Service are required to remove Windows Firewall rules.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed clearing Windows Firewall rules.");
            return new FirewallSyncResult(false, 0, 0, 0, isFirewallEnabled, false, ex.Message);
        }
        finally
        {
            ReleaseCom(fwRulesObj);
            ReleaseCom(policyObj);
        }
    }

    private FirewallStatusSnapshot GetStatusCore(CancellationToken cancellationToken)
    {
        object? policyObj = null;
        object? fwRulesObj = null;

        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
                ?? throw new InvalidOperationException("Windows Firewall COM class HNetCfg.FwPolicy2 is not registered.");
            policyObj = Activator.CreateInstance(policyType)
                ?? throw new InvalidOperationException("Failed to instantiate HNetCfg.FwPolicy2.");
            var isFirewallEnabled = ReadIsFirewallEnabled(policyType, policyObj);
            fwRulesObj = InvokeGet(policyType, policyObj, "Rules")
                ?? throw new InvalidOperationException("Failed to obtain Windows Firewall rules collection.");

            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ipCount = 0;
            var appCount = 0;
            var leakGuard = false;
            var lockdown = false;

            foreach (var ruleObj in (IEnumerable)fwRulesObj)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = InvokeGet(ruleObj.GetType(), ruleObj, "Name") as string;
                    var group = InvokeGet(ruleObj.GetType(), ruleObj, "Grouping") as string;
                    if (!IsManagedRule(name, group, transientOnly: false) || string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    if (IsGroupMatch(name, group, IWindowsFirewallManager.DnsLeakRuleGroup, IWindowsFirewallManager.DnsLeakRuleNamePrefix))
                    {
                        leakGuard = true;
                    }
                    else if (IsGroupMatch(name, group, IWindowsFirewallManager.LockdownRuleGroup, IWindowsFirewallManager.LockdownRuleNamePrefix))
                    {
                        lockdown = true;
                    }
                    else if (IsGroupMatch(name, group, IWindowsFirewallManager.AppRuleGroup, IWindowsFirewallManager.AppRuleNamePrefix))
                    {
                        appCount++;
                    }
                    else
                    {
                        ipCount++;
                        var remote = InvokeGet(ruleObj.GetType(), ruleObj, "RemoteAddresses") as string;
                        if (!string.IsNullOrWhiteSpace(remote))
                        {
                            targets.Add(remote);
                        }
                    }
                }
                finally
                {
                    ReleaseCom(ruleObj);
                }
            }

            return new FirewallStatusSnapshot(ipCount, isFirewallEnabled, false, targets.ToList(), null, leakGuard, lockdown, appCount);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            return new FirewallStatusSnapshot(0, true, true, [], ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed reading Windows Firewall status.");
            return new FirewallStatusSnapshot(0, true, false, [], ex.Message);
        }
        finally
        {
            ReleaseCom(fwRulesObj);
            ReleaseCom(policyObj);
        }
    }

    private static bool IsGroupMatch(string? name, string? grouping, string expectedGroup, string expectedPrefix) =>
        string.Equals(grouping, expectedGroup, StringComparison.OrdinalIgnoreCase)
        || (name is not null && name.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase));

    private static bool IsManagedRule(string? name, string? grouping, bool transientOnly)
    {
        if (IsGroupMatch(name, grouping, IWindowsFirewallManager.DnsLeakRuleGroup, IWindowsFirewallManager.DnsLeakRuleNamePrefix)
            || IsGroupMatch(name, grouping, IWindowsFirewallManager.LockdownRuleGroup, IWindowsFirewallManager.LockdownRuleNamePrefix))
        {
            return true;
        }

        if (transientOnly)
        {
            return false;
        }

        return IsGroupMatch(name, grouping, IWindowsFirewallManager.RuleGroup, IWindowsFirewallManager.RuleNamePrefix)
            || IsGroupMatch(name, grouping, IWindowsFirewallManager.AppRuleGroup, IWindowsFirewallManager.AppRuleNamePrefix);
    }

    private static bool ReadIsFirewallEnabled(Type policyType, object policyObj)
    {
        try
        {
            var currentProfiles = Convert.ToInt32(InvokeGet(policyType, policyObj, "CurrentProfileTypes") ?? 0, CultureInfo.InvariantCulture);
            if (currentProfiles == 0)
            {
                currentProfiles = 2 | 4;
            }

            foreach (var bit in new[] { 1, 2, 4 })
            {
                if ((currentProfiles & bit) != 0)
                {
                    var raw = policyType.InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, policyObj, [bit], CultureInfo.InvariantCulture);
                    if (Convert.ToBoolean(raw ?? false, CultureInfo.InvariantCulture))
                    {
                        return true;
                    }
                }
            }

            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static string BuildSafeRuleKey(string canonicalTarget)
    {
        var sb = new StringBuilder(canonicalTarget.Length);
        foreach (var ch in canonicalTarget)
        {
            sb.Append(char.IsLetterOrDigit(ch) || ch == '-' ? ch : '_');
        }

        return sb.Length > 48 ? sb.ToString()[..48] : sb.ToString();
    }

    private static string ComputeShortHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.ToUpperInvariant()));
        return Convert.ToHexString(bytes.AsSpan(0, 6));
    }

    private static object? InvokeGet(Type type, object instance, string propertyName) =>
        type.InvokeMember(propertyName, BindingFlags.GetProperty, null, instance, null, CultureInfo.InvariantCulture);

    private static void InvokeSet(Type type, object instance, string propertyName, object value) =>
        type.InvokeMember(propertyName, BindingFlags.SetProperty, null, instance, [value], CultureInfo.InvariantCulture);

    private static void InvokeMethod(Type type, object instance, string methodName, params object[] args) =>
        type.InvokeMember(methodName, BindingFlags.InvokeMethod, null, instance, args, CultureInfo.InvariantCulture);

    private static bool IsAccessDenied(Exception ex) =>
        ex is UnauthorizedAccessException
        || (ex is COMException comEx && comEx.ErrorCode == AccessDeniedHResult)
        || (ex is TargetInvocationException tie && tie.InnerException is not null && IsAccessDenied(tie.InnerException));

    private static void ReleaseCom(object? obj)
    {
        if (obj is not null && Marshal.IsComObject(obj))
        {
            try
            {
                _ = Marshal.FinalReleaseComObject(obj);
            }
            catch (Exception)
            {
                // Ignore COM release races on shutdown.
            }
        }
    }

    public void Dispose() => _gate.Dispose();
}
