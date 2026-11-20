using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Security;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Windows;

/// <summary>
/// Manages outbound/inbound IP and CIDR block rules via Windows Firewall COM (<c>HNetCfg.FwPolicy2</c>).
/// All rules are tagged with <see cref="IWindowsFirewallManager.RuleGroup"/> so unrelated Windows Firewall rules
/// are never modified or deleted.
/// </summary>
public sealed class WindowsFirewallService : IWindowsFirewallManager, IDisposable
{
    private const int NetFwRuleDirIn = 1;
    private const int NetFwRuleDirOut = 2;
    private const int NetFwActionBlock = 0;
    private const int NetFwIpProtocolAny = 256;
    private const int NetFwProfileAll = int.MaxValue; // 0x7FFFFFFF
    private const int AccessDeniedHResult = unchecked((int)0x80070005);

    private readonly ILogger<WindowsFirewallService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsFirewallService(ILogger<WindowsFirewallService> logger)
    {
        _logger = logger;
    }

    public async Task<FirewallSyncResult> SyncRulesAsync(
        IReadOnlyList<BlockedIpRule> rules,
        ProtectedIpContext protectedContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(protectedContext);

        if (!OperatingSystem.IsWindows())
        {
            return new FirewallSyncResult(false, 0, 0, 0, false, false, "Windows Firewall is only supported on Windows.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => SyncRulesCore(rules, protectedContext, cancellationToken), cancellationToken).ConfigureAwait(false);
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
            return await Task.Run(() => ClearAllManagedRulesCore(cancellationToken), cancellationToken).ConfigureAwait(false);
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

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => GetStatusCore(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private FirewallSyncResult SyncRulesCore(
        IReadOnlyList<BlockedIpRule> rules,
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
            var desired = new Dictionary<string, (CidrNetwork Network, string Description, int Direction)>(StringComparer.OrdinalIgnoreCase);

            foreach (var rule in rules)
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
                var noteSuffix = string.IsNullOrWhiteSpace(rule.Note) ? string.Empty : $" - {rule.Note.Trim()}";
                var desc = $"Managed by JustCryptDns IP Blocker ({cidr.CanonicalText}){noteSuffix}";

                var outName = $"{IWindowsFirewallManager.RuleNamePrefix}Out_{safeKey}";
                var inName = $"{IWindowsFirewallManager.RuleNamePrefix}In_{safeKey}";
                desired[outName] = (cidr, desc, NetFwRuleDirOut);
                desired[inName] = (cidr, desc, NetFwRuleDirIn);
            }

            var existingManaged = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (var ruleObj in (IEnumerable)fwRulesObj)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = InvokeGet(ruleObj.GetType(), ruleObj, "Name") as string;
                    var group = InvokeGet(ruleObj.GetType(), ruleObj, "Grouping") as string;
                    if (IsManagedRule(name, group) && !string.IsNullOrEmpty(name))
                    {
                        var enabled = Convert.ToBoolean(InvokeGet(ruleObj.GetType(), ruleObj, "Enabled") ?? false, CultureInfo.InvariantCulture);
                        existingManaged[name] = enabled;
                    }
                }
                finally
                {
                    ReleaseCom(ruleObj);
                }
            }

            var removed = 0;
            foreach (var (existingName, enabled) in existingManaged)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!desired.ContainsKey(existingName) || !enabled)
                {
                    InvokeMethod(fwRulesType, fwRulesObj, "Remove", existingName);
                    removed++;
                }
            }

            var added = 0;
            foreach (var (desiredName, spec) in desired)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (existingManaged.TryGetValue(desiredName, out var wasEnabled) && wasEnabled)
                {
                    continue;
                }

                object? newRule = null;
                try
                {
                    newRule = Activator.CreateInstance(ruleType)
                        ?? throw new InvalidOperationException("Failed to instantiate HNetCfg.FWRule.");
                    InvokeSet(ruleType, newRule, "Name", desiredName);
                    InvokeSet(ruleType, newRule, "Grouping", IWindowsFirewallManager.RuleGroup);
                    InvokeSet(ruleType, newRule, "Description", spec.Description);
                    InvokeSet(ruleType, newRule, "Direction", spec.Direction);
                    InvokeSet(ruleType, newRule, "Action", NetFwActionBlock);
                    InvokeSet(ruleType, newRule, "Protocol", NetFwIpProtocolAny);
                    InvokeSet(ruleType, newRule, "RemoteAddresses", spec.Network.FirewallRemoteAddress);
                    InvokeSet(ruleType, newRule, "Profiles", NetFwProfileAll);
                    InvokeSet(ruleType, newRule, "InterfaceTypes", "All");
                    InvokeSet(ruleType, newRule, "Enabled", true);

                    InvokeMethod(fwRulesType, fwRulesObj, "Add", newRule);
                    added++;
                }
                finally
                {
                    ReleaseCom(newRule);
                }
            }

            var activeRuleCount = desired.Count;
            _logger.LogInformation(
                "Windows Firewall sync finished: activeRules={ActiveRules}, added={Added}, removed={Removed}, rejected={Rejected}, firewallEnabled={FwEnabled}",
                activeRuleCount, added, removed, rejectedTargets.Count, isFirewallEnabled);

            return new FirewallSyncResult(
                Success: true,
                AppliedRuleCount: activeRuleCount / 2,
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
            return new FirewallSyncResult(
                Success: false,
                AppliedRuleCount: 0,
                RemovedRuleCount: 0,
                RejectedProtectedCount: 0,
                IsWindowsFirewallEnabled: isFirewallEnabled,
                RequiresElevation: false,
                Message: ex.Message);
        }
        finally
        {
            ReleaseCom(fwRulesObj);
            ReleaseCom(policyObj);
        }
    }

    private FirewallSyncResult ClearAllManagedRulesCore(CancellationToken cancellationToken)
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
                    if (IsManagedRule(name, group) && !string.IsNullOrEmpty(name))
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

            _logger.LogInformation("Cleared {Count} JustCryptDns Windows Firewall rules.", toDelete.Count);
            return new FirewallSyncResult(
                Success: true,
                AppliedRuleCount: 0,
                RemovedRuleCount: toDelete.Count,
                RejectedProtectedCount: 0,
                IsWindowsFirewallEnabled: isFirewallEnabled,
                RequiresElevation: false,
                Message: null);
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            _logger.LogWarning(ex, "Access denied clearing JustCryptDns Windows Firewall rules.");
            return new FirewallSyncResult(
                Success: false,
                AppliedRuleCount: 0,
                RemovedRuleCount: 0,
                RejectedProtectedCount: 0,
                IsWindowsFirewallEnabled: isFirewallEnabled,
                RequiresElevation: true,
                Message: "Administrator privileges or a running JustCryptDns Windows Service are required to remove Windows Firewall rules.");
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
            var managedCount = 0;

            foreach (var ruleObj in (IEnumerable)fwRulesObj)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var name = InvokeGet(ruleObj.GetType(), ruleObj, "Name") as string;
                    var group = InvokeGet(ruleObj.GetType(), ruleObj, "Grouping") as string;
                    if (IsManagedRule(name, group) && !string.IsNullOrEmpty(name))
                    {
                        managedCount++;
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

            return new FirewallStatusSnapshot(managedCount, isFirewallEnabled, false, targets.ToList());
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

    private static bool IsManagedRule(string? name, string? grouping) =>
        string.Equals(grouping, IWindowsFirewallManager.RuleGroup, StringComparison.OrdinalIgnoreCase)
        || (name is not null && name.StartsWith(IWindowsFirewallManager.RuleNamePrefix, StringComparison.OrdinalIgnoreCase));

    private static bool ReadIsFirewallEnabled(Type policyType, object policyObj)
    {
        try
        {
            var currentProfiles = Convert.ToInt32(InvokeGet(policyType, policyObj, "CurrentProfileTypes") ?? 0, CultureInfo.InvariantCulture);
            if (currentProfiles == 0)
            {
                currentProfiles = 2 | 4; // Private | Public fallback
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

        return sb.ToString();
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
