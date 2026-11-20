using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

public sealed record AdapterDnsTarget(
    string AdapterName,
    bool ApplyIpv4,
    bool IsIpv4Dhcp,
    IReadOnlyList<string> Ipv4Servers,
    bool ApplyIpv6,
    bool IsIpv6Dhcp,
    IReadOnlyList<string> Ipv6Servers,
    bool IgnoreIpv6Errors = false);

/// <summary>
/// Abstraction over the OS-level adapter DNS setter so the 6-step safety workflow (Part 14)
/// can be unit-tested offline without requiring Administrator privileges.
/// </summary>
public interface IAdapterDnsConfigurator
{
    (bool IsIpv4Dhcp, IReadOnlyList<string> StaticIpv4, bool IsIpv6Dhcp, IReadOnlyList<string> StaticIpv6) ReadStaticConfiguration(NetworkAdapterInfo adapter);

    Task<(bool Success, string? Error)> SetDnsAsync(
        string adapterName,
        bool ipv6,
        bool useDhcp,
        IReadOnlyList<string> servers,
        CancellationToken cancellationToken = default);

    void FlushResolverCache()
    {
    }

    async Task<(bool Success, string? Error)> ApplyBatchAsync(
        IReadOnlyList<AdapterDnsTarget> targets,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        string? firstError = null;
        foreach (var target in targets)
        {
            if (target.ApplyIpv4)
            {
                var v4 = await SetDnsAsync(target.AdapterName, ipv6: false, target.IsIpv4Dhcp, target.Ipv4Servers, cancellationToken).ConfigureAwait(false);
                if (!v4.Success)
                {
                    firstError ??= v4.Error;
                }
            }

            if (target.ApplyIpv6)
            {
                var v6 = await SetDnsAsync(target.AdapterName, ipv6: true, target.IsIpv6Dhcp, target.Ipv6Servers, cancellationToken).ConfigureAwait(false);
                if (!v6.Success && !target.IgnoreIpv6Errors)
                {
                    firstError ??= v6.Error;
                }
            }
        }

        return (firstError is null, firstError);
    }
}

public sealed partial class NetshAdapterDnsConfigurator : IAdapterDnsConfigurator
{
    public (bool IsIpv4Dhcp, IReadOnlyList<string> StaticIpv4, bool IsIpv6Dhcp, IReadOnlyList<string> StaticIpv6) ReadStaticConfiguration(NetworkAdapterInfo adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var v4Static = ReadRegistryNameServer(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" + adapter.Id);
        var v6Static = ReadRegistryNameServer(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\" + adapter.Id);

        var v4Servers = v4Static.Count > 0
            ? v4Static
            : adapter.DnsServers.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Select(a => a.ToString()).ToList();
        var v6Servers = v6Static.Count > 0
            ? v6Static
            : adapter.DnsServers.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6).Select(a => a.ToString()).ToList();

        return (IsIpv4Dhcp: v4Static.Count == 0, v4Servers, IsIpv6Dhcp: v6Static.Count == 0, v6Servers);
    }

    internal const string UacCancelledMessage = "Administrator permission prompt (UAC) was cancelled.";

    public async Task<(bool Success, string? Error)> SetDnsAsync(
        string adapterName,
        bool ipv6,
        bool useDhcp,
        IReadOnlyList<string> servers,
        CancellationToken cancellationToken = default)
    {
        var commands = new List<string>();
        AppendNetshCommands(commands, adapterName, ipv6, useDhcp, servers);
        return await ExecuteCommandListAsync(commands, cancellationToken).ConfigureAwait(false);
    }

    public async Task<(bool Success, string? Error)> ApplyBatchAsync(
        IReadOnlyList<AdapterDnsTarget> targets,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var commands = new List<string>();
        foreach (var target in targets)
        {
            if (target.ApplyIpv4)
            {
                AppendNetshCommands(commands, target.AdapterName, ipv6: false, target.IsIpv4Dhcp, target.Ipv4Servers);
            }

            if (target.ApplyIpv6)
            {
                AppendNetshCommands(commands, target.AdapterName, ipv6: true, target.IsIpv6Dhcp, target.Ipv6Servers);
            }
        }

        if (commands.Count == 0)
        {
            return (true, null);
        }

        var batchResult = await ExecuteCommandListAsync(commands, cancellationToken).ConfigureAwait(false);
        if (batchResult.Success)
        {
            return (true, null);
        }

        if (string.Equals(batchResult.Error, UacCancelledMessage, StringComparison.Ordinal))
        {
            return batchResult;
        }

        // Fallback to per-family calls only when optional IPv6 commands may have failed on a disabled IPv6 stack.
        if (!targets.Any(t => t.ApplyIpv6 && t.IgnoreIpv6Errors))
        {
            return batchResult;
        }

        string? firstError = null;
        foreach (var target in targets)
        {
            if (target.ApplyIpv4)
            {
                var v4 = await SetDnsAsync(target.AdapterName, ipv6: false, target.IsIpv4Dhcp, target.Ipv4Servers, cancellationToken).ConfigureAwait(false);
                if (!v4.Success)
                {
                    firstError ??= v4.Error;
                }
            }

            if (target.ApplyIpv6)
            {
                var v6 = await SetDnsAsync(target.AdapterName, ipv6: true, target.IsIpv6Dhcp, target.Ipv6Servers, cancellationToken).ConfigureAwait(false);
                if (!v6.Success && !target.IgnoreIpv6Errors)
                {
                    firstError ??= v6.Error;
                }
            }
        }

        return (firstError is null, firstError);
    }

    public void FlushResolverCache()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            _ = DnsFlushResolverCache();
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
        }
    }

    [LibraryImport("dnsapi.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DnsFlushResolverCache();

    private static void AppendNetshCommands(
        List<string> commands,
        string adapterName,
        bool ipv6,
        bool useDhcp,
        IReadOnlyList<string> servers)
    {
        var family = ipv6 ? "ipv6" : "ipv4";
        var safeName = adapterName.Replace("\"", string.Empty, StringComparison.Ordinal);

        if (useDhcp || servers.Count == 0)
        {
            commands.Add($"interface {family} set dnsservers name=\"{safeName}\" source=dhcp");
            return;
        }

        commands.Add($"interface {family} set dnsservers name=\"{safeName}\" static {servers[0]} primary validate=no");
        for (var i = 1; i < servers.Count; i++)
        {
            commands.Add($"interface {family} add dnsservers name=\"{safeName}\" {servers[i]} index={i + 1} validate=no");
        }
    }

    private static async Task<(bool Success, string? Error)> ExecuteCommandListAsync(
        List<string> commands,
        CancellationToken ct)
    {
        if (commands.Count == 0)
        {
            return (true, null);
        }

        if (commands.Count == 1)
        {
            return await RunNetshAsync(commands[0], ct).ConfigureAwait(false);
        }

        var scriptPath = Path.Combine(Path.GetTempPath(), $"jcdns-netsh-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllLinesAsync(scriptPath, commands, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), ct)
                .ConfigureAwait(false);
            return await RunNetshAsync($"-f \"{scriptPath}\"", ct).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                if (File.Exists(scriptPath))
                {
                    File.Delete(scriptPath);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }
    }

    private static List<string> ReadRegistryNameServer(string subKeyPath)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            var raw = key?.GetValue("NameServer") as string;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return [];
            }

            return raw.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        }
        catch (Exception)
        {
            return [];
        }
    }

    private static bool IsProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<(bool Success, string? Error)> RunNetshAsync(string arguments, CancellationToken ct)
    {
        try
        {
            if (!IsProcessElevated() && OperatingSystem.IsWindows())
            {
                var elevatedPsi = new ProcessStartInfo("netsh.exe", arguments)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                using var elevatedProc = Process.Start(elevatedPsi);
                if (elevatedProc is null)
                {
                    return (false, "Failed to launch elevated netsh.exe.");
                }

                await elevatedProc.WaitForExitAsync(ct).ConfigureAwait(false);
                return elevatedProc.ExitCode == 0
                    ? (true, null)
                    : (false, $"Elevated netsh exited with code {elevatedProc.ExitCode}.");
            }

            var psi = new ProcessStartInfo("netsh.exe", arguments)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return (false, "Failed to launch netsh.exe.");
            }

            var stdout = await proc.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            var stderr = await proc.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);

            if (proc.ExitCode == 0)
            {
                return (true, null);
            }

            var detail = !string.IsNullOrWhiteSpace(stderr) ? stderr.Trim() : stdout.Trim();
            return (false, string.IsNullOrWhiteSpace(detail)
                ? $"netsh exited with code {proc.ExitCode} (Administrator privileges may be required)."
                : detail);
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            return (false, UacCancelledMessage);
        }
        catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or OperationCanceledException)
        {
            return (false, ex.Message);
        }
    }
}

/// <summary>
/// Implements the 6-step Windows Network Safety workflow (Part 14):
/// 1. Detect current adapters
/// 2. Back up existing DNS configuration
/// 3. Verify backup SHA-256 integrity on disk
/// 4. Apply requested DNS configuration
/// 5. Verify DNS connectivity
/// 6. Roll back automatically if step 4 or 5 fails.
/// </summary>
public sealed class WindowsNetworkDnsService : IWindowsDnsManager, IDisposable
{
    private readonly IAppPaths _paths;
    private readonly INetworkInfoService _networkInfo;
    private readonly IAdapterDnsConfigurator _configurator;
    private readonly ILogger<WindowsNetworkDnsService> _logger;
    private readonly IBootRecoveryRegistrar? _bootRecovery;
    private readonly Func<IPAddress, bool> _loopbackDnsAliveProbe;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsNetworkDnsService(
        IAppPaths paths,
        INetworkInfoService networkInfo,
        ILogger<WindowsNetworkDnsService> logger,
        IAdapterDnsConfigurator? configurator = null,
        IBootRecoveryRegistrar? bootRecovery = null,
        Func<IPAddress, bool>? loopbackDnsAliveProbe = null)
    {
        _paths = paths;
        _networkInfo = networkInfo;
        _logger = logger;
        _configurator = configurator ?? new NetshAdapterDnsConfigurator();
        _bootRecovery = bootRecovery;
        _loopbackDnsAliveProbe = loopbackDnsAliveProbe ?? DefaultProbeLoopbackDnsAlive;
    }

    public bool HasActiveBackup()
    {
        var doc = ReadBackup();
        return doc is { IsActive: true } && doc.VerifyIntegrity();
    }

    public AdapterDnsBackupDocument? ReadBackup()
    {
        if (!File.Exists(_paths.DnsBackupFile))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(_paths.DnsBackupFile, Encoding.UTF8);
            var doc = JsonSerializer.Deserialize<AdapterDnsBackupDocument>(json, SettingsJson.Options);
            return doc is not null && doc.VerifyIntegrity() ? doc : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Could not read DNS backup file.");
            return null;
        }
    }

    public async Task<WindowsDnsOperationResult> ApplyLocalProxyDnsAsync(
        string? targetAdapterId,
        string ipv4Dns,
        string? ipv6Dns,
        Func<CancellationToken, Task<bool>> connectivityProbe,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipv4Dns);
        ArgumentNullException.ThrowIfNull(connectivityProbe);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Step 1: Detect current network adapters.
            var snapshot = _networkInfo.GetSnapshot();
            var adapter = SelectTargetAdapter(snapshot, targetAdapterId);
            if (adapter is null)
            {
                return new WindowsDnsOperationResult(false, "No active network adapter found to configure.");
            }

            // Step 2: Back up existing DNS configuration (preserve existing active backup if one is already active).
            var existingBackup = ReadBackup();
            var hadExistingActiveBackup = existingBackup is { IsActive: true } && existingBackup.VerifyIntegrity();
            AdapterDnsBackupDocument backup;
            if (hadExistingActiveBackup)
            {
                backup = existingBackup!;
            }
            else
            {
                var (rawV4Dhcp, rawV4Servers, rawV6Dhcp, rawV6Servers) = _configurator.ReadStaticConfiguration(adapter);
                var (v4Dhcp, v4Servers) = SanitizeBackupServers(rawV4Dhcp, rawV4Servers, ipv4Dns, adapter.Name);
                var (v6Dhcp, v6Servers) = SanitizeBackupServers(rawV6Dhcp, rawV6Servers, ipv6Dns, adapter.Name);
                var entries = new List<AdapterDnsBackupEntry>
                {
                    new()
                    {
                        AdapterId = adapter.Id,
                        AdapterName = adapter.Name,
                        WasIpv4Dhcp = v4Dhcp,
                        Ipv4DnsServers = v4Servers,
                        WasIpv6Dhcp = v6Dhcp,
                        Ipv6DnsServers = v6Servers,
                    },
                };
                backup = new AdapterDnsBackupDocument
                {
                    CreatedAt = DateTimeOffset.UtcNow,
                    IsActive = true,
                    Adapters = entries,
                    IntegrityHash = AdapterDnsBackupDocument.ComputeHash(entries),
                };
                await WriteBackupAsync(backup, cancellationToken).ConfigureAwait(false);
            }

            // Step 3: Verify backup integrity from disk before touching the adapter.
            var verified = ReadBackup();
            if (verified is null || !verified.VerifyIntegrity())
            {
                return new WindowsDnsOperationResult(false, "Aborted adapter DNS change: backup integrity verification failed.");
            }

            _bootRecovery?.Arm("dns");

            // Step 4: Apply the requested DNS configuration (batched IPv4 + IPv6).
            var hasStaleIpv6Loopback = verified.Adapters.FirstOrDefault(a => a.AdapterId == adapter.Id) is { WasIpv6Dhcp: false } v6Entry
                && v6Entry.Ipv6DnsServers.Any(s => string.Equals(s, "::1", StringComparison.OrdinalIgnoreCase));
            var hasExplicitIpv6 = !string.IsNullOrWhiteSpace(ipv6Dns);
            var adapterHasIpv6 = adapter.IPv6Addresses.Count > 0
                || adapter.DnsServers.Any(d => d.AddressFamily == AddressFamily.InterNetworkV6);
            var target = new AdapterDnsTarget(
                AdapterName: adapter.Name,
                ApplyIpv4: true,
                IsIpv4Dhcp: false,
                Ipv4Servers: [ipv4Dns],
                ApplyIpv6: hasExplicitIpv6 || hasStaleIpv6Loopback,
                IsIpv6Dhcp: !hasExplicitIpv6,
                Ipv6Servers: hasExplicitIpv6 ? [ipv6Dns!] : [],
                IgnoreIpv6Errors: !hasExplicitIpv6 || !adapterHasIpv6);

            var applyResult = await _configurator.ApplyBatchAsync([target], cancellationToken).ConfigureAwait(false);
            if (!applyResult.Success)
            {
                if (!hadExistingActiveBackup
                    && string.Equals(applyResult.Error, NetshAdapterDnsConfigurator.UacCancelledMessage, StringComparison.Ordinal))
                {
                    await WriteBackupAsync(verified with { IsActive = false }, cancellationToken).ConfigureAwait(false);
                    _bootRecovery?.Disarm("dns");
                    return new WindowsDnsOperationResult(false, applyResult.Error, RolledBack: false);
                }

                await RollbackFromDocumentAsync(verified, cancellationToken).ConfigureAwait(false);
                return new WindowsDnsOperationResult(false, applyResult.Error, RolledBack: true);
            }

            _configurator.FlushResolverCache();

            // Step 5: Verify DNS connectivity.
            var connected = false;
            try
            {
                connected = await connectivityProbe(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DNS connectivity verification probe threw an exception.");
            }

            // Step 6: Roll back automatically if verification fails.
            if (!connected)
            {
                _logger.LogWarning("DNS connectivity verification failed after applying proxy DNS; rolling back adapter {Adapter}.", adapter.Name);
                await RollbackFromDocumentAsync(verified, cancellationToken).ConfigureAwait(false);
                return new WindowsDnsOperationResult(
                    Success: false,
                    ErrorMessage: "DNS connectivity check failed after applying settings; original adapter DNS was automatically restored.",
                    RolledBack: true);
            }

            _logger.LogInformation("Configured adapter '{Adapter}' to use local proxy DNS {Ipv4}", adapter.Name, ipv4Dns);
            return new WindowsDnsOperationResult(true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<WindowsDnsOperationResult> RestoreOriginalDnsAsync(
        string? targetAdapterId = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var backup = ReadBackup();
            if (backup is not null && backup.Adapters.Count > 0)
            {
                var err = await RollbackFromDocumentAsync(backup, cancellationToken).ConfigureAwait(false);
                return err is null
                    ? new WindowsDnsOperationResult(true)
                    : new WindowsDnsOperationResult(false, err);
            }

            // Emergency fallback when no backup file exists: reset target or primary adapter to DHCP.
            var snapshot = _networkInfo.GetSnapshot();
            var adapter = SelectTargetAdapter(snapshot, targetAdapterId);
            if (adapter is null)
            {
                return new WindowsDnsOperationResult(false, "No active network adapter found to restore.");
            }

            var fallbackTarget = new AdapterDnsTarget(
                AdapterName: adapter.Name,
                ApplyIpv4: true,
                IsIpv4Dhcp: true,
                Ipv4Servers: [],
                ApplyIpv6: true,
                IsIpv6Dhcp: true,
                Ipv6Servers: [],
                IgnoreIpv6Errors: true);
            var (ok, error) = await _configurator.ApplyBatchAsync([fallbackTarget], cancellationToken).ConfigureAwait(false);
            _configurator.FlushResolverCache();
            if (ok)
            {
                _bootRecovery?.Disarm("dns");
                _logger.LogInformation("Emergency DNS restore reset adapter '{Adapter}' to DHCP.", adapter.Name);
            }

            return new WindowsDnsOperationResult(ok, error);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RecoverAfterCrashIfNeededAsync(bool proxyIsRunning, CancellationToken cancellationToken = default)
    {
        if (proxyIsRunning || !HasActiveBackup())
        {
            return;
        }

        _logger.LogWarning("Detected active adapter DNS backup from an unexpected shutdown; restoring original DNS settings.");
        await RestoreOriginalDnsAsync(null, cancellationToken).ConfigureAwait(false);
    }

    private static NetworkAdapterInfo? SelectTargetAdapter(NetworkSnapshot snapshot, string? targetAdapterId)
    {
        if (!string.IsNullOrWhiteSpace(targetAdapterId))
        {
            var match = snapshot.Adapters.FirstOrDefault(a => string.Equals(a.Id, targetAdapterId, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                return match;
            }
        }

        return snapshot.PrimaryAdapter ?? snapshot.Adapters.FirstOrDefault(a => a.IsUp);
    }

    private async Task<string?> RollbackFromDocumentAsync(AdapterDnsBackupDocument doc, CancellationToken ct)
    {
        var targets = new List<AdapterDnsTarget>(doc.Adapters.Count);
        foreach (var entry in doc.Adapters)
        {
            var (v4Dhcp, v4Servers) = ResolveSafeRestoreServers(entry.WasIpv4Dhcp, entry.Ipv4DnsServers, entry.AdapterName);
            var (v6Dhcp, v6Servers) = ResolveSafeRestoreServers(entry.WasIpv6Dhcp, entry.Ipv6DnsServers, entry.AdapterName);
            targets.Add(new AdapterDnsTarget(
                AdapterName: entry.AdapterName,
                ApplyIpv4: true,
                IsIpv4Dhcp: v4Dhcp,
                Ipv4Servers: v4Servers,
                ApplyIpv6: true,
                IsIpv6Dhcp: v6Dhcp,
                Ipv6Servers: v6Servers,
                IgnoreIpv6Errors: v6Dhcp));
        }

        var (success, firstError) = await _configurator.ApplyBatchAsync(targets, ct).ConfigureAwait(false);
        _configurator.FlushResolverCache();

        if (success)
        {
            var inactive = doc with { IsActive = false };
            await WriteBackupAsync(inactive, ct).ConfigureAwait(false);
            _bootRecovery?.Disarm("dns");
            return null;
        }

        _bootRecovery?.Arm("dns");
        _logger.LogError(
            "Failed to restore original adapter DNS settings ({Error}); keeping active backup and RunOnce recovery armed.",
            firstError ?? "unknown error");
        return firstError ?? "Failed to restore original adapter DNS settings.";
    }

    private (bool UseDhcp, IReadOnlyList<string> Servers) SanitizeBackupServers(
        bool wasDhcp,
        IReadOnlyList<string> servers,
        string? appliedProxyDns,
        string adapterName)
    {
        if (wasDhcp || servers.Count == 0)
        {
            return (true, []);
        }

        var kept = new List<string>(servers.Count);
        foreach (var server in servers)
        {
            var trimmed = server.Trim();
            if (!IPAddress.TryParse(trimmed, out var ip))
            {
                continue;
            }

            if (IsSelfLoopbackDns(ip, appliedProxyDns))
            {
                _logger.LogWarning(
                    "Ignored self-loopback DNS {Server} when backing up adapter '{Adapter}'.",
                    trimmed,
                    adapterName);
                continue;
            }

            kept.Add(ip.ToString());
        }

        return kept.Count == 0
            ? (true, [])
            : (false, kept);
    }

    private (bool UseDhcp, IReadOnlyList<string> Servers) ResolveSafeRestoreServers(
        bool wasDhcp,
        IReadOnlyList<string> backedUpServers,
        string adapterName)
    {
        if (wasDhcp || backedUpServers.Count == 0)
        {
            return (true, []);
        }

        var kept = new List<string>(backedUpServers.Count);
        foreach (var server in backedUpServers)
        {
            var trimmed = server.Trim();
            if (!IPAddress.TryParse(trimmed, out var ip))
            {
                continue;
            }

            if (IsSelfLoopbackDns(ip, appliedProxyDns: null))
            {
                _logger.LogWarning(
                    "Skipping self-loopback DNS {Server} during restore of adapter '{Adapter}'.",
                    trimmed,
                    adapterName);
                continue;
            }

            if (IPAddress.IsLoopback(ip) && !_loopbackDnsAliveProbe(ip))
            {
                _logger.LogWarning(
                    "Skipping dead loopback DNS {Server} during restore of adapter '{Adapter}' because nothing is listening on port 53.",
                    trimmed,
                    adapterName);
                continue;
            }

            kept.Add(ip.ToString());
        }

        if (kept.Count == 0)
        {
            _logger.LogWarning(
                "All backed-up DNS servers for adapter '{Adapter}' were unavailable loopback addresses; falling back to DHCP.",
                adapterName);
            return (true, []);
        }

        return (false, kept);
    }

    private static bool IsSelfLoopbackDns(IPAddress ip, string? appliedProxyDns)
    {
        if (!string.IsNullOrWhiteSpace(appliedProxyDns)
            && IPAddress.TryParse(appliedProxyDns.Trim(), out var appliedIp)
            && ip.Equals(appliedIp))
        {
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 127 && !(bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 1);
        }

        return false;
    }

    private static bool DefaultProbeLoopbackDnsAlive(IPAddress address)
    {
        // Standard minimal DNS query for root NS (17 bytes): ID=0x1234, QDCOUNT=1, QNAME=., QTYPE=NS, QCLASS=IN.
        ReadOnlySpan<byte> query = [0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01];
        try
        {
            using var udp = new UdpClient(address.AddressFamily);
            udp.Client.SendTimeout = 250;
            udp.Client.ReceiveTimeout = 250;
            udp.Connect(address, 53);
            _ = udp.Send(query.ToArray(), query.Length);
            IPEndPoint? remote = null;
            var response = udp.Receive(ref remote);
            if (response.Length >= 12)
            {
                return true;
            }
        }
        catch (SocketException)
        {
        }

        try
        {
            using var tcp = new TcpClient(address.AddressFamily);
            var ar = tcp.BeginConnect(address, 53, null, null);
            using var waitHandle = ar.AsyncWaitHandle;
            if (waitHandle.WaitOne(200))
            {
                tcp.EndConnect(ar);
                return tcp.Connected;
            }
        }
        catch (SocketException)
        {
        }

        return false;
    }

    private async Task WriteBackupAsync(AdapterDnsBackupDocument doc, CancellationToken ct)
    {
        Directory.CreateDirectory(_paths.DataDirectory);
        var json = JsonSerializer.Serialize(doc, SettingsJson.Options);
        await File.WriteAllTextAsync(_paths.DnsBackupFile, json, Encoding.UTF8, ct).ConfigureAwait(false);
    }

    public void Dispose() => _gate.Dispose();
}
