using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace JustCryptDns.Infrastructure.Windows;

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
}

public sealed class NetshAdapterDnsConfigurator : IAdapterDnsConfigurator
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

    public async Task<(bool Success, string? Error)> SetDnsAsync(
        string adapterName,
        bool ipv6,
        bool useDhcp,
        IReadOnlyList<string> servers,
        CancellationToken cancellationToken = default)
    {
        var family = ipv6 ? "ipv6" : "ipv4";
        var safeName = adapterName.Replace("\"", string.Empty, StringComparison.Ordinal);

        if (useDhcp || servers.Count == 0)
        {
            return await RunNetshAsync($"interface {family} set dnsservers name=\"{safeName}\" source=dhcp", cancellationToken).ConfigureAwait(false);
        }

        var primary = await RunNetshAsync(
            $"interface {family} set dnsservers name=\"{safeName}\" static {servers[0]} primary validate=no",
            cancellationToken).ConfigureAwait(false);
        if (!primary.Success)
        {
            return primary;
        }

        for (var i = 1; i < servers.Count; i++)
        {
            var index = i + 1;
            var secondary = await RunNetshAsync(
                $"interface {family} add dnsservers name=\"{safeName}\" {servers[i]} index={index} validate=no",
                cancellationToken).ConfigureAwait(false);
            if (!secondary.Success)
            {
                return secondary;
            }
        }

        return (true, null);
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
            return (false, "Administrator permission prompt (UAC) was cancelled.");
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
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsNetworkDnsService(
        IAppPaths paths,
        INetworkInfoService networkInfo,
        ILogger<WindowsNetworkDnsService> logger,
        IAdapterDnsConfigurator? configurator = null)
    {
        _paths = paths;
        _networkInfo = networkInfo;
        _logger = logger;
        _configurator = configurator ?? new NetshAdapterDnsConfigurator();
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
            AdapterDnsBackupDocument backup;
            if (existingBackup is { IsActive: true } && existingBackup.VerifyIntegrity())
            {
                backup = existingBackup;
            }
            else
            {
                var (v4Dhcp, v4Servers, v6Dhcp, v6Servers) = _configurator.ReadStaticConfiguration(adapter);
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

            // Step 4: Apply the requested DNS configuration.
            var v4Apply = await _configurator.SetDnsAsync(
                adapter.Name,
                ipv6: false,
                useDhcp: false,
                servers: [ipv4Dns],
                cancellationToken).ConfigureAwait(false);
            if (!v4Apply.Success)
            {
                await RollbackFromDocumentAsync(verified, cancellationToken).ConfigureAwait(false);
                return new WindowsDnsOperationResult(false, v4Apply.Error, RolledBack: true);
            }

            if (!string.IsNullOrWhiteSpace(ipv6Dns))
            {
                var v6Apply = await _configurator.SetDnsAsync(
                    adapter.Name,
                    ipv6: true,
                    useDhcp: false,
                    servers: [ipv6Dns],
                    cancellationToken).ConfigureAwait(false);
                if (!v6Apply.Success)
                {
                    await RollbackFromDocumentAsync(verified, cancellationToken).ConfigureAwait(false);
                    return new WindowsDnsOperationResult(false, v6Apply.Error, RolledBack: true);
                }
            }
            else if (verified.Adapters.FirstOrDefault(a => a.AdapterId == adapter.Id) is { WasIpv6Dhcp: false } v6Entry
                && v6Entry.Ipv6DnsServers.Any(s => string.Equals(s, "::1", StringComparison.OrdinalIgnoreCase)))
            {
                // Clear stale ::1 IPv6 DNS so Windows doesn't bypass our IPv4 loopback proxy (e.g. 127.0.0.2:53).
                _ = await _configurator.SetDnsAsync(adapter.Name, ipv6: true, useDhcp: true, servers: [], cancellationToken).ConfigureAwait(false);
            }

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

            var (ok, error) = await _configurator.SetDnsAsync(adapter.Name, ipv6: false, useDhcp: true, servers: [], cancellationToken).ConfigureAwait(false);
            if (ok)
            {
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
        string? firstError = null;
        foreach (var entry in doc.Adapters)
        {
            var v4 = await _configurator.SetDnsAsync(entry.AdapterName, ipv6: false, entry.WasIpv4Dhcp, entry.Ipv4DnsServers, ct).ConfigureAwait(false);
            if (!v4.Success)
            {
                firstError ??= v4.Error;
            }

            var v6 = await _configurator.SetDnsAsync(entry.AdapterName, ipv6: true, entry.WasIpv6Dhcp, entry.Ipv6DnsServers, ct).ConfigureAwait(false);
            if (!v6.Success && !entry.WasIpv6Dhcp)
            {
                firstError ??= v6.Error;
            }
        }

        var inactive = doc with { IsActive = false };
        await WriteBackupAsync(inactive, ct).ConfigureAwait(false);
        return firstError;
    }

    private async Task WriteBackupAsync(AdapterDnsBackupDocument doc, CancellationToken ct)
    {
        Directory.CreateDirectory(_paths.DataDirectory);
        var json = JsonSerializer.Serialize(doc, SettingsJson.Options);
        await File.WriteAllTextAsync(_paths.DnsBackupFile, json, Encoding.UTF8, ct).ConfigureAwait(false);
    }

    public void Dispose() => _gate.Dispose();
}
