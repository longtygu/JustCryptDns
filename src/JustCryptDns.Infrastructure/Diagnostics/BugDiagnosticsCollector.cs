using System.Reflection;
using System.Text;
using JustCryptDns.Core.Configuration;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using JustCryptDns.Core.Services;
using JustCryptDns.Infrastructure.Windows;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Diagnostics;

/// <summary>
/// Captures a sanitized diagnostics snapshot (app/OS versions, engine status, primary adapter,
/// and the most recent warning/error log lines) for user bug reports.
/// </summary>
public sealed class BugDiagnosticsCollector : IBugDiagnosticsCollector
{
    private const int MaxLogLines = 20;

    private readonly IAppPaths _paths;
    private readonly ISettingsService _settings;
    private readonly IDnsEngine _dnsEngine;
    private readonly IBypassEngineService _bypassEngine;
    private readonly INetworkInfoService _networkInfo;
    private readonly ILogger<BugDiagnosticsCollector> _logger;

    public BugDiagnosticsCollector(
        IAppPaths paths,
        ISettingsService settings,
        IDnsEngine dnsEngine,
        IBypassEngineService bypassEngine,
        INetworkInfoService networkInfo,
        ILogger<BugDiagnosticsCollector> logger)
    {
        _paths = paths;
        _settings = settings;
        _dnsEngine = dnsEngine;
        _bypassEngine = bypassEngine;
        _networkInfo = networkInfo;
        _logger = logger;
    }

    public BugDiagnosticsSnapshot Capture()
    {
        var infoVersion = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
            ?.Split('+')[0] ?? "1.7.1";

        var dnsStats = _dnsEngine.GetStats();
        var bypassStats = _bypassEngine.GetStats();
        var snapshot = _networkInfo.GetSnapshot();
        var adapterText = snapshot.PrimaryAdapter is { } adapter
            ? $"{adapter.Name} ({adapter.Kind}, {adapter.Status})"
            : "None";

        return new BugDiagnosticsSnapshot(
            AppVersion: infoVersion,
            OsVersion: WindowsVersion.DisplayName,
            DnsEngineState: $"{dnsStats.State} ({dnsStats.TrafficStatus})",
            ActiveResolver: $"{dnsStats.ActiveResolverName} [{dnsStats.ActiveProtocol}]",
            BypassState: $"{bypassStats.State} (WinProxyApplied={bypassStats.WindowsProxyApplied})",
            BypassCoverage: _settings.Current.Bypass.CoverageMode.ToString(),
            PrimaryAdapter: adapterText,
            RecentLogLines: ReadRecentWarningOrErrorLines());
    }

    private List<string> ReadRecentWarningOrErrorLines()
    {
        var results = new List<string>();
        try
        {
            if (!Directory.Exists(_paths.LogsDirectory))
            {
                return results;
            }

            var latestLogs = new DirectoryInfo(_paths.LogsDirectory)
                .EnumerateFiles("*.log")
                .Where(f => f.Name.StartsWith("ui-", StringComparison.OrdinalIgnoreCase)
                         || f.Name.StartsWith("service-", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Take(2)
                .ToList();
            if (latestLogs.Count == 0)
            {
                return results;
            }

            var warningsAndErrors = new Queue<string>(MaxLogLines + 1);
            var tailFallback = new Queue<string>(MaxLogLines + 1);

            foreach (var logFile in latestLogs.AsEnumerable().Reverse())
            {
                using var stream = new FileStream(logFile.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream, Encoding.UTF8);

                while (reader.ReadLine() is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    var sanitized = BugReportBuilder.SanitizeLogLine(line);
                    if (tailFallback.Count >= MaxLogLines)
                    {
                        tailFallback.Dequeue();
                    }
                    tailFallback.Enqueue(sanitized);

                    if (line.Contains("[WRN]", StringComparison.Ordinal)
                        || line.Contains("[ERR]", StringComparison.Ordinal)
                        || line.Contains("[FTL]", StringComparison.Ordinal))
                    {
                        if (warningsAndErrors.Count >= MaxLogLines)
                        {
                            warningsAndErrors.Dequeue();
                        }
                        warningsAndErrors.Enqueue(sanitized);
                    }
                }
            }

            results.AddRange(warningsAndErrors.Count > 0 ? warningsAndErrors : tailFallback);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogDebug(ex, "Could not inspect log files for bug report diagnostics.");
        }

        return results;
    }
}
