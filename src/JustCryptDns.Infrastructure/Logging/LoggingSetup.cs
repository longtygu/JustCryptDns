using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace JustCryptDns.Infrastructure.Logging;

/// <summary>
/// Configures Serilog with size-capped, rolling, retention-limited log files.
/// </summary>
public static class LoggingSetup
{
    /// <summary>Maximum size of a single log file before rolling.</summary>
    public const long FileSizeLimitBytes = 5 * 1024 * 1024;

    public static LoggingLevelSwitch LevelSwitch { get; } = new(LogEventLevel.Information);

    public static ILoggerFactory CreateLoggerFactory(IAppPaths paths, string fileNamePrefix, LogLevelSetting level, int retainedFiles)
    {
        Directory.CreateDirectory(paths.LogsDirectory);
        LevelSwitch.MinimumLevel = ToSerilog(level);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.ControlledBy(LevelSwitch)
            .Enrich.WithProperty("Pid", Environment.ProcessId)
            .WriteTo.File(
                Path.Combine(paths.LogsDirectory, fileNamePrefix + "-.log"),
                formatProvider: System.Globalization.CultureInfo.InvariantCulture,
                rollingInterval: RollingInterval.Day,
                fileSizeLimitBytes: FileSizeLimitBytes,
                rollOnFileSizeLimit: true,
                retainedFileCountLimit: Math.Clamp(retainedFiles, 1, 90),
                shared: false,
                buffered: true,
                flushToDiskInterval: TimeSpan.FromSeconds(5),
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
            .CreateLogger();

        return LoggerFactory.Create(builder => builder.AddSerilog(Log.Logger, dispose: false).SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace));
    }

    public static void SetLevel(LogLevelSetting level) => LevelSwitch.MinimumLevel = ToSerilog(level);

    public static LogEventLevel ToSerilog(LogLevelSetting level) => level switch
    {
        LogLevelSetting.Debug => LogEventLevel.Debug,
        LogLevelSetting.Warning => LogEventLevel.Warning,
        LogLevelSetting.Error => LogEventLevel.Error,
        _ => LogEventLevel.Information,
    };

    public static void Shutdown() => Log.CloseAndFlush();
}
