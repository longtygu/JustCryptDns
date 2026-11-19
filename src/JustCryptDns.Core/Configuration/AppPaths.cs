namespace JustCryptDns.Core.Configuration;

/// <summary>
/// Resolves the on-disk locations used by the application.
/// </summary>
public interface IAppPaths
{
    /// <summary>Per-user data root (settings, UI state).</summary>
    string DataDirectory { get; }

    /// <summary>Directory containing rolling log files.</summary>
    string LogsDirectory { get; }

    /// <summary>Full path of the user settings JSON file.</summary>
    string SettingsFile { get; }

    /// <summary>Full path of the verified Windows adapter DNS backup file.</summary>
    string DnsBackupFile { get; }

    /// <summary>Full path of the verified Windows system proxy backup file.</summary>
    string ProxyBackupFile { get; }

    /// <summary>Directory holding managed engine binaries and runtime configs (e.g. dnscrypt-proxy).</summary>
    string EngineDirectory { get; }
}

/// <summary>
/// Default implementation rooted at <c>%LOCALAPPDATA%\JustCryptDns</c>, or a custom root (portable mode / tests).
/// </summary>
public sealed class AppPaths : IAppPaths
{
    public const string ProductFolderName = "JustCryptDns";

    public AppPaths(string? rootOverride = null)
    {
        DataDirectory = string.IsNullOrWhiteSpace(rootOverride)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), ProductFolderName)
            : Path.GetFullPath(rootOverride);
        LogsDirectory = Path.Combine(DataDirectory, "logs");
        SettingsFile = Path.Combine(DataDirectory, "settings.json");
        DnsBackupFile = Path.Combine(DataDirectory, "dns-backup.json");
        ProxyBackupFile = Path.Combine(DataDirectory, "proxy-backup.json");
        EngineDirectory = Path.Combine(DataDirectory, "engine");
    }

    public string DataDirectory { get; }

    public string LogsDirectory { get; }

    public string SettingsFile { get; }

    public string DnsBackupFile { get; }

    public string ProxyBackupFile { get; }

    public string EngineDirectory { get; }

    /// <summary>Creates the data, log and engine directories if they do not exist.</summary>
    public void EnsureCreated()
    {
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogsDirectory);
        Directory.CreateDirectory(EngineDirectory);
    }
}
