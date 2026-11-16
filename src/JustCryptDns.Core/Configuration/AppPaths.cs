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
    }

    public string DataDirectory { get; }

    public string LogsDirectory { get; }

    public string SettingsFile { get; }

    /// <summary>Creates the data and log directories if they do not exist.</summary>
    public void EnsureCreated()
    {
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogsDirectory);
    }
}
