namespace JustCryptDns.Core.Configuration;

/// <summary>
/// Resolves the on-disk locations used by the application.
/// </summary>
public interface IAppPaths
{
    /// <summary>True when running in self-contained portable mode (portable.flag present beside the executable).</summary>
    bool IsPortableMode { get; }

    /// <summary>Shared machine-wide data root (<c>%ProgramData%\JustCryptDns</c>) or portable data root.</summary>
    string DataDirectory { get; }

    /// <summary>Directory containing rolling log files.</summary>
    string LogsDirectory { get; }

    /// <summary>Full path of the user settings JSON file.</summary>
    string SettingsFile { get; }

    /// <summary>Full path of the verified Windows adapter DNS backup file.</summary>
    string DnsBackupFile { get; }

    /// <summary>Full path of the per-user verified Windows system proxy backup file.</summary>
    string ProxyBackupFile { get; }

    /// <summary>Directory holding managed engine binaries and runtime configs (e.g. dnscrypt-proxy).</summary>
    string EngineDirectory { get; }

    /// <summary>Directory storing downloaded updates and temporary staging files.</summary>
    string UpdatesDirectory { get; }

    /// <summary>Creates required data directories on disk.</summary>
    void EnsureCreated();
}

/// <summary>
/// Default implementation rooted at <c>%ProgramData%\JustCryptDns</c> when installed,
/// <c>&lt;AppDir&gt;\data</c> when <c>portable.flag</c> is present, or a custom root (tests / override).
/// </summary>
public sealed class AppPaths : IAppPaths
{
    public const string ProductFolderName = "JustCryptDns";
    public const string PortableFlagFileName = "portable.flag";
    private const string LegacyMigrationMarkerFileName = ".legacy-v1-migrated";

    private readonly bool _hasRootOverride;
    private readonly string? _legacyUserDataDirectory;
    private readonly string? _ignoredPortableDataDirectory;

    public AppPaths(string? rootOverride = null, string? baseDirectoryOverride = null)
    {
        var effectiveBaseDir = string.IsNullOrWhiteSpace(baseDirectoryOverride)
            ? AppContext.BaseDirectory
            : Path.GetFullPath(baseDirectoryOverride);
        var portableFlagPath = Path.Combine(effectiveBaseDir, PortableFlagFileName);

        _hasRootOverride = !string.IsNullOrWhiteSpace(rootOverride);
        if (_hasRootOverride)
        {
            IsPortableMode = File.Exists(portableFlagPath) && !IsProtectedSystemDirectory(effectiveBaseDir);
            DataDirectory = Path.GetFullPath(rootOverride!);
            ProxyBackupFile = Path.Combine(DataDirectory, "proxy-backup.json");
            UpdatesDirectory = Path.Combine(DataDirectory, "updates");
        }
        else if (File.Exists(portableFlagPath)
                 && !IsProtectedSystemDirectory(effectiveBaseDir)
                 && CanWriteToPortableDataDirectory(effectiveBaseDir))
        {
            IsPortableMode = true;
            DataDirectory = Path.Combine(effectiveBaseDir, "data");
            ProxyBackupFile = Path.Combine(DataDirectory, "proxy-backup.json");
            UpdatesDirectory = Path.Combine(DataDirectory, "updates");
        }
        else
        {
            IsPortableMode = false;
            if (File.Exists(portableFlagPath))
            {
                IgnoredUnwritablePortableFlag = true;
                _ignoredPortableDataDirectory = Path.Combine(effectiveBaseDir, "data");
            }

            var commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            DataDirectory = Path.Combine(commonAppData, ProductFolderName);
            ProxyBackupFile = Path.Combine(localAppData, ProductFolderName, "proxy-backup.json");
            UpdatesDirectory = Path.Combine(localAppData, ProductFolderName, "updates");
            _legacyUserDataDirectory = Path.Combine(localAppData, ProductFolderName);
        }

        LogsDirectory = Path.Combine(DataDirectory, "logs");
        SettingsFile = Path.Combine(DataDirectory, "settings.json");
        DnsBackupFile = Path.Combine(DataDirectory, "dns-backup.json");
        EngineDirectory = Path.Combine(DataDirectory, "engine");
    }

    public bool IsPortableMode { get; }

    /// <summary>True when a portable.flag was found inside a protected or read-only directory (e.g. Program Files) and safely ignored.</summary>
    public bool IgnoredUnwritablePortableFlag { get; }

    /// <summary>
    /// Returns true when <paramref name="directoryPath"/> resides inside Windows protected installation roots
    /// (<c>Program Files</c>, <c>Program Files (x86)</c>, or <c>Windows</c>), where standard users lack write access.
    /// </summary>
    public static bool IsProtectedSystemDirectory(string? directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directoryPath)) + Path.DirectorySeparatorChar;
        }
        catch
        {
            return false;
        }

        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (var special in new[]
        {
            Environment.SpecialFolder.ProgramFiles,
            Environment.SpecialFolder.ProgramFilesX86,
            Environment.SpecialFolder.Windows,
        })
        {
            var root = Environment.GetFolderPath(special);
            if (string.IsNullOrWhiteSpace(root))
            {
                continue;
            }

            var normRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(normRoot, comparison))
            {
                return true;
            }
        }

        return false;
    }

    private static bool CanWriteToPortableDataDirectory(string baseDir)
    {
        try
        {
            var dataDir = Path.Combine(baseDir, "data");
            var probeDir = Directory.Exists(dataDir) ? dataDir : baseDir;
            var probeFile = Path.Combine(probeDir, $".write-probe-{Guid.NewGuid():N}.tmp");
            using (File.Create(probeFile))
            {
            }

            File.Delete(probeFile);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public string DataDirectory { get; }

    public string LogsDirectory { get; }

    public string SettingsFile { get; }

    public string DnsBackupFile { get; }

    public string ProxyBackupFile { get; }

    public string EngineDirectory { get; }

    public string UpdatesDirectory { get; }

    /// <summary>Creates the data, log, engine, updates, and proxy-backup directories if they do not exist.</summary>
    public void EnsureCreated()
    {
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogsDirectory);
        Directory.CreateDirectory(EngineDirectory);
        Directory.CreateDirectory(UpdatesDirectory);

        var proxyBackupDir = Path.GetDirectoryName(ProxyBackupFile);
        if (!string.IsNullOrWhiteSpace(proxyBackupDir))
        {
            Directory.CreateDirectory(proxyBackupDir);
        }
    }

    /// <summary>
    /// Performs a one-time best-effort migration of legacy per-user settings, DNS backup, and managed engine
    /// assets from <c>%LOCALAPPDATA%\JustCryptDns</c> into the shared <c>%ProgramData%\JustCryptDns</c> root.
    /// </summary>
    /// <returns><c>true</c> if legacy settings were copied into <see cref="SettingsFile"/>.</returns>
    public bool TryMigrateLegacyUserDataToShared(string? legacySourceDirectoryOverride = null)
    {
        if (legacySourceDirectoryOverride is null && (_hasRootOverride || IsPortableMode))
        {
            return false;
        }

        var legacySourceDir = !string.IsNullOrWhiteSpace(legacySourceDirectoryOverride)
            ? Path.GetFullPath(legacySourceDirectoryOverride)
            : (!string.IsNullOrWhiteSpace(_ignoredPortableDataDirectory)
               && File.Exists(Path.Combine(_ignoredPortableDataDirectory, "settings.json"))
               && !File.Exists(SettingsFile)
                ? _ignoredPortableDataDirectory
                : _legacyUserDataDirectory);

        if (string.IsNullOrWhiteSpace(legacySourceDir)
            || !Directory.Exists(legacySourceDir)
            || PathsEqual(legacySourceDir, DataDirectory))
        {
            return false;
        }

        try
        {
            EnsureCreated();
            var markerPath = Path.Combine(DataDirectory, LegacyMigrationMarkerFileName);
            if (File.Exists(markerPath))
            {
                return false;
            }

            var migratedSettings = false;
            var legacySettings = Path.Combine(legacySourceDir, "settings.json");
            if (File.Exists(legacySettings))
            {
                File.Copy(legacySettings, SettingsFile, overwrite: true);
                migratedSettings = true;
            }

            var legacyDnsBackup = Path.Combine(legacySourceDir, "dns-backup.json");
            if (File.Exists(legacyDnsBackup) && !File.Exists(DnsBackupFile))
            {
                File.Copy(legacyDnsBackup, DnsBackupFile, overwrite: false);
            }

            var legacyEngineDir = Path.Combine(legacySourceDir, "engine");
            if (Directory.Exists(legacyEngineDir))
            {
                CopyMissingDirectoryFiles(legacyEngineDir, EngineDirectory);
            }

            File.WriteAllText(markerPath, DateTimeOffset.UtcNow.ToString("O"));
            return migratedSettings;
        }
        catch
        {
            return false;
        }
    }

    private static bool PathsEqual(string left, string right)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            comparison);
    }

    private static void CopyMissingDirectoryFiles(string sourceDir, string targetDir)
    {
        Directory.CreateDirectory(targetDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDir, file);
            var dest = Path.Combine(targetDir, relative);
            var destParent = Path.GetDirectoryName(dest);
            if (!string.IsNullOrWhiteSpace(destParent))
            {
                Directory.CreateDirectory(destParent);
            }

            if (!File.Exists(dest))
            {
                File.Copy(file, dest, overwrite: false);
            }
        }
    }
}
