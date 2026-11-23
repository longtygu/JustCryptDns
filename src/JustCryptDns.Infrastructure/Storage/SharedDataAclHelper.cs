using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Storage;

/// <summary>
/// Manages ACLs on <c>%ProgramData%\JustCryptDns</c>: grants <c>BUILTIN\Users</c> modify access
/// only to shared configuration/log files while locking executable/privilege-sensitive paths
/// (<c>engine\</c>, <c>updates\</c>, <c>dns-backup.json</c>) to <c>SYSTEM</c> and <c>Administrators</c>.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SharedDataAclHelper
{
    public static bool EnsureSharedDirectoryWritable(IAppPaths paths, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        paths.EnsureCreated();

        if (paths.IsPortableMode)
        {
            return true;
        }

        var commonAppDataRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)))
            + Path.DirectorySeparatorChar;
        var targetRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(paths.DataDirectory))
            + Path.DirectorySeparatorChar;

        if (!targetRoot.StartsWith(commonAppDataRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var ok = TryApplyUsersModifyAcl(paths.DataDirectory, logger);
        TryApplyUsersModifyAcl(paths.LogsDirectory, logger);
        TryApplyUsersModifyAcl(Path.Combine(paths.DataDirectory, "blocklists"), logger);

        if (IsCurrentProcessElevatedOrSystem())
        {
            TryApplyAdminOnlyWriteAcl(paths.EngineDirectory, logger);
            var updatesFull = Path.TrimEndingDirectorySeparator(Path.GetFullPath(paths.UpdatesDirectory)) + Path.DirectorySeparatorChar;
            if (updatesFull.StartsWith(commonAppDataRoot, StringComparison.OrdinalIgnoreCase))
            {
                TryApplyAdminOnlyWriteAcl(paths.UpdatesDirectory, logger);
            }

            TryApplyAdminOnlyWriteFileAcl(paths.DnsBackupFile, logger);
        }

        return ok;
    }

    public static bool TryApplyUsersModifyAcl(string directoryPath, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return false;
        }

        try
        {
            if (IsReparsePoint(directoryPath))
            {
                logger?.LogWarning("Refusing to apply Users:Modify ACL on reparse point '{DirectoryPath}'.", directoryPath);
                return false;
            }

            Directory.CreateDirectory(directoryPath);
            var directoryInfo = new DirectoryInfo(directoryPath);
            if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            var security = directoryInfo.GetAccessControl();

            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.Modify,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                adminsSid,
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            directoryInfo.SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
            or IOException
            or IdentityNotMappedException
            or PrivilegeNotHeldException
            or PlatformNotSupportedException)
        {
            logger?.LogDebug(ex, "Could not update shared data ACL on '{DirectoryPath}'.", directoryPath);
            return false;
        }
    }

    /// <summary>
    /// Locks a privilege-sensitive directory so only <c>SYSTEM</c> and <c>Administrators</c> can write,
    /// while <c>BUILTIN\Users</c> has read/execute access only (protected DACL, inheritance disabled).
    /// </summary>
    public static bool TryApplyAdminOnlyWriteAcl(string directoryPath, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return false;
        }

        try
        {
            if (IsReparsePoint(directoryPath))
            {
                logger?.LogWarning("Refusing to apply admin-only ACL on reparse point '{DirectoryPath}'.", directoryPath);
                return false;
            }

            Directory.CreateDirectory(directoryPath);
            var directoryInfo = new DirectoryInfo(directoryPath);
            if ((directoryInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                adminsSid,
                FileSystemRights.FullControl,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.ReadAndExecute,
                inherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            directoryInfo.SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
            or IOException
            or IdentityNotMappedException
            or PrivilegeNotHeldException
            or PlatformNotSupportedException)
        {
            logger?.LogDebug(ex, "Could not lock admin-only ACL on '{DirectoryPath}'.", directoryPath);
            return false;
        }
    }

    public static bool TryApplyAdminOnlyWriteFileAcl(string filePath, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                systemSid,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                adminsSid,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.Read,
                AccessControlType.Allow));

            fileInfo.SetAccessControl(security);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException
            or IOException
            or IdentityNotMappedException
            or PrivilegeNotHeldException
            or PlatformNotSupportedException)
        {
            logger?.LogDebug(ex, "Could not lock admin-only file ACL on '{FilePath}'.", filePath);
            return false;
        }
    }

    internal static bool IsReparsePoint(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                return false;
            }

            var attrs = File.GetAttributes(path);
            return (attrs & FileAttributes.ReparsePoint) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }

    private static bool IsCurrentProcessElevatedOrSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (identity.IsSystem)
            {
                return true;
            }

            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
