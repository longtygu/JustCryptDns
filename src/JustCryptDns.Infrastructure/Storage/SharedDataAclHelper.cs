using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using JustCryptDns.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Infrastructure.Storage;

/// <summary>
/// Ensures the shared <c>%ProgramData%\JustCryptDns</c> data directory grants <c>BUILTIN\Users</c>
/// modify access so both the <c>LocalSystem</c> Windows Service and the desktop UI process can
/// read and write <c>settings.json</c>, logs, and engine runtime state without split-brain copies.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SharedDataAclHelper
{
    /// <summary>
    /// Ensures <see cref="IAppPaths.DataDirectory"/> exists and applies <c>Users:Modify</c> ACLs
    /// when running in shared installed mode (no-op in portable mode).
    /// </summary>
    public static bool EnsureSharedDirectoryWritable(IAppPaths paths, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(paths);
        paths.EnsureCreated();

        if (paths.IsPortableMode)
        {
            return true;
        }

        // Only apply machine-wide ACLs when operating under the shared CommonApplicationData root.
        var commonAppDataRoot = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var targetRoot = Path.GetFullPath(paths.DataDirectory);
        if (!targetRoot.StartsWith(commonAppDataRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return TryApplyUsersModifyAcl(paths.DataDirectory, logger);
    }

    /// <summary>
    /// Applies inheritable <c>BUILTIN\Users</c> Modify permissions (alongside <c>SYSTEM</c> and
    /// <c>BUILTIN\Administrators</c> FullControl) to <paramref name="directoryPath"/>.
    /// </summary>
    public static bool TryApplyUsersModifyAcl(string directoryPath, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return false;
        }

        try
        {
            Directory.CreateDirectory(directoryPath);
            var directoryInfo = new DirectoryInfo(directoryPath);
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
}
