namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Manages per-user Windows logon startup registration without creating duplicate entries.
/// </summary>
public interface IStartupService
{
    /// <summary>Returns true when the application is currently registered to start with Windows.</summary>
    bool IsRegistered();

    /// <summary>Enables, updates or removes the Windows startup entry for the current user.</summary>
    void SetRegistration(bool enabled, bool startMinimized);
}
