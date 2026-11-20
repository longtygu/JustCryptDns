namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Manages an automatic Windows boot-time recovery registration (HKCU RunOnce) so that
/// orphaned DNS or proxy backups are restored cleanly on startup after crashes or abrupt shutdowns.
/// </summary>
public interface IBootRecoveryRegistrar
{
    bool IsArmed { get; }

    void Arm(string component);

    void Disarm(string component);

    void ClearAll();
}
