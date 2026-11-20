using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Collects a privacy-sanitized runtime snapshot and recent warnings/errors for bug reports.
/// </summary>
public interface IBugDiagnosticsCollector
{
    BugDiagnosticsSnapshot Capture();
}
