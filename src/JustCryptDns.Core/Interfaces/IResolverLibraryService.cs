using JustCryptDns.Core.Models;

namespace JustCryptDns.Core.Interfaces;

/// <summary>
/// Manages the complete resolver catalog (Part 3): predefined providers, custom resolvers,
/// primary/secondary assignment, resolver groups, validation, profile import/export, and health checks.
/// </summary>
public interface IResolverLibraryService
{
    event EventHandler? LibraryChanged;

    event EventHandler<ResolverHealthStatus>? HealthUpdated;

    IReadOnlyList<DnsResolverEndpoint> GetAll();

    IReadOnlyList<DnsResolverEndpoint> GetEnabled();

    DnsResolverEndpoint GetByIdOrDefault(string? resolverId);

    DnsResolverEndpoint GetPrimaryResolver();

    DnsResolverEndpoint GetSecondaryResolver();

    IReadOnlyList<string> GetGroups();

    ResolverHealthStatus GetHealth(string resolverId);

    IReadOnlyDictionary<string, ResolverHealthStatus> GetAllHealth();

    Task<(bool Success, DnsResolverEndpoint? Resolver, ResolverValidationResult Validation)> AddCustomResolverAsync(
        DnsResolverEndpoint resolver,
        CancellationToken cancellationToken = default);

    Task<(bool Success, DnsResolverEndpoint? Resolver, ResolverValidationResult Validation)> UpdateResolverAsync(
        DnsResolverEndpoint resolver,
        CancellationToken cancellationToken = default);

    Task<bool> RemoveCustomResolverAsync(
        string resolverId,
        CancellationToken cancellationToken = default);

    Task SetResolverEnabledAsync(
        string resolverId,
        bool enabled,
        CancellationToken cancellationToken = default);

    Task SetResolverGroupAsync(
        string resolverId,
        string groupName,
        CancellationToken cancellationToken = default);

    Task AddGroupAsync(
        string groupName,
        CancellationToken cancellationToken = default);

    Task<(bool Success, string? Error)> SetPrimaryResolverAsync(
        string resolverId,
        CancellationToken cancellationToken = default);

    Task<(bool Success, string? Error)> SetSecondaryResolverAsync(
        string resolverId,
        CancellationToken cancellationToken = default);

    Task<ResolverHealthStatus> CheckHealthAsync(
        string resolverId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ResolverHealthStatus>> CheckAllEnabledHealthAsync(
        CancellationToken cancellationToken = default);

    string ExportProfileJson();

    Task<(bool Success, int ImportedCount, string? Error)> ImportProfileJsonAsync(
        string json,
        CancellationToken cancellationToken = default);
}
