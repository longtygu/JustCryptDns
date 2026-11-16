using System.Net;
using System.Net.NetworkInformation;

namespace JustCryptDns.Core.Models;

public enum AdapterKind
{
    Ethernet,
    WiFi,
    Cellular,
    Virtual,
    Other,
}

/// <summary>
/// Immutable snapshot of a network adapter as reported by the local OS. No external probing involved.
/// </summary>
public sealed record NetworkAdapterInfo
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public required AdapterKind Kind { get; init; }

    public required OperationalStatus Status { get; init; }

    /// <summary>Link speed in bits per second, or -1 if unknown.</summary>
    public long SpeedBitsPerSecond { get; init; } = -1;

    public IReadOnlyList<IPAddress> IPv4Addresses { get; init; } = [];

    public IReadOnlyList<IPAddress> IPv6Addresses { get; init; } = [];

    public IReadOnlyList<IPAddress> Gateways { get; init; } = [];

    public IReadOnlyList<IPAddress> DnsServers { get; init; } = [];

    public bool IsUp => Status == OperationalStatus.Up;

    public bool HasIPv4Gateway => Gateways.Any(g => g.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !g.Equals(IPAddress.Any));

    public bool HasIPv6Gateway => Gateways.Any(g => g.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !g.Equals(IPAddress.IPv6Any));

    /// <summary>True if the adapter has a global (non link-local) IPv6 address.</summary>
    public bool HasGlobalIPv6 => IPv6Addresses.Any(a => !a.IsIPv6LinkLocal && !a.IsIPv6SiteLocal && !IPAddress.IsLoopback(a));
}

public enum LocalConnectivity
{
    /// <summary>No adapter is up.</summary>
    Offline,

    /// <summary>An adapter is up but has no default gateway.</summary>
    LocalOnly,

    /// <summary>An adapter is up with a default gateway (internet not verified).</summary>
    GatewayAvailable,
}

public sealed record NetworkSnapshot(
    IReadOnlyList<NetworkAdapterInfo> Adapters,
    NetworkAdapterInfo? PrimaryAdapter,
    LocalConnectivity Connectivity,
    DateTimeOffset CapturedAt);
