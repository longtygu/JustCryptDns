using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using JustCryptDns.Core.Interfaces;
using JustCryptDns.Core.Models;
using Microsoft.Extensions.Logging;

namespace JustCryptDns.Network.Monitoring;

/// <summary>
/// Reads adapter state from <see cref="NetworkInterface"/> and raises debounced change events.
/// OS notifications are only subscribed while handlers are attached (no polling).
/// </summary>
public sealed class NetworkInfoService : INetworkInfoService, IDisposable
{
    private static readonly TimeSpan DebounceDelay = TimeSpan.FromMilliseconds(750);
    private const long SnapshotCacheTtlMs = 2500;

    // Public anycast addresses used only to ask the local routing table which source address it would pick.
    // A UDP "connect" sends no packets.
    private static readonly IPEndPoint RouteProbeV4 = new(IPAddress.Parse("1.1.1.1"), 53);
    private static readonly IPEndPoint RouteProbeV6 = new(IPAddress.Parse("2606:4700:4700::1111"), 53);

    private readonly ILogger<NetworkInfoService> _logger;
    private readonly object _sync = new();
    private readonly Timer _debounce;
    private EventHandler? _networkChanged;
    private bool _hooked;
    private NetworkSnapshot? _cachedSnapshot;
    private long _cachedSnapshotTick;

    public NetworkInfoService(ILogger<NetworkInfoService> logger)
    {
        _logger = logger;
        _debounce = new Timer(_ => _networkChanged?.Invoke(this, EventArgs.Empty), null, Timeout.Infinite, Timeout.Infinite);
    }

    public event EventHandler? NetworkChanged
    {
        add
        {
            lock (_sync)
            {
                _networkChanged += value;
                if (!_hooked && _networkChanged is not null)
                {
                    NetworkChange.NetworkAddressChanged += OnOsNetworkChanged;
                    NetworkChange.NetworkAvailabilityChanged += OnOsAvailabilityChanged;
                    _hooked = true;
                }
            }
        }

        remove
        {
            lock (_sync)
            {
                _networkChanged -= value;
                if (_hooked && _networkChanged is null)
                {
                    Unhook();
                }
            }
        }
    }

    public NetworkSnapshot GetSnapshot()
    {
        var cached = Volatile.Read(ref _cachedSnapshot);
        if (cached is not null && Environment.TickCount64 - Volatile.Read(ref _cachedSnapshotTick) < SnapshotCacheTtlMs)
        {
            return cached;
        }

        var adapters = new List<NetworkAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || IsSystemPseudoTunnel(nic))
            {
                continue;
            }

            try
            {
                adapters.Add(Map(nic));
            }
            catch (NetworkInformationException ex)
            {
                _logger.LogDebug(ex, "Skipping adapter {Name}", nic.Name);
            }
        }

        var routed = new[] { ProbeRouteSource(RouteProbeV4), ProbeRouteSource(RouteProbeV6) };
        var primary = SelectPrimary(adapters, routed.Where(a => a is not null).Cast<IPAddress>().ToList());
        var fresh = new NetworkSnapshot(adapters, primary, ClassifyConnectivity(adapters), DateTimeOffset.Now);
        Volatile.Write(ref _cachedSnapshotTick, Environment.TickCount64);
        Volatile.Write(ref _cachedSnapshot, fresh);
        return fresh;
    }

    internal static bool IsSystemPseudoTunnel(NetworkInterface nic)
    {
        if (nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
        {
            return false;
        }

        var desc = nic.Description ?? string.Empty;
        var name = nic.Name ?? string.Empty;
        return desc.Contains("Teredo", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("isatap", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("6to4", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("IPHTTPS", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("Pseudo-Interface", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Teredo", StringComparison.OrdinalIgnoreCase)
            || name.Contains("isatap", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Picks the adapter that owns the routing-table source address; otherwise the best "up" adapter with a gateway.
    /// </summary>
    internal static NetworkAdapterInfo? SelectPrimary(IReadOnlyList<NetworkAdapterInfo> adapters, IReadOnlyList<IPAddress> routedSources)
    {
        foreach (var source in routedSources)
        {
            var match = adapters.FirstOrDefault(a => a.IsUp && a.IPv4Addresses.Concat(a.IPv6Addresses).Contains(source));
            if (match is not null)
            {
                return match;
            }
        }

        return adapters
            .Where(a => a.IsUp)
            .OrderByDescending(a => a.HasIPv4Gateway || a.HasIPv6Gateway)
            .ThenBy(a => a.Kind == AdapterKind.Virtual)
            .ThenByDescending(a => a.SpeedBitsPerSecond)
            .FirstOrDefault();
    }

    internal static LocalConnectivity ClassifyConnectivity(IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        var up = adapters.Where(a => a.IsUp).ToList();
        if (up.Count == 0)
        {
            return LocalConnectivity.Offline;
        }

        return up.Any(a => a.HasIPv4Gateway || a.HasIPv6Gateway) ? LocalConnectivity.GatewayAvailable : LocalConnectivity.LocalOnly;
    }

    internal static AdapterKind Classify(NetworkInterfaceType type, string description)
    {
        if (description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
            || description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
            || description.Contains("VMware", StringComparison.OrdinalIgnoreCase)
            || description.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
            || description.Contains("TAP-", StringComparison.OrdinalIgnoreCase)
            || description.Contains("WireGuard", StringComparison.OrdinalIgnoreCase))
        {
            return AdapterKind.Virtual;
        }

        return type switch
        {
            NetworkInterfaceType.Tunnel => AdapterKind.Virtual,
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.Ethernet3Megabit or NetworkInterfaceType.FastEthernetT
                or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.GigabitEthernet => AdapterKind.Ethernet,
            NetworkInterfaceType.Wireless80211 => AdapterKind.WiFi,
            NetworkInterfaceType.Wman or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => AdapterKind.Cellular,
            _ => AdapterKind.Other,
        };
    }

    private static NetworkAdapterInfo Map(NetworkInterface nic)
    {
        var props = nic.GetIPProperties();
        var unicast = props.UnicastAddresses.Select(u => u.Address).ToList();
        long speed;
        try
        {
            speed = nic.Speed;
        }
        catch (PlatformNotSupportedException)
        {
            speed = -1;
        }

        return new NetworkAdapterInfo
        {
            Id = nic.Id,
            Name = nic.Name,
            Description = nic.Description,
            Kind = Classify(nic.NetworkInterfaceType, nic.Description),
            Status = nic.OperationalStatus,
            SpeedBitsPerSecond = speed,
            IPv4Addresses = unicast.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList(),
            IPv6Addresses = unicast.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).ToList(),
            Gateways = props.GatewayAddresses.Select(g => g.Address).ToList(),
            DnsServers = props.DnsAddresses.ToList(),
        };
    }

    private static IPAddress? ProbeRouteSource(IPEndPoint target)
    {
        try
        {
            using var socket = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(target);
            return (socket.LocalEndPoint as IPEndPoint)?.Address;
        }
        catch (SocketException)
        {
            return null; // No route for this address family.
        }
    }

    private void OnOsNetworkChanged(object? sender, EventArgs e)
    {
        Volatile.Write(ref _cachedSnapshot, null);
        try
        {
            _debounce.Change(DebounceDelay, Timeout.InfiniteTimeSpan);
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private void OnOsAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
    {
        Volatile.Write(ref _cachedSnapshot, null);
        try
        {
            _debounce.Change(DebounceDelay, Timeout.InfiniteTimeSpan);
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private void Unhook()
    {
        NetworkChange.NetworkAddressChanged -= OnOsNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnOsAvailabilityChanged;
        _hooked = false;
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_hooked)
            {
                Unhook();
            }

            _networkChanged = null;
        }

        _debounce.Dispose();
    }
}
