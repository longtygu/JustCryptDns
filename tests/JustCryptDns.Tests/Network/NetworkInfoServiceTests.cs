using System.Net;
using System.Net.NetworkInformation;
using JustCryptDns.App.ViewModels;
using JustCryptDns.Core.Models;
using JustCryptDns.Network.Monitoring;

namespace JustCryptDns.Tests.Network;

public sealed class NetworkInfoServiceTests
{
    private static NetworkAdapterInfo Adapter(
        string name,
        OperationalStatus status = OperationalStatus.Up,
        string[]? v4 = null,
        string[]? v6 = null,
        string[]? gateways = null,
        AdapterKind kind = AdapterKind.Ethernet,
        long speed = 1_000_000_000) => new()
        {
            Id = name,
            Name = name,
            Description = name,
            Kind = kind,
            Status = status,
            SpeedBitsPerSecond = speed,
            IPv4Addresses = (v4 ?? []).Select(IPAddress.Parse).ToList(),
            IPv6Addresses = (v6 ?? []).Select(IPAddress.Parse).ToList(),
            Gateways = (gateways ?? []).Select(IPAddress.Parse).ToList(),
        };

    [Fact]
    public void SelectPrimary_PrefersAdapterOwningRoutedSource()
    {
        var eth = Adapter("eth", v4: ["192.168.1.10"], gateways: ["192.168.1.1"]);
        var wifi = Adapter("wifi", v4: ["10.0.0.5"], gateways: ["10.0.0.1"], kind: AdapterKind.WiFi, speed: 100);

        var primary = NetworkInfoService.SelectPrimary([eth, wifi], [IPAddress.Parse("10.0.0.5")]);

        Assert.Same(wifi, primary);
    }

    [Fact]
    public void SelectPrimary_WithoutRoute_PrefersGatewayAndPhysical()
    {
        var virt = Adapter("vEthernet", v4: ["172.20.0.1"], gateways: ["172.20.0.254"], kind: AdapterKind.Virtual, speed: 10_000_000_000);
        var noGw = Adapter("lan2", v4: ["169.254.3.3"]);
        var eth = Adapter("eth", v4: ["192.168.1.10"], gateways: ["192.168.1.1"]);
        var down = Adapter("down", status: OperationalStatus.Down, v4: ["192.168.5.5"], gateways: ["192.168.5.1"]);

        var primary = NetworkInfoService.SelectPrimary([down, virt, noGw, eth], []);

        Assert.Same(eth, primary);
    }

    [Fact]
    public void SelectPrimary_NothingUp_ReturnsNull()
    {
        Assert.Null(NetworkInfoService.SelectPrimary([Adapter("a", status: OperationalStatus.Down)], []));
    }

    [Theory]
    [InlineData(OperationalStatus.Down, null, LocalConnectivity.Offline)]
    [InlineData(OperationalStatus.Up, null, LocalConnectivity.LocalOnly)]
    [InlineData(OperationalStatus.Up, "192.168.1.1", LocalConnectivity.GatewayAvailable)]
    public void ClassifyConnectivity(OperationalStatus status, string? gateway, LocalConnectivity expected)
    {
        var adapter = Adapter("a", status, v4: ["192.168.1.2"], gateways: gateway is null ? [] : [gateway]);
        Assert.Equal(expected, NetworkInfoService.ClassifyConnectivity([adapter]));
    }

    [Fact]
    public void ZeroGateway_IsNotTreatedAsGateway()
    {
        var adapter = Adapter("a", gateways: ["0.0.0.0"]);
        Assert.False(adapter.HasIPv4Gateway);
    }

    [Theory]
    [InlineData(NetworkInterfaceType.Ethernet, "Intel(R) Ethernet Connection", AdapterKind.Ethernet)]
    [InlineData(NetworkInterfaceType.Wireless80211, "Intel(R) Wi-Fi 6 AX201", AdapterKind.WiFi)]
    [InlineData(NetworkInterfaceType.Ethernet, "Hyper-V Virtual Ethernet Adapter", AdapterKind.Virtual)]
    [InlineData(NetworkInterfaceType.Unknown, "WireGuard Tunnel", AdapterKind.Virtual)]
    public void Classify_AdapterKinds(NetworkInterfaceType type, string description, AdapterKind expected)
    {
        Assert.Equal(expected, NetworkInfoService.Classify(type, description));
    }

    [Fact]
    public void IpStatus_Evaluation()
    {
        Assert.Equal(IpFamilyStatus.None, DashboardViewModel.EvaluateIPv4(null));
        Assert.Equal(IpFamilyStatus.LinkLocal, DashboardViewModel.EvaluateIPv4(Adapter("a", v4: ["169.254.10.1"])));
        Assert.Equal(IpFamilyStatus.Configured, DashboardViewModel.EvaluateIPv4(Adapter("a", v4: ["192.168.1.2"])));
        Assert.Equal(IpFamilyStatus.LinkLocal, DashboardViewModel.EvaluateIPv6(Adapter("a", v6: ["fe80::1"])));
        Assert.Equal(IpFamilyStatus.Global, DashboardViewModel.EvaluateIPv6(Adapter("a", v6: ["fe80::1", "2001:db8::5"])));
    }
}
