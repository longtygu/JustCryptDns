using System.Net;
using JustCryptDns.Core.Models;

namespace JustCryptDns.DNS.Proxy;

/// <summary>
/// Evaluates active network adapters for VPN tunnels and probes for HTTP captive portals
/// so the local DNS engine can safely defer or re-apply adapter configuration.
/// </summary>
public static class NetworkAdaptationEvaluator
{
    public const string CaptivePortalProbeUrl = "http://www.msftconnecttest.com/connecttest.txt";
    public const string ExpectedConnectTestBody = "Microsoft Connect Test";

    private static readonly string[] VpnMarkers =
    [
        "WireGuard",
        "CloudflareWARP",
        "Wintun",
        "OpenVPN",
        "TAP-Windows",
        "Tailscale",
        "ZeroTier",
        "AnyConnect",
        "Fortinet",
        "NordLynx",
        "ProtonVPN",
        "Mullvad",
        "Surfshark",
        "ExpressVPN",
        "WARP",
        "VPN",
    ];

    public static NetworkAdapterInfo? DetectActiveVpnAdapter(NetworkSnapshot? snapshot)
    {
        if (snapshot is null)
        {
            return null;
        }

        foreach (var adapter in snapshot.Adapters)
        {
            if (!adapter.IsUp || (adapter.IPv4Addresses.Count == 0 && adapter.IPv6Addresses.Count == 0))
            {
                continue;
            }

            if (IsVpnAdapter(adapter))
            {
                return adapter;
            }
        }

        return null;
    }

    public static bool IsVpnAdapter(NetworkAdapterInfo adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var combined = $"{adapter.Name} {adapter.Description}";
        foreach (var marker in VpnMarkers)
        {
            if (combined.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return adapter.Kind == AdapterKind.Virtual
            && (combined.Contains("TUN", StringComparison.OrdinalIgnoreCase)
                || combined.Contains("PPP", StringComparison.OrdinalIgnoreCase))
            && !combined.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
            && !combined.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
            && !combined.Contains("VMware", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsCaptivePortalHttpResponse(HttpStatusCode statusCode, string? body)
    {
        var code = (int)statusCode;
        if (code is >= 300 and < 400)
        {
            return true;
        }

        return statusCode == HttpStatusCode.OK
            && !string.Equals(body?.Trim(), ExpectedConnectTestBody, StringComparison.Ordinal);
    }

    public static async Task<bool> CheckCaptivePortalAsync(
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        HttpClientHandler? ownedHandler = null;
        HttpClient? ownedClient = null;
        try
        {
            var client = httpClient;
            if (client is null)
            {
                ownedHandler = new HttpClientHandler { AllowAutoRedirect = false };
                ownedClient = new HttpClient(ownedHandler) { Timeout = TimeSpan.FromMilliseconds(2500) };
                client = ownedClient;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMilliseconds(2500));

            using var response = await client
                .GetAsync(CaptivePortalProbeUrl, HttpCompletionOption.ResponseContentRead, cts.Token)
                .ConfigureAwait(false);

            string? body = null;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                body = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            }

            return IsCaptivePortalHttpResponse(response.StatusCode, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or InvalidOperationException)
        {
            return false;
        }
        finally
        {
            ownedClient?.Dispose();
            ownedHandler?.Dispose();
        }
    }
}
