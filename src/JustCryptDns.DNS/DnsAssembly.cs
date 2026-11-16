namespace JustCryptDns.DNS;

/// <summary>
/// Assembly marker for the DNS engine library.
/// Protocol clients, local proxy, routing, filtering, cache and dnscrypt-proxy management are added from Phase 4 onward.
/// </summary>
public static class DnsAssembly
{
    public static string Name => typeof(DnsAssembly).Assembly.GetName().Name!;
}
