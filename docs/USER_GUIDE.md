# JustCryptDns User Guide

## 1. Quick Start
1. Launch **JustCryptDns**.
2. Open **DNS Manager** and verify your local proxy endpoint (default `127.0.0.1:53`). If another DNS service is already listening on port 53, JustCryptDns detects the conflict automatically and suggests a free alternate port.
3. Click **Start DNS engine** to activate the local encrypted DNS proxy.
4. Click **Test resolver** to verify live end-to-end resolution and view measured latency.
5. (Optional) Enable **Configure Windows adapter automatically** to route Windows DNS queries through JustCryptDns. Your original DNS configuration is always backed up with SHA-256 verification before any change is applied.

## 2. Resolver Library
- Includes 28 curated endpoints across **Cloudflare**, **Google Public DNS**, **Quad9**, **OpenDNS**, **AdGuard DNS**, **Control D**, **NextDNS**, **Mullvad DNS**, and **DNS0** supporting DoH, DoT, DNSCrypt (`sdns://`), and UDP/TCP.
- Add, edit, validate, and group custom resolvers, set **Primary** and **Secondary failover** resolvers, run single or batch live health checks, and export/import JSON resolver profiles.

## 3. Smart DNS Routing
- Create prioritized domain routing rules using **Exact**, **Domain & subdomains**, or **Wildcard (`*`)** patterns.
- Switch between built-in **Gaming**, **Privacy**, **Security**, and **Custom** profiles or create your own.
- Use the **Interactive rule tester** to verify which rule and resolver handle any domain before applying changes.
- Note: Smart Routing operates strictly at the DNS domain level.

## 4. DNS Filtering & TTL Cache
- Enable or update **Advertising**, **Tracking**, **Malware**, **Phishing**, and **Telemetry** blocklists, or import custom `hosts` files.
- Add permanent **Allowlist** entries or **30-minute temporary exceptions**.
- Essential Windows connectivity, update, time-sync, and sign-in domains are protected by the built-in **Windows Service Guard** so they are never silently broken.
- Manage the lightweight positive/negative **TTL DNS Cache** and clear it on demand.

## 5. Gaming Optimization
- Run the **Multi-domain resolver benchmark** to measure average, min, max, P95 latency, jitter, success rate, timeout rate, and reliability score across multiple gaming domains.
- Choose **Lowest Latency**, **Balanced**, or **Maximum Reliability**, or override manually.
- Enable **Gaming Mode** to activate platform routing rules (**Steam**, **Riot Games**, **Epic Games**, **EA Games**, **Ubisoft Connect**, **Battle.net**, **General Gaming**, or **Custom**), keep the DNS cache warm, and pin the active resolver during gaming sessions.
- **Technical note:** DNS latency only affects hostname lookup before connecting to a game server; it does not reduce established in-game ping.

## 6. Network Diagnostics & Live Monitor
- Inspect **Local Adapter & Engine Diagnostics** separately from **External Tests** (A/AAAA/CNAME/MX/TXT/NS Lookup, DNSSEC test, DoH test, DNSCrypt test, DNS Leak check, UDP/TCP 53 restriction scan, Resolver Comparison, and Global Propagation).
- Watch real-time queries and failover events in the virtualized **Live Monitor**.

## 7. Appearance, System Tray & Resource Optimization
- Open **Settings → Customize appearance** to configure Dark/Light/System/Custom themes, window transparency (0–90 %), Windows 11 Mica/Acrylic or Windows 10 DWM Blur, accent colors, UI scaling (80–150 %), font size, density, and motion.
- Configure **Close button behavior** (Minimize to tray, Exit, or Ask every time), **Start with Windows**, **Monitoring mode** (Power Saving / Balanced / Performance), and **Developer performance diagnostics** in **Settings**.
