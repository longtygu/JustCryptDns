# JustCryptDns User Guide

## 1. Quick Start & Service Unification
1. Launch **JustCryptDns** (when installed with **JustCryptDns Background Service**, the desktop UI automatically connects over named-pipe IPC so UI and Service share one DNS engine, one DPI Bypass proxy, and one configuration store in `%ProgramData%\JustCryptDns`).
2. Open **DNS Manager** and verify your local proxy endpoint (default `127.0.0.1:53`). If another DNS service is already listening on port 53, JustCryptDns detects the conflict automatically and suggests a free alternate port.
3. Click **Start DNS engine** to activate the local encrypted DNS proxy. If you ever switch to an unencrypted `UDP/TCP` resolver, **Dashboard** and **DNS Manager** display a warning banner with a one-click **Switch to Cloudflare (DoH)** button.
4. Click **Test resolver** to verify live end-to-end resolution and view measured latency.
5. (Optional) Enable **Configure Windows adapter automatically** to route Windows DNS queries through JustCryptDns. Your original DNS configuration is always backed up with SHA-256 verification before any change is applied.
6. Portable ZIP builds include `portable.flag` beside `JustCryptDns.exe` so settings, logs, backups, and managed engines remain self-contained in `<AppDir>\data`.

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

## 6. All-Website Smart DPI Bypass & Split-Tunnel
- JustCryptDns v1.2.0 includes a pure-C# local smart proxy (`127.0.0.1:10808` supporting HTTP CONNECT and SOCKS5) and local **Auto-PAC** server (`http://127.0.0.1:10809/proxy.pac`).
- **All Websites (Smart Auto-PAC) Coverage:** By default (`AllWebsitesSmart`), **every external website** is protected automatically without adding manual rules, while LAN/RFC1918 networks (`10.*`, `172.16-31.*`, `192.168.*`), `.local`/`.lan`, banking/intranet **Direct Exclusions**, and **PC game match UDP/TCP sockets** remain 100% direct (`0 ms` ping overhead). You can switch to **Rule List Only** anytime.
- **4-Stage Self-Healing Cascade:**
  1. Primary TLS/HTTP fragmentation (40B TLS chunks / HTTP `Host:` split) via encrypted DNS.
  2. Automatic 16B aggressive TLS escalation if stricter DPI drops the initial attempt.
  3. Instant self-healing Direct Unfragmented recovery if a legacy/banking server rejects split `ClientHello` packets (or if TLS handshake stalls over fragmentation when TCP connect is fast).
  4. Tier 2 Split-Tunnel fallback (**Cloudflare WARP local SOCKS5** on `127.0.0.1:40000`, SOCKS5, or HTTP CONNECT) for IP/geo-blocked sites, with 30-minute adaptive host learning and 1-click pinning/exclusion.
  - To prepare Cloudflare WARP without affecting game ping: run `warp-cli mode proxy` and `warp-cli connect`, then click **Detect Cloudflare WARP** inside **DPI Bypass & Tunnel**.
- Original Windows WinINet proxy settings are backed up per-user with SHA-256 verification to `%LOCALAPPDATA%\JustCryptDns\proxy-backup.json` (or `<AppDir>\data\proxy-backup.json` in portable mode) and synchronized cleanly by the desktop UI even when **JustCryptDnsService** runs under `LocalSystem`.

## 7. Network Diagnostics, Browser DoH Audit & Live Monitor
- Inspect **Local Adapter & Engine Diagnostics** separately from **External Tests** (A/AAAA/CNAME/MX/TXT/NS Lookup, DNSSEC test, DoH test, DNSCrypt test, DNS Leak check, UDP/TCP 53 restriction scan, Resolver Comparison, and Global Propagation).
- **Browser DoH Bypass Audit:** Scan Chrome, Edge, and Firefox Windows Registry policies and local Firefox DoH canary status (`use-application-dns.net`) from **Diagnostics → Check Browser DoH Policies**.

## 8. Batch 2 Upgrades (v1.7.0)
- **Persistent DoT Connection Pooling & Pipelining:** TLS 1.3 / DoT queries reuse pooled persistent connections with concurrent transaction ID pipelining and automatic idle reconnect recovery.
- **RFC 8767 Serve-Stale & Background Prefetch Cache:** Optionally serves stale cached DNS answers (30s TTL) during transient upstream outages and refreshes popular domains near TTL expiry (configured under **DNS Filtering & Cache**).
- **Network Adaptation, VPN Deferral & Captive Portal Pause:** Automatically adapts when Wi-Fi/Ethernet adapters switch, defers Windows adapter DNS cleanly when an active VPN tunnel (e.g., WireGuard, WARP, Tailscale, OpenVPN) is detected, and offers a **Pause 5 min (Captive Portal)** / **Resume DNS Protection** toggle when signing in on public Wi-Fi portals.
- **Firefox DoH Canary Guard:** Enabled by default under **DNS Manager**; returns `NXDOMAIN` for `use-application-dns.net` so Firefox honors local encrypted DNS filtering and routing rules.
- **Local DNS Rewrites:** Map exact or `*.wildcard` domains directly to custom `A`, `AAAA`, or `CNAME` records under **Smart DNS Routing → Local DNS Rewrites**.
- **UI & Navigation Enhancements:**
  - **Grouped Sidebar & Security Alert Badge** alongside a **Global Security Strip** (`DNS`, `DPI`, `Leak Guard`, `Lockdown`) in the top bar.
  - **Quick Command Palette (`Ctrl+K`):** Jump to any page or run common toggles/actions via keyboard.
  - **Connection Monitor Inspector Drawer:** Select any row in **Connections** to inspect process binary details, remote endpoint, organization, signature/threat status, edit notes inline, and apply firewall actions.
  - **Tray Mini Control Center:** Single-click the system tray icon for quick toggles (Encrypted DNS, DPI Bypass, Game Mode, Emergency Lockdown, Captive Portal pause, Flush Cache), double-click to open the main window, or right-click for the classic context menu.
- Watch real-time queries and failover events in the virtualized **Live Monitor**.

## 8. Appearance, System Tray & Resource Optimization
- Open **Settings → Customize appearance** to configure Dark/Light/System/Custom themes, window transparency (0–90 %), Windows 11 Mica/Acrylic or Windows 10 DWM Blur, accent colors, UI scaling (80–150 %), font size, density, and motion.
- Configure **Close button behavior** (Minimize to tray, Exit, or Ask every time), **Start with Windows**, **Monitoring mode** (Power Saving / Balanced / Performance), and **Developer performance diagnostics** in **Settings**.
