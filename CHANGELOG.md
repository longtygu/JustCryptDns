# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Phase 6 — Smart DNS Routing
- **Domain-based routing matcher (`RoutingMatcher`):** supports `Exact`, `DomainSuffix` (root domain + subdomains), and `Wildcard` (`*.domain.com`, `ads.*`, etc.) matching with pattern validation.
- **Smart DNS routing service (`DnsRoutingService`, `IDnsRoutingService`):**
  - Built-in routing profiles (**Gaming**, **Privacy**, **Security**, **Custom**) with starter domain rules (Steam, Riot Games, Epic Games, Battle.net, Wikipedia, Microsoft Identity, etc.) plus user-created custom profiles and per-profile fallback resolver configuration.
  - Prioritized rule evaluation (`Priority` ascending, then match specificity, then pattern length), rule enable/disable, and bounded thread-safe routing decision log (`MaxLogEntries = 200`).
- **Live proxy integration (`DnsEngineService`):** inspects incoming DNS queries by domain, dispatches each query to its matched rule's upstream resolver (or profile fallback resolver), and logs the real routing decision and latency.
- **Smart Routing UI (`RoutingView`, `RoutingViewModel`):** profile & fallback selector, visual rule editor, interactive domain rule tester, live routing log, schema v6 (`MigrationV5ToV6`), and 87 offline unit tests.

### Phase 5 — Resolver Management & Provider Library
- **Complete predefined resolver catalog (`BuiltInResolvers`):** 27 curated endpoints across all 9 required providers (**Cloudflare**, **Google Public DNS**, **Quad9**, **OpenDNS**, **AdGuard DNS**, **Control D**, **NextDNS**, **Mullvad DNS**, **DNS0**) covering DoH, DoT, DNSCrypt (`sdns://`), and UDP/TCP with accurate IPv4, secondary IPv4, IPv6, port, DNSSEC, No-Log policy, ECS, and filtering capability metadata (`None`, `Malware`, `AdsAndTrackers`, `Family`).
- **Resolver validation (`ResolverValidator`):** validates IPv4/IPv6 addresses, port ranges, HTTPS URIs for DoH, TLS hostnames for DoT, IP addresses for UDP/TCP, and decodes/verifies `sdns://` Base64URL stamps and protocol bytes for DNSCrypt.
- **Resolver Library service (`ResolverLibraryService`, `IResolverLibraryService`):**
  - Full CRUD for custom resolvers (`AddCustomResolverAsync`, `UpdateResolverAsync`, `RemoveCustomResolverAsync`), enable/disable per resolver, primary and secondary failover resolver assignment with pre-activation validation, and built-in + custom resolver groups (`General`, `Privacy`, `Security`, `Gaming`, `Ad-Blocking`, plus user-created groups).
  - JSON resolver profile export and validated import (`ExportProfileJson`, `ImportProfileJsonAsync`).
  - Live health & reliability checks (`CheckHealthAsync`, `CheckAllEnabledHealthAsync`) computing real latency and a `0–100%` reliability score from probe success rate and latency responsiveness.
- **Resolver Library UI (`ResolverLibraryView`, `ResolverLibraryViewModel`):** search, group & protocol filtering, inline custom resolver editor, one-click Primary/Secondary assignment integrated with `IDnsEngine`, single & batch health checks, profile import/export dialogs, schema v5 (`MigrationV4ToV5`), and 83 offline unit tests.

### Phase 4 — Core DNS engine & Windows DNS safety integration
- **RFC 1035 wire-format parser & encoder (`DnsPacket`):** bounds-checked header/question/RR parsing with pointer-compression jump cap (`MaxCompressionJumps = 16`), EDNS0 `DO` support, transaction ID rewriting, and synthetic error responses (`SERVFAIL`, `REFUSED`, `NXDOMAIN`).
- **Multi-protocol upstream DNS clients:**
  - **DNS over HTTPS (`DohDnsUpstream`, RFC 8484):** pooled HTTP/2 `SocketsHttpHandler` with direct bootstrap IP connection (`ConnectCallback`) so DoH never loops back through OS DNS.
  - **DNS over TLS (`DotDnsUpstream`, RFC 7858):** port 853 `SslStream` with strict TLS 1.2/1.3 SNI and X.509 certificate verification.
  - **Traditional DNS over UDP/TCP (`UdpTcpDnsUpstream`):** UDP with automatic TCP retry on truncation (`TC=1`).
  - **DNSCrypt v2 (`DnsCryptProxyManager` & `DnsCryptUpstream`):** manages official `dnscrypt-proxy` child process, generates self-contained `dnscrypt-proxy.toml` (including static `sdns://` stamps), detects version, installs/updates from official GitHub releases, and automatically recovers from crashes.
- **Local DNS proxy (`LocalDnsProxy`, `PortConflictDetector`, `DnsLoopGuard`):** UDP/TCP listener on configurable loopback IP/port (default `127.0.0.1:53`, optional `::1`), pre-bind port conflict detection with suggested free port, and self-forwarding DNS loop prevention.
- **6-step Windows Network Safety (`WindowsNetworkDnsService`):** adapter detection, `dns-backup.json` creation with SHA-256 `IntegrityHash` verification, adapter DNS configuration, connectivity verification probe, automatic rollback on failure, Emergency Restore DNS, and startup crash recovery.
- **DNS Manager UI & Dashboard integration:** full **DNS Manager** page and live **Dashboard** engine controls, real query counters and latency, schema v4 (`MigrationV3ToV4`), and 76 offline unit tests.

### Phase 3 — Background service, system tray & startup integration
- **Independent background service (`JustCryptDns.Service`):** Windows Service (`JustCryptDnsService`) and console host built on `Microsoft.Extensions.Hosting.WindowsServices`, with rolling `service-YYYYMMDD.log` logs and graceful shutdown.
- **Secure local IPC (`JustCryptDns.Ipc.v1`):** length-prefixed (256 KB max) versioned JSON protocol over a Named Pipe with explicit `PipeSecurity` ACLs (grants LocalSystem, Administrators, owner, and local AuthenticatedUsers; explicitly denies `NetworkSid`), backed by `NamedPipeIpcServer` and non-blocking `NamedPipeServiceClient`.
- **System tray (`TrayIconService`):** native Win32 `Shell_NotifyIconW` implementation (zero `System.Windows.Forms` overhead) with automatic `TaskbarCreated` recovery and a themed, localized WPF context menu (Open, Enable/Disable DNS, Enable/Disable Gaming Mode, Active resolver, Restore original DNS, Exit).
- **Window close behavior:** configurable `MinimizeToTray`, `ExitApplication`, or `AskEveryTime` (inline themed confirmation modal with "Remember my choice").
- **Windows startup integration (`RegistryStartupService`):** idempotent per-user `HKCU\...\Run` registration (never creates duplicate entries), `--autostart` / `--minimized` / `--show` command-line handling, and startup options in Settings (Start with Windows, Start minimized, Auto-start DNS engine, Restore previous profile, Enable Gaming Mode on startup, live Service connection status).
- **Settings schema v3:** `MigrationV2ToV3` and 69 offline unit tests.

### Phase 2 — Appearance customization & window transparency
- Dedicated **Appearance** settings sub-page (reachable from Settings while keeping Settings highlighted in the sidebar).
- **Theme modes:** Dark, Light, System default, and **Custom** (Dark/Light base palette + surface tint color).
- **Window transparency (0–90 %):** master enable switch, 0–90 % slider with level indicator (Opaque, Slight, Moderate, Strong, High), and readability-preserving surface opacity hierarchy (window background, sidebar, and cards keep progressive opacity so text contrast is always preserved).
- **Windows composition backdrop engine (`WindowBackdropController` + `DwmInterop`):** supports Windows 11 22H2+ `DWMWA_SYSTEMBACKDROP_TYPE` (Mica / Acrylic), Windows 10/11 DWM blur-behind (`SetWindowCompositionAttribute`), immersive dark mode, and Windows 11 `DWM_WINDOW_CORNER_PREFERENCE` with automatic fallback to opaque when unsupported or disabled.
- **Accent color customization:** 12 curated presets, custom `#RRGGBB` / `#RGB` input with validation, optional sync with the Windows system accent color, and WCAG contrast ratio calculation (`ColorMath.ContrastRatio`) for foreground-on-accent legibility.
- **Layout, scaling & motion:** sidebar mode (Expanded / Compact), card density (Compact / Comfortable / Spacious), window corner preference (Windows 11), independent UI scaling (80–150 %), 4-step font size scaling across all typography tokens, animation intensity (Off / Reduced / Normal), background style (Plain / Accent glow), and one-click reset to defaults.
- **Settings schema v2:** `MigrationV1ToV2`, debounced persistence (`UpdateDeferred` + `FlushAsync` on exit) for smooth slider dragging without excessive disk writes, and 63 offline unit tests.
- Added MIT `LICENSE`.

### Phase 1 — Foundation & modern UI
- Solution structure: Core, DNS, Network, Infrastructure, App, Tests.
- WPF shell with custom window chrome, collapsible sidebar and nine navigation sections.
- Dark/Light/System themes with live switching; accent color brush generation with contrast-aware foreground.
- English and Vietnamese localization with runtime language switching.
- Versioned JSON settings (schema v1): atomic writes, `.bak` backup, corruption recovery, newer-schema protection, migration chain.
- Serilog rolling file logging (daily + 5 MB size cap, configurable retention).
- Dashboard with real local adapter information and event-driven (no polling) refresh.
- Honest "Planned · Phase N" pages for modules not yet implemented.
- Single-instance guard with window activation.
- 38 offline unit tests.
