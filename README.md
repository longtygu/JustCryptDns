# JustCryptDns

Advanced DNS security, smart routing and gaming DNS optimization suite for Windows 10 22H2 / Windows 11 (x64).

> **Status: active development (Phase 10 of 12).** All 9 main application sections are now live and functional:
> Dashboard, DNS Manager, Resolver Library, Smart Routing, Gaming Optimization, DNS Filtering & Cache, Network Diagnostics, Live Monitor, and Settings + Appearance.
> No section displays fabricated data or simulated DNS responses.

## Features implemented so far

| Area | Status |
|---|---|
| Modern WPF shell (custom chrome, collapsible sidebar, 9 sections) | ✅ |
| Dark / Light / System / Custom theme, runtime switching, WCAG-checked accent color engine | ✅ |
| Window transparency (0–90 %) with Windows 11 Mica/Acrylic & Windows 10 DWM Blur + graceful fallback | ✅ |
| Dedicated Appearance page (accent presets & hex input, Windows accent sync, UI scale 80–150 %, font size, card density, animation intensity, window corners, background glow, reset) | ✅ |
| Independent background service (`JustCryptDns.Service`) + ACL-secured Named Pipe IPC (`JustCryptDns.Ipc.v1`) | ✅ |
| System tray icon (`Shell_NotifyIconW`, no WinForms) with themed context menu & close behavior (Minimize to tray / Exit / Ask every time) | ✅ |
| Windows startup integration (`HKCU\...\Run`, idempotent, `--minimized` support) | ✅ |
| Core DNS engine: DNS over HTTPS (RFC 8484), DNS over TLS (RFC 7858), DNSCrypt v2 (`dnscrypt-proxy`), and UDP/TCP | ✅ |
| Local DNS proxy (`127.0.0.1`, configurable IP/port, IPv4 & IPv6, port conflict detection & DNS loop guard) | ✅ |
| Windows adapter DNS integration & 6-step safety (backup, SHA-256 check, apply, probe, auto-rollback, emergency restore, crash recovery) | ✅ |
| Complete Resolver Library: Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D, NextDNS, Mullvad, DNS0 + custom resolvers, groups, validation, JSON profile import/export & live health checks | ✅ |
| Smart DNS Routing: domain-based rules (Exact, Domain & Subdomains, Wildcard), priority order, Gaming/Privacy/Security/Custom profiles, fallback resolver, visual rule editor, rule tester & live routing log | ✅ |
| DNS Filtering & TTL Cache: Advertising/Tracking/Malware/Phishing/Telemetry/Custom blocklists, hosts import, allowlist, temporary exceptions, essential Windows domain guard, decision inspector & TTL-aware positive/negative cache | ✅ |
| Gaming Low Latency Engine: repeated multi-domain benchmark (avg, min, max, P95, jitter, success/timeout rate, reliability score), 3 optimization profiles, 8 built-in + custom gaming profiles, and Gaming Mode with session pinning | ✅ |
| Network Resilience & Failover: Primary/Secondary & encrypted failover policies, configurable retries, failure classification (UDP/53, TCP/53, DoH, DoT, DNSCrypt, IPv4/IPv6) & failover event history | ✅ |
| Network Diagnostics & Virtualized Live Monitor: A/AAAA/CNAME/MX/TXT/NS lookup, DNSSEC/DoH/DNSCrypt/leak/propagation/restriction tests, clearly separated local vs. external results, and recycling virtualized live query & failover monitor | ✅ |
| English / Vietnamese UI, switchable without restart | ✅ |
| Versioned JSON settings (schema v9) with atomic save, backup, corruption recovery and migration | ✅ |
| Rolling, size-capped logs (Serilog) | ✅ |
| Single-instance guard (second launch activates the first window) | ✅ |
| Extreme Resource Optimization (Monitoring Modes & Perf Diagnostics) and Release Packaging (Inno Setup + Portable ZIP) | Phase 11–12 |

See the full roadmap in [docs/ROADMAP.md](docs/ROADMAP.md).

## Building

Requirements: .NET SDK 8.0 or newer (the projects target `net8.0` / `net8.0-windows`), Windows 10/11 x64.

```powershell
dotnet build JustCryptDns.sln
dotnet test  JustCryptDns.sln
dotnet run --project src/JustCryptDns.App
```

## Solution layout

```
src/JustCryptDns.Core            Models, interfaces, settings schema + migration (no Windows/UI dependencies)
src/JustCryptDns.DNS             DNS engine (Phase 4+)
src/JustCryptDns.Network         Network information, benchmark, failover, monitoring
src/JustCryptDns.Infrastructure  Windows integration, IPC, startup, storage, logging
src/JustCryptDns.Service         Independent Windows Service / background host
src/JustCryptDns.App             WPF UI (MVVM, CommunityToolkit.Mvvm)
tests/JustCryptDns.Tests         xUnit tests (offline)
tools/                           Developer scripts (string table, icon, window diagnostics)
```

## Data locations

| What | Where |
|---|---|
| Settings | `%LOCALAPPDATA%\JustCryptDns\settings.json` (+ `settings.json.bak`) |
| Logs | `%LOCALAPPDATA%\JustCryptDns\logs\ui-YYYYMMDD.log` (5 MB cap per file, 7 days by default) |

No telemetry is collected. Nothing leaves the computer.

## Developer notes

* **UI strings** live in `tools/strings.tsv` (key | English | Vietnamese). Edit it and run
  `tools/Generate-Strings.ps1` to regenerate `Strings.resx` / `Strings.vi.resx`. Tests verify key parity,
  placeholders, and that every key used in XAML exists.
* Environment variables for development:

| Variable | Effect |
|---|---|
| `JUSTCRYPTDNS_DATA_DIR` | Use a different data folder (portable mode / testing) |
| `JUSTCRYPTDNS_SOFTWARE_RENDER=1` | Force WPF software rendering |
| `JUSTCRYPTDNS_SNAPSHOT_DIR` | Render pages to PNG after startup (`JUSTCRYPTDNS_SNAPSHOT_PAGES`, `JUSTCRYPTDNS_SNAPSHOT_SUFFIX`) |

## License

Released under the [MIT License](LICENSE).
