# JustCryptDns

Advanced DNS security, smart routing and gaming DNS optimization suite for Windows 10 22H2 / Windows 11 (x64).

> **Status: v1.0.0 Release Ready (12 of 12 phases complete).** All 9 main application sections, the core DNS engine,
> Resolver Library, Smart DNS Routing, DNS Filtering & TTL Cache, Gaming Low Latency Engine, Network Resilience & Failover,
> Network Diagnostics, Virtualized Live Monitor, Appearance & Window Transparency, Background Windows Service, System Tray,
> Resource Optimization, and Release Packaging (self-contained `win-x64` portable ZIP + Inno Setup installer) are implemented and verified.

## Features

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
| Extreme Resource Optimization: Power Saving / Balanced / Performance monitoring modes, Developer Performance Diagnostics, automatic tray working-set trimming | ✅ |
| English / Vietnamese UI, switchable without restart | ✅ |
| Versioned JSON settings (schema v10) with atomic save, backup, corruption recovery and migration | ✅ |
| Rolling, size-capped logs (Serilog) | ✅ |
| Single-instance guard (second launch activates the first window) | ✅ |
| Self-contained `win-x64` Release build, portable ZIP + SHA-256 checksums, Inno Setup installer (`installer/JustCryptDns.iss`), User Guide & Troubleshooting Guide | ✅ |

See documentation:
- [User Guide](docs/USER_GUIDE.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- [Performance & Resource Measurements](docs/PERFORMANCE.md)
- [Architecture & Roadmap](docs/ROADMAP.md)
- [Third-Party Notices](THIRD-PARTY-NOTICES.md)

## Building & Release Packaging

Requirements: .NET SDK 8.0 or newer (the projects target `net8.0` / `net8.0-windows`), Windows 10 22H2 / Windows 11 x64.

```powershell
dotnet build JustCryptDns.sln -c Release
dotnet test  JustCryptDns.sln -c Release
dotnet run --project src/JustCryptDns.App

# Build self-contained win-x64 release, portable ZIP, SHA-256 checksums, and Inno Setup installer:
.\tools\Build-Release.ps1
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
