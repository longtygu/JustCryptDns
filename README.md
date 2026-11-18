# JustCryptDns

Advanced DNS security, smart routing and gaming DNS optimization suite for Windows 10 22H2 / Windows 11 (x64).

> **Status: active development (Phase 7 of 12).** The core DNS engine (DoH, DoT, DNSCrypt via `dnscrypt-proxy`, UDP/TCP),
> complete Resolver Library (9 predefined providers across DoH, DoT, DNSCrypt & UDP/TCP, custom resolver CRUD, `sdns://` stamp & endpoint validation, primary/secondary assignment, resolver groups, profile import/export, live health & reliability checks),
> Smart DNS Routing (domain-based Exact, Domain Suffix & Wildcard matching, prioritized rules, Gaming/Privacy/Security/Custom profiles, fallback resolver, interactive rule tester & live routing logs),
> DNS Filtering & TTL Cache (Advertising, Tracking, Malware, Phishing, Telemetry & Custom blocklists, hosts-file import, allowlist, temporary exceptions, essential Windows service guard, decision inspector, and TTL-aware positive/negative DNS response cache),
> local DNS proxy (`127.0.0.1` with port conflict & DNS loop detection), 6-step Windows network adapter DNS safety integration
> (backup, SHA-256 verification, connectivity probe, automatic rollback, emergency restore, crash recovery),
> background service (`JustCryptDns.Service`), Named Pipe IPC, system tray integration, Windows startup registration,
> window transparency (Mica / Acrylic / DWM Blur), appearance customization, and localization work.
> Pages for modules scheduled in Phase 8+ show an explicit *"Planned · Phase N"* notice and never display fabricated data.

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
| English / Vietnamese UI, switchable without restart | ✅ |
| Versioned JSON settings (schema v7) with atomic save, backup, corruption recovery and migration | ✅ |
| Rolling, size-capped logs (Serilog) | ✅ |
| Dashboard & DNS Manager: live DNS engine controls, real latency, blocked query & cache hit counters, local adapter status | ✅ |
| Single-instance guard (second launch activates the first window) | ✅ |
| Gaming Low Latency Engine, Network Resilience & Failover, Diagnostics & Live Monitor | Phase 8+ |

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
