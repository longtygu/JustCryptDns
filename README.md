# JustCryptDns

Advanced DNS security, smart routing and gaming DNS optimization suite for Windows 10 22H2 / Windows 11 (x64).

> **Status: early development (Phase 1 of 12).** The application shell, theming, localization, settings and
> local network information work. The DNS engine itself (DoH/DoT/DNSCrypt, local proxy) arrives in Phase 4.
> Pages for modules not yet built show an explicit *"Planned · Phase N"* notice and never display fabricated data.

## Features implemented so far

| Area | Status |
|---|---|
| Modern WPF shell (custom chrome, collapsible sidebar, 9 sections) | ✅ |
| Dark / Light / System theme, runtime switching, accent color engine | ✅ |
| English / Vietnamese UI, switchable without restart | ✅ |
| Versioned JSON settings with atomic save, backup, corruption recovery and migration | ✅ |
| Rolling, size-capped logs (Serilog) | ✅ |
| Dashboard: real local adapter info (adapter, IP, gateway, current DNS, IPv4/IPv6), event-driven refresh | ✅ |
| Single-instance guard (second launch activates the first window) | ✅ |
| Appearance page, window transparency (Acrylic / Mica / blur) | Phase 2 |
| Background service, tray, startup | Phase 3 |
| DNS engine | Phase 4+ |

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
src/JustCryptDns.Infrastructure  Windows integration, storage, logging
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

To be decided (see open decisions in the roadmap).
