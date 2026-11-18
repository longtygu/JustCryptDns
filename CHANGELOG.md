# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
