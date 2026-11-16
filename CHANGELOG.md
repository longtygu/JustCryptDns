# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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
