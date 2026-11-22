# Design Specification: Query Explorer & Analytics + 5-Mode Operation Switcher (`v1.8.0`)

**Date:** 2026-11-23  
**Target Version:** `1.8.0` (Schema Version `18` → `19`)  
**Status:** Draft for User Review  

---

## 1. Goals & Scope

This specification unifies two major upgrades to JustCryptDns:

1. **Feature 1 — Query Explorer & Analytics (Upgrading `Live Monitor`):**
   - Transform `Live Monitor` from a small 300–500 item feed into a full DNS query inspection, analytics, and management tool capable of diagnosing high query volumes (e.g., 2,000+ queries/hour) and taking immediate 1-click actions.
   - Support both **Standalone** and **Windows Service (Named Pipe IPC)** execution modes without exceeding IPC frame limits or causing UI lag.
2. **Feature 2 — Seamless 5-Mode Operation Switcher Bar on Dashboard + Per-Mode Customization:**
   - Add a seamless 5-switch segmented control directly beneath the 5-gauge cluster (`UniformGrid x:Name="Metrics"`) on `DashboardView.xaml` in the exact order:
     `[ Tốc độ cao ] — [ Chế độ Game ] — [ Cân bằng ] — [ Tự động ] — [ Bảo mật ]`.
   - Smooth sliding transition animation across the continuous track, with a luminous glowing/pulsing indicator on whichever mode switch is currently active.
   - Snapshot & restore baseline user preferences when switching modes, never deleting user custom rules, **plus** full per-mode customizability with per-mode reset to defaults.

---

## 2. Feature 1: Query Explorer & Analytics

### 2.1 Enriched Data Models (`JustCryptDns.Core`)

In `src/JustCryptDns.Core/Models/DiagnosticsModels.cs`:

- Extend `LiveQueryMonitorEntry` (all new fields optional with safe defaults for JSON/IPC compatibility):
  - `long SequenceId { get; init; }` — monotonically increasing counter assigned by `NetworkDiagnosticsService`.
  - `string? ResponseCode { get; init; }` — e.g., `NoError`, `NxDomain`, `ServFail`, `Refused`.
  - `string? AnswerSummary { get; init; }` — compact summary extracted from the DNS response packet (e.g., `"142.250.190.46 (+2)"`, `"CNAME -> edge.cdn.net"`, `"NXDOMAIN"`, `"No answers"`).
  - `string? MatchedRule { get; init; }` — exact blocklist name, allowlist entry, local rewrite target, or routing rule name.

- Add session analytics models:
  - `DomainQueryAggregate`:
    - `string Domain`
    - `long TotalCount`, `long BlockedCount`, `long CachedCount`, `long FailedCount`, `long RoutedCount`, `long RewrittenCount`
    - `double AverageLatencyMs`
    - `double QueriesPerMinute` (rolling 60-second window rate)
    - `bool IsHighFrequency` (true when `QueriesPerMinute >= 20` or blocked retry burst `>= 10/min`)
    - `string LastOutcome`, `string LastResolverName`, `string? LastAnswerSummary`
    - `DateTimeOffset LastSeenUtc`
  - `QueryAnalyticsSnapshot`:
    - `DateTimeOffset SessionStartedUtc`
    - `long TotalObservedQueries`
    - `long TotalBlockedQueries`
    - `long TotalCachedQueries`
    - `long TotalFailedQueries`
    - `int UniqueDomainCount`
    - `double CurrentQueriesPerMinute`
    - `IReadOnlyList<DomainQueryAggregate> TopQueried`
    - `IReadOnlyList<DomainQueryAggregate> TopBlocked`
    - `IReadOnlyList<DomainQueryAggregate> TopFailed`

### 2.2 Engine Capture & Bounded Diagnostics Storage

- **`PerformanceSettings.GetMonitorBufferLimit()`** (`AppSettings.cs`):
  - `PowerSaving`: `1000` (was `100`)
  - `Balanced`: `3000` (was `300`)
  - `Performance`: `5000` (was `500`)
- **`DnsEngineService.cs`**:
  - Add a lightweight static helper `ExtractResponseMetadata(ReadOnlySpan<byte> responseWire)` using existing `DnsPacket.TryParse` to extract `ResponseCode` and a concise `AnswerSummary` (up to 2 IP/target records + `(+N)` count) with zero extra network calls.
  - Populate `ResponseCode`, `AnswerSummary`, and `MatchedRule` across all 8 `RecordMonitorEntry` call sites (`Canary`, `Rewritten`, `Blocked`, `Cached`, `Stale`, `Routed`, `Allowed`, `Failed`).
- **`NetworkDiagnosticsService.cs`** & **`INetworkDiagnosticsService.cs`**:
  - Assign monotonic `SequenceId` on every `RecordMonitorEntry`.
  - Maintain a thread-safe bounded per-domain aggregator (`Dictionary<string, DomainAggregateState>`, capped at `4,096` unique domains; when cap is reached, evicts oldest low-count tail entries so memory stays bounded indefinitely).
  - Track a 60-second sliding ring of timestamps per hot domain (and global) to compute real `QueriesPerMinute` and flag retry loops (`IsHighFrequency`).
  - Add methods:
    - `IReadOnlyList<LiveQueryMonitorEntry> GetMonitorEntriesSince(long afterSequenceId, int maxCount = 1000)`
    - `QueryAnalyticsSnapshot GetQueryAnalyticsSnapshot(int topN = 50)`
  - `ClearMonitorEntries()` clears both the ring-buffer and resets the session aggregator.

### 2.3 Windows Service IPC Sync (`IpcContracts.cs`, `ServiceStateManager.cs`)

- Raise `IpcConstants.MaxMessageBytes` from `256 * 1024` to `2 * 1024 * 1024` (2 MB upper bound).
- Enhance `IpcRequestKind.GetLiveQueriesSnapshot`:
  - Accepts optional `StringValue` format `"after=<sequenceId>&limit=<count>"` (default `after=0`, `limit=1000`).
  - `LiveMonitorViewModel` tracks `_lastSyncedSequenceId` and fetches only incremental deltas on each 1.5s poll, merging into its bounded in-memory list (`<= 5,000` entries). Normal polling frames stay `< 10 KB`.
- Add `IpcRequestKind.GetQueryAnalyticsSnapshot`:
  - Returns JSON-serialized `QueryAnalyticsSnapshot` (`topN = 50`, typically `10–25 KB`), polled on the Live Monitor page.

### 2.4 Upgraded `LiveMonitorView` & `LiveMonitorViewModel`

- **Header KPI Strip:** `Session Queries`, `Unique Domains`, `Q/min`, `Blocked %`, `Cache Hit %`, `Failed` + `Pause/Resume`, `Clear`, `Export CSV`.
- **Two Inner Sub-Tabs:**
  1. **Detailed Query Log (`Nhật ký chi tiết`):**
     - Search box (matches `Domain`, `AnswerSummary`, `ResolverName`, `MatchedRule`).
     - Quick outcome filter chips: `All`, `Blocked`, `Allowed`, `Cached`, `Routed`, `Rewritten`, `Failed`, `Stale`, `Canary`.
     - Record type combo (`All`, `A`, `AAAA`, `HTTPS`, `SVCB`, `CNAME`, `TXT`, `MX`, `PTR`, `SRV`) + `Slow (>100ms)` filter toggle.
     - Virtualized `DataGrid` (`EnableRowVirtualization="True"`, `Recycling`) showing: `Time`, `Domain`, `Type`, `Outcome`, `RCODE`, `Answer / IP`, `Rule / Resolver`, `Latency`.
     - **Inspector Drawer (on row selection):** Full query details + 1-click actions:
       - `Block Domain` → adds to `Filtering.CustomBlockedDomains`, reloads filtering & notifies Service.
       - `Allow Domain` / `Allow 30m` → adds permanent or 30-minute expiring entry to `Filtering.Allowlist`.
       - `Local Rewrite` → inline target IP/CNAME input adding a `LocalDnsRewriteRule` to `Routing.LocalRewrites`.
       - `Route Resolver` → inline resolver dropdown adding a `DnsRoutingRule` to `Routing.Rules`.
       - `Add to DPI Bypass` → adds domain rule to `Bypass.Rules` and reloads Bypass if active.
       - `Copy Domain` / `Copy Row`.
  2. **Top Domains & Spam Detector (`Phân tích & Spam`):**
     - Category toggle: `Top Queried` | `Top Blocked (Retry Loops)` | `Top Failed`.
     - Table columns: `Domain`, `Total`, `Q/min` (with warning badge when `IsHighFrequency`), `Blocked`, `Cached`, `Failed`, `Avg ms`, `Last Answer`, plus inline quick actions (`Filter Log`, `Block`, `Allow`).
- **CSV Export:**
  - Exports either the currently filtered Query Log or active Top Domains view to UTF-8 BOM `.csv` via `SaveFileDialog`.
  - Sanitizes leading formula characters (`=`, `+`, `-`, `@`, `\t`, `\r`) to prevent spreadsheet formula injection.

---

## 3. Feature 2: 5-Mode Seamless Operation Switcher Bar + Per-Mode Customization

### 3.1 Dashboard UI & Animation (`DashboardView.xaml`, `OperationModeSwitcherControl`)

- **Placement:** Immediately below `<UniformGrid x:Name="Metrics">` (the 5 speedometer gauges) and directly above `<!-- Live Ping & Network Speed Waveform Gauge -->` in `src/JustCryptDns.App/Views/DashboardView.xaml`.
- **Visual Design — Seamless 5-Switch Track:**
  - Single continuous pill/track container (`Border` with subtle recessed track background `Brush.ControlFill` and border `Brush.CardBorder`) housing **5 seamlessly joined switch segments** in exact order:
    1. `[ Tốc độ cao ]` (`HighSpeed`) — Lightning glyph (`&#xE945;`), accent `#FF9F1C`
    2. `[ Chế độ Game ]` (`Gaming`) — Gamepad glyph (`&#xE7FC;`), accent `#00D4FF`
    3. `[ Cân bằng ]` (`Balanced`) — Balance/tune glyph (`&#xE9E9;`), accent `#4F8CFF`
    4. `[ Tự động ]` (`Auto`) — Auto/sparkle glyph (`&#xE946;`), accent `#2DD4BF`
    5. `[ Bảo mật ]` (`Security`) — Shield glyph (`&#xEA18;`), accent `#3DD68C`
  - **Sliding Transition Effect:** A shared active highlight thumb sits behind the 5 segments in a `Grid`/`Canvas` and slides smoothly (`DoubleAnimation` with `CubicEase`, `220ms`) to the active segment's slot while smoothly transitioning its accent brush.
  - **Active Glowing Pulse ("sáng nhấp nháy"):**
    - Whichever mode is active lights up its switch button with a pulsing accent glow ring, bright illuminated border, and pulsing LED dot.
    - **Performance-safe Gaming Pulse:** When `MinimizeVisualEffects` is active (default in `Gaming` mode), the dashboard disables heavy GPU `DropShadowEffect` blur shaders, window transparency/Mica/Acrylic backdrop, and reduces gauge/waveform redraw rate from 30 fps to low-cost stepped updates (`~4 fps` or on-data-change) to protect game FPS; meanwhile, the active `Chế độ Game` switch button uses a **lightweight, shader-free border & indicator opacity pulse** so it still visibly glows and blinks with negligible CPU/GPU cost!
- **Status Footer & Inline Per-Mode Customizer:**
  - Directly integrated at the bottom of the 5-mode card:
    - Live status text explaining the active mode (in `Auto` mode, displays the resolved live target and reason, e.g., `Tự động → Chế độ Game (Phát hiện ứng dụng toàn màn hình)` or `Tự động → Bảo mật (Tỉ lệ chặn tăng đột biến)`).
    - Compact `⚙ Tùy chỉnh` (`Customize Mode`) toggle button.
  - Expanding `⚙ Tùy chỉnh` reveals a clean inline editor for the **currently selected mode**:
    - For `HighSpeed`, `Gaming`, `Balanced`, `Security`: allows customizing Resolver, Secondary Resolver, Filtering on/off, Gaming Engine pin on/off, Encrypted-only enforcement, Cache size / Prefetch / Serve-Stale, Query timeout, DNS Leak Guard, Threat Intel, Auto-Block Threats, Monitoring Mode, and Minimize Visual Effects — plus a `Khôi phục mặc định chế độ này` (`Reset this mode`) button.
    - For `Auto`: allows toggling Fullscreen/Game auto-switch, Threat/High-block-rate auto-switch, High-block threshold (Q/min), Cooldown duration (seconds), and editing the custom game process name list — plus `Khôi phục mặc định`.

### 3.2 Configuration Schema v19 (`AppSettings.cs`)

Bump `AppSettings.CurrentSchemaVersion` from `18` to `19` and add `OperationModeSettings OperationMode { get; set; } = new();`:

```csharp
[JsonConverter(typeof(JsonStringEnumConverter<AppOperationMode>))]
public enum AppOperationMode
{
    HighSpeed,
    Gaming,
    Balanced,
    Auto,
    Security,
}
```

- **`OperationModeProfile`** (mutable/record per mode, normalized on load):
  - `string ResolverId`, `string SecondaryResolverId`
  - `bool EnableFiltering`, `bool EnableAllBuiltInBlocklists`
  - `bool EnableGamingEngine`, `bool ForceEncryptedOnly`
  - `int QueryTimeoutMs` (clamped `500–15000`)
  - `int CacheMaxEntries` (clamped `256–16384`), `bool EnableCachePrefetch`, `bool EnableServeStale`
  - `bool EnableDnsLeakGuard`, `bool EnableThreatIntelligence`, `bool AutoBlockDetectedThreats`, `bool VerifyProcessSignatures`, `bool BlockFirefoxDohCanary`
  - `MonitoringMode MonitoringMode`
  - `bool MinimizeVisualEffects`
- **`AutoModeRulesSettings`**:
  - `bool SwitchToGamingOnFullscreenGame = true`
  - `bool SwitchToSecurityOnThreatOrSpike = true`
  - `int HighBlockRateThresholdPerMinute = 40` (clamped `10–500`)
  - `int CooldownSeconds = 20` (clamped `5–120`)
  - `List<string> CustomGameProcessNames` (merged with built-in common game process list)
- **`OperationBaselineSnapshot`**:
  - Stores the user's pre-override baseline for `Appearance` (`Animations`, `TransparencyEnabled`, `Transparency`, `StatusPulseStyle`), `Performance.MonitoringMode`, `Dns` (`ActiveResolverId`, `SecondaryResolverId`, `QueryTimeoutMs`, `BlockFirefoxDohCanary`), `Filtering.IsFilteringEnabled` + enabled built-in blocklist IDs, `Cache` settings, `Resilience.Policy`, `Connections` security flags.
  - Captured once before applying an overriding mode and restored cleanly when returning to baseline / disabling visual minimization.
  - **Strict Preservation Guarantee:** Mode switching NEVER modifies or deletes `Filtering.CustomBlockedDomains`, `Filtering.Allowlist`, `Routing.Rules`, `Routing.LocalRewrites`, `Bypass.Rules`, `Connections.BlockedRules`, or `Connections.BlockedApps`.

### 3.3 Built-in Default Tuning Matrix (Customizable per Mode)

| Setting | High Speed (`Tốc độ cao`) | Gaming (`Chế độ Game`) | Balanced (`Cân bằng`) | Security (`Bảo mật`) |
| :--- | :--- | :--- | :--- | :--- |
| **Primary Resolver** | `cloudflare-udp` (1.1.1.1 UDP thuần) | `cloudflare-doh` + Gaming Engine pin | `cloudflare-doh` | `quad9-doh` |
| **Secondary Resolver** | `google-udp` | `google-doh` | `quad9-doh` | `cloudflare-security-doh` |
| **Force Encrypted Only** | `false` | `false` | `false` | `true` (`EncryptedOnly`) |
| **Query Timeout** | `1500 ms` | `1800 ms` | `2500 ms` | `4000 ms` |
| **DNS Cache / Prefetch / Stale** | `8192` / `On` / `On` | `8192` / `On` / `On` | `6144` / `On` / `On` | `4096` / `Off` / `Off` |
| **DNS Filtering** | `Off` | `Off` | `On` (user's lists) | `On` (all built-in lists enabled) |
| **Gaming Engine Pin** | `Off` | `On` | `Off` | `Off` |
| **DNS Leak Guard** | `Off` | `Off` | `Off` (or baseline) | `On` |
| **Threat Intel / Auto-Block / Verify Sig** | `Off` / `Off` / `Off` | `Off` / `Off` / `Off` | `On` / `Off` / `On` | `On` / `On` / `On` |
| **Block Firefox DoH Canary** | `Off` | `On` | `On` | `On` |
| **Monitoring Mode** | `Performance` | `PowerSaving` | `Balanced` | `Balanced` |
| **Minimize Visual Effects** | `false` | **`true`** | `false` | `false` |

### 3.4 Auto Mode Decision Engine (`OperationModeEvaluator` + `OperationModeService`)

- **Pure Decision Engine (`JustCryptDns.Core/Services/OperationModeEvaluator.cs`):**
  - Stateless/clock-injected evaluator taking `AutoModeSignals(bool IsFullscreenOrGameActive, string? DetectedGameProcess, bool HasActiveThreatAlert, double BlockedQueriesPerMinute, bool IsUntrustedNetwork)` + `AutoModeRulesSettings` + previous state & last transition timestamp.
  - **Priority Order:**
    1. If `SwitchToGamingOnFullscreenGame && IsFullscreenOrGameActive` → `AppOperationMode.Gaming` (reason: detected game / fullscreen D3D).
    2. Else if `SwitchToSecurityOnThreatOrSpike && (HasActiveThreatAlert || BlockedQueriesPerMinute >= HighBlockRateThresholdPerMinute || IsUntrustedNetwork)` → `AppOperationMode.Security` (reason: threat / block spike / public network).
    3. Else → `AppOperationMode.Balanced`.
  - **Hysteresis / Cooldown:** Escalations to `Gaming` or `Security` take effect immediately (after 1 confirmation sample = ~5s), whereas downgrading back to `Balanced` requires `CooldownSeconds` (default `20s`) of clear conditions so brief Alt-Tabs or transient spikes never cause thrashing.
- **Lightweight System Signal Probe (`JustCryptDns.App/Services/OperationModeService.cs`):**
  - Polls every `5 seconds` only when `ActiveMode == AppOperationMode.Auto`.
  - Uses Win32 `SHQueryUserNotificationState` (`QUNS_RUNNING_D3D_FULL_SCREEN`) + `GetForegroundWindow` / `GetWindowThreadProcessId` to inspect ONLY the single foreground process name (never enumerates all system processes!) and compares against built-in + user-configured game process names.
  - Reads `BlockedQueriesPerMinute` from `INetworkDiagnosticsService` (or cached Service analytics) and active threats from `IConnectionMonitorService` (if running).
  - Applies mode profiles idempotently: only touches changed subsystems, invokes `IAppearanceService.Apply(...)`, reloads local/Service configuration cleanly via `IServiceClient` (`ReloadConfiguration`, `SetGamingMode`, `SyncFirewallBlocklist`) without unnecessary DNS proxy restarts.

---

## 4. Verification & Testing Plan

1. **Core & Diagnostics Unit Tests:**
   - `LiveQueryMonitorEntry` enriched metadata extraction from real DNS wire responses (`A`, `AAAA`, `CNAME`, `NXDOMAIN`).
   - `NetworkDiagnosticsService` 5,000-entry ring buffer, `SequenceId` delta queries, `DomainQueryAggregate` rolling Q/min & `IsHighFrequency` detection, bounded unique-domain cap, and clear/reset behavior.
   - `OperationModeSettings` schema v19 migration, default profiles, per-mode customization & reset, baseline snapshot capture/restore, and preservation of all custom rules.
   - `OperationModeEvaluator` priority & hysteresis cooldown tests.
   - CSV export formula-injection sanitization tests.
2. **UI & Localization Smoke Tests:**
   - Full `en` and `vi` localization keys verified by `LocalizationResourceTests`.
   - `DashboardView` (with new 5-mode switcher + customizer) and upgraded `LiveMonitorView` verified by `ViewInstantiationSmokeTests`.
3. **Build & Regression Gate:**
   - `dotnet build JustCryptDns.sln -c Release` → `0 Warning(s), 0 Error(s)`.
   - `dotnet test JustCryptDns.sln -c Release` → `100%` tests passing (`Failed: 0`).
