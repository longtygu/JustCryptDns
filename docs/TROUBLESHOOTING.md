# JustCryptDns Troubleshooting Guide

## 1. Port 53 Conflict ("Port 53 is already in use")
- **Cause:** Another local DNS proxy, VPN client, Hyper-V/WSL DNS forwarder, or Windows Internet Connection Sharing (ICS) is already bound to `127.0.0.1:53`.
- **Solution:**
  - Click **Use port 15353** (or the suggested free port) in the warning banner on **DNS Manager** to test JustCryptDns immediately, **or**
  - Stop the conflicting DNS service (`Get-NetUDPEndpoint -LocalPort 53`) so JustCryptDns can bind to standard port `53`.

## 2. Emergency Restore Windows Adapter DNS
- If Windows loses DNS resolution after an unexpected shutdown or external network change:
  1. Open **DNS Manager** (or right-click the **JustCryptDns** system tray icon) and click **Restore original DNS**.
  2. JustCryptDns restores the SHA-256 verified backup stored in `%ProgramData%\JustCryptDns\dns-backup.json` (or `<AppDir>\data\dns-backup.json` in portable mode; resets the active adapter to DHCP if no backup is present).
  3. On startup, JustCryptDns also automatically detects orphaned adapter backups from crashes and restores original DNS settings safely (leaving active Service protections intact when `JustCryptDnsService` is running).

## 3. DNSCrypt Resolvers Require `dnscrypt-proxy`
- JustCryptDns uses official `dnscrypt-proxy` binaries rather than re-implementing cryptography.
- Go to **DNS Manager → dnscrypt-proxy** and click **Install / Update** to download and verify the latest Windows x64 release into `%ProgramData%\JustCryptDns\engine\` (or `<AppDir>\data\engine\` in portable mode).

## 4. DPI Bypass, All-Web Recovery & Banking Exclusions
- **Websites or Steam Store hang during loading even with encrypted DNS:**
  1. Ensure **DPI Bypass & Tunnel** is active (`127.0.0.1:10808`) and **Website coverage mode** is set to **All Websites (Smart Auto-PAC)** (or switch a custom rule cleanly).
  2. Use **Test Bypass** or **Test Multiple Sites** inside **DPI Bypass & Tunnel** to inspect Direct vs. TLS Fragmentation vs. Tunnel reachability.
  3. Enable **4-stage self-healing** so JustCryptDns automatically escalates to 16B splits, recovers legacy/slow-TLS servers as Direct, or falls back to Tier 2 Split-Tunnel (`warp-cli mode proxy && warp-cli connect`).
- **A banking or intranet site dislikes TLS splitting:** Self-healing detects TLS Alerts or slow fragmented handshakes automatically and learns `Direct` for 30 minutes; you can also click **Direct** beside any entry in **Recent bypass connection stream** or add the domain under **Direct exclusions** for a permanent bypass exemption with instant Auto-PAC refresh.
- **Emergency restore Windows Proxy:** If browser connections fail after an unclean shutdown, click **Restore Windows Proxy** inside **DPI Bypass & Tunnel** or right-click the tray icon and choose **Restore original DNS** (which also restores your per-user `%LOCALAPPDATA%\JustCryptDns\proxy-backup.json`).

## 5. Window Transparency on Windows 10 vs. Windows 11
- **Windows 11 (build 22621+):** Supports hardware **Mica**, **Acrylic**, and **Rounded Corners** via DWM.
- **Windows 10 (22H2):** Automatically falls back to **Windows DWM Blur** (`SetWindowCompositionAttribute`). Hardware rounded corners are Windows 11 only.
- If transparency effects are disabled in Windows Personalization settings or in remote/virtual sessions, JustCryptDns gracefully renders an opaque surface with full readability.

## 6. Inspecting Logs & Portable Mode
- Installed shared mode logs: `%ProgramData%\JustCryptDns\logs\ui-YYYYMMDD.log` and `service-YYYYMMDD.log` (legacy v1.5.x settings from `%LOCALAPPDATA%\JustCryptDns` are migrated automatically on first launch).
- Portable ZIP mode (`portable.flag` beside `JustCryptDns.exe`): logs and settings live in `<AppDir>\data\`.
- Custom data directory override: set environment variable `JUSTCRYPTDNS_DATA_DIR` before starting `JustCryptDns.exe`.
