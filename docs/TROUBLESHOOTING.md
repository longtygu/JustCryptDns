# JustCryptDns Troubleshooting Guide

## 1. Port 53 Conflict ("Port 53 is already in use")
- **Cause:** Another local DNS proxy, VPN client, Hyper-V/WSL DNS forwarder, or Windows Internet Connection Sharing (ICS) is already bound to `127.0.0.1:53`.
- **Solution:**
  - Click **Use port 15353** (or the suggested free port) in the warning banner on **DNS Manager** to test JustCryptDns immediately, **or**
  - Stop the conflicting DNS service (`Get-NetUDPEndpoint -LocalPort 53`) so JustCryptDns can bind to standard port `53`.

## 2. Emergency Restore Windows Adapter DNS
- If Windows loses DNS resolution after an unexpected shutdown or external network change:
  1. Open **DNS Manager** (or right-click the **JustCryptDns** system tray icon) and click **Restore original DNS**.
  2. JustCryptDns restores the SHA-256 verified backup stored in `%LOCALAPPDATA%\JustCryptDns\dns-backup.json` (or resets the active adapter to DHCP if no backup is present).
  3. On startup, JustCryptDns also automatically detects orphaned adapter backups from crashes and restores original DNS settings safely.

## 3. DNSCrypt Resolvers Require `dnscrypt-proxy`
- JustCryptDns uses official `dnscrypt-proxy` binaries rather than re-implementing cryptography.
- Go to **DNS Manager → dnscrypt-proxy** and click **Install / Update** to download and verify the latest Windows x64 release into `%LOCALAPPDATA%\JustCryptDns\engines\dnscrypt-proxy\`.

## 4. Window Transparency on Windows 10 vs. Windows 11
- **Windows 11 (build 22621+):** Supports hardware **Mica**, **Acrylic**, and **Rounded Corners** via DWM.
- **Windows 10 (22H2):** Automatically falls back to **Windows DWM Blur** (`SetWindowCompositionAttribute`). Hardware rounded corners are Windows 11 only.
- If transparency effects are disabled in Windows Personalization settings or in remote/virtual sessions, JustCryptDns gracefully renders an opaque surface with full readability.

## 5. Inspecting Logs & Portable Mode
- UI logs: `%LOCALAPPDATA%\JustCryptDns\logs\ui-YYYYMMDD.log`
- Service logs: `%LOCALAPPDATA%\JustCryptDns\logs\service-YYYYMMDD.log`
- To run in portable mode or isolate configuration/logs, set the environment variable `JUSTCRYPTDNS_DATA_DIR` to your preferred folder before starting `JustCryptDns.exe`.
