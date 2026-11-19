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

## 4. DPI Bypass, Steam & Windows Proxy Recovery
- **Steam Store / Community or websites hang during loading even with encrypted DNS:**
  1. Ensure **DPI Bypass & Tunnel** is started on the Dashboard or **DPI Bypass & Tunnel** page (`127.0.0.1:10808` and Auto-PAC `http://127.0.0.1:10809/proxy.pac`).
  2. Click **Test Bypass** on `store.steampowered.com` inside **DPI Bypass & Tunnel**. If Direct HTTPS times out while TLS DPI Bypass succeeds, verify the domain's rule is enabled under **Domain bypass rules**.
  3. If both Direct and TLS DPI Bypass fail for a specific site (IP-block / geo-block), switch Cloudflare WARP to proxy mode (`warp-cli mode proxy && warp-cli connect`), click **Detect Cloudflare WARP**, and enable Tier 2 Split-Tunnel upstream.
- **Emergency restore Windows Proxy:** If browser connections fail after an unclean shutdown, click **Restore Windows Proxy** inside **DPI Bypass & Tunnel** or right-click the tray icon and choose **Restore original DNS** (which also restores `%LOCALAPPDATA%\JustCryptDns\proxy-backup.json`).

## 5. Window Transparency on Windows 10 vs. Windows 11
- **Windows 11 (build 22621+):** Supports hardware **Mica**, **Acrylic**, and **Rounded Corners** via DWM.
- **Windows 10 (22H2):** Automatically falls back to **Windows DWM Blur** (`SetWindowCompositionAttribute`). Hardware rounded corners are Windows 11 only.
- If transparency effects are disabled in Windows Personalization settings or in remote/virtual sessions, JustCryptDns gracefully renders an opaque surface with full readability.

## 6. Inspecting Logs & Portable Mode
- UI logs: `%LOCALAPPDATA%\JustCryptDns\logs\ui-YYYYMMDD.log`
- Service logs: `%LOCALAPPDATA%\JustCryptDns\logs\service-YYYYMMDD.log`
- To run in portable mode or isolate configuration/logs, set the environment variable `JUSTCRYPTDNS_DATA_DIR` to your preferred folder before starting `JustCryptDns.exe`.
