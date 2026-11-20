# JustCryptDns [ ENGLISH ]

Advanced DNS security, smart routing and gaming DNS optimization suite for Windows 10 22H2 / Windows 11 (x64).

> **Status: v1.0.0 Release Ready (12 of 12 phases complete).** All 9 main application sections, the core DNS engine,
> Resolver Library, Smart DNS Routing, DNS Filtering & TTL Cache, Gaming Low Latency Engine, Network Resilience & Failover,
> Network Diagnostics, Virtualized Live Monitor, Appearance & Window Transparency, Background Windows Service, System Tray,
> Resource Optimization, and Release Packaging (self-contained `win-x64` portable ZIP + Inno Setup installer) are implemented and verified.

<img width="1183" height="765" alt="image" src="https://github.com/user-attachments/assets/80f394b2-b160-4c2b-98fa-4487d90ff019" />

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

# JustCryptDns [ VIETNAMESE ]

Bộ công cụ bảo mật DNS nâng cao, định tuyến thông minh và tối ưu hóa DNS chơi game cho Windows 10 22H2 / Windows 11 (x64).

> **Trạng thái: Sẵn sàng phát hành v1.0.0 (hoàn thành 12/12 giai đoạn).** Toàn bộ 9 phân mục chính của ứng dụng, nhân xử lý DNS cốt lõi,
> Thư viện Resolver, Định tuyến DNS thông minh, Lọc DNS & Bộ nhớ đệm TTL, Nhân tối ưu độ trễ chơi game (Gaming Low Latency Engine),
> Khả năng phục hồi mạng & Chuyển đổi dự phòng (Failover), Chẩn đoán mạng, Trình giám sát trực tiếp ảo hóa (Virtualized Live Monitor),
> Tùy biến giao diện & Độ trong suốt cửa sổ, Dịch vụ chạy nền Windows Service, Khay hệ thống (System Tray), Tối ưu hóa tài nguyên
> và Đóng gói phát hành (gói ZIP portable `win-x64` độc lập + trình cài đặt Inno Setup) đều đã được hoàn thiện và kiểm thử.

<img width="1183" height="765" alt="image" src="https://github.com/user-attachments/assets/80f394b2-b160-4c2b-98fa-4487d90ff019" />

## Tính năng

| Hạng mục | Trạng thái |
|---|---|
| Khung giao diện WPF hiện đại (thanh tiêu đề tùy biến, thanh bên thu gọn được, 9 phân mục) | ✅ |
| Chủ đề Tối / Sáng / Theo hệ thống / Tùy chỉnh, chuyển đổi tức thì khi đang chạy, bộ màu nhấn (accent color) đạt chuẩn tương phản WCAG | ✅ |
| Độ trong suốt cửa sổ (0–90 %) hỗ trợ Mica/Acrylic trên Windows 11 & DWM Blur trên Windows 10 kèm cơ chế hạ cấp an toàn (graceful fallback) | ✅ |
| Trang Giao diện chuyên biệt (bộ màu nhấn có sẵn & nhập mã Hex, đồng bộ màu nhấn Windows, tỷ lệ giao diện 80–150 %, cỡ chữ, mật độ thẻ, mức độ hiệu ứng chuyển động, bo góc cửa sổ, hiệu ứng phát sáng nền, khôi phục mặc định) | ✅ |
| Dịch vụ chạy nền độc lập (`JustCryptDns.Service`) + giao tiếp liên tiến trình Named Pipe IPC bảo mật bằng ACL (`JustCryptDns.Ipc.v1`) | ✅ |
| Biểu tượng khay hệ thống (`Shell_NotifyIconW`, không phụ thuộc WinForms) với menu ngữ cảnh đồng bộ giao diện & tùy chọn hành vi khi đóng (Thu nhỏ xuống khay / Thoát / Hỏi mỗi lần) | ✅ |
| Tích hợp khởi động cùng Windows (`HKCU\...\Run`, ghi khóa an toàn không trùng lặp, hỗ trợ tham số `--minimized`) | ✅ |
| Nhân xử lý DNS cốt lõi: DNS over HTTPS (RFC 8484), DNS over TLS (RFC 7858), DNSCrypt v2 (`dnscrypt-proxy`) và UDP/TCP | ✅ |
| Proxy DNS cục bộ (`127.0.0.1`, tùy chỉnh IP/cổng, hỗ trợ IPv4 & IPv6, phát hiện xung đột cổng & chống vòng lặp DNS) | ✅ |
| Tích hợp cấu hình DNS card mạng Windows với quy trình an toàn 6 bước (sao lưu, kiểm tra SHA-256, áp dụng, thăm dò kết nối, tự động hoàn tác, khôi phục khẩn cấp, phục hồi sau sự cố) | ✅ |
| Thư viện Resolver đầy đủ: Cloudflare, Google, Quad9, OpenDNS, AdGuard, Control D, NextDNS, Mullvad, DNS0 + máy chủ tùy chỉnh, phân nhóm, kiểm tra hợp lệ, nhập/xuất hồ sơ JSON & kiểm tra trạng thái hoạt động trực tiếp | ✅ |
| Định tuyến DNS thông minh: quy tắc theo tên miền (Khớp chính xác, Tên miền & Tên miền phụ, Ký tự đại diện Wildcard), thứ tự ưu tiên, hồ sơ Chơi game/Riêng tư/Bảo mật/Tùy chỉnh, máy chủ dự phòng (fallback), trình chỉnh sửa quy tắc trực quan, công cụ kiểm thử quy tắc & nhật ký định tuyến thời gian thực | ✅ |
| Lọc DNS & Bộ nhớ đệm TTL: danh sách chặn Quảng cáo/Theo dõi/Mã độc/Lừa đảo/Thu thập dữ liệu/Tùy chỉnh, nhập tệp hosts, danh sách cho phép (allowlist), ngoại lệ tạm thời, bảo vệ tên miền thiết yếu của Windows, trình kiểm tra quyết định lọc & bộ nhớ đệm phản hồi thành công/lỗi tuân thủ TTL | ✅ |
| Nhân tối ưu độ trễ chơi game: đo kiểm đa tên miền lặp lại (trung bình, tối thiểu, tối đa, P95, độ biến thiên trễ jitter, tỷ lệ thành công/hết thời gian chờ, điểm tin cậy), 3 cấu hình tối ưu, 8 hồ sơ game tích hợp sẵn + tùy chỉnh, cùng Chế độ Chơi game (Gaming Mode) hỗ trợ ghim phiên kết nối | ✅ |
| Phục hồi mạng & Chuyển đổi dự phòng (Failover): chính sách dự phòng Chính/Phụ & máy chủ mã hóa, tùy chỉnh số lần thử lại, phân loại lỗi (UDP/53, TCP/53, DoH, DoT, DNSCrypt, IPv4/IPv6) & lịch sử sự kiện chuyển đổi | ✅ |
| Chẩn đoán mạng & Trình giám sát trực tiếp ảo hóa: tra cứu bản ghi A/AAAA/CNAME/MX/TXT/NS, kiểm tra DNSSEC/DoH/DNSCrypt/rò rỉ DNS/lan truyền bản ghi/hạn chế truy cập, tách biệt rõ kết quả cục bộ và bên ngoài, cùng trình giám sát truy vấn trực tiếp & chuyển đổi dự phòng tối ưu bộ nhớ bằng ảo hóa danh sách | ✅ |
| Tối ưu hóa tài nguyên triệt để: các chế độ giám sát Tiết kiệm điện / Cân bằng / Hiệu năng cao, Chẩn đoán hiệu năng cho nhà phát triển, tự động giải phóng RAM (working-set trimming) khi thu nhỏ xuống khay hệ thống | ✅ |
| Giao diện Tiếng Anh / Tiếng Việt, chuyển đổi trực tiếp không cần khởi động lại | ✅ |
| Lưu trữ cấu hình JSON phân phiên bản (schema v10) với cơ chế ghi nguyên tử (atomic save), sao lưu, tự phục hồi khi hỏng tệp và nâng cấp dữ liệu tự động | ✅ |
| Ghi nhật ký xoay vòng có giới hạn dung lượng (Serilog) | ✅ |
| Chống mở trùng lặp tiến trình (mở lần thứ hai sẽ tự kích hoạt cửa sổ đang chạy) | ✅ |
| Bản phát hành `win-x64` độc lập (self-contained), gói nén ZIP portable kèm mã băm SHA-256, trình cài đặt Inno Setup (`installer/JustCryptDns.iss`), Tài liệu hướng dẫn sử dụng & Xử lý sự cố | ✅ |

Xem thêm tài liệu:
- [Hướng dẫn sử dụng](docs/USER_GUIDE.md)
- [Hướng dẫn xử lý sự cố](docs/TROUBLESHOOTING.md)
- [Đo kiểm hiệu năng & tài nguyên](docs/PERFORMANCE.md)
- [Kiến trúc & Lộ trình phát triển](docs/ROADMAP.md)
- [Thông báo về phần mềm bên thứ ba](THIRD-PARTY-NOTICES.md)

## Biên dịch & Đóng gói phát hành

Yêu cầu: .NET SDK 8.0 trở lên (các dự án sử dụng nền tảng `net8.0` / `net8.0-windows`), Windows 10 22H2 / Windows 11 x64.

```powershell
dotnet build JustCryptDns.sln -c Release
dotnet test  JustCryptDns.sln -c Release
dotnet run --project src/JustCryptDns.App

# Biên dịch bản phát hành win-x64 độc lập, gói ZIP portable, mã kiểm tra SHA-256 và trình cài đặt Inno Setup:
.\tools\Build-Release.ps1
```

## Cấu trúc mã nguồn (Solution)

```
src/JustCryptDns.Core            Mô hình dữ liệu, giao diện (interface), schema cấu hình + nâng cấp dữ liệu (không phụ thuộc Windows/UI)
src/JustCryptDns.DNS             Nhân xử lý DNS (từ Giai đoạn 4 trở đi)
src/JustCryptDns.Network         Thông tin mạng, đo kiểm (benchmark), chuyển đổi dự phòng, giám sát
src/JustCryptDns.Infrastructure  Tích hợp Windows, IPC, khởi động cùng hệ thống, lưu trữ, ghi nhật ký
src/JustCryptDns.Service         Windows Service độc lập / tiến trình chạy nền
src/JustCryptDns.App             Giao diện WPF (MVVM, CommunityToolkit.Mvvm)
tests/JustCryptDns.Tests         Bộ kiểm thử đơn vị xUnit (chạy ngoại tuyến)
tools/                           Script hỗ trợ nhà phát triển (bảng chuỗi ngôn ngữ, biểu tượng, chẩn đoán cửa sổ)
```

## Vị trí lưu trữ dữ liệu

| Loại dữ liệu | Đường dẫn |
|---|---|
| Cài đặt | `%LOCALAPPDATA%\JustCryptDns\settings.json` (+ `settings.json.bak`) |
| Nhật ký (Logs) | `%LOCALAPPDATA%\JustCryptDns\logs\ui-YYYYMMDD.log` (giới hạn 5 MB mỗi tệp, lưu mặc định 7 ngày) |

Ứng dụng không thu thập dữ liệu đo từ xa (telemetry). Không có dữ liệu nào bị gửi ra khỏi máy tính của bạn.

## Ghi chú dành cho nhà phát triển

- **Chuỗi giao diện (UI strings)** nằm trong tệp `tools/strings.tsv` (key | English | Vietnamese). Sau khi chỉnh sửa, hãy chạy
  `tools/Generate-Strings.ps1` để tạo lại tệp `Strings.resx` / `Strings.vi.resx`. Bộ kiểm thử sẽ tự động xác minh sự đồng bộ của khóa (key),
  tham số định dạng (placeholder) và đảm bảo mọi khóa dùng trong XAML đều tồn tại.
- Các biến môi trường hỗ trợ phát triển:

| Biến môi trường | Tác dụng |
|---|---|
| `JUSTCRYPTDNS_DATA_DIR` | Chỉ định thư mục dữ liệu khác (chế độ portable / kiểm thử) |
| `JUSTCRYPTDNS_SOFTWARE_RENDER=1` | Buộc WPF sử dụng chế độ kết xuất phần mềm (software rendering) |
| `JUSTCRYPTDNS_SNAPSHOT_DIR` | Xuất ảnh chụp PNG các trang giao diện sau khi khởi động (`JUSTCRYPTDNS_SNAPSHOT_PAGES`, `JUSTCRYPTDNS_SNAPSHOT_SUFFIX`) |

## Giấy phép

Phát hành theo [Giấy phép MIT](LICENSE).
