# Third-Party Notices

JustCryptDns is released under the [MIT License](LICENSE). It incorporates or interfaces with the following third-party open-source components:

## Bundled NuGet Dependencies

| Package | License | Project URL |
|---|---|---|
| CommunityToolkit.Mvvm | MIT | https://github.com/CommunityToolkit/dotnet |
| Microsoft.Extensions.DependencyInjection | MIT | https://github.com/dotnet/runtime |
| Microsoft.Extensions.Hosting | MIT | https://github.com/dotnet/runtime |
| Microsoft.Extensions.Hosting.WindowsServices | MIT | https://github.com/dotnet/runtime |
| Microsoft.Extensions.Logging | MIT | https://github.com/dotnet/runtime |
| Serilog | Apache-2.0 | https://github.com/serilog/serilog |
| Serilog.Extensions.Logging | Apache-2.0 | https://github.com/serilog/serilog-extensions-logging |
| Serilog.Sinks.File | Apache-2.0 | https://github.com/serilog/serilog-sinks-file |

## Optional External Engine (Downloaded on User Action)

| Component | License | Project URL |
|---|---|---|
| dnscrypt-proxy | ISC | https://github.com/DNSCrypt/dnscrypt-proxy |

JustCryptDns does not re-implement DNSCrypt cryptographic primitives; instead it invokes official `dnscrypt-proxy` releases when the user selects a DNSCrypt v2 resolver.

## Development & Test Dependencies (Not Shipped in Release)

| Package | License | Project URL |
|---|---|---|
| xUnit | Apache-2.0 | https://github.com/xunit/xunit |
| Microsoft.NET.Test.Sdk | MIT | https://github.com/microsoft/vstest |
