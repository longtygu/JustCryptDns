<#
.SYNOPSIS
    Builds, tests, publishes self-contained win-x64 Release binaries, creates the portable ZIP archive,
    computes SHA-256 checksums, and compiles the Inno Setup installer when ISCC.exe is installed.
#>
[CmdletBinding()]
param(
    [string]$Version = "1.7.1",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $RepoRoot
try {
    Write-Host "==> 1/5 Building JustCryptDns solution (Release)..." -ForegroundColor Cyan
    dotnet build JustCryptDns.sln -c Release
    if ($LASTEXITCODE -ne 0) { throw "Release build failed." }

    if (-not $SkipTests) {
        Write-Host "==> 2/5 Running automated unit tests (Release)..." -ForegroundColor Cyan
        dotnet test JustCryptDns.sln -c Release --no-build -v q
        if ($LASTEXITCODE -ne 0) { throw "Unit tests failed." }
    }

    $DistDir = Join-Path $RepoRoot "dist"
    $PublishDir = Join-Path $DistDir "publish\win-x64"
    $LockedExe = Join-Path $PublishDir "JustCryptDns.exe"
    $InUse = $false
    if (Test-Path $LockedExe) {
        try {
            $stream = [System.IO.File]::Open($LockedExe, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Dispose()
        }
        catch {
            $InUse = $true
        }
    }

    if ($InUse) {
        Write-Warning "Default publish directory '$PublishDir' is in use by a running instance; publishing to '$DistDir\publish\win-x64-$Version' instead."
        $PublishDir = Join-Path $DistDir "publish\win-x64-$Version"
    }

    if (Test-Path $PublishDir) {
        Remove-Item -Recurse -Force $PublishDir -ErrorAction Stop
    }
    New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null

    Write-Host "==> 3/5 Publishing self-contained win-x64 binaries..." -ForegroundColor Cyan
    dotnet publish src\JustCryptDns.App\JustCryptDns.App.csproj `
        -c Release -r win-x64 --self-contained true `
        -p:PublishReadyToRun=true -p:DebugSymbols=false -p:DebugType=none `
        -o $PublishDir
    if ($LASTEXITCODE -ne 0) { throw "App publish failed." }

    dotnet publish src\JustCryptDns.Service\JustCryptDns.Service.csproj `
        -c Release -r win-x64 --self-contained true `
        -p:PublishReadyToRun=true -p:DebugSymbols=false -p:DebugType=none `
        -o $PublishDir
    if ($LASTEXITCODE -ne 0) { throw "Service publish failed." }

    # Bundle documentation and license notices alongside binaries
    Copy-Item LICENSE, THIRD-PARTY-NOTICES.md, README.md -Destination $PublishDir -Force
    $DocsOut = Join-Path $PublishDir "docs"
    New-Item -ItemType Directory -Path $DocsOut -Force | Out-Null
    Copy-Item docs\USER_GUIDE.md, docs\TROUBLESHOOTING.md, docs\PERFORMANCE.md -Destination $DocsOut -Force

    Write-Host "==> 4/5 Packaging portable ZIP archive..." -ForegroundColor Cyan
    $PortableFlagPath = Join-Path $PublishDir "portable.flag"
    Set-Content -Path $PortableFlagPath -Value "Portable mode enabled: store settings, logs, and engine binaries in .\data next to JustCryptDns.exe." -Encoding UTF8
    $ZipPath = Join-Path $DistDir "JustCryptDns-$Version-win-x64-portable.zip"
    if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
    Compress-Archive -Path "$PublishDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
    Remove-Item -Force $PortableFlagPath -ErrorAction SilentlyContinue

    # Optional Inno Setup installer compilation
    $Iscc = (Get-Command "ISCC.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
    if (-not $Iscc) {
        $IsccCandidates = @(
            "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
        )
        $Iscc = $IsccCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    }

    if ($Iscc) {
        Write-Host "==> Compiling Inno Setup installer..." -ForegroundColor Cyan
        & $Iscc "/DPublishDir=$PublishDir" (Join-Path $RepoRoot "installer\JustCryptDns.iss")
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed." }
    } else {
        Write-Host "    Note: Inno Setup (ISCC.exe) not installed locally; installer\JustCryptDns.iss is ready for CI or local Inno Setup 6 compilation." -ForegroundColor Yellow
    }

    Write-Host "==> 5/5 Generating SHA-256 checksums..." -ForegroundColor Cyan
    $Artifacts = Get-ChildItem -Path $DistDir -File | Where-Object { $_.Extension -in ".zip", ".exe" }
    $SumsPath = Join-Path $DistDir "SHA256SUMS.txt"
    $Lines = foreach ($a in $Artifacts) {
        $hash = (Get-FileHash -Path $a.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $($a.Name)"
    }
    Set-Content -Path $SumsPath -Value $Lines -Encoding UTF8

    Write-Host ""
    Write-Host "Release packaging complete!" -ForegroundColor Green
    Get-ChildItem -Path $DistDir -File | Select-Object Name, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
}
finally {
    Pop-Location
}
