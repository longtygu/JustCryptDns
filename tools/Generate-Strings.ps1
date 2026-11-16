<#
.SYNOPSIS
  Regenerates Strings.resx (en) and Strings.vi.resx from tools/strings.tsv.
  The TSV is the single source of truth for UI strings; edit it, then run this script.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tsv = Join-Path $PSScriptRoot 'strings.tsv'
$outDir = Join-Path $root 'src/JustCryptDns.App/Resources/Strings'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$rows = Get-Content -LiteralPath $tsv -Encoding UTF8 | Select-Object -Skip 1 | Where-Object { $_.Trim() -ne '' }
$seen = @{}
$entries = foreach ($line in $rows) {
    $parts = $line.Split('|')
    if ($parts.Count -ne 3) { throw "Malformed line: $line" }
    if ($seen.ContainsKey($parts[0])) { throw "Duplicate key: $($parts[0])" }
    $seen[$parts[0]] = $true
    [pscustomobject]@{ Key = $parts[0]; En = $parts[1]; Vi = $parts[2] }
}

function Write-Resx([string]$path, [string]$column) {
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)
    $w = [System.Xml.XmlWriter]::Create($path, $settings)
    $w.WriteStartDocument()
    $w.WriteStartElement('root')
    foreach ($h in @(@('resmimetype', 'text/microsoft-resx'), @('version', '2.0'),
            @('reader', 'System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'),
            @('writer', 'System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'))) {
        $w.WriteStartElement('resheader'); $w.WriteAttributeString('name', $h[0])
        $w.WriteElementString('value', $h[1]); $w.WriteEndElement()
    }
    foreach ($e in $entries) {
        $w.WriteStartElement('data')
        $w.WriteAttributeString('name', $e.Key)
        $w.WriteAttributeString('xml', 'space', 'http://www.w3.org/XML/1998/namespace', 'preserve')
        $w.WriteElementString('value', $e.$column)
        $w.WriteEndElement()
    }
    $w.WriteEndElement(); $w.WriteEndDocument(); $w.Close()
}

Write-Resx (Join-Path $outDir 'Strings.resx') 'En'
Write-Resx (Join-Path $outDir 'Strings.vi.resx') 'Vi'
Write-Host "Generated $($entries.Count) strings."
