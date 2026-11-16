<#
.SYNOPSIS
  Renders the JustCryptDns application icon (multi-size, PNG-compressed ICO) to src/JustCryptDns.App/Resources/AppIcon.ico.
#>
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'src/JustCryptDns.App/Resources/AppIcon.ico'
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null

function New-IconPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 24.0
    # Rounded square background
    $r = 6 * $s; $rect = New-Object System.Drawing.RectangleF 0, 0, ($size - 1), ($size - 1)
    $bg = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bg.AddArc($rect.X, $rect.Y, $r * 2, $r * 2, 180, 90)
    $bg.AddArc($rect.Right - $r * 2, $rect.Y, $r * 2, $r * 2, 270, 90)
    $bg.AddArc($rect.Right - $r * 2, $rect.Bottom - $r * 2, $r * 2, $r * 2, 0, 90)
    $bg.AddArc($rect.X, $rect.Bottom - $r * 2, $r * 2, $r * 2, 90, 90)
    $bg.CloseFigure()
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, ([System.Drawing.Color]::FromArgb(255, 79, 140, 255)), ([System.Drawing.Color]::FromArgb(255, 123, 92, 255)), 45
    $g.FillPath($brush, $bg)
    # Shield
    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $m = 0.18 * $size; $k = (24 - 2 * ($m / $s)) / 24.0
    function P([double]$x, [double]$y) { New-Object System.Drawing.PointF ($m + $x * $s * $k), ($m + $y * $s * $k) }
    $shield.AddLine((P 12 2), (P 20 5)); $shield.AddLine((P 20 5), (P 20 11))
    $shield.AddBezier((P 20 11), (P 20 16), (P 16.5 20.5), (P 12 22))
    $shield.AddBezier((P 12 22), (P 7.5 20.5), (P 4 16), (P 4 11))
    $shield.AddLine((P 4 11), (P 4 5)); $shield.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(60, 255, 255, 255))), $shield)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([Math]::Max(1.0, 1.9 * $s * $k))
    $pen.LineJoin = 'Round'; $g.DrawPath($pen, $shield)
    $pen2 = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), ([Math]::Max(1.2, 2.2 * $s * $k))
    $pen2.StartCap = 'Round'; $pen2.EndCap = 'Round'; $pen2.LineJoin = 'Round'
    $g.DrawLines($pen2, [System.Drawing.PointF[]]@((P 8.5 12), (P 11 14.5), (P 15.5 9.5)))
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    return , $ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$images = foreach ($sz in $sizes) { , (New-IconPng $sz) }
$fs = [System.IO.File]::Create($out); $bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $dim = if ($sz -ge 256) { 0 } else { $sz }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$images[$i].Length); $bw.Write([UInt32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $bw.Write($img) }
$bw.Close()
Write-Host "Wrote $out"
