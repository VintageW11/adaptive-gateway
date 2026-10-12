$ErrorActionPreference = "Stop"
$root = "C:\Users\rosea\Projects\adaptive-gateway"
$htmlPath = Join-Path $root "docs\autovpn_source_code.html"
$outPdf = "C:\Users\rosea\Downloads\SuiSSD_AutoVPN_Source_Code.pdf"
$altPdf = "C:\Users\rosea\Downloads\AutoVPN_Source_Code.pdf"
$outDocx = "C:\Users\rosea\Downloads\SuiSSD_AutoVPN_Source_Code.docx"

$files = @(
  @{ Path = "backend-api\app.py"; Role = "Flask control plane: status API, Auto, SAW host loop, speed test, consent, accounts." },
  @{ Path = "backend-api\device_manager.py"; Role = "Per-device SAW, Auto classify, client tables 110+, LAN-proof, dummy deny." },
  @{ Path = "backend-api\saw.py"; Role = "Live-first SAW score, normalization, affinity cap, Fail scale." },
  @{ Path = "backend-api\db.py"; Role = "SQLite accounts, sessions, exclusive device bind, consent, delete device." },
  @{ Path = "frontend\index.html"; Role = "Dashboard SPA served by Flask on :5006 / autovpn.lab." },
  @{ Path = "scripts\autovpn-port80-redirect.py"; Role = "iptables REDIRECT 80 to 5006 so http://autovpn.lab/ stays the name." },
  @{ Path = "scripts\autovpn-port80.service"; Role = "systemd unit for the port-80 redirect loop." },
  @{ Path = "scripts\defense-watchdog.sh"; Role = "Host default stays MikroTik; client tables pinned if a VPN is unsafe." }
)

function Html-Encode([string]$s) {
  if ($null -eq $s) { return "" }
  return (($s -replace '&', '&amp;') -replace '<', '&lt;' -replace '>', '&gt;')
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
[void]$sb.AppendLine('<title>AutoVPN used source code</title>')
[void]$sb.AppendLine('<style>
  @page { size: A4; margin: 14mm 12mm; }
  html, body { margin: 0; padding: 0; font-family: "Times New Roman", Times, serif; font-size: 11pt; color: #111; }
  h1 { font-size: 16pt; text-align: center; margin: 0 0 10pt; }
  h2 { font-size: 13pt; margin: 18pt 0 8pt; page-break-before: always; }
  h2.first { page-break-before: auto; }
  p { margin: 0 0 8pt; }
  table.toc { width: 100%; border-collapse: collapse; margin: 10pt 0 16pt; font-size: 10.5pt; }
  table.toc th, table.toc td { border: 1px solid #444; padding: 4pt 6pt; text-align: left; vertical-align: top; }
  table.toc th { background: #efefef; }
  pre {
    font-family: Consolas, "Courier New", monospace;
    font-size: 7.5pt;
    line-height: 1.28;
    white-space: pre-wrap;
    word-wrap: break-word;
    margin: 0 0 12pt;
  }
  .meta { color: #333; font-size: 10.5pt; }
  code { font-family: Consolas, "Courier New", monospace; font-size: 10pt; }
</style></head><body>')

[void]$sb.AppendLine('<h1>AutoVPN lab — used source code</h1>')
[void]$sb.AppendLine('<p>This appendix is the source that runs the Ubuntu AutoVPN gateway (Flask on :5006, SAW, Auto classify, client steering, dashboard, port-80 name, defense watchdog). Unused leftovers (<code>gateway_engine.py</code>) and one-off check scripts are omitted. The live VirtualBox guest was not started or changed.</p>')
[void]$sb.AppendLine('<table class="toc"><thead><tr><th>File</th><th>Lines</th><th>What it does</th></tr></thead><tbody>')

$bodies = @()
foreach ($item in $files) {
  $full = Join-Path $root $item.Path
  $raw = [System.IO.File]::ReadAllText($full)
  $raw = $raw -replace "`r`n", "`n" -replace "`r", "`n"
  $lines = $raw -split "`n", -1
  $n = $lines.Count
  [void]$sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1}</td><td>{2}</td></tr>' -f (Html-Encode $item.Path), $n, (Html-Encode $item.Role)))
  $pre = New-Object System.Text.StringBuilder
  $i = 1
  foreach ($ln in $lines) {
    [void]$pre.Append(('{0,5}| {1}' -f $i, (Html-Encode $ln)))
    [void]$pre.Append("`n")
    $i++
  }
  $bodies += @{ Path = $item.Path; Role = $item.Role; Lines = $n; Pre = $pre.ToString() }
}

[void]$sb.AppendLine('</tbody></table>')
[void]$sb.AppendLine('<p class="meta">Line numbers are 1-based from the start of each file. Long lines wrap.</p>')

$first = $true
foreach ($b in $bodies) {
  $cls = if ($first) { ' class="first"' } else { '' }
  $first = $false
  [void]$sb.AppendLine(('<h2{0}><code>{1}</code></h2>' -f $cls, (Html-Encode $b.Path)))
  [void]$sb.AppendLine(('<p class="meta">{0} &nbsp;·&nbsp; {1} lines</p>' -f (Html-Encode $b.Role), $b.Lines))
  [void]$sb.AppendLine('<pre>')
  [void]$sb.Append($b.Pre)
  [void]$sb.AppendLine('</pre>')
}

[void]$sb.AppendLine('</body></html>')
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), $utf8)
Write-Host "HTML $htmlPath bytes=$((Get-Item $htmlPath).Length)"

try {
  $existing = [Runtime.InteropServices.Marshal]::GetActiveObject("Word.Application")
  if ($existing -and -not $existing.Visible) {
    foreach ($d in @($existing.Documents)) { try { $d.Close([ref]$false) } catch { } }
    $existing.Quit()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($existing) | Out-Null
    Start-Sleep -Seconds 2
  }
} catch { }

$word = $null
$doc = $null
try {
  $word = New-Object -ComObject Word.Application
  $word.Visible = $false
  $word.DisplayAlerts = 0
  $confirm = $false
  $readOnly = $true
  $doc = $word.Documents.Open($htmlPath, $confirm, $readOnly)
  $doc.PageSetup.TopMargin = 54
  $doc.PageSetup.BottomMargin = 54
  $doc.PageSetup.LeftMargin = 50
  $doc.PageSetup.RightMargin = 50

  $wdExportFormatPDF = 17
  $exported = $null
  foreach ($target in @($outPdf, $altPdf)) {
    try {
      if (Test-Path $target) { Remove-Item $target -Force -ErrorAction Stop }
      $doc.ExportAsFixedFormat($target, $wdExportFormatPDF)
      if ((Test-Path $target) -and ((Get-Item $target).Length -gt 5000)) {
        $exported = $target
        break
      }
    } catch {
      Write-Host "EXPORT_SKIP $target : $($_.Exception.Message)"
    }
  }

  try {
    if (Test-Path $outDocx) { Remove-Item $outDocx -Force -ErrorAction SilentlyContinue }
    $wdFormatXMLDocument = 12
    $null = $doc.SaveAs2($outDocx, $wdFormatXMLDocument)
  } catch {
    Write-Host "DOCX_SKIP $($_.Exception.Message)"
  }

  if (-not $exported) { throw "PDF was not created (file may be open)" }
  Get-Item $exported | Select-Object FullName, Length, LastWriteTime | Format-List
  Write-Host "PDF_OK $exported"
}
finally {
  if ($doc -ne $null) { try { $doc.Close([ref]$false) } catch { } }
  if ($word -ne $null) { try { $word.Quit() } catch { } }
  if ($doc -ne $null) { try { [Runtime.InteropServices.Marshal]::ReleaseComObject($doc) | Out-Null } catch { } }
  if ($word -ne $null) { try { [Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null } catch { } }
  [GC]::Collect()
  [GC]::WaitForPendingFinalizers()
}
