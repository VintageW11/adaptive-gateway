$ErrorActionPreference = "Stop"
$html = "C:\Users\rosea\Projects\adaptive-gateway\docs\saw_vpn_selection.html"
$outPdf = "C:\Users\rosea\Downloads\SuiSSD_SAW_VPN_Selection.pdf"
$altPdf = "C:\Users\rosea\Downloads\SAW_VPN_Selection.pdf"
$outDocx = "C:\Users\rosea\Downloads\SuiSSD_SAW_VPN_Selection.docx"

# Release a leftover hidden Automation instance so Open is not blocked.
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
  $doc = $word.Documents.Open($html, $confirm, $readOnly)
  $doc.PageSetup.TopMargin = 72
  $doc.PageSetup.BottomMargin = 72
  $doc.PageSetup.LeftMargin = 64
  $doc.PageSetup.RightMargin = 64

  $wdExportFormatPDF = 17
  $exported = $null
  foreach ($target in @($outPdf, $altPdf)) {
    try {
      if (Test-Path $target) { Remove-Item $target -Force -ErrorAction Stop }
      $doc.ExportAsFixedFormat($target, $wdExportFormatPDF)
      if ((Test-Path $target) -and ((Get-Item $target).Length -gt 1000)) {
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
    $copy = $doc.SaveAs2($outDocx, $wdFormatXMLDocument)
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
