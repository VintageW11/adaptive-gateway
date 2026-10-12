# Reports this PC's visible windows and browser address bars to the lab gateway.
# Titles and URLs stay off the public dashboard. The Test slide is the only viewer.
$ErrorActionPreference = "SilentlyContinue"
if (-not ("OpenedWindows" -as [type])) {
  Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class OpenedWindows {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
}
"@
}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$script:openedRows = New-Object System.Collections.ArrayList
$script:openedCb = [OpenedWindows+EnumProc]{
  param($h, $l)
  if (-not [OpenedWindows]::IsWindowVisible($h)) { return $true }
  $sb = New-Object System.Text.StringBuilder 256
  [void][OpenedWindows]::GetWindowText($h, $sb, $sb.Capacity)
  $title = $sb.ToString().Trim()
  if (-not $title) { return $true }
  $procId = [uint32]0
  [void][OpenedWindows]::GetWindowThreadProcessId($h, [ref]$procId)
  $name = ""
  try { $name = (Get-Process -Id $procId -ErrorAction SilentlyContinue).ProcessName } catch {}
  [void]$script:openedRows.Add([pscustomobject]@{ process = "$name"; title = "$title"; hwnd = "$h" })
  return $true
}

function Get-BrowserUrl([string]$hwndText) {
  $ps = [powershell]::Create()
  [void]$ps.AddScript({
    param($hwndText)
    $ErrorActionPreference = "SilentlyContinue"
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $hwnd = [IntPtr]::new([int64]$hwndText)
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    if (-not $root) { return "" }
    $byType = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::Edit)
    $names = New-Object System.Windows.Automation.OrCondition(@(
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Address and search bar")),
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Address and search bar, omnibox")),
      (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, "Search with Google or enter address"))
    ))
    $cond = New-Object System.Windows.Automation.AndCondition($byType, $names)
    $edit = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    if (-not $edit) { return "" }
    $pattern = $edit.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    return ([string]$pattern.Current.Value).Trim()
  }).AddArgument($hwndText)
  $handle = $ps.BeginInvoke()
  if (-not $handle.AsyncWaitHandle.WaitOne(1200)) {
    $ps.Stop()
    $ps.Dispose()
    return ""
  }
  $url = ""
  try { $url = [string]$ps.EndInvoke($handle) } catch { $url = "" }
  $ps.Dispose()
  return $url
}

function Test-DiscordCall([string]$hwndText) {
  $ps = [powershell]::Create()
  [void]$ps.AddScript({
    param($hwndText)
    $ErrorActionPreference = "SilentlyContinue"
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $hwnd = [IntPtr]::new([int64]$hwndText)
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    if (-not $root) { return $false }
    $byType = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::Button)
    $byName = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::NameProperty, "Disconnect")
    $cond = New-Object System.Windows.Automation.AndCondition($byType, $byName)
    $hit = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
    return [bool]$hit
  }).AddArgument($hwndText)
  $handle = $ps.BeginInvoke()
  if (-not $handle.AsyncWaitHandle.WaitOne(1200)) {
    $ps.Stop()
    $ps.Dispose()
    return $false
  }
  $onCall = $false
  try { $onCall = [bool]$ps.EndInvoke($handle) } catch { $onCall = $false }
  $ps.Dispose()
  return $onCall
}

function Get-BrowserTabs([string]$hwndText) {
  $titles = @()
  try {
    $hwnd = [IntPtr]::new([int64]$hwndText)
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
    if (-not $root) { return @() }
    $cond = New-Object System.Windows.Automation.PropertyCondition(
      [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
      [System.Windows.Automation.ControlType]::TabItem)
    $tabs = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond)
    foreach ($tab in $tabs) {
      $name = ""
      try { $name = [string]$tab.Current.Name } catch { continue }
      $name = $name.Trim()
      if ($name) { $titles += $name }
      if ($titles.Count -ge 30) { break }
    }
  } catch {}
  return $titles
}

$browsers = @("chrome", "msedge", "firefox", "brave", "opera")

while ($true) {
  $script:openedRows.Clear()
  try { [OpenedWindows]::EnumWindows($script:openedCb, [IntPtr]::Zero) | Out-Null } catch {}
  $apps = @()
  foreach ($row in @($script:openedRows | Select-Object -First 40)) {
    $url = ""
    $onCall = $false
    $tabTitles = @()
    if ($browsers -contains $row.process) {
      $url = Get-BrowserUrl $row.hwnd
      $tabTitles = @(Get-BrowserTabs $row.hwnd)
    } elseif ($row.process -eq "discord") {
      $onCall = Test-DiscordCall $row.hwnd
    }
    $apps += [pscustomobject]@{ process = $row.process; title = $row.title; url = $url; call = [bool]$onCall }
    foreach ($tabTitle in $tabTitles) {
      if ($tabTitle -and $tabTitle -ne $row.title) {
        $apps += [pscustomobject]@{ process = $row.process; title = $tabTitle; url = ""; call = $false }
      }
    }
  }
  if ($apps.Count -eq 0) {
    $json = '{"apps":[]}'
  } elseif ($apps.Count -eq 1) {
    $json = '{"apps":[' + ($apps | ConvertTo-Json -Compress -Depth 4) + ']}'
  } else {
    $json = '{"apps":' + ($apps | ConvertTo-Json -Compress -Depth 4) + '}'
  }
  try {
    Invoke-RestMethod -Uri "http://192.168.50.10:5006/api/opened" -Method Post -Body $json -ContentType "application/json; charset=utf-8" -TimeoutSec 4 | Out-Null
  } catch {}
  Start-Sleep -Seconds 2
}
