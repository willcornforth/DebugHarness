<#
.SYNOPSIS
  Client for the debug_harness loopback listener.

.EXAMPLE
  .\tools\mem.ps1 ping
  .\tools\mem.ps1 routes
  .\tools\mem.ps1 roots
  .\tools\mem.ps1 chain '@base[+0x3C]'
  .\tools\mem.ps1 read  '@base+0x3C' -As u32
  .\tools\mem.ps1 struct '@base' -N 0x100
  .\tools\mem.ps1 vtable 'va:0x7FF6A0001000' -Count 32
  .\tools\mem.ps1 scan  '4D 5A 90 00'
  .\tools\mem.ps1 addr  'rva:0x1000'
  .\tools\mem.ps1 offsets Player
  .\tools\mem.ps1 log -Since 100
  .\tools\mem.ps1 write '@base+0x10' -As u8 -Value 0x90     # requires arming in-process
  .\tools\mem.ps1 get   '/my-host-route?x=1'               # any host-registered GET route

.NOTES
  The host must have called debug_harness::start() first (default port 27015).
  /offsets and /log are only as useful as the host's host_config callbacks; /log
  answers 404 when the host provides no log_entries. For 'log', a host that trims
  aged entries makes -Since a best-effort cursor rather than a stable one.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('ping','routes','roots','addr','region','read','chain','struct','vtable',
                 'scan','offsets','log','write','get')]
    [string]$Command,

    [Parameter(Position = 1)]
    [string]$Argument,

    [int]$Port = 27015,
    [string]$As = 'hex',
    [string]$N,
    [int]$Count = 64,
    [string]$Value,
    [string]$Since,
    [switch]$Force,
    [switch]$Raw
)

$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$Port"

function Invoke-Harness {
    param([string]$Url, [string]$Method = 'GET', [string]$Body)
    try {
        if ($Method -eq 'POST') {
            return Invoke-RestMethod -Uri $Url -Method Post -Body $Body -ContentType 'text/plain'
        }
        return Invoke-RestMethod -Uri $Url -Method Get
    }
    catch {
        # The harness answers with JSON on 4xx/5xx too; surface it rather than the wrapper error.
        $response = $_.Exception.Response
        if ($response) {
            try {
                $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
                $text = $reader.ReadToEnd()
                if ($text) { return ($text | ConvertFrom-Json) }
            } catch { }
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try { return ($_.ErrorDetails.Message | ConvertFrom-Json) } catch { }
            }
        }
        throw "harness unreachable at $base - has the host called debug_harness::start()? ($_)"
    }
}

$expression = [uri]::EscapeDataString($Argument)

switch ($Command) {
    'ping'    { $result = Invoke-Harness "$base/ping" }
    'routes'  { $result = Invoke-Harness "$base/routes" }
    'roots'   { $result = Invoke-Harness "$base/roots" }
    'addr'    { $result = Invoke-Harness "$base/addr?e=$expression" }
    'region'  { $result = Invoke-Harness "$base/region?e=$expression" }
    'chain'   { $result = Invoke-Harness "$base/chain?e=$expression" }
    'vtable'  { $result = Invoke-Harness "$base/vtable?e=$expression&count=$Count" }
    'offsets' { $result = Invoke-Harness "$base/offsets?filter=$expression" }
    'scan'    { $result = Invoke-Harness "$base/scan?p=$expression" }
    'log' {
        $url = "$base/log"
        if ($Since) { $url += "?since=$Since" }
        $result = Invoke-Harness $url
    }
    'read' {
        $url = "$base/read?e=$expression&as=$As"
        if ($N) { $url += "&n=$N" }
        $result = Invoke-Harness $url
    }
    'struct' {
        $url = "$base/struct?e=$expression"
        if ($N) { $url += "&n=$N" }
        $result = Invoke-Harness $url
    }
    'write' {
        if (-not $Value) { throw "write requires -Value" }
        $url = "$base/write?e=$expression&as=$As&v=$([uri]::EscapeDataString($Value))"
        if ($Force) { $url += "&force=1" }
        $result = Invoke-Harness $url -Method POST -Body ''
    }
    'get' {
        # Raw path, already URL-encoded by the caller: for host-registered routes.
        if (-not $Argument -or -not $Argument.StartsWith('/')) { throw "get requires a path starting with '/'" }
        $result = Invoke-Harness "$base$Argument"
    }
}

if ($Raw) {
    $result | ConvertTo-Json -Depth 10
}
else {
    switch ($Command) {
        # A chain is only readable as a table; everything else prints fine as objects.
        'chain' {
            if ($result.ok) { Write-Host "= $($result.result)" -ForegroundColor Green }
            else { Write-Host "error: $($result.error) (at $($result.errorAt))" -ForegroundColor Red }
            $result.steps | Format-Table label, address, value, ok, note -AutoSize
        }
        'struct'  { $result.fields  | Format-Table offset, value, kind -AutoSize }
        'vtable'  { $result.slots   | Format-Table index, indexHex, ida, section -AutoSize }
        'roots'   { $result.roots   | Format-Table name, value, valid, note -AutoSize }
        'routes'  { $result.routes  | Format-Table path, builtIn, shadowed, description -AutoSize }
        'offsets' {
            if ($result.note) { Write-Host $result.note -ForegroundColor Yellow }
            $result.offsets | Format-Table qualified, value -AutoSize
        }
        'log' {
            if ($result.ok -eq $false) { Write-Host "error: $($result.error)" -ForegroundColor Red }
            else { $result.entries | Format-Table index, level, message -AutoSize }
        }
        default   { $result | ConvertTo-Json -Depth 10 }
    }
}
