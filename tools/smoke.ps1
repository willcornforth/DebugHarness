<#
.SYNOPSIS
  Live invariant checks for a debug_harness listener. Run against any host that has
  called debug_harness::start(); nothing here depends on what the host is.

.NOTES
  A write round-trip is deliberately absent: writes have to be armed in-process
  (mem::arm_writes), which by design cannot be done over HTTP, so it cannot run
  unattended. Verify it by hand instead.
#>
[CmdletBinding()]
param([int]$Port = 27015)

$ErrorActionPreference = 'Continue'
$base = "http://127.0.0.1:$Port"
$script:passed = 0
$script:failed = 0

function Check {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) { Write-Host "  PASS  $Name" -ForegroundColor Green; $script:passed++ }
        else { Write-Host "  FAIL  $Name" -ForegroundColor Red; $script:failed++ }
    }
    catch {
        Write-Host "  FAIL  $Name -- $_" -ForegroundColor Red
        $script:failed++
    }
}

function Get-Harness { param([string]$Path) Invoke-RestMethod -Uri "$base$Path" -Method Get }
function Esc { param([string]$Text) [uri]::EscapeDataString($Text) }

Write-Host "Debug harness smoke checks against $base`n"

try {
    $ping = Get-Harness "/ping"
}
catch {
    Write-Host "Cannot reach $base - has the host called debug_harness::start()?" -ForegroundColor Red
    exit 1
}

Check "1. /ping answers ok with a module base" {
    $ping.ok -and $ping.base -ne '0x0' -and $ping.module -ne ''
}

Check "2. /roots contains @base, valid and equal to the /ping base" {
    $roots = Get-Harness "/roots"
    $entry = $roots.roots | Where-Object { $_.name -eq '@base' }
    $roots.ok -and $entry -and $entry.valid -and $entry.value -eq $ping.base
}

Check "3. /addr of rva:0x0 is the module base, at rva 0x0" {
    $addr = Get-Harness "/addr?e=$(Esc 'rva:0x0')"
    $addr.ok -and $addr.va -eq $ping.base -and $addr.rva -eq '0x0'
}

Check "4. ida: and rva: agree for the same offset" {
    $ida = [Convert]::ToUInt64($ping.preferredBase.Substring(2), 16) + 0x1000
    $viaIda = Get-Harness "/addr?e=$(Esc ("ida:0x{0:X}" -f $ida))"
    $viaRva = Get-Harness "/addr?e=$(Esc 'rva:0x1000')"
    $viaIda.ok -and $viaIda.va -eq $viaRva.va
}

Check "5. /chain of '@base' resolves to the module base" {
    $chain = Get-Harness "/chain?e=$(Esc '@base')"
    $chain.ok -and $chain.result -eq $ping.base -and $chain.steps.Count -ge 1
}

Check "6. a scan for the PE 'MZ' header finds the module base" {
    # Every PE image starts with the DOS magic, and the scan walks the configured module
    # from its base, so the first hit is the image itself.
    $scan = Get-Harness "/scan?p=$(Esc '4D 5A')&max=4"
    $scan.ok -and $scan.totalHits -ge 1 -and $scan.hits[0].va -eq $ping.base -and $scan.hits[0].rva -eq '0x0'
}

Check "7. /routes lists the built-in endpoints" {
    $routes = Get-Harness "/routes"
    $builtIn = @($routes.routes | Where-Object { $_.builtIn } | ForEach-Object { $_.path })
    $routes.ok -and ($builtIn -contains '/ping') -and ($builtIn -contains '/routes') -and
        ($builtIn -contains '/chain') -and ($builtIn -contains '/write')
}

Check "8. an unmapped read fails without crashing" {
    $read = Get-Harness "/read?e=$(Esc 'va:0x10')&n=8"
    $read.ok -and (-not $read.read)
}

Check "9. a broken chain reports the failing link, not an error page" {
    # Windows permanently reserves the low 64K, so a deref at 0x1000 can never succeed.
    $chain = Get-Harness "/chain?e=$(Esc 'va:0x1000[]')"
    (-not $chain.ok) -and $chain.steps.Count -ge 2 -and $chain.steps[0].ok -and (-not $chain.steps[-1].ok)
}

Check "10. /write is refused while disarmed" {
    if ($ping.writesArmed) { throw "writes are armed in-process; disarm them to run this check" }
    try {
        Invoke-RestMethod -Uri "$base/write?e=$(Esc '@base')&as=u8&v=1" -Method Post | Out-Null
        $false   # a 200 here means the arm gate leaked
    }
    catch {
        $_.Exception.Response.StatusCode.value__ -eq 403
    }
}

Write-Host "`n$script:passed passed, $script:failed failed"
if ($script:failed -gt 0) { exit 1 }
exit 0
