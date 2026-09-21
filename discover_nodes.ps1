$ErrorActionPreference = "Stop"

$configPath = Join-Path $PSScriptRoot "config\workstation.ps1"

if (-not (Test-Path $configPath)) {
    throw "Workstation configuration not found: $configPath. Copy config\workstation.example.ps1 to config\workstation.ps1 and customize it for your environment."
}

$workstation = & $configPath

$vmrun = $workstation.VmrunPath
$vmRoot = $workstation.VmRoot

# Read node name and permanent IP from nodes.py.
$nodesJson = python -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from nodes import NODES; print(json.dumps(NODES))' $PSScriptRoot

if ($LASTEXITCODE -ne 0) {
    throw "Unable to read node definitions from nodes.py"
}

$nodes = $nodesJson | ConvertFrom-Json

foreach ($node in $nodes) {
    $name = $node.name
    $desiredIp = $node.ip
    $vmx = Join-Path (Join-Path $vmRoot $name) "$name.vmx"

    if (-not (Test-Path $vmx)) {
        Write-Host "$name : VM not found"
        continue
    }

    $guestIp = & $vmrun -T ws getGuestIPAddress $vmx 2>$null

    if ($LASTEXITCODE -eq 0 -and $guestIp) {
        Write-Host "$name : current=$guestIp desired=$desiredIp"
    }
    else {
        Write-Host "$name : powered off or IP unavailable; desired=$desiredIp"
    }
}
