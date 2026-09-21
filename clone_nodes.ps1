$ErrorActionPreference = "Stop"

$configPath = Join-Path $PSScriptRoot "config\workstation.ps1"

if (-not (Test-Path $configPath)) {
    throw "Workstation configuration not found: $configPath. Copy config\workstation.example.ps1 to config\workstation.ps1 and customize it for your environment."
}

$workstation = & $configPath

$vmrun = $workstation.VmrunPath
$vmRoot = $workstation.VmRoot
$baseVmx = Join-Path (Join-Path $vmRoot "k3s-base-v2") "k3s-base-v2.vmx"

# Read node names from nodes.py, the cluster source of truth.
$nodeNames = @(
    python -c 'import sys; sys.path.insert(0, sys.argv[1]); from nodes import NODES; [print(n[\"name\"]) for n in NODES]' $PSScriptRoot
)

if ($LASTEXITCODE -ne 0 -or $nodeNames.Count -eq 0) {
    throw "Unable to read node definitions from nodes.py"
}

Write-Host "Nodes defined in nodes.py:"
$nodeNames | ForEach-Object { Write-Host "  $_" }

foreach ($name in $nodeNames) {
    $destDir = Join-Path $vmRoot $name
    $destVmx = Join-Path $destDir "$name.vmx"

    if (Test-Path $destVmx) {
        Write-Host "$name already exists - skipping"
        continue
    }

    Write-Host "Cloning $name..."
    & $vmrun -T ws clone $baseVmx $destVmx full

    if ($LASTEXITCODE -eq 0) {
        # vmrun names cloned VMs "Clone of <source>" by default.
        # Make the VMware display name match the node name.
        (Get-Content $destVmx) `
            -replace '^displayname\s*=.*$', "displayName = `"$name`"" |
            Set-Content $destVmx

        Write-Host "$name cloned successfully"
    }
    else {
        throw "Clone failed for $name"
    }
}

Write-Host "Done. VMs are ready for V2 bootstrap."
