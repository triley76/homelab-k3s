$ErrorActionPreference = "Stop"

$configPath = Join-Path $PSScriptRoot "config\workstation.ps1"

if (-not (Test-Path $configPath)) {
    throw "Workstation configuration not found: $configPath. Copy config\workstation.example.ps1 to config\workstation.ps1 and customize it for your environment."
}

$workstation = & $configPath

$vmrun = $workstation.VmrunPath
$vmRoot = $workstation.VmRoot
$inventoryPath = Join-Path $PSScriptRoot "ansible\inventory\bootstrap.ini"

# Read cluster configuration from nodes.py.
$configJson = python -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from nodes import NODES, GATEWAY, DNS_SERVERS, DNS_ZONE; print(json.dumps(dict(nodes=NODES, gateway=GATEWAY, dns_servers=DNS_SERVERS, dns_zone=DNS_ZONE)))' $PSScriptRoot

if ($LASTEXITCODE -ne 0 -or -not $configJson) {
    throw "Unable to read cluster configuration from nodes.py"
}

$config = $configJson | ConvertFrom-Json

# Determine which VMs VMware actually considers running.
$runningOutput = & $vmrun -T ws list

if ($LASTEXITCODE -ne 0) {
    throw "Unable to retrieve running VMware VMs"
}

$runningVmx = @(
    $runningOutput |
        Select-Object -Skip 1 |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)

$lines = @()
$lines += "[bootstrap]"

foreach ($node in $config.nodes) {
    $name = $node.name
    $desiredIp = $node.ip
    $vmx = Join-Path (Join-Path $vmRoot $name) "$name.vmx"

    if (-not (Test-Path $vmx)) {
        Write-Host "$name : VM not found - skipping"
        continue
    }

    if ($runningVmx -notcontains $vmx) {
        Write-Host "$name : powered off - skipping"
        continue
    }

    $guestIp = & $vmrun -T ws getGuestIPAddress $vmx 2>$null

    if ($LASTEXITCODE -ne 0 -or -not $guestIp) {
        Write-Host "$name : running but IP unavailable - skipping"
        continue
    }

    if ($guestIp -eq $desiredIp) {
        Write-Host "$name : already configured at $desiredIp - skipping"
        continue
    }

    Write-Host "$name : bootstrap $guestIp -> $desiredIp"
    $lines += "$name ansible_host=$guestIp node_ip=$desiredIp"
}

$lines += ""
$lines += "[bootstrap:vars]"
$lines += "ansible_user=ansible"
$lines += "ansible_ssh_private_key_file=~/.ssh/id_ed25519"
$lines += "gateway=$($config.gateway)"

$dnsJson = ConvertTo-Json -InputObject @($config.dns_servers) -Compress
$lines += "dns_servers=$dnsJson"

$lines += "dns_zone=$($config.dns_zone)"

$lines | Set-Content $inventoryPath

Write-Host ""
Write-Host "Wrote $inventoryPath"
