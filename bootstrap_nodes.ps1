param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$NodeName
)

$ErrorActionPreference = "Stop"

$configPath = Join-Path $PSScriptRoot "config\workstation.ps1"

if (-not (Test-Path $configPath)) {
    throw "Workstation configuration not found: $configPath. Copy config\workstation.example.ps1 to config\workstation.ps1 and customize it for your environment."
}

$workstation = & $configPath

$vmrun = $workstation.VmrunPath
$vmRoot = $workstation.VmRoot
$repoWsl = $workstation.RepoWsl
$inventoryPath = Join-Path $PSScriptRoot "ansible\inventory\bootstrap.ini"

function Fail {
    param([string]$Message)
    throw $Message
}

Write-Host ""
Write-Host "=== V2 NODE BOOTSTRAP: $NodeName ==="
Write-Host ""

# ----------------------------------------------------------------------
# 1. Load desired state from nodes.py
# ----------------------------------------------------------------------

$configJson = python -c 'import json, sys; sys.path.insert(0, sys.argv[1]); from nodes import NODES, GATEWAY, DNS_SERVERS, DNS_ZONE; print(json.dumps(dict(nodes=NODES, gateway=GATEWAY, dns_servers=DNS_SERVERS, dns_zone=DNS_ZONE)))' $PSScriptRoot

if ($LASTEXITCODE -ne 0 -or -not $configJson) {
    Fail "Unable to read cluster configuration from nodes.py"
}

$config = $configJson | ConvertFrom-Json
$node = $config.nodes | Where-Object { $_.name -eq $NodeName }

if (-not $node) {
    $validNames = ($config.nodes | ForEach-Object { $_.name }) -join ", "
    Fail "Unknown node '$NodeName'. Valid nodes: $validNames"
}

$desiredIp = $node.ip
$vmx = Join-Path (Join-Path $vmRoot $NodeName) "$NodeName.vmx"

Write-Host "Desired state:"
Write-Host "  Node: $NodeName"
Write-Host "  IP:   $desiredIp"
Write-Host ""

if (-not (Test-Path $vmx)) {
    Fail "VMX not found: $vmx"
}

# ----------------------------------------------------------------------
# 2. Determine whether VM is already running
# ----------------------------------------------------------------------

$runningOutput = & $vmrun -T ws list

if ($LASTEXITCODE -ne 0) {
    Fail "Unable to retrieve running VMware VMs"
}

$runningVmx = @(
    $runningOutput |
        Select-Object -Skip 1 |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)

$isRunning = $runningVmx -contains $vmx

if (-not $isRunning) {
    Write-Host "Starting $NodeName..."
    & $vmrun -T ws start $vmx nogui

    if ($LASTEXITCODE -ne 0) {
        Fail "Unable to start $NodeName"
    }
}
else {
    Write-Host "$NodeName is already running."
}

# ----------------------------------------------------------------------
# 3. Wait for VMware Tools to report an IPv4 address
# ----------------------------------------------------------------------

Write-Host "Waiting for guest IP..."

$guestIp = $null
$deadline = (Get-Date).AddMinutes(3)

while ((Get-Date) -lt $deadline) {
    $candidate = & $vmrun -T ws getGuestIPAddress $vmx 2>$null

    if ($LASTEXITCODE -eq 0 -and
        $candidate -match '^\d{1,3}(\.\d{1,3}){3}$') {
        $guestIp = $candidate.Trim()
        break
    }

    Start-Sleep -Seconds 5
}

if (-not $guestIp) {
    Fail "Timed out waiting for an IPv4 address from $NodeName"
}

Write-Host "VMware reports: $guestIp"

# ----------------------------------------------------------------------
# 4. Refuse to bootstrap an already-configured node
# ----------------------------------------------------------------------

if ($guestIp -eq $desiredIp) {
    Fail "$NodeName is already using its desired address $desiredIp. Bootstrap not required."
}

Write-Host "Bootstrap transition: $guestIp -> $desiredIp"
Write-Host ""

# ----------------------------------------------------------------------
# 5. Generate a SINGLE-NODE bootstrap inventory
# ----------------------------------------------------------------------

$dnsJson = ConvertTo-Json -InputObject @($config.dns_servers) -Compress

$inventory = @(
    "[bootstrap]"
    "$NodeName ansible_host=$guestIp node_ip=$desiredIp"
    ""
    "[bootstrap:vars]"
    "ansible_user=ansible"
    "ansible_ssh_private_key_file=~/.ssh/id_ed25519"
    "gateway=$($config.gateway)"
    "dns_servers=$dnsJson"
    "dns_zone=$($config.dns_zone)"
)

$inventory | Set-Content $inventoryPath

Write-Host "Generated single-node bootstrap inventory:"
Get-Content $inventoryPath
Write-Host ""

# ----------------------------------------------------------------------
# 6. Wait for SSH and establish host-key trust
# ----------------------------------------------------------------------

Write-Host "Waiting for SSH on $guestIp..."

$sshReady = $false
$deadline = (Get-Date).AddMinutes(3)

while ((Get-Date) -lt $deadline) {

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    wsl -d Ubuntu -- bash -lc "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 ansible@$guestIp 'true'" 2>$null
    $sshExitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldErrorActionPreference

    if ($sshExitCode -eq 0) {
        $sshReady = $true
        break
    }

    Start-Sleep -Seconds 5
}

if (-not $sshReady) {
    Fail "Timed out waiting for SSH on $guestIp"
}

Write-Host "SSH ready."
Write-Host ""

# ----------------------------------------------------------------------
# 7. Run Ansible bootstrap
# ----------------------------------------------------------------------

Write-Host "Running Ansible bootstrap..."

wsl -d Ubuntu -- bash -lc "cd $repoWsl && ansible-playbook -i ansible/inventory/bootstrap.ini ansible/bootstrap.yml --diff"

if ($LASTEXITCODE -ne 0) {
    Fail "Ansible bootstrap failed. Node will NOT be rebooted."
}

Write-Host ""
Write-Host "Ansible bootstrap completed successfully."

# ----------------------------------------------------------------------
# 8. Reboot from temporary DHCP address
# ----------------------------------------------------------------------

Write-Host "Rebooting $NodeName..."

wsl -d Ubuntu -- bash -lc "ssh ansible@$guestIp 'sudo reboot'" 2>$null

# SSH may disconnect abruptly during reboot. Do not treat that as failure.

# ----------------------------------------------------------------------
# 9. Wait for permanent address
# ----------------------------------------------------------------------

Write-Host "Waiting for $desiredIp..."

$targetReady = $false
$deadline = (Get-Date).AddMinutes(3)

while ((Get-Date) -lt $deadline) {

    $oldErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    wsl -d Ubuntu -- bash -lc "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 ansible@$desiredIp 'true'" 2>$null
    $sshExitCode = $LASTEXITCODE
    $ErrorActionPreference = $oldErrorActionPreference

    if ($sshExitCode -eq 0) {
        $targetReady = $true
        break
    }

    Start-Sleep -Seconds 5
}

if (-not $targetReady) {
    Fail "$NodeName did not become reachable at $desiredIp"
}

Write-Host "$NodeName is reachable at $desiredIp."
Write-Host ""

# ----------------------------------------------------------------------
# 10. Final acceptance checks
# ----------------------------------------------------------------------

Write-Host "Running final acceptance checks..."

$validationCommand = @"
set -e
test "`$(hostname)" = "$NodeName"
ip -4 addr show ens160 | grep -q "$desiredIp/24"
ip route | grep -q "default via $($config.gateway)"
sudo grep -q "$desiredIp/24" /etc/netplan/60-static-network.yaml
sudo grep -q "network: {config: disabled}" /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
ping -c 2 $($config.gateway) >/dev/null
getent hosts github.com >/dev/null
echo "hostname: OK"
echo "static IP: OK"
echo "default route: OK"
echo "netplan: OK"
echo "cloud-init network disable: OK"
echo "gateway connectivity: OK"
echo "DNS resolution: OK"
"@

wsl -d Ubuntu -- bash -lc "ssh ansible@$desiredIp '$validationCommand'"

if ($LASTEXITCODE -ne 0) {
    Fail "Final validation failed for $NodeName"
}

Write-Host ""
Write-Host "=== BOOTSTRAP COMPLETE ==="
Write-Host "$NodeName -> $desiredIp"
