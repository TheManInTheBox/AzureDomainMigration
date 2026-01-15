param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true)]
    [string]$VmName,
    
    [Parameter(Mandatory = $true)]
    [string]$OldDomain,
    
    [Parameter(Mandatory = $true)]
    [string]$NewDomain,
    
    [Parameter(Mandatory = $true)]
    [string]$NewDomainUsername,
    
    [Parameter(Mandatory = $true)]
    [securestring]$NewDomainPassword,
    
    [string]$UnjoinUsername,
    
    [securestring]$UnjoinPassword,
    
    [switch]$WhatIf = $false,
    
    [switch]$Force = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Define script configuration
$scriptConfig = @{
    AzCliRequired     = $true
    ExtensionName     = "DomainMigration"
    ExtensionVersion  = "1.0"
    CommandTimeout    = 3600
    RetryAttempts     = 3
    RetryDelaySeconds = 10
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Azure VM Domain Migration Script" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Parameters:"
Write-Host "  Resource Group: $ResourceGroupName"
Write-Host "  VM Name: $VmName"
Write-Host "  Current Domain: $OldDomain"
Write-Host "  New Domain: $NewDomain"
Write-Host "  WhatIf Mode: $WhatIf"
Write-Host ""

function Test-AzCliInstalled {
    try {
        $version = az version 2>$null | ConvertFrom-Json
        Write-Host "✓ Azure CLI is installed (Version: $($version.'azure-cli'))" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Azure CLI is not installed or not accessible" -ForegroundColor Red
        Write-Host "  Please install Azure CLI from: https://aka.ms/installazurecliwindows" -ForegroundColor Yellow
        return $false
    }
}

function Test-AzureVmExtension {
    param(
        [string]$ResourceGroup,
        [string]$VmName,
        [string]$ExtensionName
    )
    
    try {
        $extension = az vm extension image list --location "eastus" --name $ExtensionName 2>$null | ConvertFrom-Json
        return $null -ne $extension -and $extension.Count -gt 0
    }
    catch {
        return $false
    }
}

function Invoke-VmCommand {
    param(
        [string]$ResourceGroup,
        [string]$VmName,
        [string]$Command,
        [bool]$IsWhatIf = $false
    )
    
    $commandId = "RunPowerShellScript"
    
    if ($IsWhatIf) {
        Write-Host "  [WhatIf] Would execute command on VM: $VmName" -ForegroundColor Yellow
        Write-Host "  [WhatIf] Command: $Command" -ForegroundColor Yellow
        return @{ success = $true; output = "WhatIf mode - command not executed" }
    }
    
    try {
        Write-Host "  Executing command on VM: $VmName..." -ForegroundColor Cyan
        
        $result = az vm run-command invoke `
            --resource-group $ResourceGroup `
            --name $VmName `
            --command-id $commandId `
            --scripts $Command | ConvertFrom-Json
        
        if ($result.value -and $result.value[0].message) {
            return @{ success = $true; output = $result.value[0].message }
        }
        return @{ success = $false; output = "No output returned" }
    }
    catch {
        return @{ success = $false; output = $_.Exception.Message }
    }
}

function Unjoin-Domain {
    param(
        [string]$ResourceGroup,
        [string]$VmName,
        [string]$Domain,
        [string]$Username,
        [securestring]$Password,
        [bool]$IsWhatIf = $false
    )
    
    Write-Host ""
    Write-Host "Step 1: Unjoining from domain: $Domain" -ForegroundColor Cyan
    Write-Host "=========================================="
    
    # Create the unjoin command
    if ($Username -and $Password) {
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Password))
        $unjoinCommand = @"
`$credential = New-Object System.Management.Automation.PSCredential('$Username', (ConvertTo-SecureString '$plainPassword' -AsPlainText -Force))
Remove-Computer -ComputerName localhost -UnjoinDomainCredential `$credential -Restart -Force -ErrorAction Stop
"@
    }
    else {
        $unjoinCommand = "Remove-Computer -ComputerName localhost -Restart -Force -ErrorAction Stop"
    }
    
    $result = Invoke-VmCommand -ResourceGroup $ResourceGroup -VmName $VmName -Command $unjoinCommand -IsWhatIf $IsWhatIf
    
    if ($result.success -or $IsWhatIf) {
        Write-Host "✓ Domain unjoin command issued successfully" -ForegroundColor Green
        if ($IsWhatIf) {
            Write-Host "  Note: In WhatIf mode, command was not actually executed" -ForegroundColor Yellow
        }
        return $true
    }
    else {
        Write-Host "✗ Failed to unjoin domain: $($result.output)" -ForegroundColor Red
        return $false
    }
}

function Join-NewDomain {
    param(
        [string]$ResourceGroup,
        [string]$VmName,
        [string]$Domain,
        [string]$Username,
        [securestring]$Password,
        [bool]$IsWhatIf = $false,
        [bool]$WaitForRestart = $true
    )
    
    Write-Host ""
    Write-Host "Step 2: Joining new domain: $Domain" -ForegroundColor Cyan
    Write-Host "=========================================="
    
    if ($WaitForRestart) {
        Write-Host "  Waiting for VM to restart after unjoin..." -ForegroundColor Yellow
        Start-Sleep -Seconds 120
        
        Write-Host "  Checking VM status..." -ForegroundColor Cyan
        $retryCount = 0
        while ($retryCount -lt 30) {
            try {
                $vmStatus = az vm get-instance-view --resource-group $ResourceGroup --name $VmName --query "instanceView.statuses[?starts_with(code, 'PowerState')].displayStatus" --output tsv
                if ($vmStatus -like "*running*") {
                    Write-Host "  ✓ VM is running and ready" -ForegroundColor Green
                    break
                }
            }
            catch { }
            $retryCount++
            Start-Sleep -Seconds 10
        }
    }
    
    # Create the join command
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Password))
    $joinCommand = @"
`$credential = New-Object System.Management.Automation.PSCredential('$Username', (ConvertTo-SecureString '$plainPassword' -AsPlainText -Force))
Add-Computer -DomainName '$Domain' -Credential `$credential -Restart -Force -ErrorAction Stop
"@
    
    $result = Invoke-VmCommand -ResourceGroup $ResourceGroup -VmName $VmName -Command $joinCommand -IsWhatIf $IsWhatIf
    
    if ($result.success -or $IsWhatIf) {
        Write-Host "✓ Domain join command issued successfully" -ForegroundColor Green
        if ($IsWhatIf) {
            Write-Host "  Note: In WhatIf mode, command was not actually executed" -ForegroundColor Yellow
        }
        if ($IsWhatIf -eq $false) {
            Write-Host "  VM will restart to complete domain join" -ForegroundColor Yellow
        }
        return $true
    }
    else {
        Write-Host "✗ Failed to join domain: $($result.output)" -ForegroundColor Red
        return $false
    }
}

function Get-VmStatus {
    param(
        [string]$ResourceGroup,
        [string]$VmName
    )
    
    try {
        $vm = az vm get-instance-view --resource-group $ResourceGroup --name $VmName --query "instanceView.statuses[?starts_with(code, 'PowerState')].displayStatus" --output tsv
        return $vm
    }
    catch {
        return "Unknown"
    }
}

# Main execution
try {
    Write-Host "Validating prerequisites..." -ForegroundColor Cyan
    Write-Host ""
    
    # Check Azure CLI
    if (-not (Test-AzCliInstalled)) {
        throw "Azure CLI is required but not installed"
    }
    
    # Verify VM exists
    Write-Host "Verifying VM exists..."
    try {
        $vm = az vm show --resource-group $ResourceGroupName --name $VmName 2>$null | ConvertFrom-Json
        Write-Host "✓ VM found: $VmName" -ForegroundColor Green
    }
    catch {
        throw "VM '$VmName' not found in resource group '$ResourceGroupName'"
    }
    
    # Check VM is running
    $vmStatus = Get-VmStatus -ResourceGroup $ResourceGroupName -VmName $VmName
    if ($vmStatus -notlike "*running*") {
        throw "VM is not in running state. Current state: $vmStatus"
    }
    Write-Host "✓ VM is in running state" -ForegroundColor Green
    
    if (-not $WhatIf -and -not $Force) {
        Write-Host ""
        Write-Host "WARNING: This operation will:" -ForegroundColor Yellow
        Write-Host "  1. Unjoin the VM from domain: $OldDomain"
        Write-Host "  2. Restart the VM"
        Write-Host "  3. Join the VM to domain: $NewDomain"
        Write-Host "  4. Restart the VM again"
        Write-Host ""
        $confirmation = Read-Host "Do you want to proceed? (yes/no)"
        if ($confirmation -ne "yes") {
            Write-Host "Operation cancelled by user" -ForegroundColor Yellow
            exit 0
        }
    }
    
    Write-Host ""
    Write-Host "Starting domain migration process..." -ForegroundColor Cyan
    
    # Step 1: Unjoin from old domain
    $unjoinSuccess = Unjoin-Domain -ResourceGroup $ResourceGroupName -VmName $VmName -Domain $OldDomain -Username $UnjoinUsername -Password $UnjoinPassword -IsWhatIf $WhatIf
    
    if (-not $unjoinSuccess) {
        throw "Failed to unjoin from domain $OldDomain"
    }
    
    # Step 2: Join new domain
    $joinSuccess = Join-NewDomain -ResourceGroup $ResourceGroupName -VmName $VmName -Domain $NewDomain -Username $NewDomainUsername -Password $NewDomainPassword -IsWhatIf $WhatIf
    
    if (-not $joinSuccess) {
        throw "Failed to join domain $NewDomain"
    }
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "Domain migration process completed successfully!" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    
    if (-not $WhatIf) {
        Write-Host ""
        Write-Host "Note: The VM will restart to complete the domain join." -ForegroundColor Yellow
        Write-Host "Please verify the VM is properly joined to $NewDomain after restart." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host "WhatIf execution completed. No changes were made to the VM." -ForegroundColor Yellow
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
