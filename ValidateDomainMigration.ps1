param(
    [Parameter(Mandatory = $true)]
    [string]$NewDomain,
    
    [string]$OldDomain,
    
    [string]$IISWebsiteName = "*"
)

$results = @()

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AppCmdPath {
    $path = "$env:windir\System32\inetsrv\appcmd.exe"
    if (Test-Path $path) { return $path }
    return $null
}

function Convert-BindingString {
    param(
        [string]$BindingString,
        [string]$SiteName
    )

    if (-not $BindingString) { return @() }

    $bindingList = $BindingString -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    $bindings = @()

    foreach ($binding in $bindingList) {
        if ($binding -match '^(?<protocol>[^/]+)/(?<binding>.+)$') {
            $protocol = $Matches.protocol
            $bindingInfo = $Matches.binding
            $parts = $bindingInfo -split ':', 3
            $ip = if ($parts.Count -ge 1) { $parts[0] } else { "" }
            $port = if ($parts.Count -ge 2) { $parts[1] } else { "" }
            $hostHeader = if ($parts.Count -ge 3) { $parts[2] } else { "" }

            $bindings += [pscustomobject]@{
                SiteName           = $SiteName
                Protocol           = $protocol
                IP                 = $ip
                Port               = $port
                Host               = $hostHeader
                BindingInformation = $bindingInfo
            }
        }
    }

    return $bindings
}

function Get-IisBindings {
    param(
        [string]$SiteName
    )

    $bindings = @()
    $appcmd = Get-AppCmdPath

    if (Get-Command Get-WebBinding -ErrorAction SilentlyContinue) {
        $webBindings = Get-WebBinding -Name $SiteName -Protocol http, https 2>$null
        if ($webBindings) {
            $bindings += $webBindings | ForEach-Object {
                $parts = $_.BindingInformation -split ':', 3
                [pscustomobject]@{
                    SiteName           = $_.ItemXPath.Split("'")[1]
                    Protocol           = $_.Protocol
                    IP                 = $parts[0]
                    Port               = $parts[1]
                    Host               = $parts[2]
                    BindingInformation = $_.BindingInformation
                }
            }
        }
    }
    elseif ($appcmd) {
        if ($SiteName -eq "*") {
            $siteLines = & $appcmd list site 2>$null
            foreach ($line in $siteLines) {
                if ($line -match '^SITE "(?<name>[^"]+)" .*bindings:(?<bindings>[^)]+)') {
                    $bindings += Convert-BindingString -BindingString $Matches.bindings -SiteName $Matches.name
                }
            }
        }
        else {
            $bindingText = & $appcmd list site /name:$SiteName /text:bindings 2>$null
            $bindings += Convert-BindingString -BindingString $bindingText -SiteName $SiteName
        }
    }

    return $bindings
}

function Get-IisSiteInfo {
    param(
        [string]$SiteName
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-IISSite -ErrorAction SilentlyContinue) {
        return Get-IISSite -Name $SiteName 2>$null
    }
    elseif ($appcmd) {
        return & $appcmd list site /name:$SiteName 2>$null
    }

    return $null
}

function Get-IisSitePhysicalPath {
    param(
        [string]$SiteName
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-IISSite -ErrorAction SilentlyContinue) {
        $site = Get-IISSite -Name $SiteName 2>$null
        return $site.PhysicalPath
    }
    elseif ($appcmd) {
        return & $appcmd list vdir "$SiteName/" /text:physicalPath 2>$null
    }

    return $null
}

function Get-IisAppPoolForSite {
    param(
        [string]$SiteName
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-WebApplication -ErrorAction SilentlyContinue) {
        $rootApp = Get-WebApplication -Site $SiteName -Name '/' 2>$null
        return $rootApp.applicationPool
    }
    elseif ($appcmd) {
        return & $appcmd list app "$SiteName/" /text:applicationPool 2>$null
    }

    return $null
}

function Get-IisAppPoolState {
    param(
        [string]$AppPoolName
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-IISAppPool -ErrorAction SilentlyContinue) {
        $pool = Get-IISAppPool -Name $AppPoolName 2>$null
        return $pool.State
    }
    elseif ($appcmd) {
        $poolInfo = & $appcmd list apppool /name:$AppPoolName 2>$null
        if ($poolInfo -match 'state:(?<state>[^)]+)') {
            return $Matches.state
        }
    }

    return $null
}

function Get-IisConfigValue {
    param(
        [string]$SiteName,
        [string]$Section,
        [string]$Attribute
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-WebConfigurationProperty -ErrorAction SilentlyContinue) {
        return Get-WebConfigurationProperty -PSPath "IIS:\Sites\$SiteName" -Filter $Section -Name $Attribute 2>$null
    }
    elseif ($appcmd) {
        return & $appcmd list config "$SiteName/" /section:$Section /text:$Attribute 2>$null
    }

    return $null
}

function Get-IisSiteLogSetting {
    param(
        [string]$SiteName,
        [string]$Attribute
    )

    $appcmd = Get-AppCmdPath
    if (Get-Command Get-IISSite -ErrorAction SilentlyContinue) {
        $site = Get-IISSite -Name $SiteName 2>$null
        if ($site -and $site.logFile) {
            return $site.logFile.$Attribute
        }
    }
    elseif ($appcmd) {
        return & $appcmd list site /name:$SiteName /text:logFile.$Attribute 2>$null
    }

    return $null
}

Write-Host "Domain Migration Configuration Check for: $NewDomain" -ForegroundColor Cyan
Write-Host "=" * 60
Write-Host ""

$siteAppPoolName = $null
$sitePhysicalPath = $null

# Check IIS bindings
Write-Host "1. Checking IIS Site Bindings..." -ForegroundColor Yellow
try {
    $bindings = Get-IisBindings -SiteName $IISWebsiteName
    $newDomainBinding = $bindings | Where-Object { $_.Host -match [regex]::Escape($NewDomain) }
    
    if ($newDomainBinding) {
        Write-Host "   ✓ Binding found for $NewDomain" -ForegroundColor Green
        $newDomainBinding | ForEach-Object { Write-Host "     - $($_.Protocol) $($_.BindingInformation)" }
        $results += @{Check = "IIS Bindings"; Status = "PASS"; Details = "New domain binding configured"; Fix = "" }
    } else {
        Write-Host "   ✗ No binding found for $NewDomain" -ForegroundColor Red
        $results += @{Check = "IIS Bindings"; Status = "FAIL"; Details = "New domain binding missing"; Fix = "Add an IIS binding for the new host (e.g., appcmd set site /site.name:<site> /+bindings.[protocol='http',bindingInformation='*:80:$NewDomain'])." }
    }
    
    if ($OldDomain) {
        $oldDomainBinding = $bindings | Where-Object { $_.Host -match [regex]::Escape($OldDomain) }
        if ($oldDomainBinding) {
            Write-Host "   ⚠ Old domain binding still exists for $OldDomain" -ForegroundColor Yellow
            $oldDomainBinding | ForEach-Object { Write-Host "     - $($_.Protocol) $($_.BindingInformation)" }
        }
    }
} catch {
    Write-Host "   ⚠ Could not verify IIS bindings: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "IIS Bindings"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Run with elevated permissions and ensure IIS is installed. Use appcmd if WebAdministration cmdlets are unavailable." }
}

# Check SSL certificates
Write-Host "2. Checking SSL Certificates..." -ForegroundColor Yellow
try {
    $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
    $matchingCert = $certs | Where-Object { $_.Subject -match [regex]::Escape($NewDomain) -or $_.DnsNameList -contains $NewDomain }
    $httpsBinding = $bindings | Where-Object { $_.Protocol -eq "https" -and $_.Host -match [regex]::Escape($NewDomain) }
    
    if ($matchingCert) {
        Write-Host "   ✓ Certificate found for $NewDomain" -ForegroundColor Green
        $matchingCert | ForEach-Object {
            Write-Host "     - Subject: $($_.Subject)"
            Write-Host "     - Thumbprint: $($_.Thumbprint)"
            Write-Host "     - Expires: $($_.NotAfter)"
        }
        $results += @{Check = "SSL Certificate"; Status = "PASS"; Details = "Certificate configured"; Fix = "" }
    } else {
        Write-Host "   ⚠ No certificate found for $NewDomain (may not be needed for HTTP)" -ForegroundColor Yellow
        $results += @{Check = "SSL Certificate"; Status = "WARN"; Details = "Certificate not found"; Fix = "Install a cert that covers the new host and has a private key, then bind it to HTTPS." }
    }

    if (-not $httpsBinding) {
        Write-Host "   ⚠ No HTTPS binding found for $NewDomain" -ForegroundColor Yellow
        $results += @{Check = "HTTPS Binding"; Status = "WARN"; Details = "HTTPS binding missing"; Fix = "Add HTTPS binding with the correct certificate thumbprint and SNI host name." }
    } else {
        $results += @{Check = "HTTPS Binding"; Status = "PASS"; Details = "HTTPS binding found"; Fix = "" }
    }
} catch {
    Write-Host "   ⚠ Could not check certificates: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "SSL Certificate"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Run with admin permissions and ensure certificate store access." }
}

# Check application pool configuration
Write-Host "3. Checking Application Pool Configuration..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        $appPoolName = Get-IisAppPoolForSite -SiteName $IISWebsiteName
        if ($appPoolName) {
            $poolState = Get-IisAppPoolState -AppPoolName $appPoolName
            $siteAppPoolName = $appPoolName
            Write-Host "   ✓ App pool for site '$IISWebsiteName' is $appPoolName ($poolState)" -ForegroundColor Green
            $results += @{Check = "Application Pool"; Status = "PASS"; Details = "$appPoolName ($poolState)"; Fix = "" }
        } else {
            Write-Host "   ⚠ Could not determine app pool for site '$IISWebsiteName'" -ForegroundColor Yellow
            $results += @{Check = "Application Pool"; Status = "WARN"; Details = "App pool not found for site"; Fix = "Ensure the site has a root application and an assigned app pool." }
        }
    } else {
        Write-Host "   ⚠ Site name is '*'. App pool check skipped." -ForegroundColor Yellow
        $results += @{Check = "Application Pool"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check the app pool." }
    }
} catch {
    Write-Host "   ⚠ Could not verify application pools: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "Application Pools"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS cmdlets are available or use appcmd." }
}

# Check hosts file
Write-Host "4. Checking Hosts File Entries..." -ForegroundColor Yellow
try {
    $hostsFile = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsFile -ErrorAction Stop
    
    $newDomainEntry = $hostsContent | Where-Object { $_ -match [regex]::Escape($NewDomain) }
    if ($newDomainEntry) {
        Write-Host "   ✓ Entry found for $NewDomain in hosts file" -ForegroundColor Green
        $newDomainEntry | ForEach-Object { Write-Host "     - $_" }
        $results += @{Check = "Hosts File"; Status = "PASS"; Details = "New domain entry exists"; Fix = "" }
    } else {
        Write-Host "   ⚠ No entry found for $NewDomain in hosts file" -ForegroundColor Yellow
        $results += @{Check = "Hosts File"; Status = "WARN"; Details = "Entry not found (may use DNS)"; Fix = "Add a hosts entry mapping $NewDomain to 127.0.0.1 or configure DNS." }
    }
    
    if ($OldDomain) {
        $oldDomainEntry = $hostsContent | Where-Object { $_ -match [regex]::Escape($OldDomain) }
        if ($oldDomainEntry) {
            Write-Host "   ⚠ Old domain entry still exists for $OldDomain" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "   ⚠ Could not check hosts file: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "Hosts File"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Run with admin permissions to read hosts file." }
}

# Check DNS resolution
Write-Host "5. Checking DNS Resolution..." -ForegroundColor Yellow
try {
    $dnsResult = Resolve-DnsName -Name $NewDomain -ErrorAction Stop | Select-Object -First 1 -ExpandProperty IPAddress
    Write-Host "   ✓ DNS resolves for $NewDomain ($dnsResult)" -ForegroundColor Green
    $results += @{Check = "DNS Resolution"; Status = "PASS"; Details = "Resolves to $dnsResult"; Fix = "" }
} catch {
    Write-Host "   ⚠ DNS does not resolve for $NewDomain" -ForegroundColor Yellow
    $results += @{Check = "DNS Resolution"; Status = "WARN"; Details = "DNS lookup failed"; Fix = "Create DNS A/AAAA or hosts entry for $NewDomain." }
}

# Check IIS configuration
Write-Host "6. Checking IIS Configuration..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        $siteInfo = Get-IisSiteInfo -SiteName $IISWebsiteName
        $physicalPath = Get-IisSitePhysicalPath -SiteName $IISWebsiteName
        if ($siteInfo) {
            Write-Host "   ✓ IIS site '$IISWebsiteName' is configured" -ForegroundColor Green
            if ($siteInfo -is [string]) {
                Write-Host "     - Info: $siteInfo"
            }
            if ($physicalPath) {
                $sitePhysicalPath = $physicalPath
                Write-Host "     - Physical Path: $physicalPath"
                if (-not (Test-Path $physicalPath)) {
                    Write-Host "     ⚠ Physical path does not exist" -ForegroundColor Yellow
                    $results += @{Check = "IIS Physical Path"; Status = "WARN"; Details = "Path missing"; Fix = "Create the physical path or update the site root to a valid folder." }
                } else {
                    $results += @{Check = "IIS Physical Path"; Status = "PASS"; Details = "Path exists"; Fix = "" }
                }
            }
            $results += @{Check = "IIS Site Config"; Status = "PASS"; Details = "Site properly configured"; Fix = "" }
        } else {
            Write-Host "   ✗ IIS site '$IISWebsiteName' not found" -ForegroundColor Red
            $results += @{Check = "IIS Site Config"; Status = "FAIL"; Details = "Site not found"; Fix = "Create the IIS site or correct -IISWebsiteName." }
        }
    } else {
        Write-Host "   ⚠ Site name is '*'. IIS site configuration check skipped." -ForegroundColor Yellow
        $results += @{Check = "IIS Site Config"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check site configuration." }
    }
} catch {
    Write-Host "   ⚠ Could not verify IIS site configuration: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "IIS Site Config"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS is installed and accessible." }
}

# Check authentication settings
Write-Host "7. Checking Authentication Settings..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        $anonEnabled = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/security/authentication/anonymousAuthentication" -Attribute "enabled"
        $windowsEnabled = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/security/authentication/windowsAuthentication" -Attribute "enabled"
        $basicEnabled = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/security/authentication/basicAuthentication" -Attribute "enabled"

        Write-Host "     - Anonymous: $anonEnabled"
        Write-Host "     - Windows:   $windowsEnabled"
        Write-Host "     - Basic:     $basicEnabled"

        if ($anonEnabled -ne $true -and $windowsEnabled -ne $true -and $basicEnabled -ne $true) {
            Write-Host "   ✗ No authentication methods enabled" -ForegroundColor Red
            $results += @{Check = "Authentication"; Status = "FAIL"; Details = "No auth methods enabled"; Fix = "Enable at least one auth method (Anonymous/Windows/Basic) for the site." }
        } else {
            $results += @{Check = "Authentication"; Status = "PASS"; Details = "Authentication configured"; Fix = "" }
        }
    } else {
        Write-Host "   ⚠ Site name is '*'. Authentication check skipped." -ForegroundColor Yellow
        $results += @{Check = "Authentication"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check auth settings." }
    }
} catch {
    Write-Host "   ⚠ Could not verify authentication settings: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "Authentication"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS is installed and WebAdministration is accessible." }
}

# Check default document and directory browsing
Write-Host "8. Checking Default Document and Directory Browsing..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        $defaultDocEnabled = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/defaultDocument" -Attribute "enabled"
        $dirBrowseEnabled = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/directoryBrowse" -Attribute "enabled"

        Write-Host "     - Default Document Enabled: $defaultDocEnabled"
        Write-Host "     - Directory Browsing Enabled: $dirBrowseEnabled"

        if ($defaultDocEnabled -eq $true) {
            $results += @{Check = "Default Document"; Status = "PASS"; Details = "Enabled"; Fix = "" }
        } else {
            $results += @{Check = "Default Document"; Status = "WARN"; Details = "Disabled"; Fix = "Enable default documents or ensure explicit file paths are used." }
        }

        if ($dirBrowseEnabled -eq $true) {
            $results += @{Check = "Directory Browsing"; Status = "WARN"; Details = "Enabled"; Fix = "Disable directory browsing unless explicitly required." }
        } else {
            $results += @{Check = "Directory Browsing"; Status = "PASS"; Details = "Disabled"; Fix = "" }
        }
    } else {
        Write-Host "   ⚠ Site name is '*'. Default document check skipped." -ForegroundColor Yellow
        $results += @{Check = "Default Document"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check default documents." }
        $results += @{Check = "Directory Browsing"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check directory browsing." }
    }
} catch {
    Write-Host "   ⚠ Could not verify default document/directory browsing: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "Default Document"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS configuration is accessible." }
}

# Check request filtering and IP restrictions
Write-Host "9. Checking Request Filtering and IP Restrictions..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        if (Get-Command Get-WebConfigurationProperty -ErrorAction SilentlyContinue) {
            $maxAllowedContentLength = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/security/requestFiltering/requestLimits" -Attribute "maxAllowedContentLength"
        } else {
            $appcmd = Get-AppCmdPath
            $maxAllowedContentLength = if ($appcmd) { & $appcmd list config "$IISWebsiteName/" /section:system.webServer/security/requestFiltering /text:requestLimits.maxAllowedContentLength 2>$null } else { $null }
        }
        $allowUnlisted = Get-IisConfigValue -SiteName $IISWebsiteName -Section "system.webServer/security/ipSecurity" -Attribute "allowUnlisted"

        Write-Host "     - maxAllowedContentLength: $maxAllowedContentLength"
        Write-Host "     - IP allowUnlisted: $allowUnlisted"

        $results += @{Check = "Request Filtering"; Status = "PASS"; Details = "Request limits checked"; Fix = "" }
        $results += @{Check = "IP Restrictions"; Status = "PASS"; Details = "IP restrictions checked"; Fix = "" }
    } else {
        Write-Host "   ⚠ Site name is '*'. Request filtering check skipped." -ForegroundColor Yellow
        $results += @{Check = "Request Filtering"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check request filtering." }
        $results += @{Check = "IP Restrictions"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check IP restrictions." }
    }
} catch {
    Write-Host "   ⚠ Could not verify request filtering/IP restrictions: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "Request Filtering"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS configuration is accessible." }
}

# Check IIS logging and URL Rewrite module
Write-Host "10. Checking IIS Logging and URL Rewrite..." -ForegroundColor Yellow
try {
    if ($IISWebsiteName -ne "*") {
        $logEnabled = Get-IisSiteLogSetting -SiteName $IISWebsiteName -Attribute "enabled"
        $logDirectory = Get-IisSiteLogSetting -SiteName $IISWebsiteName -Attribute "directory"

        Write-Host "     - Logging Enabled: $logEnabled"
        Write-Host "     - Log Directory: $logDirectory"

        if ($logEnabled -eq $true) {
            $results += @{Check = "IIS Logging"; Status = "PASS"; Details = "Logging enabled"; Fix = "" }
        } else {
            $results += @{Check = "IIS Logging"; Status = "WARN"; Details = "Logging disabled"; Fix = "Enable logging for troubleshooting and auditability." }
        }

        $appcmd = Get-AppCmdPath
        if ($appcmd) {
            $rewriteModule = & $appcmd list module /name:RewriteModule 2>$null
            if ($rewriteModule) {
                $results += @{Check = "URL Rewrite"; Status = "PASS"; Details = "Rewrite module installed"; Fix = "" }
            } else {
                $results += @{Check = "URL Rewrite"; Status = "WARN"; Details = "Rewrite module not installed"; Fix = "Install the IIS URL Rewrite module if you need redirects." }
            }
        } else {
            $results += @{Check = "URL Rewrite"; Status = "WARN"; Details = "appcmd not found"; Fix = "Ensure IIS is installed or run in Windows PowerShell with WebAdministration." }
        }
    } else {
        Write-Host "   ⚠ Site name is '*'. Logging check skipped." -ForegroundColor Yellow
        $results += @{Check = "IIS Logging"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check logging." }
        $results += @{Check = "URL Rewrite"; Status = "WARN"; Details = "Skipped (site name wildcard)"; Fix = "Specify -IISWebsiteName to check URL Rewrite." }
    }
} catch {
    Write-Host "   ⚠ Could not verify logging/URL rewrite: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "IIS Logging"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure IIS is installed and accessible." }
}

# Check NTFS permissions on site path
Write-Host "11. Checking NTFS Permissions..." -ForegroundColor Yellow
try {
    if ($sitePhysicalPath) {
        $acl = Get-Acl -Path $sitePhysicalPath -ErrorAction Stop
        $hasIisRead = $acl.Access | Where-Object {
            ($_.IdentityReference -match "IIS_IUSRS" -or ($siteAppPoolName -and $_.IdentityReference -match [regex]::Escape("IIS AppPool\\$siteAppPoolName"))) -and
            ($_.FileSystemRights.ToString() -match "Read") -and
            ($_.AccessControlType -eq "Allow")
        }

        if ($hasIisRead) {
            Write-Host "   ✓ IIS read access detected on $sitePhysicalPath" -ForegroundColor Green
            $results += @{Check = "NTFS Permissions"; Status = "PASS"; Details = "IIS read access present"; Fix = "" }
        } else {
            Write-Host "   ⚠ IIS read access not detected on $sitePhysicalPath" -ForegroundColor Yellow
            $results += @{Check = "NTFS Permissions"; Status = "WARN"; Details = "IIS read access missing"; Fix = "Grant IIS_IUSRS or the app pool identity read access on the site folder." }
        }
    } else {
        Write-Host "   ⚠ Physical path not available. NTFS check skipped." -ForegroundColor Yellow
        $results += @{Check = "NTFS Permissions"; Status = "WARN"; Details = "Skipped (no path)"; Fix = "Ensure the site has a valid physical path." }
    }
} catch {
    Write-Host "   ⚠ Could not verify NTFS permissions: $($_.Exception.Message)" -ForegroundColor Yellow
    $results += @{Check = "NTFS Permissions"; Status = "WARN"; Details = $_.Exception.Message; Fix = "Ensure you have permission to read ACLs." }
}

# Summary
Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "Configuration Check Summary" -ForegroundColor Cyan
Write-Host "=" * 60

$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$warnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count

$results | ForEach-Object {
    $color = switch ($_.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
    }
    Write-Host "$($_.Check): $($_.Status)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Results: $passCount passed, $failCount failed, $warnCount warnings" -ForegroundColor Cyan

if ($failCount -gt 0 -or $warnCount -gt 0) {
    Write-Host "" 
    Write-Host "Recommended Fixes" -ForegroundColor Cyan
    Write-Host "=" * 60
    $results | Where-Object { $_.Status -ne "PASS" } | ForEach-Object {
        Write-Host "- $($_.Check): $($_.Status)" -ForegroundColor Yellow
        if ($_.Fix) {
            Write-Host "  Fix: $($_.Fix)" -ForegroundColor Gray
        }
        if ($_.Details) {
            Write-Host "  Details: $($_.Details)" -ForegroundColor DarkGray
        }
    }
}

if ($failCount -eq 0) {
    Write-Host "✓ Configuration check complete!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "✗ Configuration issues detected. Please review above." -ForegroundColor Red
    exit 1
}
