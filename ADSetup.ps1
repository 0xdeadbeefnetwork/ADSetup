# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logPath -Append
    Write-Host $message
}

# Initial Setup: Prompt for Configuration Details
function InitialSetup {
    $global:adminUser = Read-Host "Enter the local administrator username"
    $global:adminPass = Read-Host "Enter the local administrator password" -AsSecureString
    $global:domainName = Read-Host "Enter the domain name (e.g., ad-lab.afflicted.sh)"
    $global:domainNetbios = Read-Host "Enter the NetBIOS name (e.g., ADLAB)"
    $global:serverIP = Read-Host "Enter the static IP address for the server (e.g., 192.168.2.119)"
    $global:subnetMask = Read-Host "Enter the subnet mask (e.g., 255.255.255.0)"
    $global:gateway = Read-Host "Enter the gateway IP (e.g., 192.168.2.1)"
    $global:logPath = "C:\ADSetupLog.txt"
    $global:sharePathBase = "C:\Shares"
    $global:shares = @("StaffDocs", "Backups", "Storage")
}

# Function to set static IP address
function Set-StaticIP {
    Log-Message "Setting static IP address..."
    $networkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name

    if (-not $networkAdapter) {
        Log-Message "Error: No active network adapter found."
        return
    }

    # Set the static IP address, subnet mask, and gateway
    New-NetIPAddress -InterfaceAlias $networkAdapter -IPAddress $serverIP -PrefixLength 24 -DefaultGateway $gateway
    Set-DnsClientServerAddress -InterfaceAlias $networkAdapter -ServerAddresses $serverIP

    Log-Message "Static IP address set to $serverIP with subnet mask $subnetMask and gateway $gateway."
}

# Function to set the Primary DNS Suffix
function Set-PrimaryDNSSuffix {
    param (
        [string]$suffix
    )
    
    Log-Message "Setting Primary DNS Suffix to $suffix..."
    # Set the primary DNS suffix
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name "NV Domain" -Value $suffix
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name "Domain" -Value $suffix

    Log-Message "Primary DNS Suffix set to $suffix. A restart might be required for this change to take full effect."
}

# Network Configuration Verification (updated to include Primary DNS Suffix check)
function Verify-NetworkConfig {
    Log-Message "Verifying network configuration..."
    $networkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name

    if (-not $networkAdapter) {
        Log-Message "Error: No active network adapter found."
        return
    }

    $currentIP = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $networkAdapter).IPAddress
    $dnsServer = (Get-DnsClientServerAddress -InterfaceAlias $networkAdapter).ServerAddresses

    # Check and set static IP if needed
    if ($currentIP -ne $serverIP) {
        Log-Message "Current IP address ($currentIP) does not match the expected IP ($serverIP). Setting static IP."
        Set-StaticIP
    }
    if ($dnsServer -notcontains $serverIP) {
        Log-Message "Setting DNS server to the domain controller IP ($serverIP)."
        Set-DnsClientServerAddress -InterfaceAlias $networkAdapter -ServerAddresses $serverIP
    }

    # Check and set Primary DNS Suffix
    $primaryDNSSuffix = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name "NV Domain")."NV Domain"
    if ($primaryDNSSuffix -ne $domainName) {
        Log-Message "Current Primary DNS Suffix ($primaryDNSSuffix) does not match the domain ($domainName). Setting it now."
        Set-PrimaryDNSSuffix $domainName
    }

    Log-Message "Network configuration verified."
}

# Set up Active Directory Domain Services and DNS
function Setup-ADDS {
    Log-Message "Setting up Active Directory Domain Services and DNS..."
    Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
    Import-Module ADDSDeployment

    $securePassword = ConvertTo-SecureString $adminPass -AsPlainText -Force
    $adminCreds = New-Object System.Management.Automation.PSCredential ($adminUser, $securePassword)

    Install-ADDSForest -DomainName $domainName `
        -DomainNetbiosName $domainNetbios `
        -SafeModeAdministratorPassword $securePassword `
        -InstallDNS `
        -CreateDNSDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -LogPath "C:\Windows\NTDS" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force `
        -Confirm:$false

    Log-Message "Domain Controller and DNS setup complete. Please restart the server."
}

# Enable Remote Desktop
function Enable-RemoteDesktop {
    Log-Message "Enabling Remote Desktop..."
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\' -Name "fDenyTSConnections" -Value 0

    # Configure the firewall rule for Remote Desktop
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    Log-Message "Remote Desktop enabled. Make sure users have appropriate permissions to connect."
}

# Configure Firewall Rules
function Configure-Firewall {
    Log-Message "Configuring firewall rules..."
    New-NetFirewallRule -DisplayName "Allow Active Directory Services" -Direction Inbound -Protocol TCP -LocalPort 135,389,636,3268,3269 -Action Allow
    New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
    New-NetFirewallRule -DisplayName "Allow File Sharing" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
    Log-Message "Firewall rules configured."
}

# Create File Shares
function Create-FileShares {
    Log-Message "Creating file shares..."
    foreach ($share in $shares) {
        $sharePath = "$sharePathBase\$share"
        New-Item -Path $sharePath -ItemType Directory -Force
        New-SmbShare -Name $share -Path $sharePath -FullAccess "Domain Users"
        Log-Message "Share $share created at $sharePath."
    }
}

# Create Domain Users and Groups
function Create-UsersAndGroups {
    Log-Message "Creating domain users..."
    Import-Module ActiveDirectory

    New-ADUser -Name "Front Desk" -SamAccountName "FrontDesk" -UserPrincipalName "FrontDesk@$domainName" `
        -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -PasswordNeverExpires $false `
        -PasswordPolicyEnabled $true -Enabled $true

    New-ADUser -Name "DomainMaster" -SamAccountName "DomainMaster" -UserPrincipalName "DomainMaster@$domainName" `
        -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -PasswordNeverExpires $false `
        -PasswordPolicyEnabled $true -Enabled $true

    New-ADUser -Name "Net_Tech" -SamAccountName "Net_Tech" -UserPrincipalName "Net_Tech@$domainName" `
        -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) -PasswordNeverExpires $false `
        -PasswordPolicyEnabled $true -Enabled $true

    Add-ADGroupMember -Identity "Domain Admins" -Members "DomainMaster", "Net_Tech"

    Set-ADUser -Identity "FrontDesk" -ChangePasswordAtLogon $true
    Set-ADUser -Identity "DomainMaster" -ChangePasswordAtLogon $true
    Set-ADUser -Identity "Net_Tech" -ChangePasswordAtLogon $true

    Log-Message "Users and permissions set. Users will be prompted to change their passwords on first login."
}

# Set Password Policy for Domain
function Set-PasswordPolicy {
    Log-Message "Setting domain password policy..."
    Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
        -MaxPasswordAge (New-TimeSpan -Days 45) `
        -ComplexityEnabled $true `
        -MinimumPasswordLength 8

    Log-Message "Password policy set: Passwords must be changed every 45 days."
}

# Health Check for the Domain Controller
function Check-Health {
    Log-Message "Checking health of the domain controller..."
    dcdiag /v | Out-File -FilePath "$logPath" -Append
    Log-Message "Health check complete. See log for details."
}

# Join a Windows 10 machine to the domain
function Join-ClientToDomain {
    Log-Message "Joining this Windows 10 machine to the domain $domainName..."
    $securePassword = ConvertTo-SecureString $adminPass -AsPlainText -Force
    $adminCreds = New-Object System.Management.Automation.PSCredential ("$adminUser@$domainName", $securePassword)

    # Set DNS to point to the domain controller's IP
    $networkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name
    Set-DnsClientServerAddress -InterfaceAlias $networkAdapter -ServerAddresses $serverIP

    # Set Primary DNS Suffix
    Set-PrimaryDNSSuffix $domainName

    # Join the computer to the domain
    Add-Computer -DomainName $domainName -Credential $adminCreds -Restart -Force

    Log-Message "This Windows 10 machine has been added to the domain and will restart."
}

# Create and propagate an account across the domain
function Create-PropagatedAccount {
    $username = Read-Host "Enter the username for the new domain account"
    $password = Read-Host "Enter the password for the new domain account" -AsSecureString
    $fullName = Read-Host "Enter the full name for the new domain account"
    Log-Message "Creating and propagating account $username..."

    New-ADUser -Name $fullName -SamAccountName $username -UserPrincipalName "$username@$domainName" `
        -AccountPassword $password -PasswordNeverExpires $false `
        -PasswordPolicyEnabled $true -Enabled $true

    Set-ADUser -Identity $username -ChangePasswordAtLogon $true

    Log-Message "Account $username created and will propagate across the domain."
}

# Main Menu
function Show-Menu {
    Log-Message "Active Directory and File Shares Setup Script"
    Write-Host "1. Initial Setup (Configure IP/Domain)"
    Write-Host "2. Verify Network Configuration"
    Write-Host "3. Configure Firewall Rules"
    Write-Host "4. Set up Domain Controller and DNS"
    Write-Host "5. Enable Remote Desktop"
    Write-Host "6. Create Domain Users and Groups"
    Write-Host "7. Set Password Policy"
    Write-Host "8. Create File Shares"
    Write-Host "9. Join Windows 10 Machine to Domain"
    Write-Host "10. Create and Propagate Domain Account"
    Write-Host "11. Check Domain Controller Health"
    Write-Host "12. Exit"
    $choice = Read-Host "Enter your choice (1-12):"

    switch ($choice) {
        "1" { InitialSetup }
        "2" { Verify-NetworkConfig }
        "3" { Configure-Firewall }
        "4" { Setup-ADDS }
        "5" { Enable-RemoteDesktop }
        "6" { Create-UsersAndGroups }
        "7" { Set-PasswordPolicy }
        "8" { Create-FileShares }
        "9" { Join-ClientToDomain }
        "10" { Create-PropagatedAccount }
        "11" { Check-Health }
        "12" { exit }
        default { Write-Host "Invalid option. Please select again."; Show-Menu }
    }
}

InitialSetup
Show-Menu
