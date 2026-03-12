#[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Reset-ServiceAccountPasswords {
    # Requires the ActiveDirectory module
    Import-Module ActiveDirectory -ErrorAction Stop

    # Generate a random alphanumeric password of specified length
    function New-RandomPassword {
        param([int]$Length = 16)
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $password = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        return $password
    }

    # Define base service accounts to always exclude
    $excludedAccounts = [System.Collections.Generic.List[string]]@()

    # Prompt for exclusions upfront
    Write-Host "`nEnter service account usernames to exclude (comma-separated), or press ENTER to skip:" -ForegroundColor Yellow
    $extraInput = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($extraInput)) {
        $extraAccounts = $extraInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($a in $extraAccounts) {
            $excludedAccounts.Add($a)
        }
        Write-Host "Excluded accounts: $($excludedAccounts -join ', ')" -ForegroundColor Cyan
    }

    Write-Host "`nQuerying Active Directory for service accounts..." -ForegroundColor Cyan

    # Pull service accounts by common naming conventions AND managed service accounts
    # Catches: accounts with 'svc', 'service', 'sa-', 'svc-' in the name
    # Also catches: OU-based service accounts and ManagedServiceAccount objects
    $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, Description, ServicePrincipalNames |
        Where-Object {
            $_.SamAccountName -match '(?i)(^svc|^sa[-_]|[-_]svc$|service|[-_]sa$|^service)' -or
            $_.ServicePrincipalNames.Count -gt 0
        } |
        Where-Object { $excludedAccounts -notcontains $_.SamAccountName }

    # Also grab Managed Service Accounts (gMSA/MSA)
    $msaAccounts = Get-ADServiceAccount -Filter { Enabled -eq $true } -Properties SamAccountName |
        Where-Object { $excludedAccounts -notcontains $_.SamAccountName }

    if ((-not $allUsers) -and (-not $msaAccounts)) {
        Write-Warning "No eligible service accounts found. Exiting."
        return
    }

    Write-Host "Found $($allUsers.Count) service account(s) and $($msaAccounts.Count) managed service account(s) to process." -ForegroundColor Cyan

    # Build the password list, ensuring uniqueness
    $passwordList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usedPasswords = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($account in $allUsers) {
        do {
            $newPassword = New-RandomPassword -Length 16
        } while (-not $usedPasswords.Add($newPassword))

        $passwordList.Add([PSCustomObject]@{
            Username = $account.SamAccountName
            Password = $newPassword
            Type     = if ($account.ServicePrincipalNames.Count -gt 0) { "SPN" } else { "ServiceAccount" }
        })
    }

    # Note MSAs in the list but flag them — their passwords are managed automatically by AD
    foreach ($msa in $msaAccounts) {
        $passwordList.Add([PSCustomObject]@{
            Username = $msa.SamAccountName
            Password = "MANAGED-BY-AD"
            Type     = "ManagedServiceAccount"
        })
    }

    # Save CSV to the current user's desktop
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $csvPath = Join-Path $desktopPath "ServiceAccountPasswords_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    "Username,Password,Type" | Set-Content -Path $csvPath
    foreach ($entry in $passwordList) {
        "$($entry.Username),$($entry.Password),$($entry.Type)" | Add-Content -Path $csvPath
    }

    Write-Host "`nPassword list saved to: $csvPath" -ForegroundColor Green
    Write-Host "Please open and review the file before proceeding." -ForegroundColor Yellow
    Write-Host "`nThe following $($passwordList.Count) account(s) will be processed:" -ForegroundColor Yellow
    $passwordList | Format-Table -AutoSize

    Write-Host "[!] NOTE: ManagedServiceAccount entries will be skipped during password change - AD manages those automatically." -ForegroundColor Cyan

    # Second chance to exclude more accounts after reviewing the list
    Write-Host "Any further accounts to remove before applying? (comma-separated), or press ENTER to continue:" -ForegroundColor Yellow
    $lateExclusions = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($lateExclusions)) {
        $lateAccounts = $lateExclusions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

        foreach ($a in $lateAccounts) {
            $match = $passwordList | Where-Object { $_.Username -eq $a }
            if ($match) {
                $passwordList.Remove($match) | Out-Null
                Write-Host "  [REMOVED] $a from password change list" -ForegroundColor Yellow
            } else {
                Write-Warning "  [NOT FOUND] $a was not in the list, skipping"
            }
        }

        # Rewrite the CSV without removed accounts
        "Username,Password,Type" | Set-Content -Path $csvPath
        foreach ($entry in $passwordList) {
            "$($entry.Username),$($entry.Password),$($entry.Type)" | Add-Content -Path $csvPath
        }
        Write-Host "CSV updated to remove excluded accounts." -ForegroundColor Cyan
    }

    Write-Host "`nPress ENTER to begin changing $($passwordList.Count) password(s), or CTRL+C to abort..." -ForegroundColor Red
    Read-Host | Out-Null

    # Apply the new passwords (skip MSAs)
    $successCount = 0
    $failCount    = 0
    $skippedCount = 0

    foreach ($entry in $passwordList) {
        if ($entry.Type -eq "ManagedServiceAccount") {
            Write-Host "  [SKIP] $($entry.Username) - Managed Service Account, password handled by AD" -ForegroundColor DarkYellow
            $skippedCount++
            continue
        }
        try {
            $securePassword = ConvertTo-SecureString $entry.Password -AsPlainText -Force
            Set-ADAccountPassword -Identity $entry.Username -NewPassword $securePassword -Reset
            Write-Host "  [OK] $($entry.Username)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Warning "  [FAIL] $($entry.Username) - $($_.Exception.Message)"
            $failCount++
        }
    }

    Write-Host "`nDone. $successCount password(s) changed, $skippedCount skipped (MSA), $failCount failure(s)." -ForegroundColor Cyan
    Write-Host "Passwords are saved at: $csvPath" -ForegroundColor Green
}
Function Get-LocalGroupMembers {
    param (
        [string]$GroupName
    )

    $groupInfo = net localgroup "$GroupName" | Select-Object -Skip 6 | Where-Object {$_ -match '\S'}  

    if ($groupInfo) {
        Write-Host "`n$GroupName" -ForegroundColor Cyan
        Write-Host "------------------------"

        if ($groupInfo.Count - 1 -le 0) {
            Write-Host "Group '$GroupName' not found or has no members." -ForegroundColor Red
        }

        for ($i = 0; $i -lt $groupInfo.Count - 1; $i++) {  # Iterate without last value
            Write-Host "  - $($groupInfo[$i])"
        }
    } else {
        Write-Host "Group '$GroupName' not found or has no members." -ForegroundColor Red
    }
}

Function Get-RegistryKeys {
    param (
        [string]$RegKey
    )
    Write-Host "$RegKey" -ForegroundColor Cyan
    $runKey = Get-Item -Path "$RegKey"
    $runKey.GetValueNames() | ForEach-Object { [PSCustomObject]@{ Name = $_; Value = $runKey.GetValue($_) } } | Out-Host
}

function Get-Binary {
    # Add Defender exclusion for C:\Tools so binaries don't get quarantined
    Write-Host "[+] Adding Defender exclusion for C:\Tools" -ForegroundColor Cyan
    Add-MpPreference -ExclusionPath "C:\Tools"

    Write-Host "[+] Downloading Cable"
    Invoke-WebRequest "https://github.com/logangoins/Cable/releases/download/1.1/Cable.exe" -OutFile "C:\Tools\Cable.exe"
    Write-Host "[+] Downloading PingCastle"
    Invoke-WebRequest "https://github.com/netwrix/pingcastle/releases/download/3.5.0.44/PingCastle_3.5.0.44.zip" -OutFile "C:\Tools\pingcastle.zip"
    Expand-Archive "C:\Tools\pingcastle.zip" -DestinationPath "C:\Tools\pingcastle" -Force
    Remove-Item "C:\Tools\pingcastle.zip"
    Write-Host "[+] Downloading Certify"
    Invoke-WebRequest "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe" -OutFile "C:\Tools\Certify.exe"

    Write-Host "[+] All binaries downloaded!" -ForegroundColor Green
}

function Reset-AllUserPasswords {
    # Requires the ActiveDirectory module
    Import-Module ActiveDirectory -ErrorAction Stop

    # Generate a random alphanumeric password of specified length
    function New-RandomPassword {
        param([int]$Length = 16)
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $password = -join ((1..$Length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
        return $password
    }

    # Define base accounts to always exclude
    $excludedUsers = [System.Collections.Generic.List[string]]@('Administrator', 'krgbt')

    # Prompt for additional exclusions
    Write-Host "`nDefault excluded accounts: $($excludedUsers -join ', ')" -ForegroundColor Cyan
    Write-Host "Enter additional usernames to exclude (comma-separated), or press ENTER to skip:" -ForegroundColor Yellow
    $extraInput = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($extraInput)) {
        $extraUsers = $extraInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($u in $extraUsers) {
            $excludedUsers.Add($u)
        }
        Write-Host "Updated exclusion list: $($excludedUsers -join ', ')" -ForegroundColor Cyan
    }

    Write-Host "`nQuerying Active Directory for all enabled user accounts..." -ForegroundColor Cyan

    # Pull all enabled users, excluding the protected accounts
    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName |
             Where-Object { $excludedUsers -notcontains $_.SamAccountName }

    if (-not $users) {
        Write-Warning "No eligible users found. Exiting."
        return
    }

    Write-Host "Found $($users.Count) user(s) to process." -ForegroundColor Cyan

    # Build the password list, ensuring uniqueness
    $passwordList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $usedPasswords = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($user in $users) {
        do {
            $newPassword = New-RandomPassword -Length 16
        } while (-not $usedPasswords.Add($newPassword))

        $passwordList.Add([PSCustomObject]@{
            Username = $user.SamAccountName
            Password = $newPassword
        })
    }

    # Save CSV to the current user's desktop (no quotes)
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $csvPath = Join-Path $desktopPath "NewPasswords_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    "Username,Password" | Set-Content -Path $csvPath
    foreach ($entry in $passwordList) {
        "$($entry.Username),$($entry.Password)" | Add-Content -Path $csvPath
    }

    Write-Host "`nPassword list saved to: $csvPath" -ForegroundColor Green
    Write-Host "Please open and review the file before proceeding." -ForegroundColor Yellow
    Write-Host "`nThe following $($users.Count) account(s) will have their passwords changed:" -ForegroundColor Yellow
    $passwordList | Format-Table -AutoSize

    # Second chance to exclude more users after reviewing the list
    Write-Host "Any further accounts to remove before applying? (comma-separated), or press ENTER to continue:" -ForegroundColor Yellow
    $lateExclusions = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($lateExclusions)) {
        $lateUsers = $lateExclusions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

        # Remove from passwordList
        foreach ($u in $lateUsers) {
            $match = $passwordList | Where-Object { $_.Username -eq $u }
            if ($match) {
                $passwordList.Remove($match) | Out-Null
                Write-Host "  [REMOVED] $u from password change list" -ForegroundColor Yellow
            } else {
                Write-Warning "  [NOT FOUND] $u was not in the list, skipping"
            }
        }

        # Rewrite the CSV without the removed users
        "Username,Password" | Set-Content -Path $csvPath
        foreach ($entry in $passwordList) {
            "$($entry.Username),$($entry.Password)" | Add-Content -Path $csvPath
        }
        Write-Host "CSV updated to remove excluded accounts." -ForegroundColor Cyan
    }

    Write-Host "`nPress ENTER to begin changing $($passwordList.Count) password(s), or CTRL+C to abort..." -ForegroundColor Red
    Read-Host | Out-Null

    # Apply the new passwords
    $successCount = 0
    $failCount    = 0

    foreach ($entry in $passwordList) {
        try {
            $securePassword = ConvertTo-SecureString $entry.Password -AsPlainText -Force
            Set-ADAccountPassword -Identity $entry.Username -NewPassword $securePassword -Reset
            Write-Host "  [OK] $($entry.Username)" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Warning "  [FAIL] $($entry.Username) - $($_.Exception.Message)"
            $failCount++
        }
    }

    Write-Host "`nDone. $successCount password(s) changed successfully, $failCount failure(s)." -ForegroundColor Cyan
    Write-Host "Passwords are saved at: $csvPath" -ForegroundColor Green
}


function Get-Tools {
    New-Item -Path C:\ -Name "Tools" -ItemType Directory -Force > $null
    Write-Host "[+] Created tools directory!"

    # Lock down C:\Tools - only Administrators and SYSTEM can access
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance, remove inherited rules
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path "C:\Tools" -AclObject $acl
    Write-Host "[+] Locked down C:\Tools - Administrators and SYSTEM only" -ForegroundColor Cyan

    Write-Host "[+] Collecting tools..."
    Write-Host "[+] Downloading SystemInformer"
    Invoke-WebRequest https://phoenixnap.dl.sourceforge.net/project/systeminformer/systeminformer-3.2.25011-release-setup.exe?viasf=1 -OutFile "C:\Tools\SystemInformer.exe"
    Write-Host "[+] Downloading Autoruns"
    Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -OutFile "C:\Tools\Autoruns.zip"
    Write-Host "[+] Downloading Sysmon"
    Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile "C:\Tools\Sysmon.zip"
    Write-Host "[+] Downloading Firefox"
    Invoke-WebRequest "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US" -OutFile "C:\Tools\FirefoxInstaller.exe"
    Write-Host "[+] Downloading LDAP Firewall"
    Invoke-WebRequest https://github.com/zeronetworks/ldapfw/releases/download/v1.0.0/ldapfw_v1.0.0-x64.zip -OutFile "C:\Tools\ldapfw.zip"
    Write-Host "[+] Downloading Account Lockout Tools"
    Invoke-WebRequest "https://download.microsoft.com/download/1/f/0/1f0e9569-3350-4329-b443-822976f29284/ALTools.exe" -OutFile "C:\Tools\ALTools.exe"
    Invoke-WebRequest "https://github.com/deryavuz1/UTSA_CCDC_Team/raw/refs/heads/main/Windows/sysmonmsix.exe" -OutFile "C:\Tools\sysint.exe"

    Write-Host "[+] Finished downloading tools!" -ForegroundColor Green
    Write-Host "Installing SysInternals"
    Invoke-WebRequest "https://raw.githubusercontent.com/deryavuz1/UTSA_CCDC_Team/refs/heads/main/Windows/sysmon-config.xml" -OutFile "C:\Tools\sysmon-config.xml"

    Write-Host "[+] Expanding archives"
    Expand-Archive -Path "C:\Tools\Autoruns.zip" -DestinationPath "C:\Tools\Autoruns" -Force
    Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
    Expand-Archive -Path "C:\Tools\ldapfw.zip" -DestinationPath "C:\Tools\ldapfw" -Force
    Write-Host "[+] Expanded Archives"
    Remove-Item "C:\Tools\Autoruns.zip"
    Remove-Item "C:\Tools\Sysmon.zip"
    Remove-Item "C:\Tools\ldapfw.zip"
    Write-Host "[+] Removed zip files"

    # Rename-Item -Path "C:\Tools\Sysmon\Sysmon.exe" -NewName "StorageSyncSvc.exe" > $null
    C:\Tools\Sysmon\Sysmon.exe -i "C:\Tools\sysmon-config.xml" -accepteula -h md5,sha256,imphash -d storagesync
    # Write-Host "[+] Installed Sysmon"
    # $acl = Get-ACL "C:\Windows\StorageSyncSvc.exe"
    # $acl.SetAccessRuleProtection($True, $False)
    # Set-ACL "C:\Windows\StorageSyncSvc.exe" $acl | Out-Null
    # $sddl = "O:BAG:DUD:PAI(A;;0x1200a9;;;SY)(A;;FA;;;BA)"
    # $FileSecurity = New-Object System.Security.AccessControl.FileSecurity
    # $FileSecurity.SetSecurityDescriptorSddlForm($sddl)
    # Set-ACL -Path "C:\Windows\StorageSyncSvc.exe" -ACLObject $FileSecurity
    # Write-Host "[+] Hardened Sysmon service configuration"

    Invoke-WebRequest https://raw.githubusercontent.com/zeronetworks/ldapfw/refs/heads/master/example_configs/DACLPrevention_config.json -OutFile "C:\Tools\ldapfw\DACLPrevention_config.json"
    Move-Item "C:\Tools\ldapfw\DACLPrevention_config.json" "C:\Tools\ldapfw\config.json" -Force
    Write-Host "[+] Downloaded LDAP Firewall configuration"

    Write-Host "[+] Done!" -ForegroundColor Green
}

function Enumerate {
    param (
        [string]$AdminPass
    )
    Write-Host "[+] Start Windows Updates and Defender Protection Updates!!" -ForegroundColor Blue
    Write-Output "=========START SYSTEM INFO========="
    $hostinfo = Get-ComputerInfo
    Write-Host "[+] Retrieved host info!" -ForegroundColor Green
    $netinfo = Get-NetIPConfiguration -Detailed
    Write-Host "[+] Retrieved network configuration!" -ForegroundColor Green
    
    Write-Output "Hostname: $($hostinfo.CsDomain)\$($hostinfo.CsName)`n"
    Write-Output "OS: $($hostinfo.WindowsProductName) - $($hostinfo.OSVersion) - $($hostinfo.OsBuildNumber)"
    
    foreach( $interface in $netinfo ) {
        Write-Output "- $($interface.InterfaceAlias)"
        Write-Output "    - IPv4: $($interface.IPv4Address.IPv4Address)"
        Write-Output "    - IPv6: $($interface.IPv6Address.IPv6Address)"
        Write-Output "    - Default gateway: $($interface.IPv4DefaultGateway.NextHop)"
        Write-Output "    - DNS: $($interface.DNSServer.ServerAddresses)"
    }
    Write-Output ""
    
    Write-Output "Domain Joined: $($hostinfo.CsPartOfDomain)"
    Write-Output "Domain Role: $($hostinfo.CsDomainRole)"

    Write-Output "=========END SYSTEM INFO========="

    Write-Output "=========START USER INFO========="
    Get-LocalUser | Out-Host
    
    Write-Host "Local Groups:"
    net localgroup

    Get-LocalGroupMembers -GroupName "Administrators"
    Get-LocalGroupMembers -GroupName "Remote Management Users"
    Get-LocalGroupMembers -GroupName "Remote Desktop Users"
    Get-LocalGroupMembers -GroupName "Backup Operators"
    Get-LocalGroupMembers -GroupName "Network Configuration Operators"
    Get-LocalGroupMembers -GroupName "Server Operators"
    Get-LocalGroupMembers -GroupName "Account Operators"
    
    Write-Output ""
    if ($AdminPass) {
        Enable-LocalUser Administrator
        Write-Host "[+] Enabled local administrator" -ForegroundColor Green
        Set-LocalUser -Name Administrator -Password (ConvertTo-SecureString $AdminPass -AsPlainText -Force)
        Write-Host "[+] Changed Administrator password!" -ForegroundColor Green
    } else {
        Write-Host "[-] Nothing was given for new Administrator password - skipping" -ForegroundColor Yellow
    }
    Write-Output "=========END USER INFO========="
    
    Write-Output "=========START LISTENING PORTS========="
    $procs = Get-Process
    $ports = netstat -ano
    $ports[4..$ports.length] |
        ConvertFrom-String -PropertyNames ProcessName,Proto,Local,Remote,State,PID  | 
        where  State -eq 'LISTENING' | 
        foreach {
            $_.ProcessName = ($procs | where ID -eq $_.PID).ProcessName
            $_
        } | 
        Format-Table
    Write-Output "=========END LISTENING PORTS========="
    
    Write-Output "=========START PROCESSES========="
    # Get session info from `query session`
    $sessions = @(query session | ForEach-Object {
        if ($_ -match "(\S+)\s+(\d+)\s") {
            [PSCustomObject]@{
                SessionName = $matches[1]
                SessionId   = [int]$matches[2]
            }
        }
    })

    # Get process details
    Get-CimInstance Win32_Process | ForEach-Object {
        $proc = $_
        $owner = $proc | Invoke-CimMethod -MethodName GetOwner
        $commandLine = $proc.CommandLine
        $sessionId = $proc.SessionId

        # Match session ID to session name
        $sessionName = ($sessions | Where-Object { $_.SessionId -eq $sessionId }).SessionName
        if (-not $sessionName) { $sessionName = "Unknown" }

        [PSCustomObject]@{
            UserName    = "$($owner.Domain)\$($owner.User)"
            ProcessID   = $proc.ProcessId
            CommandLine = $commandLine
            SessionName = $sessionName
            SessionId   = $sessionId
        }
    } | Format-Table -AutoSize
    Write-Output "==========END PROCESSES=========="

    Write-Output "==========START SERVICES=========="
    $svc = Get-WmiObject Win32_Service | Select-Object Name, PathName
    Write-Output $svc
    Write-Output "==========END SERVICES=========="

    Write-Output "==========START Installed Applications=========="
    $a1 = gci HKLM:\SOFTWARE
    $a2 = gci "C:\Program Files" -Force
    $a3 = gci "C:\Program Files (x86)" -Force
    $a4 = gci "C:\Windows\Temp" -Force
    Write-Output "HKLM:\SOFTWARE`n--------------"
    Write-Output $a1
    Write-Output "`nC:\Program Files\`n-----------------"
    Write-Output $a2
    Write-Output "`nC:\Program Files (x86)\`n-----------------------"
    Write-Output $a3
    Write-Output "`nC:\Windows\Temp\`n-----------------------"
    Write-Output $a4
    Write-Output "==========END Installed Applications=========="

    Write-Output "==========START Scheduled Tasks=========="
    $tasks = Get-ScheduledTask | ForEach-Object {
        $taskName = $_.TaskName
        $taskPath = $_.TaskPath
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath $taskPath
        $execPath = ($_ | Select-Object -ExpandProperty Actions).Execute

        [PSCustomObject]@{
            TaskPath  = $taskPath
            TaskName  = $taskName
            ExecPath  = $execPath
        }
    }
    $tasks | Format-Table -AutoSize
    Write-Output "==========END Scheduled Tasks=========="

    Write-Output "==========START Registry Keys=========="
    Get-RegistryKeys -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Get-RegistryKeys -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    Get-RegistryKeys -RegKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    Get-RegistryKeys -RegKey "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    Write-Output "==========END Registry Keys=========="

    Write-Output "==========START Startup Folder==========" 
    gci "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force | Out-Host
    Write-Output "==========END Startup Folder=========="
    Write-Output "`n"

    Get-SmbShare | ForEach-Object {
        $share = $_
        $access = Get-SmbShareAccess -Name $share.Name
        $access | Select-Object @{Name="ShareName";Expression={$share.Name}}, 
                                @{Name="SharePath";Expression={$share.Path}},
                                @{Name="AccessRight";Expression={$_.AccessRight}},
                                @{Name="AccountName";Expression={$_.AccountName}}
    } | Out-Host
    Read-Host -Prompt "Press enter to remove and limit unnecessary shares!"
    net share C$ /delete
    net share ADMIN$ /delete
    Read-Host -Prompt "Stop HERE! Change permissions on shares to readonly in the gui! If done, press enter!"

    Clear-History
    try {
        rm $(Get-PSReadLineOption).HistorySavePath -ErrorAction Stop
        Write-Host "[+] Cleared powershell history!" -ForegroundColor Green
    } catch {
        Write-Host "[-] No powershell history file found!" -ForegroundColor Yellow
    }
    
    Write-Host "[+] Finished machine enumeration!`n" -ForegroundColor Green
    Write-Host "Things to do:`n* Delete unnecessary local administrators!" -ForegroundColor Yellow
}

function Guest-Service {
    # Get the domain name automatically
    $domain = $env:USERDOMAIN
    $username = "$domain\Guest"

    # Prompt for password input for the Guest account
    $password = Read-Host -AsSecureString "Enter the password for the $username account"

    # Convert the secure password to plain text for WMI interaction
    $passwordPlainText = [System.Net.NetworkCredential]::new('', $password).Password

    # Prompt for the service name
    $serviceName = Read-Host "Enter the service name to manage"

    # Use WMI to get the service object
    $service = Get-WmiObject -Class Win32_Service -Filter "Name = '$serviceName'"

    if ($service) {
        # Change the service credentials using WMI
        $service.change($null, $null, $null, $null, $null, $null, $username, $passwordPlainText) > $null

        # Restart the service
        Restart-Service -Name $serviceName -Force # this will fail if u put random creds and its ok

        # Disable the service
        Set-Service -Name $serviceName -StartupType Disabled
        Stop-Service -Name $serviceName -Force

        Write-Host "$serviceName has been restarted and disabled using the Guest account."
    } else {
        Write-Host "Service $serviceName not found."
    }
}

function Phase2 {
    Write-Output "Starting Phase 2!"
    Read-Host -Prompt "Stopping services: WebClient, Spooler, WinRM"
    Get-Service "WebClient" | Stop-Service # MAY NOT BE PRESENT ON SOME MACHINES
    Get-Service "Spooler" | Stop-Service
    Get-Service "WinRM" | Stop-Service
    Read-Host -Prompt "Press enter to start Defender services" # ALSO NOT WORKING
    Get-Service "WinDefend" | Start-Service # Microsoft Defender Antivirus Service - MsMpEng.exe
    Get-Service "WdNisSvc" | Start-Service # Microsoft Defender Antivirus Network Inspection Service - NisSrv.exe
    Get-Service "MdCoreSvc" | Start-Service # Microsoft Defender Core Service - MpDefenderCoreService.exe # MAY NOT BE PRESENT
    Get-Service "SecurityHealthService" | Start-Service # Windows Security Service - SecurityHealthService.exe
    Get-Service "Sense" | Start-Service # Windows Defender Advanced Threat Protection Service - MsSense.exe # WILL NOT WORK IF YOU DO NOT HAVE MDE INSTALLED
    Write-Output "Current Exclusions: (Path = Folder & File, Extension = File type, Process = Process Binary"
    Get-MpPreference | Select-Object -ExpandProperty ExclusionPath,ExclusionProcess,ExclusionExtension
    $answer = Read-Host -Prompt "Do you want to remove exclusions? yes/no"
    if ($answer -eq "yes")
    {
        foreach ($i in (Get-MpPreference).ExclusionPath) {
            Remove-MpPreference -ExclusionPath $i
            Write-Host($i)
        }
        foreach ($i in (Get-MpPreference).ExclusionProcess) {
            Remove-MpPreference -ExclusionProcess $i
            Write-Host($i)
        }
        foreach ($i in (Get-MpPreference).ExclusionExtension) {
            Remove-MpPreference -ExclusionExtension $i
            Write-Host($i)
        }
    }
    
    Read-Host -Prompt "Press enter to harden Defender (SampleSubmission, Enable protections, run Defender protection threats update)"
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -DisableIOAVProtection 0
    Set-MpPreference -DisableRealtimeMonitoring 0
    Set-MpPreference -DisableBehaviorMonitoring 0
    Set-MpPreference -DisableScriptScanning 0
    Set-MpPreference -DisableArchiveScanning 0
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -EnableControlledFolderAccess Enabled
    Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\inetpub"
    Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\Public\"
    Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Windows\System32\CodeIntegrity\"

    Read-Host -Prompt "Press enter to add ASR rules & restart Defender"
    Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled # Block abuse of exploited vulnerable signed drivers
    Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled # Block Adobe Reader from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADCAD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled # Block all Office applications from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
    Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled # Block executable content from email client and webmail
    Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556801D275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled # Block execution of potentially obfuscated scripts
    Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled # Block JavaScript or VBScript from launching downloaded executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled # Block Office applications from creating executable content
    Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled # Block Office applications from injecting code into other processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled # Block Office communication application from creating child processes
    Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled # Block persistence through WMI event subscription, * File and folder exclusions not supported.
    Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA993A6D77406C -AttackSurfaceReductionRules_Actions Enabled # Block process creations originating from PSExec and WMI commands
    Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled # Block rebooting machine in Safe Mode (preview)
    Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled # Block untrusted and unsigned processes that run from USB
    Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions Enabled # Block use of copied or impersonated system tools (preview)
    Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions Enabled # Block Webshell creation for Servers
    Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled # Block Win32 API calls from Office macros
    Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3FA12568109D35 -AttackSurfaceReductionRules_Actions Enabled # Use advanced protection against ransomware
    #Restart-Service WinDefend # YOU CANNOT RESTART WINDEFEND. REBOOT HERE IS REQUIRED
    Update-MpSignature -AsJob

    Read-Host -Prompt "Press enter to enable LSA protections"
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Value 1

    Write-Host "[!] Finished Phase2!!`n" -ForegroundColor Green
    Write-Host "Things to do:`n* Run 'svcstuff'`n* Begin firewall rules!" -ForegroundColor Yellow
}

function Generate-WDAC {
    param([switch] $Refresh)

    $PolicyPath=$env:userprofile+"\Desktop\"
    $PolicyName="Policy"
    $Policy=$PolicyPath+$PolicyName+".xml"
    $DriversPolicy=$PolicyPath+"drivers.xml"
    $IISPolicy=$PolicyPath+"inetsrv.xml"
    $pf64Policy=$PolicyPath+"pf64.xml"
    $pf32Policy=$PolicyPath+"pf32.xml"
    $pdPolicy=$PolicyPath+"pd.xml"
    $toolsPolicy=$PolicyPath+"tools.xml"
    $src = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_enforced.xml"
    $dst = "$env:USERPROFILE\Desktop\DefaultWindows_Audit.xml"

    # --- NEW: Copy local file if it exists, otherwise download from GitHub ---
    if (Test-Path $src) {
        Write-Host "[+] Found DefaultWindows_Audit.xml locally, copying..." -ForegroundColor Cyan
        Copy-Item $src $dst -Force
    } else {
        Write-Host "[!] DefaultWindows_Audit.xml not found locally. Downloading from GitHub..." -ForegroundColor Yellow
        $downloadUrl = "https://raw.githubusercontent.com/deryavuz1/UTSA_CCDC_Team/refs/heads/main/Windows/DefaultWindows_Audit.xml"
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $dst -UseBasicParsing -ErrorAction Stop
            Write-Host "[+] Successfully downloaded DefaultWindows_Audit.xml" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to download DefaultWindows_Audit.xml: $_" -ForegroundColor Red
            Write-Host "[!] Cannot continue without a base policy. Exiting." -ForegroundColor Red
            return
        }
    }
    # -------------------------------------------------------------------------

    $DefaultWindowsPolicy = $dst
    New-Item $Policy -Force > $null

    if (Test-Path "C:\Program Files\Microsoft\Exchange Server\") {
        Write-Host "[!] Detected an Exchange server! Policy creation for this type of server will result in issues" -ForegroundColor Red
        return
    }

    Write-Host "[+] Generating policy..."
    $pf64 = Start-Job -ScriptBlock { param($pf64Policy) New-CIPolicy -FilePath $pf64Policy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\Program Files\" -UserPEs -OmitPaths "C:\Program Files\WindowsApps\" } -ArgumentList $pf64Policy
    $pf32 = Start-Job -ScriptBlock { param($pf32Policy) New-CIPolicy -FilePath $pf32Policy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\Program Files (x86)\" -UserPEs } -ArgumentList $pf32Policy
    $pd = Start-Job -ScriptBlock { param($pdPolicy) New-CIPolicy -FilePath $pdPolicy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\ProgramData\" -UserPEs } -ArgumentList $pdPolicy
    $tools = Start-Job -ScriptBlock { param($toolsPolicy) New-CIPolicy -FilePath $toolsPolicy -Level FilePublisher -Fallback Hash -ScanPath "C:\Tools\" -UserPEs } -ArgumentList $toolsPolicy

    if ((Get-WindowsFeature Web-Server).InstallState -eq "Installed") {
        Write-Host "[!] Detected an IIS Server! Adjusting WDAC policy creation..." -ForegroundColor Yellow
        $iis = Start-Job -ScriptBlock { param($IISPolicy) New-CIPolicy -FilePath $IISPolicy -Level FilePublisher -Fallback Hash,Filename -ScanPath "C:\Windows\System32\inetsrv\" } -ArgumentList $IISPolicy
    }
    $drivers = Start-Job -ScriptBlock { param($DriversPolicy) New-CIPolicy -FilePath $DriversPolicy -Level SignedVersion -Fallback FilePublisher,Hash -ScanPath "C:\Windows\System32\drivers\" } -ArgumentList $DriversPolicy
    
    Wait-Job $pf64,$pf32,$pd,$drivers,$tools
    if ($iis) { Wait-Job $iis ; Remove-Job $iis }
    Remove-Job $pf64,$pf32,$pd,$drivers,$tools
    $additional_blocks = New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\vssadmin.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\vssuirun.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\ntdsutil.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\reg.exe -Deny
    #$additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\wmic.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\certutil.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\mshta.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\wscript.exe -Deny
    $additional_blocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath C:\Windows\System32\cscript.exe -Deny
    Write-Host "[+] Generated policies!" -ForegroundColor Green
    
    Write-Host "[+] Merging policies..."
    Merge-CIPolicy -OutputFilePath $Policy -PolicyPaths $DefaultWindowsPolicy,$pf32Policy,$pf64Policy,$pdPolicy,$DriversPolicy,$toolsPolicy > $null
    Merge-CIPolicy -OutputFilePath $Policy -PolicyPaths $Policy -Rules $additional_blocks > $null
    if ($iis) { Merge-CIPolicy -OutputFilePath $Policy -PolicyPaths $Policy,$IISPolicy > $null }
    Write-Host "[+] Merged policies"
    
    Set-CIPolicyIdInfo -FilePath $Policy -PolicyName $PolicyName
    Set-CIPolicyVersion -FilePath $Policy -Version "1.0.0.0"
    Set-RuleOption -FilePath $Policy -Option 3 -Delete  # Audit Mode
    Set-RuleOption -FilePath $Policy -Option 6          # Unsigned Policy
    Set-RuleOption -FilePath $Policy -Option 8 -Delete  # DLL enforcement
    Set-RuleOption -FilePath $Policy -Option 9          # Advanced Boot Menu
    Set-RuleOption -FilePath $Policy -Option 10         # Boot Audit on Failure
    Set-RuleOption -FilePath $Policy -Option 12         # Enforce Store Apps

    # Options 14 (ISG) and 19 (Dynamic Code Security) require Server 2019+ / Win10 1903+
    $osBuild = [System.Environment]::OSVersion.Version.Build
    if ($osBuild -ge 17763) {
        Set-RuleOption -FilePath $Policy -Option 14     # Intelligent Security Graph
        Set-RuleOption -FilePath $Policy -Option 19     # Dynamic Code Security
    } else {
        Write-Host "[!] Skipping options 14 and 19 - not supported on this OS (build $osBuild)" -ForegroundColor Yellow
    }
    Write-Host "[+] Added configuration rules to policy!"

    $PolicyBin = $PolicyPath+"SiPolicy.p7b"
    ConvertFrom-CIPolicy -XmlFilePath $Policy -BinaryFilePath $PolicyBin > $null
    Write-Host "[+] Generated policy at $PolicyBin"

    if ($Refresh) {
        Write-Host "[+] Refreshing policy..."
        try {
            copy $PolicyBin "C:\Windows\System32\CodeIntegrity\"
            Write-Host "[+] Moved policy!"
            Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"} > $null
            Write-Host "[+] Refreshed policy!" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to copy policy! Is controlled folder access on?" -ForegroundColor Red
        }
    }
    Write-Host "[+] Exiting..."
}

function Refresh-WDAC {
    Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"}
}

function Get-GroupMembersRecursive {
    param (
        [string]$GroupName
    )

    $GroupMembers = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }
    return $GroupMembers
}

Function Add-UsersToGroup {
    param (
        [string]$Source,
        [string]$Destination
    )
    $Users = Get-GroupMembersRecursive -GroupName $Source
    foreach ($User in $Users) {
        try {
            Add-ADGroupMember -Identity $Destination -Members $User
            Write-Host "[+] Added user $User to $Destination" -ForegroundColor Green
        } catch {
            Write-Host "[-] Skill issue for user $User" -ForegroundColor Red
        }
    }
}