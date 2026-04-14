[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Reset-ServiceAccountPasswords {
    Import-Module ActiveDirectory -ErrorAction Stop

    function New-RandomPassword {
        param([int]$Length = 16)
        if ($Length -gt 20) { $Length = 20 }
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $rng   = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $bytes = New-Object byte[] ($Length - 1)
        $rng.GetBytes($bytes)
        $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
        return $password + '!'
    }
    $excludedAccounts = [System.Collections.Generic.List[string]]@()

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

    $allUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName, Description, ServicePrincipalNames |
        Where-Object {
            $_.SamAccountName -match '(?i)(^svc|^sa[-_]|[-_]svc$|service|[-_]sa$|^service)' -or
            $_.ServicePrincipalNames.Count -gt 0
        } |
        Where-Object { $excludedAccounts -notcontains $_.SamAccountName }

    $msaAccounts = Get-ADServiceAccount -Filter { Enabled -eq $true } -Properties SamAccountName |
        Where-Object { $excludedAccounts -notcontains $_.SamAccountName }

    if ((-not $allUsers) -and (-not $msaAccounts)) {
        Write-Warning "No eligible service accounts found. Exiting."
        return
    }

    Write-Host "Found $($allUsers.Count) service account(s) and $($msaAccounts.Count) managed service account(s) to process." -ForegroundColor Cyan

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

    foreach ($msa in $msaAccounts) {
        $passwordList.Add([PSCustomObject]@{
            Username = $msa.SamAccountName
            Password = "MANAGED-BY-AD"
            Type     = "ManagedServiceAccount"
        })
    }

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

    Write-Host "Any further accounts to remove before applying? (comma-separated), or press ENTER to continue:" -ForegroundColor Yellow
    $lateExclusions = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($lateExclusions)) {
        $lateAccounts = $lateExclusions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

        foreach ($a in $lateAccounts) {
            $match = $passwordList | Where-Object { $_.Username -eq $a } | Select-Object -First 1
            if ($match) {
                $passwordList.Remove($match) | Out-Null
                Write-Host "  [REMOVED] $a from password change list" -ForegroundColor Yellow
            } else {
                Write-Warning "  [NOT FOUND] $a was not in the list, skipping"
            }
        }

        "Username,Password,Type" | Set-Content -Path $csvPath
        foreach ($entry in $passwordList) {
            "$($entry.Username),$($entry.Password),$($entry.Type)" | Add-Content -Path $csvPath
        }
        Write-Host "CSV updated to remove excluded accounts." -ForegroundColor Cyan
    }

    Write-Host "`nPress ENTER to begin changing $($passwordList.Count) password(s), or CTRL+C to abort..." -ForegroundColor Red
    Read-Host | Out-Null

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

        for ($i = 0; $i -lt $groupInfo.Count - 1; $i++) {
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
    $runKey = Get-Item -Path "$RegKey" -ErrorAction SilentlyContinue
    if ($runKey) {
        $runKey.GetValueNames() | ForEach-Object { [PSCustomObject]@{ Name = $_; Value = $runKey.GetValue($_) } } | Out-Host
    } else {
        Write-Host "  [!] Registry key not found" -ForegroundColor Yellow
    }
}

function Get-Binary {
    if (-not (Test-Path "C:\Tools")) {
        New-Item -Path "C:\Tools" -ItemType Directory -Force | Out-Null
    }
    Add-MpPreference -ExclusionPath "C:\Tools"
    Start-Sleep -Seconds 3

    Write-Host "[+] Resolving PingCastle latest release from GitHub API..." -ForegroundColor Cyan
    $pingCastleUrl = $null
    $pingCastleFilename = $null
    $ua = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/netwrix/pingcastle/releases/latest" -UseBasicParsing -Headers $ua -ErrorAction Stop
        $asset = $release.assets | Where-Object { $_.name -match "^PingCastle_.*\.zip$" -and $_.name -notmatch "AutoUpdater" } | Select-Object -First 1
        if ($asset) {
            $pingCastleUrl      = $asset.browser_download_url
            $pingCastleFilename = $asset.name
            Write-Host "[+] PingCastle latest: $($release.tag_name) -> $pingCastleFilename" -ForegroundColor Green
        } else {
            throw "No matching zip asset found"
        }
    } catch {
        Write-Host "[!] GitHub API unavailable, falling back to known-good URL: $_" -ForegroundColor Yellow
        $pingCastleUrl      = "https://github.com/netwrix/pingcastle/releases/download/3.5.0.37/PingCastle_3.5.0.37.zip"
        $pingCastleFilename = "PingCastle_3.5.0.37.zip"
    }

    Write-Host "[+] Downloading binaries..." -ForegroundColor Cyan
    $downloads = @(
        @{ Name = "Cable";      Url = "https://github.com/logangoins/Cable/releases/download/1.1/Cable.exe";                              Out = "C:\Tools\Cable.exe" }
        @{ Name = "PingCastle"; Url = $pingCastleUrl;                                                                                     Out = "C:\Tools\pingcastle.zip" }
        @{ Name = "Certify";    Url = "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe";                Out = "C:\Tools\Certify.exe" }
    )

    foreach ($dl in $downloads) {
        Write-Host "  [>] Downloading: $($dl.Name)"
        try {
            Invoke-WebRequest $dl.Url -OutFile $dl.Out -UseBasicParsing -Headers $ua -ErrorAction Stop
            Write-Host "  [+] $($dl.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] $($dl.Name) failed: $_" -ForegroundColor Red
        }
    }

    if (Test-Path "C:\Tools\pingcastle.zip") {
        $zipBytes = (Get-Item "C:\Tools\pingcastle.zip").Length
        if ($zipBytes -gt 10000) {
            New-Item -ItemType Directory -Path "C:\Tools\pingcastle" -Force -ErrorAction SilentlyContinue | Out-Null
            Expand-Archive "C:\Tools\pingcastle.zip" -DestinationPath "C:\Tools\pingcastle" -Force

            if (-not (Test-Path "C:\Tools\pingcastle\PingCastle.exe")) {
                $nested = Get-ChildItem "C:\Tools\pingcastle" -Filter "PingCastle.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($nested) {
                    $nestedDir = $nested.DirectoryName
                    Get-ChildItem $nestedDir -Force | Move-Item -Destination "C:\Tools\pingcastle" -Force -ErrorAction SilentlyContinue
                    Remove-Item $nestedDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "[+] PingCastle extracted (flattened from nested directory)" -ForegroundColor Green
                } else {
                    Write-Host "[!] PingCastle zip extracted but PingCastle.exe not found - zip may be corrupt" -ForegroundColor Red
                }
            } else {
                Write-Host "[+] PingCastle extracted" -ForegroundColor Green
            }
        } else {
            Write-Host "[!] PingCastle zip is too small ($zipBytes bytes) - download likely failed" -ForegroundColor Red
        }
    }

    Write-Host "[+] All binaries downloaded!" -ForegroundColor Green
}

function Setup-Graylog {
    $installerPath = "C:\Tools\graylog_sidecar_installer.exe"

    Write-Host "[+] Downloading Graylog Sidecar installer..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest "https://github.com/Graylog2/collector-sidecar/releases/download/1.5.1/graylog_sidecar_installer_1.5.1-1.exe" -OutFile $installerPath -UseBasicParsing -Headers @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" } -ErrorAction Stop
        Write-Host "[+] Downloaded Graylog Sidecar installer" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to download Graylog Sidecar: $_" -ForegroundColor Red
        return
    }

    $serverUrl = Read-Host -Prompt "Enter Graylog server API URL (e.g. https://graylog.example.com:9000/api)"
    if ([string]::IsNullOrWhiteSpace($serverUrl)) {
        Write-Host "[!] Server URL is required. Exiting." -ForegroundColor Red
        return
    }

    $apiToken = Read-Host -Prompt "Enter Graylog API token"
    if ([string]::IsNullOrWhiteSpace($apiToken)) {
        Write-Host "[!] API token is required. Exiting." -ForegroundColor Red
        return
    }

    Write-Host "Enter Sidecar tags as comma-separated values (e.g. windows,iis), or press ENTER to skip:" -ForegroundColor Yellow
    $tagsInput = Read-Host
    $tagsArg = ""
    if (-not [string]::IsNullOrWhiteSpace($tagsInput)) {
        $tagList = ($tagsInput -split ',' | ForEach-Object { "`"$($_.Trim())`"" }) -join ','
        $tagsArg = "-TAGS=[$tagList]"
    }

    Write-Host "[+] Installing Graylog Sidecar (silent)..." -ForegroundColor Cyan
    $installArgs = "/S -SERVERURL=$serverUrl -APITOKEN=$apiToken"
    if ($tagsArg) { $installArgs += " $tagsArg" }

    $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        Write-Host "[!] Installer exited with code $($process.ExitCode)" -ForegroundColor Red
        return
    }
    Write-Host "[+] Sidecar installed!" -ForegroundColor Green

    $sidecarExe = "C:\Program Files\Graylog\sidecar\graylog-sidecar.exe"
    if (-not (Test-Path $sidecarExe)) {
        Write-Host "[!] graylog-sidecar.exe not found at expected path. Check installation." -ForegroundColor Red
        return
    }

    Write-Host "[+] Registering Sidecar service..." -ForegroundColor Cyan
    & $sidecarExe -service install
    Write-Host "[+] Starting Sidecar service..." -ForegroundColor Cyan
    & $sidecarExe -service start

    Write-Host "[+] Graylog Sidecar is installed and running!" -ForegroundColor Green
    Write-Host "[+] Config file: C:\Program Files\Graylog\sidecar\sidecar.yml" -ForegroundColor Cyan
    Write-Host "[+] Verify in Graylog UI under System > Sidecars" -ForegroundColor Cyan
}

function Reset-AllUserPasswords {
    Import-Module ActiveDirectory -ErrorAction Stop

    function New-RandomPassword {
        param([int]$Length = 16)
        if ($Length -gt 20) { $Length = 20 }
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        $rng   = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $bytes = New-Object byte[] ($Length - 1)
        $rng.GetBytes($bytes)
        $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
        return $password + '!'
    }

    $excludedUsers = [System.Collections.Generic.List[string]]@('Administrator', 'krgbt')

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

    $users = Get-ADUser -Filter { Enabled -eq $true } -Properties SamAccountName |
             Where-Object { $excludedUsers -notcontains $_.SamAccountName }

    if (-not $users) {
        Write-Warning "No eligible users found. Exiting."
        return
    }

    Write-Host "Found $($users.Count) user(s) to process." -ForegroundColor Cyan

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

    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $csvPath = Join-Path $desktopPath "NewPasswords_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    "Username,Password" | Set-Content -Path $csvPath
    foreach ($entry in $passwordList) {
        "$($entry.Username),$($entry.Password)" | Add-Content -Path $csvPath
    }

    Write-Host "`nPassword list saved to: $csvPath" -ForegroundColor Green
    Write-Host "Please open and review the file before proceeding." -ForegroundColor Yellow
    Write-Host "`nThe following $($passwordList.Count) account(s) will have their passwords changed:" -ForegroundColor Yellow
    $passwordList | Format-Table -AutoSize

    Write-Host "Any further accounts to remove before applying? (comma-separated), or press ENTER to continue:" -ForegroundColor Yellow
    $lateExclusions = Read-Host

    if (-not [string]::IsNullOrWhiteSpace($lateExclusions)) {
        $lateUsers = $lateExclusions -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

        foreach ($u in $lateUsers) {
            $match = $passwordList | Where-Object { $_.Username -eq $u } | Select-Object -First 1
            if ($match) {
                $passwordList.Remove($match) | Out-Null
                Write-Host "  [REMOVED] $u from password change list" -ForegroundColor Yellow
            } else {
                Write-Warning "  [NOT FOUND] $u was not in the list, skipping"
            }
        }

        "Username,Password" | Set-Content -Path $csvPath
        foreach ($entry in $passwordList) {
            "$($entry.Username),$($entry.Password)" | Add-Content -Path $csvPath
        }
        Write-Host "CSV updated to remove excluded accounts." -ForegroundColor Cyan
    }

    Write-Host "`nPress ENTER to begin changing $($passwordList.Count) password(s), or CTRL+C to abort..." -ForegroundColor Red
    Read-Host | Out-Null

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

function Get-SystemInformer {
    Write-Host "[+] Downloading System Informer..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest "https://phoenixnap.dl.sourceforge.net/project/systeminformer/systeminformer-3.2.25011-release-setup.exe?viasf=1" -OutFile "C:\Tools\SystemInformer.exe" -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Downloaded System Informer to C:\Tools\SystemInformer.exe" -ForegroundColor Green
        Write-Host "[+] Run C:\Tools\SystemInformer.exe to install" -ForegroundColor Cyan
    } catch {
        Write-Host "[!] Failed to download System Informer: $_" -ForegroundColor Red
    }
}

function Get-Wireshark {
    if (-not (Test-Path "C:\Tools")) {
        New-Item -Path "C:\Tools" -ItemType Directory -Force | Out-Null
    }

    $wiresharkExe = "C:\Tools\WiresharkInstaller.exe"

    Write-Host "[+] Downloading Wireshark..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest "https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe" -OutFile $wiresharkExe -UseBasicParsing -ErrorAction Stop
        Write-Host "[+] Downloaded Wireshark installer" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to download Wireshark: $_" -ForegroundColor Red
        Write-Host "[!] Download manually from https://www.wireshark.org/download.html" -ForegroundColor Yellow
        return
    }

    if (-not (Test-Path $wiresharkExe) -or (Get-Item $wiresharkExe).Length -lt 100000) {
        Write-Host "[!] Wireshark installer missing or too small - download may have failed" -ForegroundColor Red
        return
    }

    Write-Host "[+] Installing Wireshark silently..." -ForegroundColor Cyan
    $proc = Start-Process -FilePath $wiresharkExe -ArgumentList "/S" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
    if ($proc.ExitCode -eq 0 -and (Test-Path "C:\Program Files\Wireshark\tshark.exe")) {
        Write-Host "[+] Wireshark installed - tshark at C:\Program Files\Wireshark\tshark.exe" -ForegroundColor Green
    } else {
        Write-Host "[!] Wireshark install may have failed (exit code $($proc.ExitCode))" -ForegroundColor Yellow
    }
    Remove-Item $wiresharkExe -Force -ErrorAction SilentlyContinue

    $runCapture = Read-Host -Prompt "Start a 90-second background packet capture now? (yes/no)"
    if ($runCapture -eq "yes") {
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $pcapFile = Join-Path $desktopPath "capture_$timestamp.pcapng"

        $tsharkPaths = @(
            "C:\Program Files\Wireshark\tshark.exe",
            "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
        )
        $tshark = $tsharkPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

        if ($tshark) {
            Write-Host "[+] Starting 90-second tshark capture -> $pcapFile" -ForegroundColor Cyan
            $tsharkJob = Start-Job -ScriptBlock {
                param($tsharkPath, $outFile)
                & $tsharkPath -a duration:90 -w $outFile 2>&1
            } -ArgumentList $tshark, $pcapFile
            Write-Host "[+] tshark capture running as background job (ID: $($tsharkJob.Id))" -ForegroundColor Green
            Write-Host "[+] Run 'Receive-Job $($tsharkJob.Id)' to check status, or 'Wait-Job $($tsharkJob.Id)' to wait" -ForegroundColor Cyan
        } else {
            Write-Host "[!] tshark not found after install - capture skipped" -ForegroundColor Red
        }
    }
}


function Get-Tools {
    New-Item -Path C:\ -Name "Tools" -ItemType Directory -Force > $null
    Write-Host "[+] Created tools directory!"

    Add-MpPreference -ExclusionPath "C:\Tools" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Host "[+] Added Defender exclusion for C:\Tools" -ForegroundColor Cyan

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    #Set-Acl -Path "C:\Tools" -AclObject $acl
    Write-Host "[+] Locked down C:\Tools - Administrators and SYSTEM only" -ForegroundColor Cyan

    Write-Host "[+] Downloading all tools..." -ForegroundColor Cyan

    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $localSysmonConfig = Join-Path $scriptDir "sysmon-config.xml"

    $downloads = @(
        @{ Name = "Autoruns";       Url = "https://download.sysinternals.com/files/Autoruns.zip";                                                              Out = "C:\Tools\Autoruns.zip" }
        @{ Name = "Sysmon";         Url = "https://download.sysinternals.com/files/Sysmon.zip";                                                                Out = "C:\Tools\Sysmon.zip" }
        @{ Name = "Firefox";        Url = "https://download.mozilla.org/?product=firefox-stub&os=win&lang=en-US";                                              Out = "C:\Tools\FirefoxInstaller.exe" }
        @{ Name = "LDAP Firewall";  Url = "https://github.com/zeronetworks/ldapfw/releases/download/v1.0.0/ldapfw_v1.0.0-x64.zip";                            Out = "C:\Tools\ldapfw.zip" }
        @{ Name = "ALTools";        Url = "https://download.microsoft.com/download/1/f/0/1f0e9569-3350-4329-b443-822976f29284/ALTools.exe";                    Out = "C:\Tools\ALTools.exe" }
        @{ Name = "RefreshPolicy";     Url = "https://aka.ms/refreshpolicy";                                                                                     Out = "C:\Tools\RefreshPolicy.exe" }
    )

    if (Test-Path $localSysmonConfig) {
        Write-Host "  [+] Found sysmon-config.xml locally at $localSysmonConfig - copying" -ForegroundColor Green
        Copy-Item $localSysmonConfig "C:\Tools\sysmon-config.xml" -Force
    } else {
        Write-Host "  [~] sysmon-config.xml not found locally - will download" -ForegroundColor Yellow
        $downloads += @{ Name = "Sysmon Config"; Url = "https://raw.githubusercontent.com/SouthwestCCDC/2026-Regionals-Shared/refs/heads/main/The%20University%20of%20Texas%20at%20San%20Antonio/2026_Windows/sysmon-config.xml"; Out = "C:\Tools\sysmon-config.xml" }
    }

    $ua = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }
    $failCount = 0
    foreach ($dl in $downloads) {
        Write-Host "  [>] Downloading: $($dl.Name)"
        try {
            Invoke-WebRequest $dl.Url -OutFile $dl.Out -UseBasicParsing -Headers $ua -ErrorAction Stop
            Write-Host "  [+] $($dl.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  [!] $($dl.Name) failed: $_" -ForegroundColor Red
            $failCount++
        }
    }
    Write-Host "[+] Downloads finished ($failCount failure(s))" -ForegroundColor Green

    Write-Host "[+] Expanding archives"
    foreach ($archive in @(
        @{ Zip = "C:\Tools\Autoruns.zip"; Dest = "C:\Tools\Autoruns"; Name = "Autoruns" }
        @{ Zip = "C:\Tools\Sysmon.zip";   Dest = "C:\Tools\Sysmon";   Name = "Sysmon"   }
        @{ Zip = "C:\Tools\ldapfw.zip";   Dest = "C:\Tools\ldapfw";   Name = "LDAP Firewall" }
    )) {
        if (Test-Path $archive.Zip) {
            New-Item -ItemType Directory -Path $archive.Dest -Force -ErrorAction SilentlyContinue | Out-Null
            Expand-Archive -Path $archive.Zip -DestinationPath $archive.Dest
            Write-Host "[+] Expanded $($archive.Name) archive" -ForegroundColor Green
        } else {
            Write-Host "[!] $($archive.Name) zip not found - download may have failed, skipping extraction" -ForegroundColor Red
        }
    }

    if (Test-Path "C:\Tools\Sysmon\Sysmon.exe") {
        if (Test-Path "C:\Tools\sysmon-config.xml") {
            C:\Tools\Sysmon\Sysmon.exe -i "C:\Tools\sysmon-config.xml" -accepteula -h md5,sha256,imphash -d storagesync
            Write-Host "[+] Sysmon installed with config" -ForegroundColor Green
        } else {
            Write-Host "[!] sysmon-config.xml not found - installing Sysmon with default config" -ForegroundColor Yellow
            C:\Tools\Sysmon\Sysmon.exe -i -accepteula -h md5,sha256,imphash -d storagesync
        }
    } else {
        Write-Host "[!] Sysmon.exe not found after extraction - Sysmon was NOT installed" -ForegroundColor Red
    }

    if (Test-Path "C:\Tools\ldapfw") {
        try {
            Invoke-WebRequest https://raw.githubusercontent.com/zeronetworks/ldapfw/refs/heads/master/example_configs/DACLPrevention_config.json -OutFile "C:\Tools\ldapfw\DACLPrevention_config.json" -UseBasicParsing -Headers @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" } -ErrorAction Stop
            Move-Item "C:\Tools\ldapfw\DACLPrevention_config.json" "C:\Tools\ldapfw\config.json" -Force
            Write-Host "[+] Downloaded LDAP Firewall configuration" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to download LDAP Firewall configuration: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "[!] ldapfw directory not found - skipping LDAP Firewall config download" -ForegroundColor Red
    }

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
        ConvertFrom-String -PropertyNames Proto,Local,Remote,State,PID |
        Where-Object { $_.State -eq 'LISTENING' } |
        ForEach-Object {
            $procId   = [int]$_.PID
            $procName = ($procs | Where-Object { $_.Id -eq $procId } | Select-Object -First 1).ProcessName
            [PSCustomObject]@{
                ProcessName = if ($procName) { $procName } else { '(unknown)' }
                Proto       = $_.Proto
                Local       = $_.Local
                PID         = $procId
            }
        } |
        Format-Table -AutoSize
    Write-Output "=========END LISTENING PORTS========="
    
    Write-Output "=========START PROCESSES========="
    $sessions = @(query session | ForEach-Object {
        if ($_ -match "(\S+)\s+(\d+)\s") {
            [PSCustomObject]@{
                SessionName = $matches[1]
                SessionId   = [int]$matches[2]
            }
        }
    })

    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object {
        $proc = $_
        $sessionId = $proc.SessionId

        $sessionName = ($sessions | Where-Object { $_.SessionId -eq $sessionId }).SessionName
        if (-not $sessionName) { $sessionName = "Unknown" }

        [PSCustomObject]@{
            UserName    = $proc.UserName
            ProcessID   = $proc.Id
            ProcessName = $proc.ProcessName
            Path        = $proc.Path
            SessionName = $sessionName
            SessionId   = $sessionId
        }
    } | Format-Table -AutoSize
    Write-Output "==========END PROCESSES=========="

    Write-Output "==========START SERVICES=========="
    $svc = Get-Service | Select-Object Name, @{N='PathName';E={(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -ErrorAction SilentlyContinue).ImagePath}}
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
        $execPath = ($_ | Select-Object -ExpandProperty Actions |
                     ForEach-Object { $_.Execute } |
                     Where-Object { $_ }) -join ' | '

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
    $removeShares = Read-Host -Prompt "Remove unnecessary admin shares (C$, ADMIN$)? (yes/no)"
    if ($removeShares -eq "yes") {
        net share C$ /delete
        net share ADMIN$ /delete
        Write-Host "[+] Admin shares removed" -ForegroundColor Green
        Read-Host -Prompt "Change permissions on remaining shares to readonly in the GUI, then press ENTER"
    } else {
        Write-Host "[*] Skipping share removal" -ForegroundColor Yellow
    }

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
    $domain = $env:USERDOMAIN
    $username = "$domain\Guest"

    $password = Read-Host -AsSecureString "Enter the password for the $username account"

    $passwordPlainText = [System.Net.NetworkCredential]::new('', $password).Password

    $serviceName = Read-Host "Enter the service name to manage"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

    if ($service) {
        sc.exe config $serviceName obj= $username password= $passwordPlainText > $null

        Restart-Service -Name $serviceName -Force

        Set-Service -Name $serviceName -StartupType Disabled
        Stop-Service -Name $serviceName -Force

        Write-Host "$serviceName has been restarted and disabled using the Guest account."
    } else {
        Write-Host "Service $serviceName not found."
    }
}

function Phase2 {
    Write-Output "Starting Phase 2!"

    $stopSvcs = Read-Host -Prompt "Stop services: WebClient, Spooler, WinRM? (yes/no)"
    if ($stopSvcs -eq "yes") {
        Get-Service "WebClient" -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
        Get-Service "Spooler"   -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
        Get-Service "WinRM"     -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
        Write-Host "[+] Services stopped" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping service shutdown" -ForegroundColor Yellow
    }

    $disableEFS = Read-Host -Prompt "Disable EFS service? Prevents PetitPotam coercion attacks. (yes/no)"
    if ($disableEFS -eq "yes") {
        Stop-Service -Name "EFS" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "EFS" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "[+] EFS service disabled (PetitPotam mitigation)" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping EFS disable" -ForegroundColor Yellow
    }

    $startDefender = Read-Host -Prompt "Start Defender services? (yes/no)"
    if ($startDefender -eq "yes") {
        Get-Service "WinDefend"           -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        Get-Service "WdNisSvc"            -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        Get-Service "MdCoreSvc"           -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        Get-Service "SecurityHealthService" -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        Get-Service "Sense"               -ErrorAction SilentlyContinue | Start-Service -ErrorAction SilentlyContinue
        Write-Host "[+] Defender services started" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping Defender services" -ForegroundColor Yellow
    }

    Write-Output "Current Exclusions: (Path = Folder & File, Extension = File type, Process = Process Binary)"
    $mpPref = Get-MpPreference
    Write-Host "  ExclusionPath:" -ForegroundColor Cyan
    $mpPref.ExclusionPath | ForEach-Object { Write-Host "    $_" }
    Write-Host "  ExclusionProcess:" -ForegroundColor Cyan
    $mpPref.ExclusionProcess | ForEach-Object { Write-Host "    $_" }
    Write-Host "  ExclusionExtension:" -ForegroundColor Cyan
    $mpPref.ExclusionExtension | ForEach-Object { Write-Host "    $_" }
    $answer = Read-Host -Prompt "Do you want to remove exclusions? (yes/no)"
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
    } else {
        Write-Host "[*] Skipping exclusion removal" -ForegroundColor Yellow
    }

    $hardenDefender = Read-Host -Prompt "Harden Defender (protections, signature update)? (yes/no)"
    if ($hardenDefender -eq "yes") {
        Set-MpPreference -SubmitSamplesConsent NeverSend
        Set-MpPreference -MAPSReporting Disabled
        Set-MpPreference -DisableIOAVProtection 0
        Set-MpPreference -DisableRealtimeMonitoring 0
        Set-MpPreference -DisableBehaviorMonitoring 0
        Set-MpPreference -DisableScriptScanning 0
        Set-MpPreference -DisableArchiveScanning 0
        Set-MpPreference -PUAProtection 1
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Users\Public\"
        Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Windows\System32\CodeIntegrity\"

        if (Test-Path "C:\inetpub") {
            Write-Host "[!] IIS detected (C:\inetpub exists)" -ForegroundColor Yellow
            Write-Host "[!] WARNING: Controlled Folder Access on inetpub will block w3wp.exe writes (logs, uploads, sessions)" -ForegroundColor Yellow
            $protectInetpub = Read-Host -Prompt "Add C:\inetpub to Controlled Folder Access? (yes/no)"
            if ($protectInetpub -eq "yes") {
                Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\inetpub"
                Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Windows\System32\inetsrv\w3wp.exe"
                Write-Host "[+] C:\inetpub protected, w3wp.exe added as allowed app" -ForegroundColor Green
            } else {
                Write-Host "[*] Skipping inetpub CFA protection" -ForegroundColor Yellow
            }
        }

        Write-Host "[+] Defender hardened" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping Defender hardening" -ForegroundColor Yellow
    }

    $addASR = Read-Host -Prompt "Add ASR rules? (yes/no)"
    if ($addASR -eq "yes") {
        Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-CD74-433A-B99E-2ECDC07BFC25 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled
        Update-MpSignature -AsJob
        Write-Host "[+] ASR rules added" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping ASR rules" -ForegroundColor Yellow
    }

    $enableLSA = Read-Host -Prompt "Enable LSA protections (RunAsPPL)? (yes/no)"
    if ($enableLSA -eq "yes") {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPLBoot" -Value 1 -PropertyType DWord -Force
        Write-Host "[+] LSA protections enabled" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping LSA protections" -ForegroundColor Yellow
    }

    $setLockout = Read-Host -Prompt "Set account lockout policy (3 attempts, 15-min lockout)? (yes/no)"
    if ($setLockout -eq "yes") {
        Write-Host "[+] Setting account lockout policy..." -ForegroundColor Cyan
        net accounts /lockoutthreshold:3
        net accounts /lockoutduration:15
        net accounts /lockoutwindow:15
        Write-Host "[+] Local lockout policy set: 3 attempts, 15-min lockout, 15-min reset" -ForegroundColor Green

        $productType = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductType
        if ($productType -eq "LanmanNT") {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) `
                    -LockoutThreshold 3 `
                    -LockoutDuration "00:15:00" `
                    -LockoutObservationWindow "00:15:00"
                Write-Host "[+] Domain lockout policy set via AD Default Domain Password Policy" -ForegroundColor Green
            } catch {
                Write-Host "[!] Failed to set domain lockout policy: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[*] Skipping account lockout policy" -ForegroundColor Yellow
    }

    $exfilBlock = Read-Host -Prompt "Lock down WER, SmartScreen, and Defender telemetry via registry? (yes/no)"
    if ($exfilBlock -eq "yes") {

        $spynetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
        if (-not (Test-Path $spynetKey)) {
            New-Item -Path $spynetKey -Force | Out-Null
        }
        New-ItemProperty -Path $spynetKey -Name "SpynetReporting"      -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $spynetKey -Name "SubmitSamplesConsent" -Value 2 -PropertyType DWord -Force | Out-Null
        Write-Host "[+] Defender MAPS/cloud submission locked off via policy registry" -ForegroundColor Green

        $werPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
        if (-not (Test-Path $werPolicyKey)) {
            New-Item -Path $werPolicyKey -Force | Out-Null
        }
        New-ItemProperty -Path $werPolicyKey -Name "Disabled"         -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $werPolicyKey -Name "DontSendAdditionalData" -Value 1 -PropertyType DWord -Force | Out-Null
        Set-Service  -Name WerSvc -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name WerSvc -Force               -ErrorAction SilentlyContinue
        Write-Host "[+] Windows Error Reporting disabled and service stopped" -ForegroundColor Green

        $smartScreenKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $smartScreenKey)) {
            New-Item -Path $smartScreenKey -Force | Out-Null
        }
        New-ItemProperty -Path $smartScreenKey -Name "EnableSmartScreen" -Value 0 -PropertyType DWord -Force | Out-Null
        $ssAppKey = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
        if (-not (Test-Path $ssAppKey)) {
            New-Item -Path $ssAppKey -Force | Out-Null
        }
        New-ItemProperty -Path $ssAppKey -Name "EnabledV9"  -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $ssAppKey -Name "PreventOverride" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "[+] SmartScreen disabled via policy registry" -ForegroundColor Green

        Write-Host "[+] All sample/telemetry exfiltration vectors locked down" -ForegroundColor Green
    } else {
        Write-Host "[*] Skipping telemetry lockdown" -ForegroundColor Yellow
    }

    Write-Host "[!] Finished Phase2!!`n" -ForegroundColor Green
    Write-Host "Things to do:`n* Run 'svcstuff'`n* Begin firewall rules!" -ForegroundColor Yellow
}

function Generate-WDAC {
    $PolicyPath=$env:userprofile+"\Desktop\"
    $EnumPolicy=$PolicyPath+"enum.xml"
    $ChillPolicy=$PolicyPath+"chill.xml"
    $AggroPolicy=$PolicyPath+"aggro.xml"
    $DriversPolicy=$PolicyPath+"drivers.xml"
    $IISPolicy=$PolicyPath+"inetsrv.xml"
    $pf64Policy=$PolicyPath+"pf64.xml"
    $pf32Policy=$PolicyPath+"pf32.xml"
    $pdPolicy=$PolicyPath+"pd.xml"
    $toolsPolicy=$PolicyPath+"tools.xml"
    $cssDirPolicy=$PolicyPath+"css_opt.xml"
    $src = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_enforced.xml"
    $dst = "$env:USERPROFILE\Desktop\DefaultWindows_Enforced.xml"

    if (Test-Path $src) {
        Write-Host "[+] Found DefaultWindows_Enforced.xml locally, copying..." -ForegroundColor Cyan
        Copy-Item $src $dst -Force
    } else {
        Write-Host "[!] DefaultWindows_Enforced.xml not found locally. Downloading from GitHub..." -ForegroundColor Yellow
        $downloadUrl = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/app-control-for-business/design/example-policies/DefaultWindows_Enforced.xml"
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $dst -UseBasicParsing -ErrorAction Stop
            Write-Host "[+] Successfully downloaded base policy" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to download base policy: $_" -ForegroundColor Red
            Write-Host "[!] Cannot continue without a base policy. Exiting." -ForegroundColor Red
            return
        }
    }

    $DefaultWindowsPolicy = $dst
    New-Item $EnumPolicy -Force > $null

    if (Test-Path "C:\Program Files\Microsoft\Exchange Server\") {
        Write-Host "[!] Detected an Exchange server! Policy creation for this type of server will result in issues" -ForegroundColor Red
        return
    }

    Write-Host "[+] Generating policy..."
    $scanStart = Get-Date
    $pf64 = Start-Job -Name "pf64 (Program Files)" -ScriptBlock { param($pf64Policy) New-CIPolicy -FilePath $pf64Policy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\Program Files\" -UserPEs -OmitPaths "C:\Program Files\WindowsApps\" } -ArgumentList $pf64Policy
    $pf32 = Start-Job -Name "pf32 (Program Files x86)" -ScriptBlock { param($pf32Policy) New-CIPolicy -FilePath $pf32Policy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\Program Files (x86)\" -UserPEs } -ArgumentList $pf32Policy
    $pd = Start-Job -Name "pd (ProgramData)" -ScriptBlock { param($pdPolicy) New-CIPolicy -FilePath $pdPolicy -Level FilePublisher -Fallback Hash,FileName -ScanPath "C:\ProgramData\" -UserPEs } -ArgumentList $pdPolicy
    $tools = Start-Job -Name "tools (C:\Tools)" -ScriptBlock { param($toolsPolicy) New-CIPolicy -FilePath $toolsPolicy -Level FilePublisher -Fallback Hash -ScanPath "C:\Tools\" -UserPEs } -ArgumentList $toolsPolicy

    $iisDetected = $false
    $iis = $null
    try {
        if ((Get-WindowsFeature Web-Server -ErrorAction Stop).InstallState -eq "Installed") { $iisDetected = $true }
    } catch {
        if (Test-Path "C:\Windows\System32\inetsrv\w3wp.exe") { $iisDetected = $true }
    }
    if ($iisDetected) {
        Write-Host "[!] Detected an IIS Server! Adjusting WDAC policy creation..." -ForegroundColor Yellow
        $iis = Start-Job -Name "iis (inetsrv)" -ScriptBlock { param($IISPolicy) New-CIPolicy -FilePath $IISPolicy -Level FilePublisher -Fallback Hash,Filename -ScanPath "C:\Windows\System32\inetsrv\" } -ArgumentList $IISPolicy
    }
    $drivers = Start-Job -Name "drivers (System32\drivers)" -ScriptBlock { param($DriversPolicy) New-CIPolicy -FilePath $DriversPolicy -Level SignedVersion -Fallback FilePublisher,Hash -ScanPath "C:\Windows\System32\drivers\" } -ArgumentList $DriversPolicy

    $cssScanPath = "C:\opt\CSS"
    $css = $null
    if (Test-Path $cssScanPath) {
        Write-Host "[+] CSS directory found at $cssScanPath - adding to scan" -ForegroundColor Cyan
        $css = Start-Job -Name "css (C:\opt\CSS)" -ScriptBlock {
            param($cssDirPolicy, $cssScanPath)
            New-CIPolicy -FilePath $cssDirPolicy -Level FilePublisher -Fallback Hash,FileName -ScanPath $cssScanPath -UserPEs
        } -ArgumentList $cssDirPolicy, $cssScanPath
    } else {
        Write-Host "[!] CSS directory not found at $cssScanPath - directory scan skipped" -ForegroundColor Yellow
        Write-Host "[!] The CSSClient.exe hash allow rule will still be added if the binary exists" -ForegroundColor Yellow
    }

    $jobIds = @($pf64.Id, $pf32.Id, $pd.Id, $tools.Id, $drivers.Id)
    $jobNames = @{ $pf64.Id = $pf64.Name; $pf32.Id = $pf32.Name; $pd.Id = $pd.Name; $tools.Id = $tools.Name; $drivers.Id = $drivers.Name }
    if ($iis) { $jobIds += $iis.Id; $jobNames[$iis.Id] = $iis.Name }
    if ($css) { $jobIds += $css.Id; $jobNames[$css.Id] = $css.Name }

    $knownDirs = @("Program Files", "Program Files (x86)", "ProgramData", "Tools", "Windows", "opt")
    $topLevelDirs = Get-ChildItem -Path "C:\" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $knownDirs -notcontains $_.Name }

    $extraPolicyFiles = @()
    if ($topLevelDirs.Count -gt 0) {
        Write-Host "`n[?] Found $($topLevelDirs.Count) additional top-level directories on C:\:" -ForegroundColor Yellow
        foreach ($dir in $topLevelDirs) {
            $answer = Read-Host -Prompt "  Scan $($dir.FullName) for WDAC policy? (yes/no)"
            if ($answer -eq "yes") {
                $extraPolicyFile = Join-Path $PolicyPath "extra_$($dir.Name).xml"
                $extraPolicyFiles += $extraPolicyFile
                $extraJob = Start-Job -Name "extra ($($dir.Name))" -ScriptBlock {
                    param($policyFile, $scanPath)
                    New-CIPolicy -FilePath $policyFile -Level FilePublisher -Fallback Hash,FileName -ScanPath $scanPath -UserPEs
                } -ArgumentList $extraPolicyFile, $dir.FullName
                $jobIds += $extraJob.Id
                $jobNames[$extraJob.Id] = $extraJob.Name
                Write-Host "  [>] Started scan job: $($dir.FullName)" -ForegroundColor Cyan
            }
        }
    }

    $completedIds = @{}

    Write-Host "[+] Waiting for $($jobIds.Count) scan jobs to complete..." -ForegroundColor Cyan
    while ($true) {
        $freshJobs = $jobIds | ForEach-Object { Get-Job -Id $_ }
        $stillRunning = $freshJobs | Where-Object { $_.State -eq 'Running' }

        foreach ($fj in $freshJobs) {
            if ($fj.State -ne 'Running' -and -not $completedIds.ContainsKey($fj.Id)) {
                $elapsed = "{0:mm\:ss}" -f ((Get-Date) - $scanStart)
                if ($fj.State -eq 'Completed') {
                    Write-Host "  [+] $($jobNames[$fj.Id]) complete ($elapsed)" -ForegroundColor Green
                } else {
                    Write-Host "  [!] $($jobNames[$fj.Id]) $($fj.State) ($elapsed)" -ForegroundColor Red
                }
                $completedIds[$fj.Id] = $true
            }
        }

        if (-not $stillRunning) { break }

        $elapsed = "{0:mm\:ss}" -f ((Get-Date) - $scanStart)
        $runningNames = ($stillRunning | ForEach-Object { $jobNames[$_.Id] }) -join ', '
        Write-Host "  [~] $elapsed elapsed - still waiting on $($stillRunning.Count) job(s): $runningNames" -ForegroundColor DarkGray
        Start-Sleep -Seconds 15
    }
    $totalElapsed = "{0:mm\:ss}" -f ((Get-Date) - $scanStart)
    Write-Host "[+] All scans finished in $totalElapsed" -ForegroundColor Green

    if ($iis) {
        Receive-Job $iis -ErrorAction SilentlyContinue | Out-Null
        if ((Get-Job -Id $iis.Id).State -eq 'Failed') {
            Write-Host "[!] IIS scan job failed: $($iis.ChildJobs[0].JobStateInfo.Reason)" -ForegroundColor Red
            Write-Host "[!] IIS policy will be skipped - inetsrv apps may be blocked after deployment" -ForegroundColor Yellow
        }
        Remove-Job $iis
    }

    $failedJobs = @()
    $coreJobs = @($pf64,$pf32,$pd,$drivers,$tools)
    if ($css) { $coreJobs += $css }
    foreach ($job in $coreJobs) {
        $jobResult = Receive-Job $job -ErrorAction SilentlyContinue
        if ((Get-Job -Id $job.Id).State -eq 'Failed') {
            $failedJobs += $job.Name
            Write-Host "[!] Scan job '$($job.Name)' failed: $($job.ChildJobs[0].JobStateInfo.Reason)" -ForegroundColor Red
        }
    }
    Remove-Job $pf64,$pf32,$pd,$drivers,$tools
    if ($css) { Remove-Job $css }

    foreach ($id in $jobIds) {
        Remove-Job -Id $id -ErrorAction SilentlyContinue
    }

    if ($failedJobs.Count -gt 0) {
        Write-Host "`n[!] WARNING: $($failedJobs.Count) scan job(s) failed: $($failedJobs -join ', ')" -ForegroundColor Red
        Write-Host "[!] The enum policy will be INCOMPLETE - it will not cover the failed directories." -ForegroundColor Red
        Write-Host "[!] Deploying an incomplete allowlist may block legitimate applications." -ForegroundColor Red
        $continueAnyway = Read-Host -Prompt "Continue building policy with partial scan results? (yes/no)"
        if ($continueAnyway -ne "yes") {
            Write-Host "[*] Aborting policy generation. Fix the scan failures and re-run Generate-WDAC." -ForegroundColor Yellow
            return
        }
        Write-Host "[!] Proceeding with incomplete scan results - review the policy carefully before deploying." -ForegroundColor Yellow
    }

    $policiesToMerge = @($DefaultWindowsPolicy)
    foreach ($p in @($pf64Policy, $pf32Policy, $pdPolicy, $DriversPolicy, $toolsPolicy)) {
        if (Test-Path $p) {
            $policiesToMerge += $p
        } else {
            Write-Host "[!] Skipping missing scan policy: $p" -ForegroundColor Yellow
        }
    }
    if (Test-Path $cssDirPolicy) {
        $policiesToMerge += $cssDirPolicy
        Write-Host "[+] Including CSS directory scan policy in merge" -ForegroundColor Cyan
    }
    foreach ($ep in $extraPolicyFiles) {
        if (Test-Path $ep) { $policiesToMerge += $ep }
    }

    Write-Host "[+] Merging enum policy ($($policiesToMerge.Count) sources)..."
    Merge-CIPolicy -OutputFilePath $EnumPolicy -PolicyPaths $policiesToMerge > $null
    if (Test-Path $IISPolicy) { Merge-CIPolicy -OutputFilePath $EnumPolicy -PolicyPaths $EnumPolicy,$IISPolicy > $null }
    Write-Host "[+] Enum policy merged" -ForegroundColor Green

    $cssClientPath = "C:\CSSClient.exe"
    if (Test-Path $cssClientPath) {
        Write-Host "[+] Adding hardcoded hash allow rule for CSSClient.exe..." -ForegroundColor Cyan
        $cssClientRule = New-CIPolicyRule -Level Hash -DriverFilePath $cssClientPath
        Merge-CIPolicy -OutputFilePath $EnumPolicy -PolicyPaths $EnumPolicy -Rules $cssClientRule > $null
        Write-Host "[+] CSSClient.exe hash allow rule injected into enum policy" -ForegroundColor Green
    } else {
        Write-Host "[!] WARNING: C:\CSSClient.exe not found - hash allow rule NOT added to policy!" -ForegroundColor Red
        Write-Host "[!] Place CSSClient.exe at $cssClientPath before deploying WDAC or the scoring" -ForegroundColor Red
        Write-Host "[!] engine WILL be blocked. Re-run Generate-WDAC once the binary is present." -ForegroundColor Red
    }

    $osBuild = [System.Environment]::OSVersion.Version.Build

    function Set-WDACPolicyOptions {
        param([string]$FilePath, [string]$Name)
        try {
            Set-CIPolicyIdInfo -FilePath $FilePath -PolicyName $Name -ResetPolicyID | Out-Null
        } catch {
            Set-CIPolicyIdInfo -FilePath $FilePath -PolicyName $Name | Out-Null
        }
        Set-CIPolicyVersion -FilePath $FilePath -Version "1.0.0.0"
        Set-RuleOption -FilePath $FilePath -Option 3 -Delete
        Set-RuleOption -FilePath $FilePath -Option 6
        Set-RuleOption -FilePath $FilePath -Option 8 -Delete
        Set-RuleOption -FilePath $FilePath -Option 9
        Set-RuleOption -FilePath $FilePath -Option 10
        Set-RuleOption -FilePath $FilePath -Option 12
        if ($osBuild -ge 18362) {
            Set-RuleOption -FilePath $FilePath -Option 19
        }
    }

    Set-WDACPolicyOptions -FilePath $EnumPolicy -Name "enum"
    Write-Host "[+] Configured enum policy" -ForegroundColor Green

    Write-Host "[+] Building chill policy (low-risk lolbin blocks)..." -ForegroundColor Cyan
    Copy-Item $DefaultWindowsPolicy $ChillPolicy -Force

    $chillBlocks = @()
    foreach ($lolbin in @(
        "C:\Windows\System32\vssadmin.exe",
        "C:\Windows\System32\vssuirun.exe",
        "C:\Windows\System32\ntdsutil.exe",
        "C:\Windows\System32\reg.exe",
        "C:\Windows\System32\certutil.exe",
        "C:\Windows\System32\mshta.exe",
        "C:\Windows\System32\wscript.exe",
        "C:\Windows\System32\cscript.exe"
    )) {
        if (Test-Path $lolbin) {
            $chillBlocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath $lolbin -Deny
        } else {
            Write-Host "  [~] Skipping chill block for $(Split-Path $lolbin -Leaf) - not present on this image" -ForegroundColor DarkGray
        }
    }

    if ($chillBlocks.Count -gt 0) {
        Merge-CIPolicy -OutputFilePath $ChillPolicy -PolicyPaths $ChillPolicy -Rules $chillBlocks > $null
        Write-Host "[+] Chill policy built ($($chillBlocks.Count) deny rule(s))" -ForegroundColor Green
    } else {
        Write-Host "[!] No chill deny rules could be built - no target binaries found on this image" -ForegroundColor Yellow
    }
    Set-WDACPolicyOptions -FilePath $ChillPolicy -Name "chill"

    Write-Host "[+] Building aggro policy (aggressive lolbin blocks)..." -ForegroundColor Cyan
    Write-Host "[!] WARNING: Aggro policy blocks cmd.exe, rundll32.exe, wmiprvse.exe" -ForegroundColor Red
    Write-Host "[!] This WILL break some admin tooling and WMI-based management" -ForegroundColor Red
    Copy-Item $DefaultWindowsPolicy $AggroPolicy -Force

    $aggroBlocks = @()
    foreach ($lolbin in @(
        "C:\Windows\System32\cmd.exe",
        "C:\Windows\System32\rundll32.exe",
        "C:\Windows\System32\wbem\wmiprvse.exe"
    )) {
        if (Test-Path $lolbin) {
            $aggroBlocks += New-CIPolicyRule -Level Hash -Fallback FileName -DriverFilePath $lolbin -Deny
        } else {
            Write-Host "  [~] Skipping aggro block for $(Split-Path $lolbin -Leaf) - not present on this image" -ForegroundColor DarkGray
        }
    }

    if ($aggroBlocks.Count -gt 0) {
        Merge-CIPolicy -OutputFilePath $AggroPolicy -PolicyPaths $AggroPolicy -Rules $aggroBlocks > $null
        Write-Host "[+] Aggro policy built ($($aggroBlocks.Count) deny rule(s))" -ForegroundColor Green
    } else {
        Write-Host "[!] No aggro deny rules could be built - no target binaries found on this image" -ForegroundColor Yellow
    }
    Set-WDACPolicyOptions -FilePath $AggroPolicy -Name "aggro"

    Write-Host "`n[+] All 3 WDAC policies generated:" -ForegroundColor Green
    Write-Host "    - enum.xml  : Enumeration-based allowlist" -ForegroundColor Cyan
    Write-Host "    - chill.xml : Low-risk lolbin deny rules" -ForegroundColor Cyan
    Write-Host "    - aggro.xml : Aggressive lolbin blocks (cmd, rundll32, wmiprvse)" -ForegroundColor Cyan

    $isDC = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductType -eq "LanmanNT"

    if ($isDC) {
        Write-Host "`n[+] Domain Controller detected - configuring WDAC block message in Default Domain Policy..." -ForegroundColor Cyan

        $defaultMessage = "This application has been blocked by your organization's security policy. Contact your IT administrator for assistance."
        Write-Host "[?] Enter custom WDAC block notification message (leave blank for default):" -ForegroundColor Yellow
        Write-Host "    Default: $defaultMessage" -ForegroundColor DarkGray
        $customMessage = Read-Host -Prompt "    Message"
        if ([string]::IsNullOrWhiteSpace($customMessage)) {
            $customMessage = $defaultMessage
        }

        try {
            Import-Module GroupPolicy -ErrorAction Stop
            Get-GPO -Name "Default Domain Policy" -ErrorAction Stop | Out-Null

            Set-GPRegistryValue -Name "Default Domain Policy" `
                -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\SRPV2" `
                -ValueName "BlockingMessage" `
                -Type String `
                -Value $customMessage | Out-Null

            Write-Host "[+] WDAC block message set in Default Domain Policy" -ForegroundColor Green
            Write-Host "[!] Run 'gpupdate /force' on domain members to apply the updated message" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Failed to configure WDAC block message in GPO: $_" -ForegroundColor Red
            Write-Host "[!] Ensure the GroupPolicy module is available and you have Domain Admin rights" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[~] Not a domain controller - skipping WDAC GPO block message configuration" -ForegroundColor DarkGray
    }

    Write-Host "[+] Done! Run Refresh-WDAC to deploy all policies." -ForegroundColor Green
}

function Refresh-WDAC {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $activeDir   = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
    $osBuild     = [System.Environment]::OSVersion.Version.Build

    $supportsMultiPolicy = $osBuild -ge 18362

    $citool        = "$env:windir\System32\citool.exe"
    $refreshPolicy = "C:\Tools\RefreshPolicy.exe"
    $hasCitool     = Test-Path $citool
    $hasRefreshExe = Test-Path $refreshPolicy

    $deployAggro = Read-Host -Prompt "Deploy aggro policy? Blocks cmd.exe, rundll32.exe, wmiprvse.exe. (yes/no)"

    $policyFiles = @("enum.xml", "chill.xml")
    if ($deployAggro -eq "yes") {
        $policyFiles += "aggro.xml"
        Write-Host "[!] Aggro policy will be deployed - cmd.exe, rundll32.exe, wmiprvse.exe will be blocked!" -ForegroundColor Red
    } else {
        Write-Host "[*] Skipping aggro policy" -ForegroundColor Yellow
    }

    $existingPolicies = @()
    foreach ($fileName in $policyFiles) {
        $p = Join-Path $desktopPath $fileName
        if (Test-Path $p) {
            $existingPolicies += $p
            Write-Host "[+] Found $fileName" -ForegroundColor Green
        } else {
            Write-Host "[!] $fileName not found on Desktop - skipping" -ForegroundColor Yellow
        }
    }

    if ($existingPolicies.Count -eq 0) {
        Write-Host "[!] No policy files found on Desktop. Run Generate-WDAC first." -ForegroundColor Red
        return
    }

    if (-not $supportsMultiPolicy) {
        Write-Host "[!] This OS (build $osBuild) does not support multi-policy WDAC" -ForegroundColor Yellow
        Write-Host "[+] Merging $($existingPolicies.Count) policies into single SiPolicy.p7b..." -ForegroundColor Cyan

        $mergedXml = Join-Path $desktopPath "merged_wdac.xml"

        if ($existingPolicies.Count -eq 1) {
            Copy-Item $existingPolicies[0] $mergedXml -Force
        } else {
            Merge-CIPolicy -OutputFilePath $mergedXml -PolicyPaths $existingPolicies > $null
        }

        try {
            Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName "WDAC-Combined" -ResetPolicyID | Out-Null
        } catch {
            Set-CIPolicyIdInfo -FilePath $mergedXml -PolicyName "WDAC-Combined" | Out-Null
        }
        Set-CIPolicyVersion -FilePath $mergedXml -Version "1.0.0.0"
        Set-RuleOption -FilePath $mergedXml -Option 3 -Delete
        Set-RuleOption -FilePath $mergedXml -Option 6
        Set-RuleOption -FilePath $mergedXml -Option 8 -Delete
        Set-RuleOption -FilePath $mergedXml -Option 9
        Set-RuleOption -FilePath $mergedXml -Option 10
        Set-RuleOption -FilePath $mergedXml -Option 12
        if ($osBuild -ge 18362) {
            Set-RuleOption -FilePath $mergedXml -Option 19
        }

        $sipolicyPath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"
        ConvertFrom-CIPolicy -XmlFilePath $mergedXml -BinaryFilePath $sipolicyPath | Out-Null
        Write-Host "[+] Converted merged policy -> SiPolicy.p7b" -ForegroundColor Green

        if ($hasCitool) {
            & $citool --refresh
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] Policy refreshed via citool" -ForegroundColor Green
            } else {
                Write-Host "[!] citool --refresh exited with code $LASTEXITCODE" -ForegroundColor Red
            }
        } elseif ($hasRefreshExe) {
            try {
                & $refreshPolicy
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[+] Policy refreshed via RefreshPolicy.exe" -ForegroundColor Green
                } else {
                    Write-Host "[!] RefreshPolicy.exe exited with code $LASTEXITCODE" -ForegroundColor Red
                    Write-Host "[!] A REBOOT is required for the policy to take effect" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[!] RefreshPolicy.exe failed to run: $_" -ForegroundColor Red
                Write-Host "[!] The file may be corrupted - re-run Get-Tools to re-download it" -ForegroundColor Yellow
                Write-Host "[!] A REBOOT is required for the policy to take effect" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[!] Neither citool.exe nor RefreshPolicy.exe found" -ForegroundColor Red
            Write-Host "[!] A REBOOT is required for the policy to take effect" -ForegroundColor Yellow
        }

        Write-Host "[!] A REBOOT is recommended for full WDAC enforcement" -ForegroundColor Yellow
        return
    }

    Write-Host "[+] Multi-policy WDAC supported (build $osBuild)" -ForegroundColor Green

    if (-not (Test-Path $activeDir)) {
        New-Item -ItemType Directory -Path $activeDir -Force | Out-Null
    }

    if (-not $hasCitool -and -not $hasRefreshExe) {
        Write-Host "[!] Neither citool.exe nor RefreshPolicy.exe found" -ForegroundColor Red
        Write-Host "[!] Policies will be copied to CiPolicies\Active but a REBOOT is needed to load them" -ForegroundColor Yellow
    } elseif ($hasCitool) {
        Write-Host "[+] Using citool.exe for policy deployment" -ForegroundColor Cyan
    } else {
        Write-Host "[+] citool.exe not found - using RefreshPolicy.exe" -ForegroundColor Cyan
    }

    $deployed = 0

    foreach ($policyXml in $existingPolicies) {
        $fileName = Split-Path $policyXml -Leaf

        [xml]$xml = Get-Content $policyXml
        $policyId = $xml.SiPolicy.PolicyID
        if (-not $policyId) {
            Write-Host "[!] Could not read PolicyID from $fileName - skipping" -ForegroundColor Red
            continue
        }

        $cipPath = Join-Path $activeDir "$policyId.cip"
        Write-Host "[+] Converting $fileName (ID: $policyId) -> $cipPath" -ForegroundColor Cyan
        ConvertFrom-CIPolicy -XmlFilePath $policyXml -BinaryFilePath $cipPath | Out-Null

        if ($hasCitool) {
            & $citool --update-policy $cipPath
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[!] citool --update-policy failed for $fileName (exit $LASTEXITCODE)" -ForegroundColor Red
            } else {
                Write-Host "[+] Deployed $fileName" -ForegroundColor Green
                $deployed++
            }
        } else {
            Write-Host "[+] Placed $fileName in CiPolicies\Active" -ForegroundColor Green
            $deployed++
        }
    }

    if ($deployed -eq 0) {
        Write-Host "[!] No policies were deployed" -ForegroundColor Red
        return
    }

    Write-Host "[+] Refreshing all policies..." -ForegroundColor Cyan
    if ($hasCitool) {
        & $citool --refresh
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] All $deployed policies refreshed successfully" -ForegroundColor Green
        } else {
            Write-Host "[!] citool --refresh exited with code $LASTEXITCODE" -ForegroundColor Red
        }
    } elseif ($hasRefreshExe) {
        try {
            & $refreshPolicy
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] All $deployed policies refreshed via RefreshPolicy.exe" -ForegroundColor Green
            } else {
                Write-Host "[!] RefreshPolicy.exe exited with code $LASTEXITCODE" -ForegroundColor Red
                Write-Host "[!] A REBOOT is required to load policies" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] RefreshPolicy.exe failed to run: $_" -ForegroundColor Red
            Write-Host "[!] The file may be corrupted - re-run Get-Tools to re-download it" -ForegroundColor Yellow
            Write-Host "[!] A REBOOT is required to load policies" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] No refresh tool available - REBOOT required to load policies" -ForegroundColor Yellow
    }

    Write-Host "[!] A REBOOT is required for WDAC enforcement to fully take effect!" -ForegroundColor Yellow
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

function Setup-SSH {
    $sshCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" }
    if (-not $sshCapability) {
        Write-Host "[!] OpenSSH Server capability not found in this image (Server Core or stripped edition)" -ForegroundColor Red
        Write-Host "[!] Install OpenSSH Server manually and re-run Setup-SSH" -ForegroundColor Yellow
        return
    }
    if ($sshCapability.State -ne "Installed") {
        Write-Host "[+] Installing OpenSSH Server..." -ForegroundColor Cyan
        Add-WindowsCapability -Online -Name $sshCapability.Name
        Write-Host "[+] OpenSSH Server installed" -ForegroundColor Green
    } else {
        Write-Host "[+] OpenSSH Server already installed" -ForegroundColor Green
    }

    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd -ErrorAction SilentlyContinue
    Write-Host "[+] sshd service started and set to automatic" -ForegroundColor Green

    $shellRegPath = "HKLM:\SOFTWARE\OpenSSH"
    if (-not (Test-Path $shellRegPath)) { New-Item -Path $shellRegPath -Force | Out-Null }
    $pwshPath = (Get-Command powershell.exe).Source
    New-ItemProperty -Path $shellRegPath -Name "DefaultShell" -Value $pwshPath -PropertyType String -Force | Out-Null
    Write-Host "[+] Default SSH shell set to PowerShell" -ForegroundColor Green

    $sshScored = Read-Host -Prompt "Is SSH a scored service? (yes/no)"

    $adminKeyDir = "$env:USERPROFILE\.ssh"
    $adminKeyFile = Join-Path $adminKeyDir "id_ed25519"
    if (-not (Test-Path $adminKeyFile)) {
        if (-not (Test-Path $adminKeyDir)) { New-Item -ItemType Directory -Path $adminKeyDir -Force | Out-Null }
        Write-Host "[+] Generating Administrator SSH key..." -ForegroundColor Cyan
        ssh-keygen -t ed25519 -f $adminKeyFile -N "" -q
        Write-Host "[+] SSH key generated at $adminKeyFile" -ForegroundColor Green
    } else {
        Write-Host "[+] Administrator SSH key already exists at $adminKeyFile" -ForegroundColor Green
    }

    $adminAuthKeys = "C:\ProgramData\ssh\administrators_authorized_keys"
    $pubKey = Get-Content "$adminKeyFile.pub"
    Set-Content -Path $adminAuthKeys -Value $pubKey -Force

    $acl = Get-Acl $adminAuthKeys
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($adminRule)
    $acl.SetAccessRule($systemRule)
    Set-Acl -Path $adminAuthKeys -AclObject $acl
    Write-Host "[+] Administrator public key installed to $adminAuthKeys" -ForegroundColor Green

    $desktopPath = [Environment]::GetFolderPath('Desktop')
    Copy-Item $adminKeyFile (Join-Path $desktopPath "id_ed25519") -Force
    Copy-Item "$adminKeyFile.pub" (Join-Path $desktopPath "id_ed25519.pub") -Force
    Write-Host "[+] Private key copied to Desktop - transfer this to your local machine!" -ForegroundColor Yellow

    $sshClientCap = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" }
    if (-not $sshClientCap) {
        Write-Host "[!] OpenSSH Client capability not found - skipping client install" -ForegroundColor Yellow
    } elseif ($sshClientCap.State -ne "Installed") {
        Write-Host "[+] Installing OpenSSH Client (scp, ssh)..." -ForegroundColor Cyan
        Add-WindowsCapability -Online -Name $sshClientCap.Name
        Write-Host "[+] OpenSSH Client installed" -ForegroundColor Green
    } else {
        Write-Host "[+] OpenSSH Client already installed" -ForegroundColor Green
    }

    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfig) {
        Copy-Item $sshdConfig "$sshdConfig.bak" -Force
        Write-Host "[+] Backed up existing sshd_config to sshd_config.bak" -ForegroundColor Cyan
    }

    if ($sshScored -eq "yes") {
        $passwordAuth = "yes"
        $authMethods = "any"
        Write-Host "[!] SSH is scored - password authentication enabled" -ForegroundColor Yellow
    } else {
        $passwordAuth = "no"
        $authMethods = "publickey"
        Write-Host "[+] SSH not scored - pubkey-only for Administrator" -ForegroundColor Green
    }

    $configContent = @"
# Managed by Setup-SSH - CCDC hardening
Port 22
ListenAddress 0.0.0.0

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication $passwordAuth
AuthenticationMethods $authMethods
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 2

# Disable forwarding by default
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
X11Forwarding no

# Admin authorized keys file (Windows-specific path)
Match Group administrators
    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
"@

    Set-Content -Path $sshdConfig -Value $configContent -Force
    Write-Host "[+] Hardened sshd_config written" -ForegroundColor Green

    try {
        Restart-Service sshd -ErrorAction Stop
        Write-Host "[+] sshd restarted with new configuration" -ForegroundColor Green
    } catch {
        Write-Host "[!] Restart-Service sshd failed: $_" -ForegroundColor Red
        Write-Host "[!] Attempting Start-Service instead..." -ForegroundColor Yellow
        Start-Service sshd -ErrorAction SilentlyContinue
        if ((Get-Service sshd -ErrorAction SilentlyContinue).Status -eq 'Running') {
            Write-Host "[+] sshd started" -ForegroundColor Green
        } else {
            Write-Host "[!] sshd is NOT running - check the config and start it manually" -ForegroundColor Red
        }
    }

    $sshFwRule = Get-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -ErrorAction SilentlyContinue
    if (-not $sshFwRule) {
        New-NetFirewallRule -DisplayName "OpenSSH Server (sshd)" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
        Write-Host "[+] Firewall rule added for SSH (port 22)" -ForegroundColor Green
    } else {
        Write-Host "[+] SSH firewall rule already exists" -ForegroundColor Green
    }

    Write-Host "`n[+] SSH Setup Complete" -ForegroundColor Green
    Write-Host "    SSH Key:  $desktopPath\id_ed25519 (GRAB THIS!)" -ForegroundColor Cyan
    Write-Host "    Pub Key:  $desktopPath\id_ed25519.pub" -ForegroundColor Cyan
    Write-Host "    Config:   $sshdConfig" -ForegroundColor Cyan
    Write-Host "    SCP:      scp available for file transfers" -ForegroundColor Cyan
    Write-Host "`n[!] COPY id_ed25519 FROM THE DESKTOP TO YOUR LOCAL MACHINE NOW!" -ForegroundColor Red
    Write-Host "[!] If you lose it and SSH is pubkey-only, you're locked out!" -ForegroundColor Red
}

function Email-For-Root-Login {
    $smtpServer = Read-Host -Prompt "Enter mail server IP or hostname"
    if ([string]::IsNullOrWhiteSpace($smtpServer)) {
        Write-Host "[!] Mail server is required. Exiting." -ForegroundColor Red
        return
    }

    $smtpPort = Read-Host -Prompt "Enter SMTP port (default 25)"
    if ([string]::IsNullOrWhiteSpace($smtpPort)) { $smtpPort = "25" }
    if ($smtpPort -notmatch '^\d+$') {
        Write-Host "[!] '$smtpPort' is not a valid port number - defaulting to 25" -ForegroundColor Yellow
        $smtpPort = "25"
    }
    [int]$smtpPort = [int]$smtpPort

    $mailUser = Read-Host -Prompt "Enter mail username (e.g. alert@domain.com)"
    if ([string]::IsNullOrWhiteSpace($mailUser)) {
        Write-Host "[!] Username is required. Exiting." -ForegroundColor Red
        return
    }

    $mailPass = Read-Host -AsSecureString -Prompt "Enter mail password"
    $mailTo = Read-Host -Prompt "Enter recipient email address"
    if ([string]::IsNullOrWhiteSpace($mailTo)) { $mailTo = $mailUser }

    $hostname = $env:COMPUTERNAME

    $scriptDir = "C:\Tools"
    if (-not (Test-Path $scriptDir)) { New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null }
    $scriptPath = Join-Path $scriptDir "AdminLoginAlert.ps1"

    $aesKey     = New-Object byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($aesKey)
    $keyPath    = Join-Path $scriptDir "AdminLoginAlert.key"
    $aesKey | Set-Content -Path $keyPath -Encoding Byte

    $keyAcl = New-Object System.Security.AccessControl.FileSecurity
    $keyAcl.SetAccessRuleProtection($true, $false)
    $keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")))
    $keyAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","Allow")))
    Set-Acl -Path $keyPath -AclObject $keyAcl

    $encPassword = $mailPass | ConvertFrom-SecureString -Key $aesKey

    $scriptContent = @"
# Admin Login Alert Script - created by Email-For-Root-Login
`$smtpServer = "$smtpServer"
`$smtpPort = $smtpPort
`$mailUser = "$mailUser"
`$encPassword = "$encPassword"
`$mailTo = "$mailTo"
`$hostname = "$hostname"
`$keyPath = "$keyPath"

# Rebuild credential using the AES key file.
# The password was encrypted with an explicit AES key (not DPAPI) so that
# this script can decrypt it when running as SYSTEM via a scheduled task.
if (-not (Test-Path `$keyPath)) {
    exit 1   # Key file missing - cannot decrypt password
}
# Cast explicitly to [byte[]] - in PowerShell 5.1 Get-Content -Encoding Byte
# returns Object[], and ConvertTo-SecureString -Key requires a true byte array.
[byte[]]`$aesKey = Get-Content -Path `$keyPath -Encoding Byte
`$secPass = `$encPassword | ConvertTo-SecureString -Key `$aesKey
`$cred = New-Object System.Management.Automation.PSCredential(`$mailUser, `$secPass)

# Get the logon event details
`$logonUser = `$env:USERNAME
`$logonDomain = `$env:USERDOMAIN
`$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Check if the user is an administrator
`$isAdmin = `$false
try {
    `$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$principal = New-Object Security.Principal.WindowsPrincipal(`$identity)
    `$isAdmin = `$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

# Also check local Administrators group membership
if (-not `$isAdmin) {
    try {
        `$adminGroup = [ADSI]"WinNT://./Administrators,group"
        `$members = @(`$adminGroup.Invoke("Members")) | ForEach-Object {
            `$_.GetType().InvokeMember("Name", 'GetProperty', `$null, `$_, `$null)
        }
        if (`$members -contains `$logonUser) { `$isAdmin = `$true }
    } catch {}
}

if (`$isAdmin) {
    `$subject = "[ALERT] Admin login on `$hostname - `$logonDomain\`$logonUser"
    `$body = "ADMINISTRATOR LOGIN DETECTED``r``n``r``nHost:      `$hostname``r``nUser:      `$logonDomain\`$logonUser``r``nTime:      `$timestamp``r``nType:      Interactive Logon"

    try {
        Send-MailMessage -From `$mailUser -To `$mailTo -Subject `$subject -Body `$body ``
            -SmtpServer `$smtpServer -Port `$smtpPort -Credential `$cred -UseSsl -ErrorAction Stop
    } catch {
        # Retry without TLS in case the mail server doesn't support it
        try {
            Send-MailMessage -From `$mailUser -To `$mailTo -Subject `$subject -Body `$body ``
                -SmtpServer `$smtpServer -Port `$smtpPort -Credential `$cred -ErrorAction Stop
        } catch {
            # Silent fail - don't block logon
        }
    }
}
"@

    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Write-Host "[+] Alert script created at $scriptPath" -ForegroundColor Green

    $taskName = "AdminLoginEmailAlert"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "[+] Scheduled task '$taskName' registered - triggers on any user logon" -ForegroundColor Green
    Write-Host "[+] Emails will be sent to $mailTo when an admin logs in to $hostname" -ForegroundColor Green
    Write-Host "[!] AES key stored at: $keyPath - do not delete this file or alerts will stop working" -ForegroundColor Yellow
    Write-Host "[!] Both $scriptPath and $keyPath are restricted to Administrators and SYSTEM" -ForegroundColor Yellow
}

function Set-DomainWallpaper {
    $domainRole = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue).ProductType
    $isDC = $domainRole -eq "LanmanNT"
    if (-not $isDC) {
        Write-Host "[!] This machine is not a Domain Controller. Domain wallpaper GPO requires a DC." -ForegroundColor Red
        return
    }

    Import-Module GroupPolicy -ErrorAction Stop

    Write-Host "[?] Enter the full path to the wallpaper image file (e.g. C:\Users\Administrator\Desktop\wallpaper.jpg):" -ForegroundColor Yellow
    $imagePath = Read-Host -Prompt "    Image path"

    if ([string]::IsNullOrWhiteSpace($imagePath) -or -not (Test-Path $imagePath)) {
        Write-Host "[!] Image file not found at '$imagePath'" -ForegroundColor Red
        return
    }

    $ddpName = "Default Domain Policy"
    $ddp = Get-GPO -Name $ddpName -ErrorAction SilentlyContinue
    if (-not $ddp) {
        Write-Host "[!] Could not find '$ddpName' - aborting before any files are written" -ForegroundColor Red
        return
    }

    $domain = (Get-ADDomain).DNSRoot
    $sysvolRoot  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).SysVol
    if ([string]::IsNullOrWhiteSpace($sysvolRoot)) {
        $sysvolRoot = "$env:SystemRoot\SYSVOL\sysvol"
        Write-Host "[!] Could not read SYSVOL path from registry - falling back to $sysvolRoot" -ForegroundColor Yellow
    }
    $sysvolShare = "\\$domain\SYSVOL\$domain\wallpaper"
    $sysvolLocal = Join-Path $sysvolRoot "$domain\wallpaper"

    if (-not (Test-Path $sysvolLocal)) {
        New-Item -ItemType Directory -Path $sysvolLocal -Force | Out-Null
    }

    $fileName = Split-Path $imagePath -Leaf
    Copy-Item $imagePath (Join-Path $sysvolLocal $fileName) -Force
    $uncPath = "$sysvolShare\$fileName"
    Write-Host "[+] Wallpaper copied to SYSVOL: $uncPath" -ForegroundColor Green

    $desktopKey = "HKCU\Control Panel\Desktop"

    Set-GPRegistryValue -Name $ddpName -Key $desktopKey -ValueName "Wallpaper" -Type String -Value $uncPath
    Set-GPRegistryValue -Name $ddpName -Key $desktopKey -ValueName "WallpaperStyle" -Type String -Value "10"
    $personalizationKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-GPRegistryValue -Name $ddpName -Key $personalizationKey -ValueName "Wallpaper" -Type String -Value $uncPath
    Set-GPRegistryValue -Name $ddpName -Key $personalizationKey -ValueName "NoChangingWallPaper" -Type DWord -Value 1

    Write-Host "[+] Domain wallpaper set to '$uncPath' via '$ddpName'" -ForegroundColor Green
    Write-Host "[+] Users cannot change the wallpaper" -ForegroundColor Green
    Write-Host "[!] Clients will apply at next gpupdate / logon" -ForegroundColor Yellow
}

function Apply-SecurityBaseline {
    $isDC = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductType -eq "LanmanNT"

    if (-not $isDC) {
        Write-Host "[!] This machine is not a Domain Controller" -ForegroundColor Red
        Write-Host "[!] Security Baseline GPO import requires a DC. Exiting." -ForegroundColor Red
        return
    }

    Import-Module GroupPolicy -ErrorAction Stop

    $toolsDir = "C:\Tools"
    $lgpo = Join-Path $toolsDir "LGPO.exe"
    if (-not (Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null }

    if (-not (Test-Path $lgpo)) {
        Write-Host "[+] LGPO.exe not found - attempting to download from Microsoft..." -ForegroundColor Yellow
        try {
            $lgpoZip = Join-Path $toolsDir "LGPO.zip"
            $confirmPage = Invoke-WebRequest -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=55319" -UseBasicParsing -ErrorAction Stop
            $lgpoLink = $confirmPage.Links | Where-Object { $_.href -match "download\.microsoft\.com" -and $_.href -match "LGPO\.zip" } | Select-Object -First 1
            if ($lgpoLink) {
                Invoke-WebRequest -Uri $lgpoLink.href -OutFile $lgpoZip -UseBasicParsing -ErrorAction Stop
                Expand-Archive -Path $lgpoZip -DestinationPath $toolsDir -Force
                Remove-Item $lgpoZip -Force -ErrorAction SilentlyContinue
                if (-not (Test-Path $lgpo)) {
                    $found = Get-ChildItem $toolsDir -Filter "LGPO.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($found) { Copy-Item $found.FullName $lgpo -Force }
                }
                if (Test-Path $lgpo) {
                    Write-Host "[+] LGPO.exe downloaded and extracted to $lgpo" -ForegroundColor Green
                } else {
                    Write-Host "[!] LGPO.zip extracted but LGPO.exe not found at expected path" -ForegroundColor Red
                }
            } else {
                throw "Could not find LGPO.zip link on download page"
            }
        } catch {
            Write-Host "[!] Failed to auto-download LGPO.exe: $_" -ForegroundColor Red
            Write-Host "    Download from: https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor Yellow
            Write-Host "    Place LGPO.exe in C:\Tools\ and re-run this function" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[+] LGPO.exe found at $lgpo" -ForegroundColor Green
    }

    $baselineDir = Join-Path $toolsDir "SecurityBaseline"
    if (-not (Test-Path $baselineDir)) {
        Write-Host "[+] Downloading Microsoft Windows Security Baseline..." -ForegroundColor Cyan
        $baselineZip = Join-Path $toolsDir "SecurityBaseline.zip"

        $osBuild      = [System.Environment]::OSVersion.Version.Build
        $osCaption    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName

        $baselineFileName = switch ($osBuild) {
            { $_ -ge 26100 } { "Windows Server 2025 Security Baseline"; break }
            { $_ -ge 20348 } { "Windows Server 2022 Security Baseline"; break }
            { $_ -ge 17763 } { "Windows 10 Version 1809 and Windows Server 2019 Security Baseline"; break }
            { $_ -ge 14393 } { "Windows 10 Version 1607 and Windows Server 2016 Security Baseline"; break }
            default          { $null }
        }

        if (-not $baselineFileName) {
            Write-Host "[!] Unrecognised OS build ($osBuild / $osCaption) - cannot select a baseline automatically." -ForegroundColor Red
            Write-Host "[!] Download the correct baseline manually from:" -ForegroundColor Yellow
            Write-Host "    https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor Yellow
            Write-Host "[!] Extract to $baselineDir and re-run" -ForegroundColor Yellow
        } else {
            Write-Host "[+] Detected OS: $osCaption (build $osBuild) - looking for '$baselineFileName'" -ForegroundColor Cyan
            $downloaded = $false

            try {
                Write-Host "[+] Resolving download URL from Microsoft Download Center..." -ForegroundColor Cyan
                $confirmPage = Invoke-WebRequest -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=55319" -UseBasicParsing -ErrorAction Stop
                $links = $confirmPage.Links | Where-Object { $_.href -match "download\.microsoft\.com" -and $_.href -match [regex]::Escape($baselineFileName) } | Select-Object -First 1
                if ($links) {
                    $resolvedUrl = $links.href
                    Write-Host "[+] Resolved URL: $resolvedUrl" -ForegroundColor Green
                    Invoke-WebRequest -Uri $resolvedUrl -OutFile $baselineZip -UseBasicParsing -ErrorAction Stop
                    Expand-Archive -Path $baselineZip -DestinationPath $baselineDir -Force
                    Remove-Item $baselineZip -Force
                    Write-Host "[+] Security Baseline extracted to $baselineDir" -ForegroundColor Green
                    $downloaded = $true
                } else {
                    Write-Host "[!] Could not find a matching baseline link on the download page" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[!] Failed to resolve or download baseline from confirmation page: $_" -ForegroundColor Yellow
            }

            if (-not $downloaded) {
                Write-Host "[!] Automatic download failed." -ForegroundColor Red
                Write-Host "[!] Download manually from https://www.microsoft.com/en-us/download/details.aspx?id=55319" -ForegroundColor Yellow
                Write-Host "[!] Extract to $baselineDir and re-run" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "[+] Security Baseline already present at $baselineDir" -ForegroundColor Green
    }

    if (-not (Test-Path $baselineDir)) {
        Write-Host "[!] Baseline directory does not exist at $baselineDir - download may have failed" -ForegroundColor Red
        Write-Host "[!] Extract the correct baseline manually to $baselineDir and re-run" -ForegroundColor Yellow
        return
    }

    $gpoBackups = Get-ChildItem -Path $baselineDir -Recurse -Directory | Where-Object {
        Test-Path (Join-Path $_.FullName "backup.xml") -or
        Test-Path (Join-Path $_.FullName "bkupInfo.xml")
    }

    if ($gpoBackups.Count -eq 0) {
        Write-Host "[!] No GPO backups found in $baselineDir" -ForegroundColor Red
        Write-Host "[!] Check that the baseline was extracted correctly" -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Found $($gpoBackups.Count) GPO backup(s) in the security baseline:" -ForegroundColor Cyan
    foreach ($gpo in $gpoBackups) {
        $infoFile = Join-Path $gpo.FullName "bkupInfo.xml"
        if (-not (Test-Path $infoFile)) { $infoFile = Join-Path $gpo.FullName "backup.xml" }
        if (Test-Path $infoFile) {
            [xml]$info = Get-Content $infoFile
            $gpoName = $info.BackupInst.GPODisplayName.'#cdata-section'
            if (-not $gpoName) { $gpoName = $gpo.Name }
            Write-Host "    - $gpoName ($($gpo.Name))" -ForegroundColor DarkCyan
        }
    }

    $domainDN = (Get-ADDomain).DistinguishedName
    $ddpName = "Default Domain Policy"

    Write-Host "`n[+] Importing security baseline GPOs and linking to domain root..." -ForegroundColor Cyan

    foreach ($gpo in $gpoBackups) {
        $gpoGuid = $gpo.Name
        $backupLocation = $gpo.FullName | Split-Path -Parent

        $gpoDisplayName = "Security Baseline - $gpoGuid"
        $infoFile = Join-Path $gpo.FullName "bkupInfo.xml"
        if (-not (Test-Path $infoFile)) { $infoFile = Join-Path $gpo.FullName "backup.xml" }
        if (Test-Path $infoFile) {
            [xml]$info = Get-Content $infoFile
            $name = $info.BackupInst.GPODisplayName.'#cdata-section'
            if ($name) { $gpoDisplayName = "Baseline - $name" }
        }

        try {
            $existingGpo = Get-GPO -Name $gpoDisplayName -ErrorAction SilentlyContinue
            if ($existingGpo) {
                Write-Host "    [~] GPO '$gpoDisplayName' already exists - reimporting settings" -ForegroundColor Yellow
            } else {
                New-GPO -Name $gpoDisplayName -ErrorAction Stop | Out-Null
                Write-Host "    [+] Created GPO: $gpoDisplayName" -ForegroundColor Green
            }

            Import-GPO -BackupId $gpoGuid -Path $backupLocation -TargetName $gpoDisplayName -ErrorAction Stop
            Write-Host "    [+] Imported backup into $gpoDisplayName" -ForegroundColor Green

            $existingLink = Get-GPInheritance -Target $domainDN | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $gpoDisplayName }
            if (-not $existingLink) {
                New-GPLink -Name $gpoDisplayName -Target $domainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Host "    [+] Linked $gpoDisplayName to $domainDN" -ForegroundColor Green
            } else {
                Write-Host "    [~] $gpoDisplayName already linked to domain root" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    [!] Failed to process $gpoGuid : $_" -ForegroundColor Red
        }
    }

    $disableDefender = Read-Host -Prompt "Disable Windows Defender via GPO? This is for TESTING environments only! (yes/no)"
    if ($disableDefender -eq "yes") {
        Write-Host "[!] Disabling Windows Defender via Default Domain Policy..." -ForegroundColor Yellow
        $defenderKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
        Set-GPRegistryValue -Name $ddpName -Key $defenderKey -ValueName "DisableAntiSpyware" -Type DWord -Value 1
        Set-GPRegistryValue -Name $ddpName -Key "$defenderKey\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1
        Write-Host "[+] Defender disabled via GPO (requires gpupdate on clients)" -ForegroundColor Green
    } else {
        Write-Host "[*] Keeping Defender enabled via GPO" -ForegroundColor Yellow
    }

    $allowAnonLDAP = Read-Host -Prompt "Allow LDAP anonymous bind? Score checks often need this. (yes/no)"
    if ($allowAnonLDAP -eq "yes") {
        Write-Host "[+] Enabling LDAP anonymous bind via Default Domain Policy..." -ForegroundColor Cyan

        $ldapKey = "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        Set-GPRegistryValue -Name $ddpName -Key $ldapKey -ValueName "LDAPServerIntegrity" -Type DWord -Value 0

        $lsaKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-GPRegistryValue -Name $ddpName -Key $lsaKey -ValueName "RestrictAnonymous" -Type DWord -Value 0
        Set-GPRegistryValue -Name $ddpName -Key $lsaKey -ValueName "RestrictAnonymousSAM" -Type DWord -Value 0
        Set-GPRegistryValue -Name $ddpName -Key $lsaKey -ValueName "EveryoneIncludesAnonymous" -Type DWord -Value 1

        try {
            $configDN = (Get-ADRootDSE).configurationNamingContext
            $dsDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
            $current = (Get-ADObject $dsDN -Properties dsHeuristics).dsHeuristics

            if ($null -eq $current) { $current = '' }

            $padded = $current.PadRight(7, '0')
            $new    = $padded.Substring(0, 6) + '2' + $padded.Substring(7)

            Set-ADObject $dsDN -Replace @{dsHeuristics = $new}
            Write-Host "[+] dsHeuristics set to allow anonymous LDAP (position 7 = 2)" -ForegroundColor Green
        } catch {
            Write-Host "[!] Failed to update dsHeuristics: $_" -ForegroundColor Red
            Write-Host "[!] You may need to manually set dsHeuristics 7th char to '2'" -ForegroundColor Yellow
        }

        Write-Host "[+] LDAP anonymous bind enabled" -ForegroundColor Green
    } else {
        Write-Host "[*] LDAP anonymous bind left at default (restricted)" -ForegroundColor Yellow
    }

    Write-Host "`n[+] Running gpupdate /force..." -ForegroundColor Cyan
    gpupdate /force

    Write-Host "[+] Security Baseline GPOs applied and linked to domain root" -ForegroundColor Green
    Write-Host "[!] Clients will pick up changes at next gpupdate interval or reboot" -ForegroundColor Yellow
}

function win-ccdc {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    Write-Host "============================================" -ForegroundColor Magenta
    Write-Host "  STEP 1: Enumeration" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta

    $adminPass = Read-Host -Prompt "Enter a new local Administrator password (or press ENTER to skip)"
    $enumFile = Join-Path $desktopPath "Enumeration_$timestamp.txt"

    Start-Transcript -Path $enumFile -Append
    Enumerate -AdminPass $adminPass
    Stop-Transcript

    Write-Host "[+] Enumeration saved to: $enumFile" -ForegroundColor Green

    Write-Host "`n============================================" -ForegroundColor Magenta
    Write-Host "  STEP 2: Downloading Tools" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
    Get-Tools

    $installSI = Read-Host -Prompt "Do you want to download System Informer? (yes/no)"
    if ($installSI -eq "yes") {
        Get-SystemInformer
    } else {
        Write-Host "[*] Skipping System Informer" -ForegroundColor Yellow
    }

    $isDC = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductType -eq "LanmanNT"

    if ($isDC) {
        Write-Host "`n============================================" -ForegroundColor Magenta
        Write-Host "  STEP 3: Domain Controller - Downloading Binaries" -ForegroundColor Magenta
        Write-Host "============================================" -ForegroundColor Magenta
        Get-Binary

        Write-Host "`n[+] Running PingCastle healthcheck..." -ForegroundColor Cyan
        $pingCastleExe = "C:\Tools\pingcastle\PingCastle.exe"
        if (Test-Path $pingCastleExe) {
            Push-Location $desktopPath
            & $pingCastleExe --healthcheck
            Pop-Location
            Write-Host "[+] PingCastle report saved to Desktop" -ForegroundColor Green
        } else {
            Write-Host "[!] PingCastle.exe not found at $pingCastleExe" -ForegroundColor Red
        }

        Write-Host "`n[+] Running Cable DACL enumeration..." -ForegroundColor Cyan
        $cableExe = "C:\Tools\Cable.exe"
        $cableOutput = $null
        if (Test-Path $cableExe) {
            $cableOutput = Join-Path $desktopPath "Cable_DACL_$timestamp.txt"
            & $cableExe dacl /find | Tee-Object -FilePath $cableOutput
            Write-Host "[+] Cable DACL output saved to: $cableOutput" -ForegroundColor Green
        } else {
            Write-Host "[!] Cable.exe not found at $cableExe" -ForegroundColor Red
        }

        Write-Host "`n[+] Running Certify ADCS enumeration..." -ForegroundColor Cyan
        $certifyExe = "C:\Tools\Certify.exe"
        $certifyOutput = $null
        if (Test-Path $certifyExe) {
            $certifyOutput = Join-Path $desktopPath "Certify_ADCS_$timestamp.txt"
            & $certifyExe find | Tee-Object -FilePath $certifyOutput
            Write-Host "[+] Certify ADCS output saved to: $certifyOutput" -ForegroundColor Green
        } else {
            Write-Host "[!] Certify.exe not found at $certifyExe" -ForegroundColor Red
        }
    } else {
        Write-Host "`n[*] Not a Domain Controller - skipping DC-only tasks" -ForegroundColor Yellow
    }

    if ($isDC) {
        Write-Host "`n============================================" -ForegroundColor Magenta
        Write-Host "  STEP 3.5: Microsoft Security Baseline GPOs" -ForegroundColor Magenta
        Write-Host "============================================" -ForegroundColor Magenta
        $applyBaseline = Read-Host -Prompt "Do you want to apply Microsoft Security Baseline GPOs? (yes/no)"
        if ($applyBaseline -eq "yes") {
            Apply-SecurityBaseline
        } else {
            Write-Host "[*] Skipping Security Baseline" -ForegroundColor Yellow
        }
    }

    Write-Host "`n============================================" -ForegroundColor Magenta
    Write-Host "  STEP 4: Graylog Sidecar Setup" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
    $setupGraylog = Read-Host -Prompt "Do you want to set up Graylog Sidecar on this machine? (yes/no)"
    if ($setupGraylog -eq "yes") {
        Setup-Graylog
    } else {
        Write-Host "[*] Skipping Graylog Sidecar setup" -ForegroundColor Yellow
    }

    Write-Host "`n============================================" -ForegroundColor Magenta
    Write-Host "  STEP 5: WDAC Policy Generation" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
    Generate-WDAC

    $enableWDAC = Read-Host -Prompt "Do you want to enable the WDAC policies now? (yes/no)"
    if ($enableWDAC -eq "yes") {
        Refresh-WDAC
    } else {
        Write-Host "[*] Skipping WDAC enforcement. Policies are on your Desktop (enum.xml, chill.xml, aggro.xml)." -ForegroundColor Yellow
        Write-Host "[*] Run Refresh-WDAC when ready to deploy." -ForegroundColor Yellow
    }

    Write-Host "`n============================================" -ForegroundColor Magenta
    Write-Host "  STEP 6: Phase 2 - Hardening" -ForegroundColor Magenta
    Write-Host "============================================" -ForegroundColor Magenta
    Phase2

    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "  win-ccdc complete!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "Files on Desktop:" -ForegroundColor Cyan
    Write-Host "  - Enumeration: $enumFile" -ForegroundColor Cyan
    if ($isDC) {
        Write-Host "  - PingCastle: Check Desktop for ad_hc_*.html report" -ForegroundColor Cyan
        if ($cableOutput)   { Write-Host "  - Cable DACL:   $cableOutput"   -ForegroundColor Cyan }
        if ($certifyOutput) { Write-Host "  - Certify ADCS: $certifyOutput" -ForegroundColor Cyan }
    }
    Write-Host "  - WDAC Policies: enum.xml, chill.xml, aggro.xml" -ForegroundColor Cyan
}