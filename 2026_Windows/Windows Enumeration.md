- [[Windows Enumeration#Operating System|Operating System]]
- [[Windows Enumeration#Users and Groups|Users and Groups]]
- [[Windows Enumeration#Network|Network]]
	- [[Windows Enumeration#Network Details|Network Details]]
	- [[Windows Enumeration#Listening and/or Established Connections|Listening and/or Established Connections]]
	- [[Windows Enumeration#DNS|DNS]]
	- [[Windows Enumeration#Shares|Shares]]
- [[Windows Enumeration#Processes|Processes]]
- [[Windows Enumeration#Triage|Triage]]
- [[Windows Enumeration#File System|File System]]
- [[Windows Enumeration#Installed Applications|Installed Applications]]
- [[Windows Enumeration#Services|Services]]
- [[Windows Enumeration#Persistence|Persistence]]
# Operating System
| Command            | Description                                    |
| ------------------ | ---------------------------------------------- |
| `systeminfo`       | OS and *most* network information              |
| `Get-ComputerInfo` | OS information                                 |
| `wmic qfe`         | (systeminfo gives the same) Hotfixes installed |
# Users and Groups
| Command                         | Description                                                 |
| ------------------------------- | ----------------------------------------------------------- |
| `net user`                      | List all local users                                        |
| `net user <USERNAME>`           | List all attributes of user - lists group membership        |
| `net user /domain`              | List all domain users                                       |
| `net localgroup`                | List all local groups                                       |
| `net localgroup Administrators` | List local administrator group                              |
| `net group`                     | (Can only run on DC)                                        |
| `Get-LocalUser`                 | List all local users and their account status + description |
| `Get-LocalGroup`                | List all local groups and their descriptions                |
# Network
## Network Details
| Command                         | Description                      |
| ------------------------------- | -------------------------------- |
| `ipconfig /all`                 | All network adapter details      |
| `Get-NetAdapter -IncludeHidden` | Find network adapters            |
| `Get-NetAdapter -Name "<NAME>"` | Get details on a network adapter |
## Listening and/or Established Connections
| Command                | Description                                       |
| ---------------------- | ------------------------------------------------- |
| `netstat -anob`        | List all network connections and list executables |
| `Get-NetTCPConnection` | List all TCP network connections                  |
## DNS
| Command                                      | Description                |
| -------------------------------------------- | -------------------------- |
| `Get-DnsClientServerAddress`                 | Show all DNS configuration |
| `type C:\Windows\System32\drivers\etc\hosts` | Show hosts file            |
## Shares
| Command                            | Description     |
| ---------------------------------- | --------------- |
| `net share`                        | List all shares |
| `Get-WmiObject -class Win32_Share` | List all shares |
# Processes
| Command                        | Description                                                 |
| ------------------------------ | ----------------------------------------------------------- |
| `ps`                           | List all processes                                          |
| `tasklist`                     | List all processes                                          |
| `tasklist /V`                  | List all processes with extra information in table format   |
| `Get-Process`                  | List all processes                                          |
| `Get-Process -IncludeUserName` | (Elevated PowerShell) Include user's name for all processes |
# Triage
| Command                                                                                 | Description         |
| --------------------------------------------------------------------------------------- | ------------------- |
| `[System.IO.Directory]::GetFiles("\\.\\pipe\\")`                                        | List named pipes    |
| `wmic process where '(processid=<PID>)' get 'processid,parentprocessid,executablepath'` | Get ppid of process |
# File System
| Command                               | Description                                                                      |
| ------------------------------------- | -------------------------------------------------------------------------------- |
| `dir [PATH]`                          | (CMD) list contents of directory                                                 |
| `dir /a [PATH]`                       | (CMD) list contents of directory and include hidden items                        |
| `dir /q /a [PATH]`                    | (CMD) list contents of directory, including ownership and hidden items           |
| `gci`                                 | (PowerShell)                                                                     |
| `gci [-Path "PATH"] -Force`           | (PowerShell) Include hidden files and system files                               |
| `gci [-Path "PATH"] -Include "*.txt"` | (PowerShell) filter for files with specific extension                            |
| `gci -Recurse`                        | (PowerShell) recurse through every directory and list all files                  |
| `ls`                                  | (PowerShell)                                                                     |
| `ls [-Path "PATH"] -Filter "*.txt"`   | (PowerShell) filter for files with specific extension                            |
| `tree "PATH" /F`                      | (CMD) recurse through the contents of a directory in a tree + print hidden files |
# Installed Applications
| Command                                                                | Description                                             |
| ---------------------------------------------------------------------- | ------------------------------------------------------- |
| `Get-Package \| sort \| Format-Table -AutoSize > out.txt`              | (Run as admin) get **ALL** software installed on system |
| `dir /a "C:\Program Files" "C:\Program Files (x86)"`                   | (CMD only) Find all top level program file directories  |
| `reg query HKEY_LOCAL_MACHINE\SOFTWARE`                                | (CMD) Find most installed applications                  |
| `Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE \| ft Name` | (PowerShell) Find most installed applications           |
| `Get-WmiObject -Class Win32_Product \| Format-Table`                   | Gets *most* installed applications and packages         |
| `Get-AppxPackage -AllUsers \| Select Name, PackageFullName`            | Gets *most* installed applications and packages         |
# Services
| Command                                                                                | Description                                                                 |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `Get-Service \| Format-Table -AutoSize`                                                | List all services (running, stopped, etc.)                                  |
| `Get-Service \| Format-Table -AutoSize \| findstr Running`                             | List only running services                                                  |
| `Get-Service \| Format-Table -AutoSize -Property StartType, Status, Name, DisplayName` | List ALL services and their start type                                      |
| `tasklist /v`                                                                          | (CMD Only) List running services - includes name, pid, status, and username |
| `tasklist /svc`                                                                        | List **running** services with Image, PID, and Services                     |
| `tasklist /FI "STATUS eq RUNNING"`                                                     | Show running services                                                       |
| `sc query`                                                                             | (CMD only) list all running services                                        |
| `net start`                                                                            | See services that have started                                              |
# Persistence
| Command                                                                                                                                                                                                                                                                                                                                                                                                                | Description             |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `reg query` \| `Get-ChildItem -Path Registry::`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`<br>`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`<br>`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager` | Runkeys                 |
| `dir /a "C:\Windows\System32\Tasks" ; dir /a "C:\Windows\Tasks"`                                                                                                                                                                                                                                                                                                                                                       | Startup Tasks           |
| `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`<br>`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`                                                                                                                                                                                                                                                                  | Startup Folder          |
| `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows`                                                                                                                                                                | Startup Programs        |
| `HKLM\System\CurrentControlSet\Services`<br>`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`<br>`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`<br>`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices`                                                 | Startup Services        |
| `Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer`<br>`Get-WMIObject -Namespace root\Subscription -Class __EventFilter`                                                                                                                                                                                                                                                                      | WMI Event Subscriptions |
