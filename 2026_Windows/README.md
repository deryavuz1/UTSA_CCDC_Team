This is where we store our 2026 Windows tools and utils.

## Description and Usage
- `AllowAll.xml` is a WDAC policy that allows everything for if we break something by accident during the hardening build.
- `CCDC.ps1` is the main enumeration and hardening script for Windows. This will be imported with ./ccdc.ps1 through Powershell and run by the command `win-ccdc` on most machines (potentially excluding web servers). The purpose of it is to enumerate the machine using default tools as well as Certify (if ADCS is present), PingCastle and Cable for DACL enumeration, then employ a custom WDAC policy to each machine with some lolbin blocking. This will also set some MS Defender ASR rules and perform more rudimentary hardening in the `Phase2` function for the script. There is also capability to perform bulk password resets and some GPO pushes such as desktop background changes.
- `oldCCDC.ps1` is a reduced version of the script above, and we would like to keep this for simplicity purposes in case functions do not behave properly.
- `sysmon-config.xml` is a custom Sysmon Config based on SwiftonSecurity's sysmon config but also has some additional rules like fileblockexecutables. We are planning to utilize this for hardening, monitoring and defense purposes on our workstations.
