This is our windows folder.

AllowAll.xml is a WDAC policy that allows everything for if I break something.

CCDC.ps1 is the main script for windows. I will primarily import the script with . ./ccdc.ps1 and then run the win-ccdc command on most every machine (maybe not webservers). This will enumerate the machine using default tools as well as Certify (if needed), PingCastle and Cable then employ a custom WDAC policy to each machine with some lolbin blocking like mshta but I can decide that on a machine by machine basis too. This will also do defender ASR rules and more hardening in the Phase2 function. This script can also do bulk password resets and attempts to autosolve some injects like desktop background changing.  

sysmon-config.xml is based on SwiftonSecurity's sysmon config but also has some additional rules like fileblockexecutables.