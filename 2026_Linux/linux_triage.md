# Linux Live Triage

## System Information

```
uname -a
up time
timedatectl
mount
```

## Open files and related processes

```
lsof -p -i <pid> # all open files for specific ID
lsof -i # list of processes listening on ports
lsof -l -n # see open network sockets
lsof -c <SERVICE NAME> # open files on specific process
lsof +Ll #List of unlinked processes running:
ls -al /proc/<PID>/exe # Get path of suspicious process PID
```
View directory listing for /root:
`ls -la /root`

Look for files recently modified in current
directory:
`ls -alt I head`

Look for world writable files:
`find/ -xdev -type d\( -perm -0002 -a ! -perm -1000 \) -print`

## Drives and Shares

View disk space:
`df -ah`

View directory listing for /etc/init.d:
`ls -la /etc/init.d`

Get more info for a file:
`stat -x <FILE NAME>`

Identify file type:
`file <FILE NAME>`

Look for immutable files:
`lsatt r -R / I g rep 11 \`

Look for recent created files
`find/ -n ewermt 2017-01-02q`

List all files and attributes:
`find/ -printf 11%m;%Ax;%AT;%Tx;%TT;%Cx;%CT;%U;%G;%s;%p\n"`

Look at files in directory by most recent timestamp
`ls -alt /<DIRECTORY>! head`

Get full file information:
`stat /<FILE PATH>/<SUSPICIOUS FILE NAME>`

Review file type:
`file /<FILE PATH>/<SUSPICIOUS FILE NAME>`

## User and Session Information

View logged in users:
`w`

Show if a user has ever logged in remotely:
`lastlog`
`last`

View failed logins:
`faillog -a`

View local user accounts:
`cat /etc/passwd`
`cat/etc/shadow`

View local groups:
`cat/etc/group`

View sudo access:
`cat /etc/sudoers`

View accounts with UID 0:
`awk -F: '($3 == "0") {p rint}' /etc/passwd`
`egrep ':0+' /etc/passwd`

View root authorized SSH key authentications:
`cat /root/.ssh/authorized_keys`

List of files opened by user:
`lsof -u <USER NAME>`

View the root user bash history:
`cat /root/,bash_history`

## Process, Service and Module Information

`pstree`
`ps -efh`
`lsmod`

List services:
`chkconfig --list`

## Network Information

View network interfaces:
`ifconfig`

View network connections:
`netstat -antup`
`netstat -plantux`

View listening ports:
`netstat -nap`

View routes:
`route`

View arp table:
`arp -a`

List of open files, using the network:
`lsof -nPi I cut -f 1 -d " "I uniq I tail -n +2`

Save file for further malware binary analysis:
`cp /proc/<PID>/exe >/<SUSPICIOUS FILE NAME TO SAVE>,elf`

## Cronjobs and Autorun Tasks

List cron jobs:
`crontab -l`

List cron jobs by root and other users:
`crontab -u root -l`
`crontab -u <user> -l`

Review for unusual cron jobs:
`cat /etc/crontab`
`ls /etc/cron,*`

## Logging

Monitor logs in real-time:
`less +F /var/log/messages`

View root user command history:
`cat /root/,*history`

View last logins:
`last`





