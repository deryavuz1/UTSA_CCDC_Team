#!/bin/bash

BLUE='\033[1;34m'  
RED='\033[1;31m'   
YELLOW='\033[1;33m' 
GREEN='\033[1;32m' 
NC='\033[0m'       

LOGFILE="enum_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1 

print_header() {
    echo -e "\n\n${BLUE}=== $1 ===${NC}\n"
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo -e "${YELLOW}[WARN] $1 not found, skipping...${NC}"; return 1; }
}

# ===========================================================================
# SYSTEM INFORMATION
# ===========================================================================
print_header "SYSTEM INFORMATION"
echo -e "${YELLOW}[INFO] Kernel and OS details:${NC}"
uname -a
echo
[ -f /etc/os-release ] && cat /etc/os-release || echo -e "${YELLOW}[WARN] No /etc/os-release found${NC}"
echo
hostnamectl 2>/dev/null || echo "Hostname: $(hostname)"


# ===========================================================================
# NETWORK INFORMATION
# ===========================================================================
print_header "NETWORK INFORMATION"
echo -e "${YELLOW}[INFO] Listening ports and services:${NC}"
check_cmd ss && ss -tulnp || { check_cmd netstat && netstat -tulnp; }
echo
echo -e "${YELLOW}[INFO] Network interfaces:${NC}"
check_cmd ip && ip addr || { check_cmd ifconfig && ifconfig; }
echo
echo -e "${YELLOW}[INFO] Routing table:${NC}"
ip route
echo
echo -e "${YELLOW}[INFO] Open connections:${NC}"
lsof -i -P -n | grep -v "127.0.0.1" | while read -r line; do
    echo "$line" | grep -q "ESTABLISHED" && echo -e "${RED}[SUSPICIOUS] $line - External connection!${NC}" || echo "$line"
done


# ===========================================================================
# USER AND GROUP ENUMERATION
# ===========================================================================
print_header "USER AND GROUP ENUMERATION"
echo -e "${YELLOW}[INFO] Users with UID 0 (potential root access):${NC}"
awk -F: '$3 == 0 {print $1 " (UID: " $3 ")"}' /etc/passwd | while read -r line; do
    [ "$line" != "root (UID: 0)" ] && echo -e "${RED}[SUSPICIOUS] $line - Non-root UID 0!${NC}" || echo -e "${GREEN}[OK] $line${NC}"
done
echo
echo -e "${YELLOW}[INFO] Users with valid shells:${NC}"
awk -F: '$7 !~ /nologin|false/ {print $1 " (Shell: " $7 ")"}' /etc/passwd
echo
echo -e "${YELLOW}[INFO] Sudo group members:${NC}"
getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r line; do
    [ -n "$line" ] && [ "$line" != "root" ] && echo -e "${RED}[SUSPICIOUS] $line has sudo privileges - Verify necessity!${NC}" || echo "$line"
done
echo
echo -e "${YELLOW}[INFO] Checking sudoers file:${NC}"
grep -v '^#' /etc/sudoers | grep -E "ALL.*ALL" | while read -r line; do
    echo -e "${GREEN}[OK] $line${NC}"
done


# ===========================================================================
# AUTHENTICATION AND LOGINS
# ===========================================================================
print_header "AUTHENTICATION AND LOGINS"
echo -e "${YELLOW}[INFO] Currently logged-in users:${NC}"
w
echo
echo -e "${YELLOW}[INFO] Last successful logins (with IPs):${NC}"
last -i | head -n 10
echo
echo -e "${YELLOW}[INFO] Failed login attempts:${NC}"
check_cmd lastb && sudo lastb | head -n 10
echo
echo -e "${YELLOW}[INFO] SSH authorized keys:${NC}"
find /home -name "authorized_keys" -exec ls -l {} + 2>/dev/null | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Check key ownership and contents!${NC}"
done


# ===========================================================================
# SERVICE AND PROCESS CHECKS
# ===========================================================================
print_header "SERVICE AND PROCESS CHECKS"
echo -e "${YELLOW}[INFO] Running services:${NC}"
check_cmd systemctl && systemctl list-units --type=service --state=running
echo
echo -e "${YELLOW}[INFO] Processes running as root:${NC}"
ps -u root -o pid,command | tail -n +2 | while read -r line; do
    echo "$line" | grep -qvE "systemd|bash|sshd" && echo -e "${RED}[SUSPICIOUS] $line - Unusual root process?${NC}" || echo "$line"
done
echo
echo -e "${YELLOW}[INFO] Open sockets:${NC}"
lsof -i -P -n | while read -r line; do
    echo "$line" | grep -q "LISTEN" && echo "$line" || echo -e "${RED}[SUSPICIOUS] $line - Non-listening socket!${NC}"
done


# ===========================================================================
# PERSISTENCE AND BACKDOORS
# ===========================================================================
print_header "PERSISTENCE AND BACKDOORS"
echo -e "${YELLOW}[INFO] System-wide cron jobs:${NC}"
cat /etc/crontab 2>/dev/null
ls -l /etc/cron.* 2>/dev/null
echo
echo -e "${YELLOW}[INFO] User cron jobs:${NC}"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "no crontab" && echo -e "${RED}[SUSPICIOUS] Cron for $user:${NC}\n$(crontab -u "$user" -l)"
done
echo
echo -e "${YELLOW}[INFO] Suspicious files in /tmp:${NC}"
ls -la /tmp | grep -E "^[-d].*root" | grep -v "snap" | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Root-owned in /tmp!${NC}"
done


# ===========================================================================
# SECURITY CHECKS
# ===========================================================================
print_header "SECURITY CHECKS"
echo -e "${YELLOW}[INFO] World-writable files (excluding defaults):${NC}"
find / -type f -perm -o+w -not -path "/tmp/*" -not -path "/var/tmp/*" -not -path "/dev/*" -not -path "/var/run/*" -not -path "/run/*" -not -path "/proc/*" -not -path "/sys/*" -ls 2>/dev/null | head -n 5 | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Fix permissions!${NC}"
done
echo
echo -e "${YELLOW}[INFO] SUID/SGID binaries:${NC}"
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | grep -vE "/bin|/usr" | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Non-standard SUID/SGID!${NC}"
done
echo
echo -e "${YELLOW}[INFO] Checking for unexpected kernel modules:${NC}"
lsmod | grep -vE "kernel|vfat|ext4|xfs" | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Verify module legitimacy!${NC}"
done
echo
echo -e "${YELLOW}[INFO] Firewall status:${NC}"
check_cmd ufw && ufw status || echo -e "${YELLOW}[WARN] UFW not installed or not running${NC}"


# ===========================================================================
# ADDITIONAL ENUMERATION AND HARDENING
# ===========================================================================
print_header "ADDITIONAL ENUMERATION AND HARDENING"
echo -e "${YELLOW}[INFO] Checking SSH configuration:${NC}"
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config | while read -r line; do
    echo "$line" | grep -q "yes" && echo -e "${RED}[SUSPICIOUS] $line - Disable for security!${NC}" || echo -e "${GREEN}[OK] $line${NC}"
done
echo
echo -e "${YELLOW}[INFO] Suspicious installed packages:${NC}"
check_cmd dpkg && dpkg -l | grep -E "^ii.*(telnet|netcat-traditional|netcat-openbsd|rsh)" | head -n 5 | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Remove risky tools!${NC}"
done
check_cmd rpm && rpm -qa | grep -E "^(telnet|netcat|rsh)" | head -n 5 | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Remove risky tools!${NC}"
done
echo
echo -e "${YELLOW}[INFO] Checking for writable config files:${NC}"
find /etc -type f -writable 2>/dev/null | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Writable config, secure it!${NC}"
done
echo
echo -e "${YELLOW}[INFO] File integrity check (critical binaries):${NC}"
for bin in /bin/ls /usr/bin/passwd /bin/bash; do
    [ -f "$bin" ] && sha256sum "$bin" | while read -r hash file; do
        echo -e "${YELLOW}[INFO] $file: $hash${NC} - Compare with known good hash!"
    done || echo -e "${RED}[SUSPICIOUS] $bin missing!${NC}"
done
echo
echo -e "${YELLOW}[INFO] Recent auth log entries:${NC}"
[ -f /var/log/auth.log ] && tail -n 10 /var/log/auth.log | while read -r line; do
    echo "$line" | grep -qE "sudo|sshd.*Failed" && echo -e "${RED}[SUSPICIOUS] $line${NC}" || echo "$line"
done || echo -e "${YELLOW}[WARN] /var/log/auth.log not found${NC}"
echo
echo -e "${YELLOW}[INFO] SELinux/AppArmor status:${NC}"
check_cmd sestatus && sestatus || echo -e "${YELLOW}[WARN] SELinux not installed${NC}"
check_cmd aa-status && aa-status || echo -e "${YELLOW}[WARN] AppArmor not installed${NC}"
echo
echo -e "${YELLOW}[INFO] Recently modified files (last 24h):${NC}"
find / -mtime -1 -ls 2>/dev/null | grep -vE "/proc|/sys|/dev" | head -n 10 | while read -r line; do
    echo -e "${RED}[SUSPICIOUS] $line - Recent change, verify!${NC}"
done

echo -e "\n\n${GREEN}Enumeration complete! Check $LOGFILE for details.${NC}"
