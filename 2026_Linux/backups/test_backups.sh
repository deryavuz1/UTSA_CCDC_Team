#!/bin/bash

# Define service backup paths
declare -A SERVICE_PATHS
SERVICE_PATHS=(
    ["apache"]="/etc/apache2 /var/www"
    ["nginx"]="/etc/nginx /var/www /usr/share/nginx"
    ["ssh"]="/etc/ssh"
    ["mysql"]="/etc/mysql /var/lib/mysql"
    ["mariadb"]="/etc/mysql /var/lib/mysql"
    ["postgresql"]="/etc/postgresql /var/lib/postgresql"
    ["dns"]="/etc/bind /var/cache/bind"
    ["bind"]="/etc/bind /var/cache/bind"
    ["ftp"]="/etc/vsftpd.conf /etc/proftpd /srv/ftp"
    ["mail"]="/etc/postfix /etc/dovecot /var/mail"
    ["postfix"]="/etc/postfix"
    ["dovecot"]="/etc/dovecot"
    ["samba"]="/etc/samba"
    ["ldap"]="/etc/ldap /var/lib/ldap"
    ["docker"]="/etc/docker /var/lib/docker/volumes"
    ["cron"]="/etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron"
    ["users"]="/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /home"
    ["firewall"]="/etc/iptables /etc/nftables.conf /etc/ufw"
    ["all-configs"]="/etc"
)

function print_services {
    echo "Available services:"
    echo "-------------------"
    for service in "${!SERVICE_PATHS[@]}"; do
        printf "  %-15s -> %s\n" "$service" "${SERVICE_PATHS[$service]}"
    done | sort
    echo "-------------------"
}

function backup_services {
    local backup_dir="${1:-/root/backups}"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    # Create backup directory
    sudo mkdir -p "$backup_dir"
    
    print_services
    echo
    read -p "Enter services to backup (space-separated, or 'all'): " -a selected_services
    
    if [[ " ${selected_services[*]} " =~ " all " ]]; then
        selected_services=("${!SERVICE_PATHS[@]}")
    fi
    
    local paths_to_backup=()
    
    for service in "${selected_services[@]}"; do
        if [[ -v SERVICE_PATHS[$service] ]]; then
            for path in ${SERVICE_PATHS[$service]}; do
                if sudo [ -e "$path" ]; then
                    paths_to_backup+=("$path")
                    echo "[+] Added: $path ($service)"
                else
                    echo "[-] Skipped (not found): $path"
                fi
            done
        else
            echo "[!] Unknown service: $service"
        fi
    done
    
    if [ ${#paths_to_backup[@]} -eq 0 ]; then
        echo "[X] No valid paths to backup."
        return 1
    fi
    
    # Create the backup
    local backup_file="$backup_dir/backup_$timestamp.tar.gz"
    echo
    echo "[*] Creating backup: $backup_file"
    
    sudo tar -czvf "$backup_file" "${paths_to_backup[@]}" 2>/dev/null
    
    if [ -f "$backup_file" ]; then
        echo "[✓] Backup complete: $backup_file"
        echo "[*] Size: $(du -h "$backup_file" | cut -f1)"
    else
        echo "[X] Backup failed!"
        return 1
    fi
}

function restore_backup {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        read -p "Enter path to backup file: " backup_file
    fi
    
    if [ ! -f "$backup_file" ]; then
        echo "[X] Backup file not found: $backup_file"
        return 1
    fi
    
    echo "[!] WARNING: This will overwrite existing files!"
    read -p "Continue? (y/N): " confirm
    
    if [ "$confirm" = "y" ]; then
        sudo tar -xzvf "$backup_file" -C /
        echo "[✓] Restore complete"
    else
        echo "[*] Restore cancelled"
    fi
}

function main {
    echo "=========================================="
    echo "  CCDC Backup Script - $(date +"%Y-%m-%d %H:%M:%S")"
    echo "=========================================="
    echo
    echo "1) Backup services"
    echo "2) Restore from backup"
    echo "3) List available services"
    echo "4) Exit"
    echo
    read -p "Select option: " choice
    
    case $choice in
        1) backup_services "/root/backups" ;;
        2) restore_backup ;;
        3) print_services ;;
        4) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
}

main "$@"
