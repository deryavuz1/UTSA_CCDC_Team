function backups {
    print_banner "Backups"
    echo "[*] Would you like to backup any files?"
    option=$(get_input_string "(y/N): ")

    if [ "$option" != "y" ]; then
        return
    fi
    
    # Enter directories to backup
    repeat=true
    while $repeat; do
        repeat=false
        dirs_to_backup=()
        echo "Enter directories/files to backup:"
        input=$(get_input_list)
        for item in $input; do
            path=$(readlink -f "$item")
            if sudo [ -e "$path" ]; then
                dirs_to_backup+=("$path")
            else
                echo "[X] ERROR: $path is invalid or does not exist"
                repeat=true
            fi
        done
    done

    # Get backup storage name
    while true; do
        backup_name=$(get_input_string "Enter name for encrypted backups file (ex. cosmo.zip ): ")
        if [ "$backup_name" != "" ]; then
            break
        fi
        echo "[X] ERROR: Backup name cannot be blank"
    done
    # Get backup storage location
    while true; do
        backup_dir=$(get_input_string "Enter directory to place encrypted backups file (ex. /var/log/ ): ")
        backup_dir=$(readlink -f "$backup_dir")
        if sudo [ -e "$backup_dir" ]; then
            break
        fi
        echo "[X] ERROR: $backup_dir is invalid or does not exist"
    done
    # Get backup encryption password
    echo "[*] Enter the backup encryption password."
    while true; do
        password=""
        confirm_password=""

        # Ask for password
        password=$(get_silent_input_string "Enter password: ")
        echo

        # Confirm password
        confirm_password=$(get_silent_input_string "Confirm password: ")
        echo

        if [ "$password" != "$confirm_password" ]; then
            echo "Passwords do not match. Please retry."
        else
            break
        fi
    done

    # Zip all directories and store in backups directory
    sudo mkdir "$backup_dir/backups"
    for dir in "${dirs_to_backup[@]}"; do
        filename=$(basename "$dir")
        sudo zip -r "$backup_dir/backups/$filename.zip" "$dir" &> /dev/null
    done

    # Compress backups directory
    tar -czvf "$backup_dir/backups.tar.gz" -C "$backup_dir" backups &>/dev/null

    # Encrypt backup
    openssl enc -aes-256-cbc -salt -in "$backup_dir/backups.tar.gz" -out "$backup_dir/$backup_name" -k "$password"
    
    # Double check that backup exists before deleting intermediary files
    if sudo [ -e "$backup_dir/$backup_name" ]; then
        sudo rm "$backup_dir/backups.tar.gz"
        sudo rm -rf "$backup_dir/backups"
        echo "[*] Backups successfully stored and encrypted."
    else
        echo "[X] ERROR: Could not successfully create backups."
    fi
}

function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script BACKUPS. Backup the important services on the box."
    echo "[*] CHOOSE A SECURE PASSWORD FROM THE LIST AND LET YOUR CAPTAIN KNOW."
    backups

}
