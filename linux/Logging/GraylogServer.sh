#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to install Graylog
install_graylog() {
    echo -e "${GREEN}Installing Dependencies for Graylog...${NC}"

    # Asking for Graylog host IP address
    read -p "Enter the IP address of the Graylog host: " GRAYLOG_HOST_IP
    

    echo "Install Dependency"
    sleep 1.5
    apt update -y
    clear
    apt upgrade -y
    clear
    apt install apt-transport-https gnupg2 uuid-runtime pwgen curl dirmngr -y
    clear



    echo "Install Java JDK"
    sleep 1.5
    apt install openjdk-11-jre-headless -y
    sleep 1
    clear
    java -version
    sleep 2
    clear

    echo "Install Elasticsearch"
    sleep 1.5
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/oss-7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
    apt update -y
    apt install elasticsearch-oss -y
    echo "cluster.name: graylog
action.auto_create_index: false" >> /etc/elasticsearch/elasticsearch.yml
    echo "check config Elasticsearch"
    cat /etc/elasticsearch/elasticsearch.yml
    sleep 3
    systemctl daemon-reload
    systemctl start elasticsearch
    systemctl enable elasticsearch
    curl -X GET http://localhost:9200
    clear


    echo "Install MongoDB Server"
    sleep 1.5
    curl -fsSL https://pgp.mongodb.com/server-6.0.asc | \
    sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-6.0.gpg
    echo "deb [ arch=amd64,arm64 signed=/etc/apt/trusted.gpg.d/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
    apt update -y
    apt install mongodb-org -y
    mongod --version
    systemctl start mongod
    systemctl enable mongod
    clear

    echo "Install Graylog4.3"
    sleep 1.5
    wget https://packages.graylog2.org/repo/packages/graylog-4.3-repository_latest.deb
    dpkg -i graylog-4.3-repository_latest.deb
    apt update -y
    apt install graylog-server -y
    #systemctl daemon-reload
    systemctl start graylog-server
    systemctl enable graylog-server
    echo "Comment Out Config"
    config_file="/etc/graylog/server/server.conf"
    # Comment out the password_secret line
    sed -i '/^password_secret/s/^/#/' "$config_file"
    # Comment out the root_password_sha2 line
    sed -i '/^root_password_sha2/s/^/#/' "$config_file"

    password_secret=$(pwgen -N 1 -s 96)
    # Display generated password
    echo "Generated password: $password_secret"
    sleep 2.5
    clear

    echo "http_bind_address = $GRAYLOG_HOST_IP:9000" >> /etc/graylog/server/server.conf
    echo "password_secret = $password_secret" >> /etc/graylog/server/server.conf
    echo "root_password_sha2 = 2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea" >> /etc/graylog/server/server.conf

    systemctl restart graylog-server


 

    echo "Install Nginx"
    sleep 1.5
    apt install nginx -y
    systemctl restart nginx
    systemctl enable nginx
    touch /etc/nginx/sites-available/graylog.conf
    echo 'server {
    listen 80;
    server_name graylog.example.org;

    location /
    {
      proxy_set_header Host "$http_host";
      proxy_set_header X-Forwarded-Host "$host";
      proxy_set_header X-Forwarded-Server "$host";
      proxy_set_header X-Forwarded-For "$proxy_add_x_forwarded_for";
      proxy_set_header X-Graylog-Server-URL http://'$GRAYLOG_HOST_IP'/;
      proxy_pass       http://'$GRAYLOG_HOST_IP':9000;
    }

    }' > /etc/nginx/sites-available/graylog.conf
    echo "Verify Nginx Configuration"
    nginx -t
    sleep 1.5
    ln -s /etc/nginx/sites-available/graylog.conf /etc/nginx/sites-enabled/
    rm -rf /etc/nginx/sites-enabled/default
    systemctl restart nginx
    systemctl enable nginx
    clear
    echo -e "${GREEN}Complete Install Graylog4.3${NC}"
}

uninstall_graylog()
{
    clear
    echo "Uninstall Graylog v.4.3"
    sleep 1.5
    clear
    echo "Search Old Package's Graylog and uninstall"
    apt list --installed | grep graylog
    sleep 1.5
    clear
    apt remove --purge graylog-4.3-repository -y
    clear
    apt remove --purge graylog-server -y
    clear
    echo "Warning!! Your system will rebooting now...."
    echo 3
    clear
    reboot
}

upgrade_graylog()
{
    echo "Upgrade Graylog to V.5.2.5-1"
    sleep 2
    clear
    read -p "Enter the IP address of the Graylog host again: " GRAYLOG_HOST_IP
    wget https://packages.graylog2.org/repo/packages/graylog-5.2-repository_latest.deb
    sudo dpkg -i graylog-5.2-repository_latest.deb
    sudo apt-get update -y
    sudo apt-cache policy graylog-server
    sudo apt-get install graylog-server=5.2.5-1 -y
    clear
    sleep 2
    systemctl daemon-reload
    systemctl start graylog-server
    systemctl enable graylog-server
    clear

    echo "Comment Out Config"
    config_file="/etc/graylog/server/server.conf"
    # Comment out the password_secret line
    sed -i '/^password_secret/s/^/#/' "$config_file"
    # Comment out the root_password_sha2 line
    sed -i '/^root_password_sha2/s/^/#/' "$config_file"

    password_secret=$(pwgen -N 1 -s 96)
    # Display generated password
    echo "Generated password: $password_secret"
    sleep 2.5
    clear


    echo "http_bind_address = $GRAYLOG_HOST_IP:9000" >> /etc/graylog/server/server.conf
    echo "password_secret = $password_secret" >> /etc/graylog/server/server.conf
    echo "root_password_sha2 = 2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea" >> /etc/graylog/server/server.conf
    systemctl daemon-reload
    systemctl restart graylog-server
    echo "${GREEN}Upgrade Graylog to V.5.2.5-1 Complete...${NC}"
    sleep 1.5
    clear



}

# Function to display menu
display_menu() {
    echo -e "${YELLOW}Select an option:${NC}"
    echo -e "${YELLOW}1. Install Graylog V.4.3${NC}"
    echo -e "${YELLOW}2. Uninstall Graylog v.4.3${NC}"
    echo -e "${YELLOW}3. Upgrade Graylog to V.5.2.5-1${NC}"
    echo -e "${YELLOW}4. Exit${NC}"
}

# Main function
main() {
    while true; do
        display_menu

        read -p "Enter your choice: " choice

        case $choice in
            1)
                install_graylog
                ;;
            2)
                uninstall_graylog
                ;;
            3)
                upgrade_graylog
                ;;
            4)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please select again!!!${NC}"
                ;;
        esac
    done
}

main
