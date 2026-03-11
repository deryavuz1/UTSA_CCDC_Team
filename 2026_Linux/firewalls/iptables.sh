### SET UP IPTABLES ##

function setup_iptables {
    print_banner "Configuring iptables"
    echo "[*] Installing iptables packages"

    if [ "$pm" == 'apt' ]; then
        # Debian and Ubuntu
        sudo "$pm" install -y iptables iptables-persistent #ipset
        SAVE='/etc/iptables/rules.v4'
    else
        # Fedora
        sudo "$pm" install -y iptables-services
        sudo systemctl enable iptables
        sudo systemctl start iptables
        SAVE='/etc/sysconfig/iptables'
    fi

    # echo "[*] Creating private ip range ipset"
    # sudo ipset create PRIVATE-IP hash:net
    # sudo ipset add PRIVATE-IP 10.0.0.0/8
    # sudo ipset add PRIVATE-IP 172.16.0.0/12
    # sudo ipset add PRIVATE-IP 192.168.0.0/16
    # sudo ipset save | sudo tee /etc/ipset.conf
    # sudo systemctl enable ipset

    echo "[*] Creating INPUT rules"
    sudo iptables -P INPUT DROP
    sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A INPUT -s 0.0.0.0/0 -j ACCEPT

    echo "[*] Which ports should be open for incoming traffic (INPUT)?"
    echo "[*] Warning: Do NOT forget to add 22/SSH if needed- please don't accidentally lock yourself out of the system!"
    ports=$(get_input_list)
    for port in $ports; do
        sudo iptables -A INPUT --dport "$port" -j ACCEPT
    done
    sudo iptables -A INPUT -j LOG --log-prefix "[iptables] CHAIN=INPUT ACTION=DROP "

    echo "[*] Creating OUTPUT rules"
    # TODO: harden this as much as possible, like by limiting destination hosts
    # sudo iptables -P OUTPUT DROP
    # sudo iptables -A OUTPUT -o lo -j ACCEPT
    # sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set PRIVATE-IP dst -j ACCEPT
    # Web traffic
    sudo iptables -A OUTPUT -p tcp -m multiport --dport 80,443 -j WEB
    sudo iptables -N WEB
    sudo iptables -A WEB -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j LOG --log-prefix "[iptables] WEB/private ip "
    sudo iptables -A WEB -j ACCEPT
    # DNS traffic
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

    echo "[*] Saving rules"
    sudo iptables-save | sudo tee $SAVE
}

function main {
    echo "CURRENT TIME: $(date +"%Y-%m-%d_%H:%M:%S")"
    echo "[*] Start of script to set up IPTABLES rules. MAKE A LIST OF PORTS TO ALLOW."
    setup_iptables
}
