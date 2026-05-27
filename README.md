Nethunter AP

This eviltwin script lets you run a fake access point portal with handshake verification using a virtually created AP on Kali Nethunter. You only need one external adapter for deauthing the original network.


Dependencies 

```bash
apt install aircrack-ng hostapd dnsmasq php python3 python3-pip ethtool dsniff iw tshark
pip3 install flask requests
```

Usage

```bash
git clone https://github.com/dr1408/eviltwin.git
cd eviltwin
```
iptables

```bash
update-alternatives --config iptables
choose iptables-legacy
```

## IMPORTANT: One-Time iptables Setup

Evil twin attacks modify iptables rules. To prevent breaking your Android hotspot:

1. Turn OFF **WiFi** and **Mobile Data**
2. **Reboot** your phone
3. Create a clean backup:
   ```bash
   iptables-save | grep -v "bpf" > /sdcard/original
   ```
the script automatically restore this backup on exit to restore android hotspot functionallity.

for other tools like wifipumkin you need to restore it manually with this command
   ```bash
   iptables-restore < /sdcard/original
   ```


```bash
python3 attack.py
```

## NetHunter module

make sure you clone it to  /  so you can use it with nethunter GUI module  ~> final path should be /eviltwin .. for the Nethunter module version important logs will be saved to sdcard .. better first to test the terminal version attack.py :)



Attack Demo

https://github.com/user-attachments/assets/629a6c2d-ac79-46f7-b233-6c9ad3d6f469

Credits

· @yesimxev - Internet sharing rules
· @ikteach - Script editing
· @Justxd22 - Handshake verification methods and portals
    Check his repo: https://github.com/Justxd22/Eviltwin-Huawei_XD



## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. 
- Use only on networks you **own** or have **written permission** to test
- Unauthorized access to computer networks is illegal
- The author **is not responsible** for any misuse or damage caused by this tool
- Users assume full responsibility for their actions
By using this tool, you agree to use it **ethically and legally**.
