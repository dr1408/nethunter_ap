Nethunter AP

This eviltwin script lets you run a fake access point portal with handshake verification using a virtually created wlan1 on Kali Nethunter. You only need one external adapter for deauthing the original network.
Dependencies 

```bash
apt install aircrack-ng php python3 python3-pip ethtool
pip3 install flask
```

Usage

```bash
git clone https://github.com/dr1408/nethunter_ap.git
cd nethunter_ap
```
Turn of Wifi .. Turn on Cellular data (4g)

Plug in your wireless adapter

```bash
./evil.sh
```

Attack Demo

https://github.com/user-attachments/assets/629a6c2d-ac79-46f7-b233-6c9ad3d6f469

Credits

· @yesimxev - Internet sharing rules
· @ikteach - Script editing
· @Justxd22 - Handshake verification methods and portals
    Check his repo: https://github.com/Justxd22/Eviltwin-Huawei_XD
