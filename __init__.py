#!/usr/bin/env python
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr, srp 
from scapy.utils import wrpcap

def scan_port(ip, port):

    try:
        src_port = 12345  # You can choose any random source port
        response = sr1(IP(dst = ip) / 
            TCP(sport = src_port, dport = port, flags="S"), 
            timeout = 1, verbose = 0)

        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK packet
                print(f"port {port} open")
            elif response[TCP].flags == 0x14:  # RST-ACK packet
                print(f"port {port} closed")
        else:
            print(f"Port {port} is filtered")

    except Exception as e:
        print(f"error occurred: {str(e)}")

def save_to_pcap(hosts, filename):

    packets = []

    for host in hosts:

       arp = ARP(pdst = host['ip']) 
       ether = Ether(dst = host['mac'])
       packet = ether / arp
       packets.append(packet)

    wrpcap(filename, packets)
    print(f'saved to {filename}')

def arp_scan(ip: str): 

    arp = ARP(pdst = ip)
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout = 3, verbose = 0)[0]

    return result

def get_hosts(hosts: list, result) -> list:

    for sent, received in result:
    # for each response, append ip and mac address to `hosts` list
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

    print('devices in the network: \n' + 
        'IP' + " "*18+'MAC')

    for host in hosts:
        print("{:16}    {}".format(host['ip'], host['mac']))

    return hosts

if __name__ == '__main__':
    hosts = []
    ports = []
    ip = input('your IP addres: ')
    ports = input('ports to scan: ')
    get_hosts(hosts, result = arp_scan(ip))
    for port in ports:
        scan_port(ip, port)
#    save_to_pcap(hosts, filename = input('filename(.pcap): '))
