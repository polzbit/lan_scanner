import subprocess 
from scapy.all import *
import re
from enum import Enum
import requests 
import time

class ipType(Enum):
    NONE = 0
    IP = 1
    CIDR = 2

class lanServer:
    def __init__(self):
        self.ip = self.get_local_ip()
        self.cidr = 24
        self.network_addr = ".".join(self.ip.split('.')[:-1]) + ".0"

    def get_local_ip(self):
        ip = IP(dst='8.8.8.8')
        return ip.src

    def ip_validation(self, ip):
        """ verify ip address, check for CIDR """
        ip_re = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip)
        cidr_re = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b", ip)
        ret_code = ipType.NONE
        if len(cidr_re) > 0:
            self.ip = self.ip[:-3]
            self.cidr = int(ip[len(self.ip)+1:])
            ret_code =  ipType.CIDR
        elif len(ip_re) > 0:
            self.ip = ip
            ret_code =  ipType.IP
        else:
            ret_code = ipType.NONE
            print("[!] Ip Not valid.")
        return ret_code


    def ping(self, ip):
        """ Ping subprocess """
        result = subprocess.call(['ping', ip, '-n', '1'])
        return result

    def ping_scan(self):
        """ Ping Sweep using ping subprocess """
        net_addr = self.network_addr[:-1]
        for i in range(1, 255):
            addr = net_addr + str(i)
            res = self.ping(addr)
            print(res)

    def ping_sweep(self):
        """ Ping Sweep using scapy """
        net_addr = self.network_addr[:-1]
        clients = []
        for i in range(1, 255):
            addr = net_addr + str(i)
            reply = sr1( IP(dst=str(addr)) / ICMP(), timeout=2, verbose=0 )
            if not reply:
                continue
            if int(reply.getlayer(ICMP).type) == 0 and int(reply.getlayer(ICMP).code) == 0:
                print (addr + ': Host is responding to ICMP Echo Requests.')
                clients.append(addr)
        return clients

    def show_interfaces(self, resolve_mac=True):
        """Print list of available network interfaces"""
        return IFACES.show(resolve_mac)

    def arp_scan(self):
        """ ARP Sweep using scapy """
        # set Ethernet header to ff:ff:ff:ff:ff:ff
        # set ARP header to ip address (got as input)
        # use srp(packet, verbose=0, timeout=1) to send and receive
        clients = []
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        cidr = self.ip + "/" + str(self.cidr)
        arp = ARP(pdst=cidr)
        packet = broadcast/arp
        results = srp(packet, timeout=1, verbose=0)
        for result in results[0]:
            clients.append({'ip' : result[1].psrc, 'MAC' : result[1].hwsrc})
        return clients

    def get_vendor_name(self, mac_addr):
        """ Get MAC Address vendor """
        try: 
            vendors_url = "https://api.macvendors.com/"
            response = requests.get(vendors_url + mac_addr) 
            return response.content.decode()
        except:
            print("[!] No Internet Connection.")

    def print_arp_vendors(self):
        """ Sweep for lan vendors """
        clients = self.arp_scan()
        for pc in clients:
            mac_address = pc['MAC']
            vendor = s.get_vendor_name(mac_address)
            print(vendor)
            time.sleep(2)

if __name__ == "__main__":
    s = lanServer()
    s.print_arp_vendors()
