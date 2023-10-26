import ipaddress

from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

import ipwhois


class TraceRouter:
    def __init__(self, ip_address, port=80, seq=1, timeout=0.5, retry_count=3, max_ttl=20, packet_size=40, debug=True):
        self.ip = ip_address
        self.port = port
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.retry_count = retry_count
        self.seq = seq
        self.data = str([str(i) for i in range(packet_size)]).encode()
        self.ip_addresses = []
        self.debug = debug

    def get_trace(self):
        if not self.debug:
            self.print_request_status('Node number', 'Time', 'IP-address', 'Status')
        ip_version = ipaddress.ip_address(self.ip).version
        protocol_packet = ICMP(seq=self.seq)

        for ttl in range(1, self.max_ttl + 1):
            if self.debug:
                print(f'The packet with ttl = {ttl} was sent to the address {self.get_name_by_host(self.ip)}')
            reply, packet = self.get_node_info_with_retry(ttl, ip_version, protocol_packet)

            if reply is None:
                self.print_request_status(ttl, '*', '*', 'Request timeout exceeded.')
            else:
                if self.debug:
                    print(f'The packet delivered to the address {self.get_name_by_host(self.ip)} successfully')
                src = reply.src
                seq = reply[ICMP].seq
                self.seq = seq
                ping = "{:.4f}".format((reply.time - packet.sent_time) * 1000) + ' ms'
                self.print_request_status(ttl, ping, src, 'Ok')
                self.ip_addresses += [src]
                if src == self.ip:
                    break



    def get_node_info_with_retry(self, ttl, ip_version, protocol_packet):
        ip_packet = self.get_ip_packet(ttl, ip_version)
        packet = ip_packet / protocol_packet / self.data
        reply = sr1(packet, verbose=0, timeout=self.timeout, retry=self.retry_count)
        return reply, packet

    def get_ip_packet(self, i, ip_version):
        ip_packet = None
        if ip_version == 4:
            ip_packet = IP(dst=self.ip, ttl=i)
        elif ip_version == 6:
            ip_packet = IPv6(dst=self.ip, hlim=i)

        return ip_packet

    def print_request_status(self, number, ping, ip_addr, status):
        try:
            host_name = self.get_name_by_host(ip_addr)
        except:
            host_name = ''

        if self.debug:
            print(f'The packet was sent within time {ping} to the address {ip_addr} ({host_name}) with status \"{status}\"')
            return

        print(f'{status} {str(number).ljust(15)} {ping.ljust(15)}  {ip_addr.rjust(18)} {host_name.ljust(20)} ')

    def get_name_by_host(self, ip_addr):
        host_name = ipwhois.IPWhois(ip_addr).lookup_whois()['nets'][0]['name']
        return f'{ip_addr} ({host_name})'
