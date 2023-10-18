import ipaddress

from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


class TraceRouter:
    def __init__(self, ip_address, port=80, seq=1, timeout=1, max_ttl=20, packet_size=40):
        self.ip = ip_address
        self.port = port
        self.timeout = timeout
        self.max_ttl = 10
        self.seq = seq
        self.data = [str(i) for i in range(40)]
        self.ip_addresses = []

    def get_trace(self):
        self.print_request_status('Node number', 'Time', 'IP-address', 'Status')
        ip_version = ipaddress.ip_address(self.ip).version
        protocol_packet = ICMP(seq=self.seq)

        for ttl in range(1, self.max_ttl + 1):
            reply = None
            reply, packet = self.get_node_info_with_retry(ttl, ip_version, protocol_packet, reply)

            if reply is None:
                self.print_request_status(ttl, '*', '*', 'Request timeout exceeded.')
            else:
                src = reply.src
                seq = reply[ICMP].seq
                self.seq = seq
                ping = "{:.4f}".format((reply.time - packet.sent_time) * 1000) + ' ms'
                self.print_request_status(ttl, ping, src, 'Ok')
                self.ip_addresses += [src]
                if src == self.ip:
                    break

            time.sleep(0.8)

    def get_node_info_with_retry(self, ttl, ip_version, protocol_packet, reply):
        packet = None
        for attempt in range(1):
            ip_packet = self.get_ip_packet(ttl, ip_version)
            packet = ip_packet / protocol_packet / ('0'*40).encode()
            reply = sr1(packet, verbose=0, timeout=self.timeout)
            if reply is not None:
                break

        return reply, packet

    def get_ip_packet(self, i, ip_version):
        ip_packet = None
        if ip_version == 4:
            ip_packet = IP(dst=self.ip, ttl=i)
        elif ip_version == 6:
            ip_packet = IPv6(dst=self.ip, hlim=i)

        return ip_packet

    @staticmethod
    def print_request_status(number, ping, ip_addr, status):
        print(f'{str(number).ljust(15)} {ping.ljust(15)}  {ip_addr.rjust(18)}      {status}')
