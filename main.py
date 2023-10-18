import argparse
import ipaddress

from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import ICMP


class TraceRouter:
    def __init__(self, args):
        self.ip = args.IP_ADDRESS
        self.port = args.port
        self.timeout = args.timeout
        self.max_ttl = args.number

    def get_trace(self):
        ip_version = ipaddress.ip_address(self.ip).version
        protocol_packet = ICMP()
        for i in range(1, self.max_ttl + 1):
            ip_packet = None
            if ip_version == 4:
                ip_packet = IP(dst=self.ip, ttl=i)
            elif ip_version == 6:
                ip_packet = IPv6(dst=self.ip, hlim=i)
            packet = ip_packet / protocol_packet
            reply = sr1(packet, verbose=0, timeout=self.timeout)
            if reply is None:
                print(i, '*')
                continue

            src = reply.src
            num_auto_sys = None
            print(f"{i}. {src} [{(reply.time - packet.sent_time) * 1000}]"
                  f" {num_auto_sys if num_auto_sys is not None else ''}")
            if src == self.ip:
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='traceroute')

    parser.add_argument('-t', '--timeout', default=2, type=float)
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('-n', '--number', default=24, type=int)
    parser.add_argument('IP_ADDRESS')

    args = parser.parse_args()
    # args = parser.parse_args("python main.py -p 80 -t 1 172.67.182.196".split())
    if not vars(args):
        parser.print_usage()
    else:
        traceroute = TraceRouter(args)
        traceroute.get_trace()
