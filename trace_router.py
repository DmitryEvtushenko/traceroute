import ipwhois
from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP


class TraceRouter:
    def __init__(self, ip_address, port=80, seq=1, timeout=0.5, max_ttl=20, packet_size=40, requests_count=4,
                 time_interval=0.2, debug=False):
        self.ip = ip_address
        self.port = port
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.seq = seq
        self.data = str([str(i) for i in range(packet_size)]).encode()
        self.ip_addresses = []
        self.debug = debug
        self.requests_count = requests_count
        self.time_interval = time_interval

    def get_trace(self):
        protocol_packet = ICMP(seq=self.seq)
        if not self.debug:
            self.print_request_status('Node number', 'Time', 'IP-address', 'Status')

        for ttl in range(1, self.max_ttl + 1):
            if self.debug:
                print(f'The packet with ttl = {ttl} was sent to the address {self.ip} {self.get_name_by_host(self.ip)}')

            srcs = set()
            pings = []

            for _ in range(self.requests_count):
                reply, packet = self.get_node_info(ttl, protocol_packet)
                if reply is not None:
                    src = reply.src
                    seq = reply[ICMP].seq
                    self.seq = seq
                    packet_sending_time = (reply.time - packet.sent_time) * 1000
                    srcs.add(src)
                    pings += [packet_sending_time]

                    self.ip_addresses += [src]

                time.sleep(self.time_interval)

            if self.debug:
                print(f'The packet delivered to the address {self.ip} {self.get_name_by_host(self.ip)} successfully')

            if len(pings) > 0:
                average_ping = "{:.1f}".format(sum(int(p) for p in pings) / len(pings))
                self.print_request_status(ttl, average_ping, ', '.join(list(srcs)), 'Ok')
            else:
                self.print_request_status(ttl, '*', '*', 'Request timeout exceeded.')
            if self.ip in srcs:
                return

    def get_node_info(self, ttl, protocol_packet):
        ip_packet = IP(dst=self.ip, ttl=ttl)
        packet = ip_packet / protocol_packet / self.data
        reply = sr1(packet, verbose=self.debug, timeout=self.timeout)
        return reply, packet

    def print_request_status(self, number, ping, ip_addr, status):
        try:
            host_name = self.get_name_by_host(ip_addr)
        except:
            host_name = ''

        if self.debug:
            print(
                f'The packet was sent within time {ping} to the address {ip_addr} ({host_name}) with status \"{status}\"')
            return

        print(
            f'{str(number).ljust(15)} {str(ping).ljust(15)}  {str(ip_addr).rjust(30)}  {host_name.ljust(20)} {status.ljust(10)}')

    def get_name_by_host(self, ip_addr):
        return ipwhois.IPWhois(ip_addr).lookup_whois()['nets'][0]['name']
