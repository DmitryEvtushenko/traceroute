import argparse
from trace_router import TraceRouter
import socket

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Traceroute tracks the path of a packet to a given node.')
    parser.add_argument('-t', '--timeout', default=2, type=float, help='Sets a packet timeout')
    parser.add_argument('-p', '--port', type=int, help='Specifies the resource port')
    parser.add_argument('-seq', '--seq', type=int, default=1, help='Sets SEQ')
    parser.add_argument('-ttl', '--ttl', default=15, type=int, help='Sets the maximum time to live for package')
    parser.add_argument('-pkg', '--packet_size', default=40, type=int, help='Sets a packet size')
    parser.add_argument('-debug', '--debug', type=bool, default=False,
                        help='Print all information about packets')
    parser.add_argument('-rc', '--request_count', type=int, default=4,
                        help='Requests count')
    parser.add_argument('-interval', '--time_interval', type=float, default=0.5,
                        help='Setting the time interval between requests')
    parser.add_argument('IP_ADDRESS', help='Sets the target IP address')


    args = parser.parse_args()
    # args = parser.parse_args("python main.py -p 80 -t 1 176.100.119.169".split())
    # print(args)
    if not vars(args):
        parser.print_usage()
    else:
        host = socket.gethostbyname(args.IP_ADDRESS)
        traceroute = TraceRouter(host, args.port, args.seq, args.timeout, args.ttl, args.packet_size, args.request_count, args.time_interval, args.debug)
        traceroute.get_trace()