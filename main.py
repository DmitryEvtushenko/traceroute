import argparse
from trace_router import TraceRouter

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Traceroute tracks the path of a packet to a given node.')
    parser.add_argument('-t', '--timeout', default=2, type=float, help='Sets a packet timeout')
    parser.add_argument('-p', '--port', type=int, help='Specifies the resource port')
    parser.add_argument('-seq', '--seq', type=int, default=1, help='Sets SEQ')
    parser.add_argument('-ttl', '--ttl', default=15, type=int, help='Sets the maximum time to live for package')
    parser.add_argument('-pkg', '--package_size', default=40, type=int, help='Sets a packet size')
    parser.add_argument('-try', '--retry', type=int, default=20,
                        help='Sets the maximum number of attempts to send a packet and obtain information about the end node')
    parser.add_argument('IP_ADDRESS', help='Sets the target IP address')


    args = parser.parse_args()
    # args = parser.parse_args("python main.py -p 80 -t 1 176.100.119.169".split())
    print(args)
    if not vars(args):
        parser.print_usage()
    else:
        traceroute = TraceRouter(args.IP_ADDRESS, args.port, args.seq, args.timeout, args.ttl)
        traceroute.get_trace()
