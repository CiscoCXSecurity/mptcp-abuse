import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from scapy.layers.inet import TCP, IP, Neighbor
from scapy.layers import mptcp
from scapy.sendrecv import sr1 
import random
from scapy.all import sr1
from netaddr import *
import netaddr

#TODO: add the ability to scan checksum support
#TODO: add the ability to scan HMAC or other auth support
#TODO: add the ability to test MP_Join through networks, maybe via different interfaces?
#TODO: Consider porting over the ability to do tracebox-like failure analysis
#TODO: Add optional host-up checks
#TODO: Change target IPs to plain targets (to allow for dns entries)
#TODO: Make sure all params are consistently ordered and named throughout
#TODO: add address/port randomisation (modulus ringbuffers)

#From mptcptestlib
def randintb(n):
    """Picks a n-bits value at random"""
    return random.randrange(0, 1L<<(n-1))

#From mptcptestlib
def getMpOption(tcp):
    """Return a generator of mptcp options from a scapy TCP() object"""
    for opt in tcp.options:
        if opt.kind == 30:
            yield opt.mptcp

#From mptcptestlib
def getMpSubkind(pkt, kind):
    """Return a generator of mptcp kind suboptions from pkt"""
    l4 = pkt.getlayer("TCP")
    for o in getMpOption(l4):
        if MPTCP_subtypes[o.subtype] == kind:
            yield (l4, o)

def makeMPCapableSyn(sourceAddr,dport,dstAddr, sport=None, initTCPSeq=None, \
                     sendKey=None):

    if sport is None: sport = randintb(16)
    if initTCPSeq is None: initTCPSeq = randintb(32)
    if sendKey is None: sendKey = randintb(32)
    #TODO: make more elegant type handling for IPADDR
    dstAddr = str(dstAddr)


    pkt = (IP(version=4L,src=sourceAddr,dst=dstAddr)/        \
        TCP(sport=sport,dport=dport,flags="S",seq=initTCPSeq, \
        options=[TCPOption_MP(mptcp=MPTCP_CapableSYN(
                            checksum_req=1,
                            snd_key=sendKey))]))
    return pkt



def makeJoinSyn(sourceAddr,dport,dstAddr, sport=None, initTCPSeq=None, \
                mptcpAddrId=None,isBackupFlow=False, \
                rcvToken=None,sendNonce=None):

    if sport is None: sport = randintb(16)
    if sendNonce is None: sendNonce = randintb(32)
    if initTCPSeq is None: initTCPSeq = randintb(32)
    if rcvToken is None: rcvToken = randintb(32)
    if sendNonce is None: sendNonce = randintb(32)
    if mptcpAddrId is None: mptcpAddrId = randintb(8)
    #TODO: make more elegant type handling for IPADDR
    dstAddr = str(dstAddr)

    pkt = (IP(version=4L,src=sourceAddr,dst=dstAddr)/        \
        TCP(sport=sport,dport=dport,flags="S",seq=initTCPSeq, \
        options=[TCPOption_MP(mptcp=MPTCP_JoinSYN(
                            addr_id=mptcpAddrId,
                            backup_flow=isBackupFlow,
                            rcv_token=rcvToken,
                            snd_nonce=sendNonce,))]))

    return pkt

'''Check via an invalid MP_JOIN request if it actually supports MPTCP

Returns True if it appears to support MPTCP
'''
def checkMPTCPSupportViaRST(port,target,timeout,localIP,MpCapAlreadyPassed=False):
    MpCapPassed = MpCapAlreadyPassed
    #TODO: Abstract this out more elegantly so i dont repeat code from elsewhere
    if not MpCapPassed:
        pkt = makeMPCapableSyn(localIP, port, target)
        response=sr1(pkt,timeout=timeout)
        if response and getMpOption(pkt.getlayer("TCP")) is not None:
            MpCapPassed = True

    if MpCapPassed:
        pkt = makeJoinSyn(localIP, port, target)
        response=sr1(pkt,timeout=timeout)
        #TODO: Add checks for other types of response (such as ICMP)
        #TODO: Make this clearer

        #Check for the flag with a mask
        print response.getlayer("TCP").flags
        if (0x04 & response.getlayer("TCP").flags) == 0x04:
            print "RST Test indicates MPTCP support"
            return True
        else:
            print "RST Test indicates host doesn't understand MPTCP"
            return False

'''
See if we can actually complete the MPTCP Handshake

If addstream is true we then see if we can add another stream to it

'''
def checkMPTCPSupportViaHandshake(port,Host,addStream=True):
    raise NotImplementedError

'''See if the other end reflects the correct options
in the reply '''
def processResponsePacketSimple(pkt,target,localIP,port,timeout,confirmMPTCPSupport=True):
    #print "Packet Received from ", targetIP, ":",port,"...",
    #print "Checking MPTCP response...",
    #TODO: move this to use an inbuilt list index
    #TODO: Abstract this out
    results=None
    tcpResp =  pkt.getlayer("TCP")
    mpHdrs = getMpOption(tcpResp)
    MPHdrCount = 0
    if tcpResp:
        for mpSubType in mpHdrs:
            if mpSubType is not None:
                results={}
                MPHdrCount += 1
                print " got MPTCP Response from ", target,":", port , "!... ",
                if confirmMPTCPSupport and checkMPTCPSupportViaRST(port,target,timeout,localIP):
                    results[port] = "MPTCP (MP_JOIN Verified)"
                else:
                    results[port] = "MPTCP"

    #If we have a tcp response, but No MPTCP Headers
    if tcpResp and MPHdrCount == 0:
        #If we do NOT have an RST
        if not (0x04 & pkt.getlayer("TCP").flags):
            results={}
            results[port] = "TCP"
            print "Got TCP ACK result"
        else:
            #Got a TCP RST"
            #TODO: Consider handling TCP RSTs?
            pass
    else:
        #No or non-tcp response
        #TODO: Add handling to whether we have ICMP
        #TODO: if we have ICMP then check if it contains MPTCP (indicating it reached the host)
        pass

    return results


'''Simple MPTCP Syn scan, see if the other end reflects the correct options
in the reply
'''
def defaultScan(targetIPList,portList,localIP=None,checkHostUp=True,reuseRandoms=False,timeout=None):
    #The option to reuse random numbers for "increased speed"
    if reuseRandoms:
        sourcAddr   = localIP
        sport       = randintb(16)
        initSeq     = randintb(32)

    if timeout is None: timeout=5

#Form of results
#     results = {"targetIP":
#                [{"porta","ResponseType"},
#                 {"porta","ResponseType"},
#                 {"porta","ResponseType"}
#                 ]
#                }

    results = {}

    for targetIP in targetIPList:
        print "Testing:", targetIP,
        localIP = localIP if localIP else get_local_ip_address(targetIP)

        gatewayIP = Route().route(str(targetIP))[2]
        if checkHostUp and gatewayIP == '0.0.0.0':
            print "... on local network...",
            arpadd = getmacbyip(str(targetIP))
            if arpadd == None:
                print " not got MAC, skipping"
                continue
            if arpadd == "ff:ff:ff:ff:ff:ff":
                print "This appears to be localhost?"
            else:
                print " at ARP:", arpadd
        else:
            print "Via", gatewayIP, " Not on local network"

        for port in portList:
            pkt = makeMPCapableSyn(localIP,port,targetIP)
            response=sr1(pkt,timeout=timeout)
            if response is None:
                pass
                #print "No pkt received from ", targetIP,":", port
            else:
                processedResponse = processResponsePacketSimple(response,targetIP,localIP,port,timeout)

                if targetIP in results:
                    if processedResponse is not None: results[targetIP].append(processedResponse)
                else:
                    if processedResponse is not None: results[targetIP] = [processedResponse]
            #if True or port % 100 == 0:
            #    print "\n\tChecking port: ", port
    return results


'''
This one's a bit craftier, send an incorrectly authenticated MP_JOIN option to
 an open port.
  - If the host at the other end ignores it then it is probably
     NOT mptcp enabled on that port.
  - If the host replies with a RST (indicating invalid auth) then we know it
      supports mptcp!

This can be used to check for tricky hosts of middleboxes
I need to think through the actual implications
'''
def joinScan(targetIPList,portList,localIP,reuseRandoms=False,timeout=None):
    #TODO: Add return details
    #TODO: Decide where this fits in the workflow, after an open TCP port maybe?
    #TODO: Decide how we want to handle the return values from this
    raise NotImplementedError
    #The option to reuse random numbers for "increased speed"
    if reuseRandoms:
        sourceAddr   = localIP
        sport       = randintb(16)
        initSeq     = randintb(32)

    if timeout is None: timeout=5

    for targetIP in targetIPList:
        for port in portList:
            #First send a packet and see if we get a TCP response
            pkt = makeMPCapableSyn(localIP,port,targetIP)
            response=sr1(pkt,timeout=timeout)
            if response is not None:
                #if we do then send an invalid MPTCP join and see if we get a RST
                pkt = makeJoinSyn(sourceAddr, port, targetIP)
                response2=sr1(pkt,timeout=timeout)
                #If we get a RST then we know this host supports MPTCP
                if response2 is None:
                    print "Target supports MPTCP but is being shifty"
                #If we get a normal TCP reply we know it doesn't
                else:
                    mpopt = getMpOption(pkt.getlayer("TCP"))
                    if mpopt is None:
                        print "We have a normal TCP packet here"
                    else:
                        print "This header contains the following MPTCP options:",
                        for mpo in mpopt:
                            print mpo.name
                #If we get an MPACK then the host is HORRIBLY broken somehow
            else:
                #If we don't then this is just a vanilla TCP
                print "The host seems down?"

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

    parser = argparse.ArgumentParser(description='Network scanner to test hosts for multipath TCP support. Requires root privileges for scapy.')
    parser.add_argument("--ip", action="store", dest="src_ip", help="use the specified source IP for all traffic")
    parser.add_argument('host', action="store",
                        help='comma-separated IPs or ranges (globs allowed), eg "127.0.0.1,192.168.1-254,203.0.113.*"')
    parser.add_argument('port', action="store",
                        help='comma-separated port(s) or port ranges, eg "22,80,8000-8999"')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    host_entries = (netaddr.glob_to_iprange(host_entry) for host_entry in args.host.split(","))
    hosts = list(itertools.chain(*host_entries))

    port_entries =  (port_entry for port_entry in args.port.split(","))
    ports = []
    for port_entry in port_entries:
        if "-" not in port_entry:
            ports.append(int(port_entry))
        else:
            begin, end = port_entry.split("-")
            ports += range(int(begin), int(end)+1)

    return hosts, ports, args.src_ip

def main():
    hosts, ports, source_ip = parse_args()
    #TODO: Add support for multiple IPs
    #TODO:make removing the network and broadcast addesses less clunky
    #Right now they should be removed by the iter_hosts calls later on
    results = defaultScan(hosts, ports, source_ip,timeout=0.01,reuseRandoms=True)
    print "****Results:****"
    for k in results:
        print "\t", str(k)
        for port in results[k]:
            print "\t\t\t", port

if __name__ == "__main__":
    main()
# vim: set ts=4 sts=4 sw=4 et:
