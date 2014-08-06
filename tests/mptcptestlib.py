#!/usr/bin/env python2
import traceback, sys
from scapy.all import *
from tests.core import *
import hashlib
import hmac
import math
import socket

# Helper functions ###########################################################

def genhmac2(k1, k2, r1, r2):
    """Generate and return a HMAC-SHA1 with the concatenation of k1 and k2
    as key and the concatenation of r1 and r2 as message.

    k1, k2 are 64bits integers
    r1, r2 are 32bits integers
    Return a 160bits integer
    """
    key = xstr(k1).rjust(8,'\00') + xstr(k2).rjust(8,'\00')
    msg = xstr(r1).rjust(4,'\00') + xstr(r2).rjust(4,'\00')
    return xlong(hmac.new(key, msg=msg, digestmod=hashlib.sha1).digest())
def genhmac(k1, k2, r1, r2):
    """Generate and return a HMAC-SHA1 with the concatenation of k1 and k2
    as key and the concatenation of r1 and r2 as message.

    k1, k2 are 64bits integers
    r1, r2 are 32bits integers
    Return a 160bits integer
    """
    key = xstr(k1).rjust(8,'\00') + xstr(k2).rjust(8,'\00')
    msg = xstr(r1).rjust(4,'\00') + xstr(r2).rjust(4,'\00')
    return xlong(hmac.new(key, msg=msg, digestmod=hashlib.sha1).digest())

def key2tokenAndDSN(key):
    """Returns the token and dsn from a key
    Generate a simple SHA1 hash of the key

    key is a 64bits integer
    Token is a 32bits integer, dsn is a 64bits integer
    """
    import binascii
    keystr = struct.pack("!Q", key)
    h = hashlib.sha1(keystr.rjust(8,'\00'))
    shastr=h.digest() # binary
    #shastr = struct.pack("!IIIII", *struct.unpack("@IIIII",shastr)) #to net
    token, dsn = shastr[0:4], shastr[-8:]
    #print "raw: %s (len=%i)"%(shastr,len(shastr))
    #print "hex: %s"% binascii.hexlify(token), "%s"%binascii.hexlify(dsn)
    d1, d2 = struct.unpack("!II",dsn)
    #print "d1 is ", d1
    #print "d2 is", d2
    #It looks like d2 should be the IDSN32 for this key
    #Cpearce this is the old line
    #token, dsn = (struct.unpack("!I",token)[0], (long(d2)<<32)+d1)
    #CMP - Switching order and also adding one to the DSN to allow for
    #the SYN flag's effect
    token, dsn = (struct.unpack("!I",token)[0], (long(d1)<<32)+d2 + 1)
    #print "token: %x"% token
    #print "dsn: %x" % dsn
    #sys.exit()

    return (token, dsn)


def getMpOption(tcp):
    """Return a generator of mptcp options from a scapy TCP() object"""
    for opt in tcp.options:
        if opt.kind == 30:
            yield opt.mptcp

def getMpSubkind(pkt, kind):
    """Return a generator of mptcp kind suboptions from pkt"""
    l4 = pkt.getlayer("TCP")
    for o in getMpOption(l4):
        if MPTCP_subtypes[o.subtype] == kind:
            yield (l4, o)

def checkAndGetMPOption(pkt, kind):
    """Return the first option of subkind kind in pkt
    If no such option exist, an exception is raised"""
    try:
        return getMpSubkind(pkt, kind).next()
    except StopIteration:
        raise Exception("MPTCP option of kind %s not found."%kind)

def genDSSChecksum(dsn, ssn, datalen, payload):
    """Generate a DSS Checksum on a data according to current state"""
    header = struct.pack("!QIHH", dsn, ssn, datalen, 0)
    return checksum(header+payload)

def getDataAckForPkt(s, sub, l4, plen, f=False):
    # should update the data_ack only if the map is relative to this
    # data segment.

    #Cpearce - COnverting to use the remote seq instead of the local
#     if  sub["map"] and (
#             l4.seq > sub["map"]["subseq"]+sub["startseq"]\
#          and \
#             l4.seq < sub["map"]["subseq"]+sub["startseq"] + plen\
#          or \
#             f\
#          ):

    if  sub["map"] and (
            l4.seq >= sub["map"]["subseq"]+sub["rem_startseq"]\
         and \
            l4.seq < sub["map"]["subseq"]+sub["rem_startseq"] + plen\
         or \
            f\
         ):
        if f and sub["map"]["subseq"] == 0:
            subseq = 1
        else: subseq = sub["map"]["subseq"]
        #print sub
        ret = sub["map"]["dsn"] \
                + (l4.seq -(subseq+sub["rem_startseq"])) \
                + plen + 1
    else:
        print "--- alredy acked, acking again"
        ret = s["data_ack"]
    return ret

def get32bitSeq(seq64):
    seq32 = seq64 % (1 << 32)
    return seq32

def kernelEstablishConn(t, mptcp, s, dst=None, dport=80):
    """Make the kernel establish a TCP connection (MPTCP if available in
    the kernel) to dst"""
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exchange = [mptcp.cap_syn, mptcp.cap_synack, mptcp.ack]
    self.sock.connect((dst, dport))

#############################################################################

class MPTCPTest(object):
    """MPTCP Test library

    Set of methods to test an MPTCP extension implementation.
    It works together with the test framework.
    Each method uses and maintains a connection state. Every data useful for
    the packet generation should be stored in that object.
    It also contains a model of the last received packet if there is one.
    Operations involving subflows are provided with a specific subflow state."""

    def __init__(self, tester=None, initstate=None):
        self.tester = tester
        tester.proto = self
        if initstate is None:
            initstate = MPTCPState()
        tester.state = initstate

        self.DefaultPacket = self.TCPPacket
        self.Ack = self.TCPPacket
        self.Push = self.TCPPacket

    def findProtoLayer(self, pkt):
        """Return an iterator on representations of proto components to
        consider"""
        mp=getMpOption(pkt.getlayer("TCP"))
        i=0
        for p in mp:
            i += 1
            yield p
        if i==0:
            yield pkt.getlayer("TCP")


    def getClassFromPkt(self, p, pkt):
        if isinstance(p, MPTCP_DSS_Map64_AckMapCsum):
            return MPTCPTest.DSS
        if isinstance(p, TCP):
            return MPTCPTest.TCPPacket

    class CapSYN(ProtoLibPacket, MPTCP_CapableSYN):
        def generate(self, s, timeout=None, sub=None):
            """Generate a Multipath Capable SYN segment

            First packet of the three-way TCP connection negotiation
            It decides of the initial sequence number and of one of the 2 keys
            used to auth the hosts in further subflows creations."""

            if sub is None:
                sub = s.getDefaultSubflow()

            s["snd_key"] = randintb(64)
            s["snd_token"], s["dsn"] = key2tokenAndDSN(s["snd_key"])
            #print "Sender's key:", s["snd_key"]
            #print "Sender's token:", s["snd_token"]
            #print "Sender's DSN:", s["dsn"]
            sub["startseq"] = sub["seq"] = randintb(32)

            # generate the segment with scapy
            pkt = IP(version=4L,dst=sub["dst"], src=sub["src"])/ \
                    TCP(dport=sub["dport"],
                        sport=sub["sport"],
                        flags="S",
                        seq=sub["seq"],
                        options=[TCPOption_MP(mptcp=MPTCP_CapableSYN(
                            checksum_req=1,
                            snd_key=s["snd_key"]))]
                        )
            sub["seq"] = (sub["seq"]+1) % (1<<32)

            # Identifies this connection stage (packet type) by a name
            s["stage"] = "MP_CAPABLE SYN"
            # The destination is expected to reply to this packet
            #waitForReply = False
            waitForReply = True
            return (pkt, waitForReply)

        def recv(self, s, pkt):
            # retrieve reply's data
            sub = s.getSubflowFromPkt(pkt)
            (l4, opt) = checkAndGetMPOption(pkt, "MP_CAPABLE")

            s["rcv_key"] = opt.snd_key
            s["rcv_token"], s["data_ack"] = key2tokenAndDSN(s["rcv_key"])
            sub["rem_startseq"] = l4.seq
            sub["ack"] = l4.seq+1

    class CapSYNACK(ProtoLibPacket, MPTCP_CapableSYNACK):
        def generate(self, s, timeout=None, sub=None):
            """Generate a Multipath Capable SYN/ACK segment

            Second packet of the three-way TCP connection negotiation
            """
            if sub is None:
                sub = s.getDefaultSubflow()

            # retrieve reply's data
            s["snd_key"] = randintb(64)
            s["snd_token"], s["dsn"] = key2tokenAndDSN(s["snd_key"])
            sub["startseq"] = sub["seq"] = randintb(32)

            pkt = IP(version=4L,dst=sub["dst"], src=sub["src"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags="SA",
                        seq=sub["seq"],
                        ack=sub["ack"],
                        options=[TCPOption_MP(mptcp=MPTCP_CapableSYNACK(
                            snd_key=s["snd_key"],))]
                        )
            sub["seq"] = (sub["seq"]+1) % (1<<32)
            s["stage"] = "MP_CAPABLE SYNACK"
            waitForReply = False
            return (pkt, waitForReply)


        def recv(self, s, pkt):
            # retrieve reply's data
            sub = s.getSubflowFromPkt(pkt)
            (l4, opt) = checkAndGetMPOption(pkt, "MP_CAPABLE")

            s["rcv_key"] = opt.snd_key
            s["rcv_token"], s["data_ack"] = key2tokenAndDSN(s["rcv_key"])
            sub["ack"] = l4.seq+1
            sub["rem_startseq"] = l4.seq # FIXME: is reached?
            #print "Received Key is:", s["rcv_key"]
            #print "Received dataack is:", s["data_ack"]
            #print "Received token is:",s["rcv_token"]



    class CapACK(ProtoLibPacket, MPTCP_CapableACK):
        def generate(self, s, timeout=None, sub=None):
            """Generate a Multipath Capable ACK segment

            Third packet of the three-way TCP connection negotiation
            It uses the 2nd packet (syn/ack) to generate the new sequence numbers
            (seq and ack). Also, it stores the mptcp key chosen by the other peer.
            If MPTCP cant be found in the previous packet, an exception is raised."""
            if sub is None:
                sub = s.getDefaultSubflow()

            pkt = IP(version=4L,dst=sub["dst"], src=sub["src"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags="A",
                        seq=sub["seq"],
                        ack=sub["ack"],
                        options=[TCPOption_MP(mptcp=MPTCP_CapableACK(
                            snd_key=s["snd_key"],
                            rcv_key=s["rcv_key"]))])
            s["stage"] = "MP_CAPABLE ACK"
            #print "*******suback" + str(sub["ack"])
            #print "*******subseq" + str(sub["seq"])

            #sub["seq"] = (sub["seq"]+1) % (1<<32)
            # No reply is expected to this packet
            waitForReply = False
            return (pkt, waitForReply)

        def recv(self, s, pkt):
            # retrieve reply's data
            (l4, opt) = checkAndGetMPOption(pkt, "MP_CAPABLE")
            sub = s.getSubflowFromPkt(pkt)
            sub["ack"] = l4.seq+1
            #print "*******l4ack" + str(l4.seq)
            s["rcv_token"], s["data_ack"] = key2tokenAndDSN(s["rcv_key"])


    class JoinSYN(ProtoLibPacket, MPTCP_JoinSYN):
        def generate(self, s, timeout=None, sub=None):
            """Generate a Multipath Join SYN segment

            First packet of the subflow creation negotiation
            It computes the other host's token on basis of the stored keys from
            the mptcp state. It chooses a nonce and send it along the token in the
            MP_JOIN option. Another initial data sequence number is picked as the
            subflow constitutes an other TCP connection"""

            if sub is None:
                sub = s.getDefaultSubflow()

            sub["startseq"] = sub["seq"] = randintb(32)
            sub["snd_nonce"] = randintb(32)
            sub["addr_id"] = 0
            sub["backup_flow"] = 0

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(sport=sub["sport"],
                    dport=sub["dport"],
                    flags="S",
                    seq=sub["seq"],
                    options=[TCPOption_MP(mptcp=MPTCP_JoinSYN(
                        addr_id=sub["addr_id"],
                        backup_flow=sub["backup_flow"],
                        rcv_token=s["rcv_token"],
                        snd_nonce=sub["snd_nonce"],))])
            sub["seq"] = (sub["seq"]+1) % (1<<32)
            s["stage"] = "MP_JOIN SYN"
            waitForReply = True
            return (pkt, waitForReply)

        def recv(self, s, pkt):
            (l4, opt) = checkAndGetMPOption(pkt, "MP_JOIN")
            sub = s.getSubflowFromPkt(pkt)
            sub["ack"] = l4.seq+1
            sub["addr_id"] = opt.addr_id
            sub["backup_flow"] = opt.backup_flow
            sub["rcv_nonce"] = opt.snd_nonce
            sub["rem_startseq"] = l4.seq


    class JoinSYNACK(ProtoLibPacket, MPTCP_JoinSYNACK):
        def generate(self, s, timeout=None, sub=None):
            """Generate a Multipath Join SYN/ACK segment

            Second packet of the subflow creation negotiation
            In a similar way to the first packet, it picks a nonce and send it
            as a cryptographic challenge for the other host.
            It auths itself by sending a 64bits truncated MAC generated with the
            keys, the received and the newly-picked nonce.
            """
            if sub is None:
                sub = s.getDefaultSubflow()

            sub["startseq"] = sub["seq"] = randintb(32)
            sub["snd_nonce"] = randintb(32)
            sub["snd_mac"] = genhmac(
                                    s["snd_key"],s["rcv_key"],
                                    sub["snd_nonce"],sub["rcv_nonce"])

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(sport=sub["sport"],
                    dport=sub["dport"],
                    flags="SA",
                    seq=sub["seq"],
                    ack=sub["ack"],
                    options=[TCPOption_MP(mptcp=MPTCP_JoinSYNACK(
                        addr_id=sub["addr_id"],
                        backup_flow=sub["backup_flow"],
                        snd_mac64=sub["snd_mac"]>>(160-64),
                        snd_nonce=sub["snd_nonce"],))
                        ])
            sub["seq"] = (sub["seq"]+1) % (1<<32)
            s["stage"] = "MP_JOIN SYNACK"

            waitForReply = False
            return (pkt, waitForReply)

        def recv(self, s, pkt):
            (l4, opt) = checkAndGetMPOption(pkt, "MP_JOIN")
            sub = s.getSubflowFromPkt(pkt)

            sub["ack"] = l4.seq+1
            sub["rcv_nonce"] = opt.snd_nonce
            sub["rem_startseq"] = l4.seq


    class JoinACK(ProtoLibPacket, MPTCP_JoinACK):
        def generate(self, s, timeout=None, sub=None):
            if sub is None:
                sub = s.getDefaultSubflow()
            sub["snd_mac"] = genhmac(
                                    s["snd_key"],s["rcv_key"],
                                    sub["snd_nonce"],sub["rcv_nonce"])

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(sport=sub["sport"],
                    dport=sub["dport"],
                    flags="A",
                    seq=sub["seq"],
                    ack=sub["ack"],
                    options=[TCPOption_MP(mptcp=MPTCP_JoinACK(
                        snd_mac=sub["snd_mac"],))])
            s["stage"] = "MP_JOIN ACK"
            #sub["seq"] = (sub["seq"]+1) % (1<<32)
            #return (pkt, False) # FIXME : should be True according to draft
            waitForReply = False
            return (pkt, waitForReply)

        def recv(self, s, pkt):
            (l4, opt) = checkAndGetMPOption(pkt, "MP_JOIN")
            sub = s.getSubflowFromPkt(pkt)

            sub["ack"] = l4.seq #+1



    class DSSACK(ProtoLibPacket, MPTCP_DSS_Ack, MPTCP_DSS_Ack64):
        def generate(self, s, payload="", timeout=None, sub=None, a=False, f=False,
                waitAck=False):
            """Data Sequence Signal segment. Data are pushed in this type of
            segment. This uses the ACK-only variant"""
            if sub is None:
                sub = s.getDefaultSubflow()

            if a:
                data_ack = s["data_ack"]
                flags="aA"
                DSSPacket = MPTCP_DSS_Ack64
            else:
                data_ack = get32bitSeq(s["data_ack"])
                flags = "A"
                DSSPacket = MPTCP_DSS_Ack
            if f:
                flags += "F"

            mptcpDSS = DSSPacket(flags=flags,
                            data_ack=data_ack)

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags="A%s"%("P" if payload else ""),
                        seq=sub["seq"],
                        ack=sub["ack"],
                        options=[TCPOption_MP(mptcp=mptcpDSS)]
                        )/ payload

            #print "ACK is: ", ack

            s["stage"] = "DSS ACK"
            sub["seq"] += len(payload)
            s["dsn"] += len(payload)
            if f: s["dsn"] += 1 # draft: a DATA_FIN is accounted at data-level
            return (pkt, True if payload or f else False)

        def recv(self, s, pkt):
            (l4, opt) = checkAndGetMPOption(pkt, "DSS")
            return MPTCPTest.TCPPacket().recv(s, pkt)


    class DSSMAP(ProtoLibPacket, MPTCP_DSS_MapCsum, MPTCP_DSS_Map64Csum):
        def generate(self, s, payload, length, checksum, sub, m=False,
                f=False, timeout=None, waitAck=False):
            """Data Sequence Signal segment. Data are pushed in this type of
            segment. This uses the Map-only variant"""
            if m:
                flags="mM"
                dsn = s["dsn"]
                DSSPacket = MPTCP_DSS_Map64Csum
            else:
                dsn = get32bitSeq(s["dsn"])
                flags = "M"
                DSSPacket = MPTCP_DSS_MapCsum
            if f:
                flags += "F"

            mptcpDSS = DSSPacket(flags=flags,dsn=dsn,
                            subflow_seqnum=sub["seq"]-sub["startseq"],
                            datalevel_len=length,checksum = checksum)

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags="A%s"%("P" if payload else ""),
                        seq=sub["seq"],
                        ack=sub["ack"],
                        options=[TCPOption_MP(mptcp=mptcpDSS)]
                        )/ payload

            sub["seq"] += len(payload)
            s["dsn"] += len(payload)
            return (pkt, waitAck)

        def recv(self, s, pkt):
            #TODO: add handling for acking things already received
            print "ABC Received a DSSMAP macket..."
            (l4, opt) = checkAndGetMPOption(pkt, "DSS")
            sub = s.getSubflowFromPkt(pkt)
            plen = len(l4.payload)
            # TCP-level FIN accounting
            if "F" in l4.sprintf("%TCP.flags%"):
                plen += 1
            sub["ack"] = l4.seq+plen
            # Data-level FIN accounting (what about combination FIN+DataFIN?)
            if flagIn(opt.flags, "F"):
                plen += 1
            if not plen>0: return
            #print "long(s[data_ack]&0xFFFFFFFF00000000) is:" + str(s["data_ack"]&0xFFFFFFFF00000000)
            sub["map"] = {
                    "dsn":long(long(s["data_ack"]&0xFFFFFFFF00000000)|get32bitSeq(opt.dsn)),
                    "subseq":opt.subflow_seqnum,
                    "datalen": opt.datalevel_len}
            #print " --- Data Len  is:" + str(int(opt.datalevel_len))
            #print " --- Data Ack before is:" + str(long(s["data_ack"] & 0xFFFFFFFF))
            s["data_ack"] = getDataAckForPkt(s, sub, l4, plen,f=True if
                    flagIn(opt.flags, "F") else False)
            #print " -- Data Ack after  is:" + str(long(s["data_ack"] & 0xFFFFFFFF)) + "\n"
            #Cpearce inserted the following line but i think it's wrong
            #if s["data_ack"]: s["data_ack"] += 1
            #TODO: This line is almost certainlythe wrong behaviour
            if flagIn(opt.flags, "F"): return MPTCPTest.FIN
            return MPTCPTest.DSSACK

    class DSSFIN(ProtoLibPacket):
        """Regular standalone DataFIN, a map, an data ack, no payload"""
        def generate(self, s, timeout=None, sub=None):
            if sub is None:
                sub = s.getDefaultSubflow()

            p = MPTCPTest.DSS()
            checksum = genDSSChecksum(s["dsn"], 0, 1, "")
            (pkt, wait) = p.generate(s, payload="", length=1, checksum=checksum, sub=sub,
                    subseq=0,
                    f=True)
            waitForReply = False
            return (pkt, waitForReply)

        #TODO: Make sure this works
        def recv(self, s, pkt):
            print "Received a finack!"
            sub = s.getSubflowFromPkt(pkt)
            sub.unRegisterSubFlow(sub)
            #TODO: fix this so it actually responds with a packet
            return MPTCPTest.FIN().generate(s, pkt)
            pass



    DSSFINACK = DSSFIN


    class DSS(ProtoLibPacket, MPTCP_DSS, #MPTCP_DSS_AckMapCsum,
            MPTCP_DSS_Map64_AckMapCsum, MPTCP_DSS_Ack64MapCsum): #MPTCP_DSS_AckMap64Csum):
        def generate(self, s, payload, length, checksum, sub, subseq=-1,a=False,
                m=False, f=False, waitAck=False, timeout=None):
            """Data Sequence Signal segment. Data are pushed in this type of
            segment. This uses the Map+Ack variant"""
            if subseq < 0:
                subseq=sub["seq"]-sub["startseq"]

            flags = "AM"
            data_ack = get32bitSeq(s["data_ack"])
            dsn = get32bitSeq(s["dsn"])
            DSSPacket = MPTCP_DSS_AckMapCsum
            if a:
                flags+="a"
                data_ack = s["data_ack"]
                DSSPacket = MPTCP_DSS_Ack64MapCsum
            if m:
                flags+="m"
                dsn = s["dsn"]
                DSSPacket = MPTCP_DSS_AckMap64Csum
            if a and m:
                DSSPacket = MPTCP_DSS
            if f:
                flags += "F"

            mptcpDSS = DSSPacket(flags=flags, data_ack=data_ack, dsn=dsn,
                    subflow_seqnum=subseq,
                    datalevel_len=length, checksum = checksum)

            pkt = IP(version=4L,src=sub["src"],dst=sub["dst"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags="A%s"%("P" if payload else ""),
                        seq=sub["seq"],
                        ack=sub["ack"],
                        options=[TCPOption_MP(mptcp=mptcpDSS)]
                        )/ payload

            s["stage"] = "DSS MAP+ACK"
            plen = len(payload)
            sub["seq"] += plen
            s["dsn"] += plen

            #print "mptcptestlib:547---"
            #print "Data length is: " + str(plen)
            #print "Sub(seq) is: " + str(sub["seq"])
            #print "Sub(ack) is: " + str(sub["ack"])

            if f: s["dsn"] += 1 # draft: a DATA_FIN is accounted at data-level
                                # but not at the subflow level.
            return (pkt, waitAck)

        def recv(self, s, pkt):
            #same as MAP since there is no handling of DATA_ACK received
            #TODO: FIX THIS and make sure it handles the ack!
            #TODO: add handling for already acked data
            return MPTCPTest.DSSMAP().recv(s, pkt)


    def send_data_sub(self, s, data, sub=None, imap=[0], waitAck=False,timeout=None):
        """Send data using subflow sub. Split in several TCP segments if datalength is
        greater than mss"""
        if sub is None: sub = s.getDefaultSubflow()
        length = len(data)
        checksum = genDSSChecksum(s["dsn"], sub["seq"]-sub["startseq"],
                                length, data)
        mem = [] # to retrieve the packet sent and rcvd from scenario context
        i = 0
        while data:
            payload, data = data[0:sub["mss"]], data[sub["mss"]:]
            # The map is sent along only for the (i+1)th segments from imap
            if i in imap:
                mem.append(self.tester.sendpkt(self.DSS, s, payload=payload,
                    length=length, checksum=checksum,
                    sub=sub, waitAck=waitAck,timeout=None))
            else:
                mem.append(self.tester.sendpkt(self.Push, s, payload=payload,
                    sub=sub, waitAck=waitAck,timeout=None))
            i += 1
        return mem


    def send_data(self, s, data="", waitAck=False, timeout=None):
        """Send data using all necessary subflows to minimize packets sent on each
        interface"""
        mem = [] # to retrieve the packet sent and rcvd from scenario context
        subn = len(s.sub)
        pktlen = int(math.ceil(len(data)/float(subn)))
        for subflow in s.sub:
            payload, data = data[0:pktlen], data[pktlen:]
            mem.extend(self.send_data_sub(s, data=payload, sub=subflow,
                waitAck=waitAck))
        return mem


    class TCPPacket(ProtoLibPacket, TCP):
        def generate(self, s, payload="", sub=None, f=False, timeout=None, waitAck=False,rst=False):
            """Generate a regular TCP segment"""

            if sub is None:
                sub = s.getDefaultSubflow()

            flags = "A"
            if f: flags+="F"
            if rst: flags+= "R"
            if payload: flags+="P"

            pkt = IP(version=4L,dst=sub["dst"], src=sub["src"])/ \
                    TCP(
                        sport=sub["sport"],
                        dport=sub["dport"],
                        flags=flags,
                        seq=sub["seq"],
                        ack=sub["ack"]) \
                    / payload
            s["stage"] = "TCP"
            plen = len(payload)
            if f: plen += 1
            sub["seq"] += plen
            s["dsn"] += plen

            if f or waitAck: # or payload
                waitForReply = True
            else:
                waitForReply = False

            return (pkt, waitForReply)

        def recv(self, s, pkt):
            # retrieve reply's data
            l4 = pkt.getlayer("TCP")
            sub = s.getSubflowFromPkt(pkt)
            if not Raw in pkt:
                plen = 1
            else:
                plen = len(l4.payload)
            sys.exit
            if "F" in l4.sprintf("%TCP.flags%"):
                plen += 1
            rst=False
            if "R" in l4.sprintf("%TCP.flags%"):
                rst = True
            #print "Old ACK is:", sub["ack"]
            sub["ack"] = l4.seq+plen
            #print "New ACK is:", sub["ack"]
            if not plen>0: return
            s["data_ack"] = getDataAckForPkt(s, sub, l4, plen)

            if rst:
                p = MPTCPTest.RST()
                return p.generate(s, payload="", sub=sub, f=True,rst=True)
            else:
                return MPTCPTest.DSSACK

    ACK = TCPPacket

    class FINACK(ProtoLibPacket):
        """Regular standalone DataFIN, a map, an data ack, no payload"""
        def generate(self, s, timeout=None, sub=None):
            if sub is None:
                sub = s.getDefaultSubflow()
            p = MPTCPTest.TCPPacket()
            return p.generate(s, payload="", sub=sub, f=True)

        #TODO:Need to add elegant inheritance as there
        #is for other cascades (e.g. dss)
        #TODO: Need to add handling in case we still have data to send!
        def recv(self,s,pkt):
            print "Received a finack!"
            sub = s.getSubflowFromPkt(pkt)
            sub.unRegisterSubFlow(sub)
            #TODO: fix this so it actually responds with a packet
            return MPTCPTest.FIN().generate(s, pkt)



    class FIN(ProtoLibPacket):
        #TODO: Check/add handling for the sequence numbers for FIN flags
        def generate(self, s, timeout=None, sub=None):
            """Generate a regular TCP FIN segment"""
            p = MPTCPTest.TCPPacket()
            return p.generate(s, payload="", sub=sub, f=True)


        #TODO: Need to add handling in case we still have data to send!
        #TODO: Make sure we handle correctly when we have to reply with a reset
        #TODO: Make sure we handle correctly when we have to reply with an ack
        def recv(self,s,pkt):
            raise NotImplementedError
            #sub = s.getSubflowFromPkt(pkt)


    #TODO: Check RST even works, CMP had to add it in....
    class RST(ProtoLibPacket):
        def generate(self, s, timeout=None, sub=None):
            """Generate a regular TCP RST segment"""
            p = MPTCPTest.TCPPacket()
            return p.generate(s, payload="", sub=sub, rst=True)


        #TODO: Need to add handling in case we still have data to send!
        def recv(self,s,pkt):
            print "Received an RST"
            sub = s.getSubflowFromPkt(pkt)
            sub.unRegisterSubFlow(sub)

    class Wait(ProtoLibPacket):
        def generate(self, s, sub=None, waitfct=None, timeout=2,
                buffermode=False):
            if waitfct:
                if sub is None:
                    return (None, (waitfct, timeout, buffermode))

                return (None, (lambda pkt: s.isPacketFromSubflow(pkt) and
                        waitfct(pkt), timeout, buffermode))
            if sub is None:
                # accept packets from existing connection or new (SYN)
                return (None, (lambda pkt: pkt.haslayer(TCP) and
                        (pkt.sprintf("%TCP.flags%") == "S" or
                        s.isPacketFromConnection(pkt)), timeout, buffermode))
            else:
                return (None, lambda pkt: sub.isPacketFromSubflow(pkt))

        @classmethod
        def filterOnSubflow(cls, sub):
            """Filter arriving packets for subflow sub.
            To put as value for waitfct argument of
            Wait.generate()"""
            return lambda pkt: sub.isPacketFromSubflow(pkt)

        @classmethod
        def filterOnConnection(cls, s):
            """Filter arriving packets for connection s.
            To put as value for waitfct argument of
            Wait.generate()"""
            return lambda pkt: s.isPacketFromConnection(pkt)

        @classmethod
        def waitAckForPkt(cls, s, oldpkt):
            """Filter arriving ACK packets if they ack oldpkt.
            (only at the TCP sequence level)"""
            sub = s.getSubflowFromPkt(oldpkt)
            def filterfct(pkt):
                l4 = pkt.getlayer(IP)
                # FIXME: no offset ?
                #TODO: Cpearce confirm adding 1 fixed it
                #print "Subseq: " + str(sub["seq"]) + " Suback: " + str(sub["ack"])
                #print "recseq: " + str(l4.seq) + " recack: " + str(l4.ack)

                #print "Received ack for " + str(l4.ack) + " but expected " + str(sub["seq"])

                if sub["seq"] == l4.ack:# \
                        #and l4.seq == sub["ack"]:
                    print "Received ack!"
                    return True
                print "Non-matching packet received"
                return False
            return filterfct


class SubflowState(ProtoState):
    def __init__(self, mpconn, initstate={},conf=None):
        if conf: ProtoState.__init__(self, initstate=initstate, conf=conf)
        else: ProtoState.__init__(self, initstate=initstate)
        self.mpconn = mpconn # ref to mptcp connection state
        self.name = "Subflow"

    def initAttr(self):
        # per subflow
        self.d["snd_nonce"] = 0
        self.d["rcv_nonce"] = 0
        self.d["snd_mac"] = 0
        self.d["rcv_mac"] = 0
        self.d["seq"] = 0
        self.d["startseq"] = 0
        self.d["ack"] = 0
        self.d["mss"] = 500 # adjust to make more or less packets
        self.d["map"] = {}


    def getId(self):
        return (self.d["dst"], self.d["src"], self.d["dport"],
                self.d["sport"])

    def getIndex(self):
        return self.mpconn.sub.index(self)

    def isPacketFromSubflow(self, rawpkt):
        if not rawpkt.haslayer(TCP): return False
        pkt = rawpkt.getlayer("IP")
        tupleid = self.getId()
        if not pkt:
            print "No or invlaid packet?"
            return False
        self.debug("tuple: %s, should match %s"%(tupleid, (pkt.src, pkt.dst,
                pkt.sport, pkt.dport)),level=4)
        if tupleid == (pkt.dst, pkt.src, pkt.dport, pkt.sport) or \
                tupleid == (pkt.src, pkt.dst, pkt.sport, pkt.dport):
            self.debug("yes.", level=4)
            return True
        self.debug("no.", level=4)
        return False

    def invertState(self):
        """Generate a new state inverted from the current. Might be useful to
        send to other end in some cases"""
        return SubflowState(mpconn=self.mpconn,
                initstate={"dst": self["src"], "src":self["dst"],
                    "dport":self["sport"],"sport":self["dport"]
                })

    def __setitem__(self, attr, val):
        ProtoState.__setitem__(self, attr, val)
        #TODO See if this needs to be uncommented -- cpearce
        #if self.d["dst"] == self.d["src"]:
        #    raise Exception("You're sending back to yourself!")

    def __repr__(self):
        return str(self.d)

    def __str__(self):
        return str(self.d)


class MPTCPState(ProtoState):
    def __init__(self, initstate={}, conf=None):
        if conf: ProtoState.__init__(self, initstate=initstate, conf=conf)
        else: ProtoState.__init__(self, initstate=initstate)
        self.sub = []
        self.default = 0
        self.name = "MPTCP Connection"

    def initAttr(self):
        # auth
        self.d["rcv_token"] = 0
        self.d["snd_token"] = 0
        self.d["snd_key"] = 0
        self.d["rcv_key"] = 0

        # DSS related
        self.d["dsn"] = 0
        self.d["subflow_seqnum"] = 0
        self.d["datalevel_len"] = 0
        self.d["data_ack"] = 0

    def createSubflow(self, dst, src, dport=80, sport=0):
        if sport == 0: sport = random.randrange(1025,2<<15)
        return SubflowState(mpconn=self,
                initstate={"dst":dst, "src":src, "dport":dport,"sport":sport})

    def registerSubflow(self, ss):
        for sub in self.sub:
            if ss.getId() == sub.getId():
                self.debug("subflow %s already exists" % ss.getId())
                return sub
        else:
            self.sub.append(ss)
            ss.name = "Subflow #%i" % ss.getIndex()
        return ss

    def unRegisterSubflow(self, ss):
        raise NotImplementedError


    def registerNewSubflow(self, **kargs):
        return self.registerSubflow(self.createSubflow(**kargs))

    def getSubflow(self, subflow):
        if type(subflow) is int:
            if subflow < len(self.sub):
                return self.sub[subflow]
        return None

    def getDefaultSubflow(self):
        return self.sub[self.default]

    def setDefaultSubflow(self, ss):
        self.default = self.sub.index(ss)

    def newSubflowFromRcvdPkt(self, pkt):
        """create a sufblow state from data received in previous packet.
        and return its pair (id, subflowstate)"""
        return self.registerNewSubflow(dst=pkt.src, src=pkt.dst, dport=pkt.sport,
                sport=pkt.dport)

    def getSubflowFromPkt(self, pkt):
        """return the subflow on which the packet has been received"""
        if self.sub:
            for sub in self.sub:
                if sub.isPacketFromSubflow(pkt):
                    return sub
        return self.newSubflowFromRcvdPkt(pkt)

    def isPacketFromConnection(self, pkt):
        for sub in self.sub:
            if sub.isPacketFromSubflow(pkt):
                return True
        return False

    def invertState(self):
        """Generate a new state inverted from the current. Might be useful to
        send to other end in some cases"""
        return MPTCPState({
                "snd_key":self["rcv_key"], "rcv_key": self["snd_key"],
                "dst": self["src"], "src":self["dst"], "dport":self["dport"],
                })

    def update(self, extrastate):
        """Update the current state with the extrastate. Extrastate must be a
        ProtoState derivative"""
        ProtoState.update(self, extrastate)
        if type(extrastate) is type(self):
            self.sub = extrastate.sub
        return self

    def logPacket(self, pkt):
        self.d["prev_pkt"] = pkt
        sub = self.getSubflowFromPkt(pkt)
        self.setDefaultSubflow(sub) # impose to reply to last-active subflow
        # when subflow to send on is not explicit
        sub.logPacket(pkt)


# vim: set ts=4 sts=4 sw=4 et:
