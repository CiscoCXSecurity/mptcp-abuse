#!/usr/bin/env python2
from scapy.all import sr1, send, sniff
from threading import Thread
import random
import socket, select
import inspect


#TODO: ADD Handling for ADD_ADDR
#TODO: ADD Handling for REMOVE_ADDR
#TODO: ADD Handling for ADD_ADDR
#TODO: ADD Handling for MP_FAIL
#TODO: ADD Handling for MP_PRIO
#TODO: Fix Exceptions arising on RST
#TODO: Add support for SACK
#TODO: ensure sequence number increments in dssack appropriately handle fin or
#        ack flags (so these incremement it?)
#TODO: Add asynchronus reply processing (right  now it drops very fast replies
        #such as acks - perhaps use something like twisted with txscapy?
        #see hellais/txscapy on github)
#TODO: Add the ability to ignore RST flags or perhaps immediately take
# some action (toggle keys, open more streams, etc)

DEFAULT_CONF = {"check":False,  # if True, check received packets using check
                                # function given as parameter in sendpkt call
                "debug":0,      # Levels 0-5. Greater means more verbose
                "printanswer":False,
                "iptables_bin": "iptables", # iptables executable path
                }

class PktWaitTimeOutException(Exception):
    def __init__(self, timeval):
        self.timeval = timeval
    def __str__(self):
        return repr(self.timeval)

class ProtoTester(object):
    def __init__(self, conf=DEFAULT_CONF):
        self.conf = dict(DEFAULT_CONF.items() + conf.items())
        self.first = True
        # If True, allows kernel to see packets and interact with connection
        self.khandled = True
        # proto related
        self.state = None
        self.proto = None

    def sendSequence(self, pktList, initstate=None, waitAck=None, timeout=None, **kargs):
#         if "buffermode" in kargs:
#             raise Exception("Buffermode cannot be used with sendSequence()")
        return [self.sendpkt(pkt, initstate,timeout=timeout, waitAck=True, **kargs) for pkt in pktList]


    def sendpkt(self, newpkt, initstate=None, timeout=None, waitAck=None, **kargs):
        """Generate and send a new packet

        Generate a new packet using the function newpkt, from existing current
        state overriden by initstate, then send it.
        Return a tuple (sent packet, reply, new state)

        Arguments:
        newpkt -- function to generate the scapy packet to send. It must have
                  at least have a state dictionnary as first parameter
        initstate -- state overriding the current state.
        testfct -- optional function used to check the validity of a reply
        kargs -- other optional arguments to be passed to the newpkt function
        """
        if self.state is None:
            if initstate is None:
                # If no initial state is given at the first call, use a generic one
                self.state = ProtoState()
            else:
                self.state = initstate
        else:
            self.state.update(initstate)
        s = self.state # simple alias

        if self.first:
            self.first = False
#        elif not s.getLastPacket():
#            raise Exception("no previous packet, can't resume the protocol")

        try:
            (pkt, wait) = newpkt().generate(s, timeout=timeout, **kargs)

            if s.hasKey("stage") and pkt is not None:
                self.debug("Generating %s packet..." % s["stage"], 2)
            r = self.run(s, pkt, wait)
            if type(r) is list: # buffermode
                return r
            # otherwise, it's a classic (validity, reply) tuple
            (ret, reply) = r

        except PktWaitTimeOutException as e:
            raise e
#PktWaitTimeOutException(e.
        except Exception as e:
            import sys
            if self.conf["debug"]:
                import traceback
                traceback.print_exc(file=sys.stdout)
            print("Error: %s" % e)
            print("Exiting.")
            sys.exit(0)

        return (pkt, ret, reply, self.state)


    def run(self, state, pkt, wait,timeout=None):
        """Send pkt, receive the answer if wait is True, and return a tuple
        (validity of reply packet, reply packet). If no test function is
        given, assume it's valid."""
        self.dbgshow(pkt)
        if wait: # do we wait for a reply ?
            self.debug("Waiting for packet...", level=2)
            if pkt is None:
                timeout, buffermode = None, False
                if type(wait) is tuple:
                    wait, timeout, buffermode = wait
                    #print wait
                    #wait, buffermode = wait
                if hasattr(wait, '__call__'):
                    ans = self.waitForPacket(filterfct=wait, timeout=timeout)
#                     if buffermode: # ans is a buffer (list)
#                         self.debug("Entering buffer mode.", level=1)
#                         return [self.packetReceived(pkt,buffermode=True) for pkt in ans]
                else:
                    raise Exception("error, no packet generated.")
            else:
                #TODO: Make sure this waits continuously in a non blocking mode, convert this to dumping from a queue
                ans=sr1(pkt)
        else:
            send(pkt)
            #print pkt
            self.first = True # prev_pkt shouldnt be taken into account
            self.debug("Packet sent, no waiting, going on with next.",2)
            return (True, None) # no reply, no check
        return self.packetReceived(ans) # post-reply actions

    def waitForPacket(self, state=None, filterfct=None, timeout=None,
            buffermode=False, **kargs):
        """Wait for one packet matching a filter function

        state: initial state, may be empty but should be a valid state
            instance.
        filterfct: boolean function applied on a packet received to select it
            or not. Ex: lambda pkt: pkt.haslayer("TCP")
        other args: extra args for sniff function of scapy"""

        if state is None:
            if self.state is None:
                raise Exception("A state object must be given as parameter when \
                    waiting for a packet if no initstate entered in the Tester.")
            state = self.state
        else:
            self.state.update(state)
        if timeout:
            tOut = " (timeout after " + str(timeout) + " secs)"
        else: tOut = ""
        self.debug("Sniffing using custom function..." + tOut, level=2)
#         if buffermode:
#             # in buffermode, the packets are stored in buf and they are transmitted
#             # to user only when a UDP signal is encountered
#             buf = sniff(count=0, lfilter=lambda pkt: filterfct(pkt) or \
#                     pkt.haslayer(UDP), filter="udp or tcp",
#                     stop_filter=lambda pkt: pkt.haslayer(UDP),
#                     timeout=timeout, **kargs)
#             self.sendAck(buf[-1].getlayer("IP").src)
#             return buf[:-1]

        pkts = sniff(count=1, lfilter=filterfct, filter="tcp",
                    timeout=timeout, **kargs)
        if pkts is None or len(pkts) == 0:
            raise PktWaitTimeOutException(timeout)
        return pkts[0].getlayer("IP")


    def packetReceived(self, pkt, buffermode=False):
        """Called when a packet pkt is received, returns the packet and its
        supposed validity expressed as a boolean"""
        initstate = self.state.copy()
        self.printrcvd(pkt)
        self.state.logPacket(pkt)
        pktTest = None
        finder = self.proto.findProtoLayer(pkt)
        self.debug("Packets components to handle: %s" % [a for a in finder], 4)
        finder = self.proto.findProtoLayer(pkt)
        if not finder:
            return (False, pkt)
        for p in finder:
            if "recv" in dir(p):
                pktTest = p
            else:
                pktTest = self.proto.getClassFromPkt(p, pkt)()
            valid = self.checkRcvd(initstate, pkt, pktTest)
            if not valid:
                return (False, pkt)
            needReply = pktTest.recv(self.state, pkt)
#             if needReply and buffermode: # useful for acks
#                 self.sendpkt(needReply)
        return (True, pkt)

    def checkRcvd(self, init, pkt, pktTest):
        """Test the validity of a received packet according to previous
        state"""
        if self.conf["check"] is False:
            return True

        if not pktTest.check(init,pkt):
            print("Test failed: %s", ret);
            return False
        return True

    # Optional Debug / Print
    def printrcvd(self, pkt):
        if self.conf["printanswer"] or self.conf["debug"] >= 4:
            print("------ RECEIVED -------")
            pkt.show2()
            print("---- END of PACKET ----")

    def debug(self, str, level=3):
        if self.conf["debug"] >= level:
            frame,filename,line_number,function_name,lines,index=\
                    inspect.getouterframes(inspect.currentframe())[1]
            print("[%i:%s] %s"%(line_number,function_name,str))

    def dbgshow(self, pkt):
        if self.conf["debug"] >= 5:
            if not pkt:
                self.debug("No packet to send.",level=5)
                return
            print("------- TO SEND -------")
            pkt.show2()
            print("---- END of PACKET ----")



    def toggleKernelHandling(self, src_ip, enable=None, ):
        """Toggle the kernel handling of the packets received. If enabled,
        the kernel will see packets and manage the connections, which isn't
        desirable while sending forged packets
        See: http://stackoverflow.com/questions/9058052/unwanted-rst-tcp-packet-with-scapy"""
        import os
        if enable is True or self.khandled is False:
            os.system("%s -D OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP" % (self.conf["iptables_bin"], src_ip))
            os.system("%s -D OUTPUT -p tcp --tcp-flags FIN FIN -s %s -j DROP" % (self.conf["iptables_bin"], src_ip))
            self.khandled = True
        elif enable is False or self.khandled is True:
            #os.system("%s -P INPUT DROP" % self.conf["iptables_bin"])
            os.system("%s -A OUTPUT -p tcp --tcp-flags RST RST -s %s -j DROP" % (self.conf["iptables_bin"], src_ip))
            os.system("%s -A OUTPUT -p tcp --tcp-flags FIN FIN -s %s -j DROP" % (self.conf["iptables_bin"], src_ip))
            self.khandled = False

#     # For purpose of communication with the other test instance.
#     def sendData(self, data, dst):
#         if dst is None:
#             raise Exception("no destination found for sending control data")
#         self.debug("UDP packet sent to %s: %s" % (dst,data), 5)
#         outsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         outsock.sendto(data, (dst, self.conf["udp_port"]))
#         sock.bind(('', self.conf["udp_port"])) # wait for ack
#         while not select.select([sock], [], [],0.1)[0]:
#             outsock.sendto(data, (dst, self.conf["udp_port"]))
#         sock.recvfrom(10)
#         sock.close()
#         outsock.close()
#
#     def sendAck(self,addr):
#         outsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         outsock.sendto("ack", (addr, self.conf["udp_port"]))
#         outsock.close()
#
#     def receiveData(self, src=None, bindTo=''):
#         """Wait to receive state in its network representation from src, using UDP
#         Return the state as a dictionary"""
#         sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM)
#         sock.bind((bindTo, self.conf["udp_port"]))
#         data, addr = sock.recvfrom( 2048 )
#         self.debug("Received data from %s: '%s'"%(addr,data))
#         while src is not None and addr[0] != src:
#             self.debug("Not from expected source %s, waiting for another udp packet"%src)
#             data, addr = sock.recvfrom( 2048 )
#             self.debug("Received data from %s: '%s'"%(addr,data))
#         sock.close()
#         self.sendAck(addr[0])
#         return data
#
#
#     def sendState(self, state=None, dst=None):
#         """Send state in its network representation to dst, using UDP"""
#         if dst is None and state and state.hasKey("dst"):
#             dst = state["dst"]
#         self.sendData(state.toNetwork(), dst)
#
#     def receiveState(self, cls=None, src=None, bindTo=''):
#         if cls is None:
#             cls = ProtoState
#         return cls.fromNetwork(self.receiveData(src=src, bindTo=bindTo))
#
#     def syncWait(self, src=None):
#         """Useful for synchronization between client and server. It is used
#         asymmetrically. This is one is a blocking call that waits until it
#         receives a synchronization signal using UDP
#         @param src: source IP of the sync signal"""
#         self.receiveData(src=src)
#
#     def syncReady(self, dst, msg="unit"):
#         """Useful for synchronization between client and server. It is used
#         asymmetrically. This is one is a non-blocking call that notify the
#         remote host that it is ready to continue.
#         @param dst: destination IP of the sync signal"""
#         Thread(target=self.sendData, args=(msg, dst)).start()
#
#     def notifyEndOfData(self, dst):
#         self.syncReady(dst, msg="EOD")
#
#     def getTestResult(self, src=None, criterion=lambda r: r[0] == "unit" and r[1] == True):
#         """Get results from a test which depends on a remote operation,
#         sent from src, with the criterion of success criterion which must be
#         a function"""
#         import ast
#         res = ast.literal_eval(self.receiveData(src=src))
#         if not isinstance(res, tuple):
#             raise Exception("Test result not in expected format")
# #         return criterion(res)
#
#     def sendTestResult(self, result, dst=None):
#         """Send test results to dst. result shoud be a tuple (type, value).
#         For example ("unit", True) means a success with the default criterion."""
#         self.sendData(str(result), dst=dst)


class ProtoLibPacket(object):
    def generate(self, state, timeout=None):
        """Describe the packet to send for the class's packet type"""
        pass
    def recv(self, state, pkt):
        """Parse the packet and alter the state according to the class's packet type"""
        pass
    def check(self, state, pkt):
        """Check a received packet given an initial state
        Return a boolean"""
        return True


class ProtoState(object):
    def __init__(self, initstate={},conf=DEFAULT_CONF):
        self.d = {}
        self.initAttr()
        self.update(initstate)
        self.conf = conf

    def initAttr(self):
        """Populate the internal dictionary with default values."""
        pass

    def debug(self, str, level=3):
        if self.conf["debug"] >= level:
            print("[%s] %s"%(self.name,str))

    def __getitem__(self, attr):
        """ with the state dictionary"""
        return self.d[attr]

    def __setitem__(self, attr, val):
        if attr in ["ack", "seq"]:
            self.debug("%s: %i --> %i"% (attr, self.d[attr],val), level=5)
            self.debug(inspect.stack(), level=5)
        if attr in ["map"]:
            self.debug("%s: %s --> %s" % (attr, self.d[attr],val), level=4)
        if attr in ["dsn", "data_ack"]:
            self.debug("%s: %i --> %i" % (attr, self.d[attr],val), level=3)
            self.debug(inspect.stack(), level=5)
        self.d[attr] = val

    def toNetwork(self):
        return str(self.d)

    @classmethod
    def fromNetwork(cls, dictstr):
        import ast
        return ast.literal_eval(dictstr)

    def update(self, extrastate):
        """Update the current state with the extrastate. Extrastate must be a
        ProtoState derivative"""
        if extrastate is not None:
            if type(extrastate) is dict:
                e = extrastate.items()
            else:
                e = extrastate.d.items()
            self.d = dict(self.d.items() + e)
        return self

    def hasKey(self, key):
        return key in self.d.keys()

    def copy(self):
        import copy
        return copy.deepcopy(self)

    def logPacket(self, pkt):
        self.d["prev_pkt"] = pkt

    def getLastPacket(self):
        if "prev_pkt" in self.d.keys():
            return self.d["prev_pkt"]
        else:
            return None



def xlong(s):
    """Convert a string into a long integer"""
    l = len(s)-1
    return sum([ord(c) << (l-e)*8 for e,c in enumerate(s)])

def xstr(x):
    """Convert an integer into a string"""
    return xstr(x >> 8) + chr(x&255) if x else ''

def randintb(n):
    """Picks a n-bits value at random"""
    return random.randrange(0, 1L<<n)

# vim: set ts=4 sts=4 sw=4 et:
