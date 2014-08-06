#!/usr/bin/env python2
# Client part of the scenario
from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":4, "check": False}
    t = ProtoTester(conf)
    s = MPTCPState()
    m = MPTCPTest(tester=t, initstate=s)

    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"

    t.toggleKernelHandling(enable=False)
    try:
        sub1 = s.registerNewSubflow(dst=B, src=A1)
        conn_open = [m.CapSYN, m.Wait, m.CapACK]
        t.sendSequence(conn_open, initstate=s, sub=sub1)

        join_accept = [m.Wait, m.JoinSYNACK, m.Wait] # m.ACK] # omit final ACK
        t.sendSequence(join_accept, initstate=s)

        # synchronization after Wait
        t.syncReady(dst=B)
    
        # server should send data. Does the firewall drop them ?
        dataisDropped = False
        try:
            t.sendpkt(m.Wait, timeout=1)
        except PktWaitTimeOutException as e:
            print "No packet in last %i seconds"%e.timeval
            dataisDropped=True

        # Finally send 4th (JOIN) ACK
        t.sendpkt(m.ACK)

        # now, the data shouldnt be dropped anymore
        data2isDropped = False
        try:
            t.sendpkt(m.Wait, timeout=1)
        except PktWaitTimeOutException as e:
            print "No packet in last %i seconds"%e.timeval
            data2isDropped=True 

        data_fin_init = [m.DSSFIN, m.Wait, m.DSSACK]
        t.sendSequence(data_fin_init, sub=sub1)

        t.syncWait()

        sub2 = s.getSubflow(1)

        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.FIN, m.Wait, m.ACK]
        t.sendSequence(fin_init1, sub=sub1)

        t.syncWait()

        fin_init2 = [m.FIN, m.Wait, m.ACK]
        t.sendSequence(fin_init2, sub=sub2)
    finally:
        t.toggleKernelHandling(enable=True)

    import sys
    sys.exit(int(not (dataisDropped and not data2isDropped)))

if __name__ == "__main__":
    main()
# vim: set ts=4 sts=4 sw=4 et:
