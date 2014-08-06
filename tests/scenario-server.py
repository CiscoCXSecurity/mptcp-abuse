#!/usr/bin/env python2

from tests.mptcptestlib import *

def main():
    conf = {"printanswer":False, "debug":5, "check": False}
    t = ProtoTester(conf) # Core tester, protocol-agnostic.
    s = MPTCPState() # Connection, containing its state and methods to manipulate it
    m = MPTCPTest(tester=t, initstate=s) # MPTCP packets library
    
    # Client IPs
    A1 = "10.1.1.2"
    A2 = "10.1.2.2"
    # Server IP
    B = "10.2.1.2"
    
    # Block the packets before they are handled by the local network stack,
    # this permits to receive packets without any kernel interferences.
    t.toggleKernelHandling(enable=False)
    try:
        # As this is the receiver of the first packet, we wait it with a large timeout
        # to give to the user/external script to start the client
        t.sendpkt(m.Wait, timeout=100)
        #   
        # Define the sequence of packets that should be sent by this end-host.
        #   The definition consists of classes from the library that represent
        #   the packets. Every packet is sent conformly to the connection
        #   context according to maintained state s.
        #   If the host should wait for a packet to arrive, the Wait class
        #   should be used as a normal packet class.
        conn_accept = [m.CapSYNACK, m.Wait]
        # Then, we can execute that scenario part:
        t.sendSequence(conn_accept, initstate=s)#, sub=sub1)
        # It is a shortcut to execute sendpkt on every item:
        #   - t.sendpkt(m.Wait, initstate=s) # wait for a packet to arrive
        #   - t.sendpkt(m.CapSYNACK, initstate=s) # generate and send a valid
        #                                           MP_CAPABLE SYNACK
        

        # One can register a new subflow to send packets on it though 
        # it must not be used when the remote instance opens the subflow by itself.
        #   sub1 = s.registerNewSubflow(dst=A1, src=B)
        # In that event, the subflow should actually use the same ports than
        # the remote host (still unknown locally). It can be sent by the other
        # host and received using the ProtoTester.receiveState() method, which
        # creates a SubflowState object that can be registered too.
        #   sub1 = s.registerSubflow(SubflowState(mpconn=s,
        #        initstate=t.receiveState(SubflowState, A1)).invertState())
        # A simpler possibility is to let the subflow be created automatically
        # by the packets received a given 5-tuple, 
        # and then we can get it later with:
        #   subflow = s.getSubflow(subflowIndex)

        # Register a new subflow
        sub2 = s.registerNewSubflow(dst=A2, src=B)
        join_init = [m.JoinSYN, m.Wait, m.JoinACK] #, m.Wait]
        # Execute this scenario part.
        # A registered subflow on which to send (and wait) the packets can be
        # indicated as an optional parameter to sendSequence() and sendpkt().
        # The return value is the log, composed of a list of tuples:
        # (pktSent, packetValidity, pktReply, newState) for each element of the
        # input list.
        t.sendSequence(join_init, initstate=s, sub=sub2)

        # Send Data (see client side, scenario-client.py)
        # Two subflows are now open. In order to send data, there are two
        # facilities to abstract the DSS(MAP/ACK) mechanism:
        #   m.send_data_sub(s, "data flow1", sub=sub1)
        # It sends data on subflow sub1. However, if no subflow is specified,
        # it will take the default one (that is, the last-used subflow).
        # Another method enables an user to send data over all the subflows,
        # distributing the data between them.
        #   log = m.send_data(s, "a lot of data")
        #
        # When a scenario is done sending data, it can wait for a specific
        # sent packet to be acknowledged by the remote host. This can be done
        # with the Wait class, using its waitAckForPkt() filter function:
        #   last = log[-1][0]
        #   t.sendpkt(m.Wait, waitfct=m.Wait.waitAckForPkt(s,last))

        # Now, server-side: Since the data are sent dynamically
        # on the subflows, there isn't, a priori, any way to
        # aknowledge every data segment and take them content into account. 
        # A first workaround is to use the timeout parameter available for the
        # Wait class.
        # This code waits for a packet for a maximum of 1sec, aknowledges it.
        # If there is no packet, the loop is broken and the process goes on.
        #   while True:
        #       try:
        #           t.sendpkt(m.Wait, timeout=1)
        #           t.sendpkt(m.DSSACK)
        #       except PktWaitTimeOutException as e:
        #           print "No packet in last %i seconds"%e.timeval
        #           break
        # However, while it could work in practice, this is undeterministic
        # because this works in a synchronous way with asynchronous events.
        # In order to make it work properly, the buffer mode of Wait allows to
        # simulate the behaviour of a buffer: all the received packets are
        # stored and when it has finished, their content is handled and it
        # acknowledges every packet all at once. A UDP signal from the client
        # (sendData() method) is used to indicate when it has finished sending data.
        # The enabling of buffermode makes sendpkt() behave similarly to
        # sendSequence() in terms of return value.
        packets = t.sendpkt(m.Wait, buffermode=True)
        # (waiting for an UDP signal)

        # The client waits for all the ack thanks to the waitAckForPkt
        # mechanism, no further synchronization is therefore needed

        sub1 = s.getSubflow(0)
        
        data_fin_seq = [m.Wait, m.DSSFINACK, m.Wait, m.DSSACK]
        t.sendSequence(data_fin_seq, sub=sub2)

        # assuming that the remote host uses a single FINACK packet
        fin_init1 = [m.Wait, m.FINACK, m.Wait]
        t.sendSequence(fin_init1, sub=sub1)

        # Use UDP signaling for "asymmetric" synchronization
        t.syncReady(dst=A1) # without sync, the client that sends 2 packets in line
        # might not let enough time for the server to setup the wait function

        fin_init2 = [m.Wait, m.FINACK, m.Wait]
        t.sendSequence(fin_init2, sub=sub2)
    except PktWaitTimeOutException:
        print("Waiting has timed out, test exiting with failure")
        sys.exit(1)
    finally:
        t.toggleKernelHandling(enable=True)

if __name__ == "__main__":
    main()

# vim: set ts=4 sts=4 sw=4 et:
