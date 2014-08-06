mptcp-abuse
===========

A collection of tools and resources to explore MPTCP on your network. Initially released at Black Hat USA 2014.

Tools/resources currently here:
- mptcp_fragmenter.py
- mptcp_scanner.py
- MPTCP Cheatsheet.pdf


The scapy/ and tests/ code here are a modified fork of the MPTCP-capable scapy code by Nicolas Maitre at https://github.com/nimai/mptcp-scapy


Usage
==========
These allow tests of MPTCP-capable machines from non-MPTCP-capable machines. They do require root for raw packet crafting and iptables management.

mptcp_scanner.py
```bash
root@mptcp-dev# python mptcp_scanner.py 
usage: mptcp_scanner.py [-h] [--ip SRC_IP] host port

Network scanner to test hosts for multipath TCP support. Requires root
privileges for scapy.

positional arguments:
  host         comma-separated IPs or ranges (globs allowed), eg
               "127.0.0.1,192.168.1-254,203.0.113.*"
  port         comma-separated port(s) or port ranges, eg "22,80,8000-8999"

optional arguments:
  -h, --help   show this help message and exit
  --ip SRC_IP  use the specified source IP for all traffic

root@mptcp-dev# python mptcp_scanner.py  192.168.88.164 22,80
Testing: 192.168.88.164 ... on local network...  at ARP: 00:0c:29:c8:8a:61
 got MPTCP Response from  192.168.88.164 : 22 !...  20
RST Test indicates MPTCP support
 got MPTCP Response from  192.168.88.164 : 80 !...  20
RST Test indicates MPTCP support
****Results:****
	192.168.88.164
			{22: 'MPTCP (MP_JOIN Verified)'}
			{80: 'MPTCP (MP_JOIN Verified)'}
```

mptcp_fragmenter.py
```bash
# python mptcp_fragment_http.py 
usage: mptcp_fragment_http.py [-h] [--ip SRC_IP] [-p PORT] [-n NSUBFLOWS]
                              [--first_src_port FIRST_SRC_PORT] [--path PATH]
                              [--file FILE] [--shuffle SHUFFLE]
                              [--random_src_ports RANDOM_SRC_PORTS]
                              target

Fragment an HTTP request over multiple MPTCP flows. Requires root privileges
for scapy.

positional arguments:
  target                Target IP

optional arguments:
  -h, --help            show this help message and exit
  --ip SRC_IP           use the specified source IP for all traffic
  -p PORT, --port PORT  target port
  -n NSUBFLOWS, --nsubflows NSUBFLOWS
                        Number of subflows to create
  --first_src_port FIRST_SRC_PORT
                        First of nsubflows src ports
  --path PATH           Path to request
  --file FILE           File to send instead of a payload
  --shuffle SHUFFLE     Shuffle the port order
  --random_src_ports RANDOM_SRC_PORTS
                        use random ports




# python mptcp_fragment_http.py -n 5 192.168.88.165
Opening connection from port 1001
Opening connection from port 1002
Opening connection from port 1003
Opening connection from port 1004
Opening connection from port 1005
Splitting payload across 5 subflows
Subflow 0 closed FIN
Subflow 1 closed FIN
Subflow 2 closed FIN
Subflow 3 closed FIN
Subflow 4 closed FIN
```
