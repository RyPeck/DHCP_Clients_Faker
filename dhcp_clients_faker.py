"""
Compatible Versions for this Script
Python Version  - 2.6.5
Scapy Version   - 2.2.0-dev

Created By      - Ryan Peck github.com/RyPeck

Interface must be in promiscious mode

"""

from scapy.all import *
import random
import sys
import os
import time
import logging
import sys


# Turn off the annoying scapy messages...
logging.getLogger("scapy").setLevel(1)
conf.verb = 0


def genmac():
    """
    Mac addresses generated with this end look like they were made by a
    company called "Computec Oy," http://aruljohn.com/mac.pl based out of
    Finland unlikely that they will be on our network.

    Takes no arguments and returns the human readable mac address
    (XX:XX:XX:XX:XX:XX) and byte

    """

    # First three octets specify the manufacturer (OUI)
    mac = [0x00, 0x1B, 0x37,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0x7f)]

    human_readable = ':'.join(map(lambda x: "%02x" % x, mac))

    bytes = []

    # Need to convert it to a 6 byte length mac address
    for x in human_readable.split(":"):
        bytes.append(chr(int(x, 16)))

    bhw = ''.join(bytes)

    return(human_readable, bhw)


def print_helpful_info(resp):
    print "Source      - " + resp[Ether].src
    print "Destination - " + resp[Ether].dst
    print "IP Offered  - " + resp[BOOTP].yiaddr
    print "siaddr  - " + resp[BOOTP].siaddr
    print "giaddr  - " + resp[BOOTP].giaddr
    print "ciaddr  - " + resp[IP].src


def do_dhcp_handshakes(hmac, bmac):
    """
    This function actually exececutes the 4 way DHCP handshake which should
    generate a lease on the server side
    """

    conf.checkIPaddr = False

    trans_id = random.randint(0x00, 0xffffffff)

    # Create DHCP_Discover Request
    dhcp_discover = (Ether(dst="ff:ff:ff:ff:ff:ff", src=hmac) /
                     IP(src="0.0.0.0", dst="255.255.255.255") /
                     UDP(sport=68, dport=67) /
                     BOOTP(chaddr=bmac, xid=trans_id) /
                     DHCP(options=[("message-type", "discover"), "end"]))

    # This filter doesn't appear to be working.
    resp = srp1(dhcp_discover, filter="ether dst " + hmac,
                retry=3, timeout=12)

    if resp is None:
        print "No response"
        return

    print_helpful_info(resp)

    if (resp[Ether].dst == hmac):
        dhcp_request = (Ether(dst=resp[Ether].src, src=hmac) /
                        IP(src="0.0.0.0", dst="255.255.255.255") /
                        UDP(sport=68, dport=67) /
                        BOOTP(chaddr=bmac, xid=trans_id) /
                        DHCP(options=[("message-type", "request"),
                                      ("requested_addr", resp[BOOTP].yiaddr),
                                      ("server_id", resp[IP].src), "end"]))

        resp2 = srp1(dhcp_request, filter="ether dst " + hmac, timeout=6)

        if (resp[Ether].dst == hmac):
            print "Got IP - " + resp[BOOTP].yiaddr
        else:
            print "Check pcap to see if you got the ip"
    else:
        print "Problems."

if __name__ == "__main__":

    start = time.time()
    fork = False

    if sys.argv[1] == "--fork":
        number = int(sys.arv[2])
        fork = True
    else:
        number = int(sys.argv[1])

    for x in range(0, number):
        hmac, bmac = genmac()
        if fork:
            child_pid = os.fork()

            if child_pid == 0:
                #time.sleep(random.random())
                do_dhcp_handshakes(hmac, bmac)
                elapsed = time.time() - start
                #print "Took", elapsed, "seconds to generate", number, "leases"
                sys.exit()
        else:
            do_dhcp_handshakes(hmac, bmac)

#    elapsed = time.time() - start
#    print "Took", elapsed, "seconds to generate", number, "leases"
#    print "That took roughly", (elapsed / number), "seconds per lease"
