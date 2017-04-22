from scapy.all import *
from scapy.layers import *

from subprocess import check_output

import socket
import docopt
import os
import sys
from struct import *
from scapy import all
import scapy.layers.l2

import scapy.layers.all
import socket
import struct
import sys
import netifaces
import binascii

ipAddress = "188.130.155.76"
sender = True
interface = "ens33"

def packet_loop(s):
    # receive a packet
    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        addrinfo = [
            'Destination MAC: {}'.format(eth_addr(packet[0:6])),
            'Source MAC: {}'.format(eth_addr(packet[6:12])),
            'Protocol: {}'.format(eth_protocol)
        ]
        if eth_protocol == 1544:
            print(' '.join(addrinfo))
        print('')


def make_arp_packet(destip):
    return 0  # packet


def send_arp_packet(arppacket):
    return 0  # packet


def ecode_msg(msg, iptable):  # msg array of bytes []
    return 0  # array of packets


def marshaling_msg(msg):  # msg array of bytes []
    return 0  # array of bytes []


def listener_loop(socket):  # msg array of bytes []
    return 0  # array of bytes []


def sender_loop(socket):  # msg array of bytes []
    return 0  # array of bytes []


#        # Parse IP packets, IP Protocol number = 8
#        if eth_protocol == 8:
#            # Parse IP header
#            # take first 20 characters for the ip header
#            ip_header = packet[eth_length:20 + eth_length]
#
#            # now unpack them :)
#            iph = unpack('!BBHHHBBH4s4s', ip_header)
#
#            version_ihl = iph[0]
#            version = version_ihl >> 4
#            ihl = version_ihl & 0xF
#
#            iph_length = ihl * 4
#
#            ttl = iph[5]
#            protocol = iph[6]
#            s_addr = socket.inet_ntoa(iph[8])
#            d_addr = socket.inet_ntoa(iph[9])
#
#            headerinfo = [
#                'Version: {}'.format(version),
#                'IP Header Length: {}'.format(ihl),
#                'TTL: {}'.format(ttl),
#                'Protocol: {}'.format(protocol),
#                'Source Addr: {}'.format(s_addr),
#                'Desr.Addr: {}'.format(d_addr)]
#            print(' '.join(headerinfo))
#
#            # TCP protocol
#            if protocol == 6:
#                t = iph_length + eth_length
#                tcp_header = packet[t:t + 20]
#
#                # now unpack them :)
#                tcph = unpack('!HHLLBBHHH', tcp_header)
#
#                source_port = tcph[0]
#                dest_port = tcph[1]
#                sequence = tcph[2]
#                acknowledgement = tcph[3]
#                doff_reserved = tcph[4]
#                tcph_length = doff_reserved >> 4
#
#                tcpinfo = [
#                    'Source Port: {}'.format(source_port),
#                    'Dest. Port: {}'.format(dest_port),
#                    'Sequence Num: {}'.format(sequence),
#                    'Acknowledgement: {}'.format(acknowledgement),
#                    'TCP Header Len.: {}'.format(tcph_length),
#                ]
#                print(' '.join(tcpinfo))
#
#                h_size = eth_length + iph_length + tcph_length * 4
#                data_size = len(packet) - h_size
#
#                # get data from the packet
#                data = packet[h_size:]
#
#                print('Data: {}'.format(data_decode(data)))
#
#            # ICMP Packets
#            elif protocol == 1:
#                u = iph_length + eth_length
#                icmph_length = 4
#                icmp_header = packet[u:u + 4]
#
#                # now unpack them :)
#                icmph = unpack('!BBH', icmp_header)
#
#                icmp_type = icmph[0]
#                code = icmph[1]
#                checksum = icmph[2]
#
#                icmpinfo = [
#                    'Type: {}'.format(icmp_type),
#                    'Code: {}'.format(code),
#                    'Checksum: {}'.format(checksum)
#                ]
#                print(' '.join(icmpinfo))
#
#                h_size = eth_length + iph_length + icmph_length
#                data_size = len(packet) - h_size
#
#                # get data from the packet
#                data = packet[h_size:]
#
#                print('Data : {}'.format(data_decode(data)))
#
#            # UDP packets
#            elif protocol == 17:
#                u = iph_length + eth_length
#                udph_length = 8
#                udp_header = packet[u:u + 8]
#
#                # now unpack them :)
#                udph = unpack('!HHHH', udp_header)
#
#                source_port = udph[0]
#                dest_port = udph[1]
#                length = udph[2]
#                checksum = udph[3]
#
#                udpinfo = [
#                    'Source Port: {}'.format(source_port),
#                    'Dest. Port: {}'.format(dest_port),
#                    'Length: {}'.format(length),
#                    'Checksum: {}'.format(checksum)
#                ]
#                print(udpinfo)
#
#                h_size = eth_length + iph_length + udph_length
#                data_size = len(packet) - h_size
#
#                # get data from the packet
#                data = packet[h_size:]
#
#                print('Data: {}'.format(data_decode(data)))
#
#            # some other IP packet like IGMP
#            else:
#                print('Protocol other than TCP/UDP/ICMP')
#

def data_decode(b):
    if sys.version_info.major == 2:
        return b
    return b.decode('ascii', errors='replace')


def eth_addr(a):
    """ Convert a string of 6 characters of ethernet address into a
        dash separated hex string
    """
    pieces = (a[i] for i in range(6))
    return '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(*pieces)


def eth_addr2(a):
    """ Same as eth_addr, for Python 2 """
    pieces = tuple(ord(a[i]) for i in range(6))
    return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % pieces


ipnCommand = check_output(["ip", "n"])
result = "".join(map(chr, ipnCommand))
result = result.split("\n")
del (result[-1])
for i in range(len(result)):
    result[i] = result[i].split(" ")[0]
result.sort()
print(result)
if sender:
    arp = scapy.layers.l2.ARP()#op=ARP.who_has, psrc="192.168.5.51", pdst="192.168.5.46")
    #pkt = send(ARP(op=ARP.who_has, psrc="192.168.5.51", pdst="192.168.5.46"))
    #x = sniff(filter="arp", count=10)
    #print (x.summary())
    print ("done")

# else:
#   i = 1
