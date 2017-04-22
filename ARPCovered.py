from struct import *
import scapy.layers.l2
import scapy.layers.all
from scapy.all import *
import socket
from subprocess import *
import binascii
import time

ipAddress = "192.168.0.3"
srcIP = "192.168.0.1"
sender = True
ifname = "ens33"
delay = 5

def make_arp_packet(destip):
    return 0  # packet

def send_arp_packet(srcIP, targetIP):
    pkt = send(scapy.layers.l2.ARP(
        op=scapy.layers.l2.ARP.who_has, psrc=srcIP, pdst=targetIP))


def ecode_msg(msg, iptable):  # msg array of bytes []
    return 0  # array of packets


def marshaling_msg(msg):  # msg array of bytes []
    return 0  # array of bytes []


def listener_loop(socket):  # msg array of bytes []
    return 0  # array of bytes []


def sender_loop(socket):  # msg array of bytes []
    return 0  # array of bytes []



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


def start_listen(raw_socket, ip_list):
    while True:
        packet = raw_socket.recvfrom(65565)
        print(packet)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 1544:
            arp_header = packet [14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
            source_ip = socket.inet_ntoa(arp_detailed[6])
            print("ARP from:"+source_ip)
            dest_ip = socket.inet_ntoa(arp_detailed[8])
            print ("ARP to:"+dest_ip)
            if (source_ip == ipAddress):
                ip_list.append(dest_ip)
            print ("Source MAC:", binascii.hexlify(arp_detailed[5]))
            print ("Source IP:", socket.inet_ntoa(arp_detailed[6]))
            print ("Dest MAC:", binascii.hexlify(arp_detailed[7]))
            print ("Dest IP:", socket.inet_ntoa(arp_detailed[8]))

ipnCommand = check_output(["ip", "n"])
result = "".join(map(chr, ipnCommand))
result = result.split("\n")
del (result[-1])
for i in range(len(result)):
    result[i] = result[i].split(" ")[0]
result.sort()
print(result)
if sender:
    print("Waiting "+ str(delay) + " seconds")
    time.sleep(5)
    for i in result:
        if i != ipAddress:
            send_arp_packet(srcIP,i)
        send_arp_packet(srcIP,ipAddress)
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    start_listen(rawSocket,result)
    print ("done")
