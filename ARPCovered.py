from struct import *
import logging
# to off annoying scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.layers.l2
import scapy.layers.all
from scapy.all import *
import socket
from subprocess import *
import binascii
import time
import sys
import getopt

delay = 5

#def make_arp_packet(destip):
#    return 0  # packet

#def ecode_msg(msg, iptable):  # msg array of bytes []
#    return 0  # array of packets


#def marshaling_msg(msg):  # msg array of bytes []
#    return 0  # array of bytes []


#def listener_loop(socket):  # msg array of bytes []
#    return 0  # array of bytes []


#def sender_loop(socket):  # msg array of bytes []
#    return 0  # array of bytes []

def send_arp_packet(srcIP, targetIP):
    pkt = send(scapy.layers.l2.ARP(
        op=scapy.layers.l2.ARP.who_has, psrc=srcIP, pdst=targetIP))

def send_arp_table(ipTableList,selfIP,ipAddress):
    for i in ipTableList:
        if i != ipAddress:
            print (i)
            send_arp_packet(selfIP, i)
    print(ipAddress)
    send_arp_packet(selfIP, ipAddress)

def start_listen(raw_socket, ip_list,selfIP,comIP,sender):
    ''' Inputs: socket to receive from
    List of IP which will synchronized
    IP address of this computer
    IP address of companion
     From which we start this function from listener or initiator '''
    while True:
        packet = raw_socket.recvfrom(65565)
        packet = packet[0]
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        if eth_protocol == 1544:
            arp_header = packet [14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
            source_ip = socket.inet_ntoa(arp_detailed[6])
            if sender == True:
                if source_ip == comIP:
                    print (source_ip)
                    dest_ip = socket.inet_ntoa(arp_detailed[8])
                    print (dest_ip)
                    ip_list.add(dest_ip)
                    if dest_ip == selfIP:
                        break
            else:
                dest_ip = socket.inet_ntoa(arp_detailed[8])
                ip_list.add(dest_ip)
                #print("Added value")
                if dest_ip == selfIP and source_ip == comIP:
                    break
            #print ("ARP to:"+dest_ip)
            #if (source_ip == ipAddress):
            #    ip_list.append(dest_ip)
            #print ("Source MAC:", binascii.hexlify(arp_detailed[5]))
            #print ("Source IP:", socket.inet_ntoa(arp_detailed[6]))
            #print ("Dest MAC:", binascii.hexlify(arp_detailed[7]))
            #print ("Dest IP:", socket.inet_ntoa(arp_detailed[8]))

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "hi:o:r:")
    for opt, arg in opts:
        if opt == '-h':
            print('test.py -i <Your IP> -o <IP of destination> -r <Role> \n Role: "1" for listener "0" for initiator')
            sys.exit()
        elif opt in ("-i"):
            selfIP = arg
        elif opt in ("-o"):
            ipAddress = arg
        elif opt in ("-r"):
            print (arg)
            if arg == "1":
                sender = False
            else:
                sender = True
    ipnCommand = check_output(["ip", "n"])
    result = "".join(map(chr, ipnCommand))
    result = result.split("\n")
    del (result[-1])
    for i in range(len(result)):
        result[i] = result[i].split(" ")[0]
    result.sort()
    print(result)
    result = set(result)
    if sender:
        print ("Sender")
        print("Waiting "+ str(delay) + " seconds")
        time.sleep(delay)
        send_arp_table(result, selfIP, ipAddress)
        #if you want to extract this step from branch - Ne Nado
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        start_listen (rawSocket,result,selfIP,ipAddress, sender)
        print (sorted(result))
    else:
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        start_listen(rawSocket,result,selfIP,ipAddress, sender)
        print("After 1st transmission:")
        print (result)
        time.sleep(delay)
        send_arp_table(result, selfIP, ipAddress)
        print("Full table")
        print (sorted(result))