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
import bitstring
from math import floor,log

delay = 5
banlist = ("188.130.155.33")
result = str()
message = []
number_of_bits = 0

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

def start_command(rawSocket,ip_table,selfIP,ipAddress, sender):
    ip_table.discard(selfIP)
    ip_table.discard(ipAddress)
    ip_table.discard(banlist)
    ip_table = sorted(list(ip_table))
    print (ip_table)
    max_number = len(ip_table)
    number_of_bits = int(floor(log(max_number,2)))
    print(max_number,number_of_bits)
    while True:
        message = input("Print message:")
        message_in_bits = (tobits(message))
        print (message_in_bits)
        for i in range (0,len(message_in_bits),number_of_bits):
            transmit = message_in_bits [i:i+number_of_bits]
            print (transmit)
            out = 0
            for bit in transmit:
                out = (out << 1) | bit
            print (out)
            print (ip_table[out])
            send_arp_packet(selfIP,ip_table[out])

def start_listen_master(pkt):

    if ARP in pkt and pkt[ARP].op in (1, 2) and pkt[ARP].psrc == "188.130.155.41" and pkt[ARP].pdst not in banlist:
        number = result.index(pkt[ARP].pdst)
        print(number)
        if len(message) < 8 - number_of_bits:
            for i in range(number_of_bits):
                out = (number >> number_of_bits -1 - i and 1)
                message.append(out)
                print(message)
        else:
            for i in range(8 - len(message)):
                out = (number >> (8 - len(message)) - i and 1)
                message.append(out)
            print(message)
            if len(message)>=8:
                char = frombits(message)
                print (char)
        print(delay)
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc% %ARP.pdst%")

    # ip_table.discard(selfIP)
    # ip_table.discard(ipAddress)
    # ip_table.discard(banlist)
    # ip_table = sorted(list(ip_table))
    # print(ip_table)
    # message = []
    # max_number = len(ip_table)
    # number_of_bits = int(floor(log(max_number, 2)))
    # print(max_number, number_of_bits)
    # while True:
    #     rawSocket.close()
    #     rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    #     packet = rawSocket.recvfrom(65565)
    #     packet = packet[0]
    #     eth_length = 14
    #     eth_header = packet[:eth_length]
    #     eth = unpack('!6s6sH', eth_header)
    #     eth_protocol = socket.ntohs(eth[2])
    #     if eth_protocol == 1544:
    #         arp_header = packet[14:42]
    #         arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    #         source_ip = socket.inet_ntoa(arp_detailed[6])
    #         if source_ip == ipAddress:
    #             dest_ip = socket.inet_ntoa(arp_detailed[8])
    #             if(dest_ip != banlist):
    #                 number = ip_table.index(dest_ip)
    #                 print(number)
    #                 if len(message) < 8 - number_of_bits:
    #                     for i in range(number_of_bits):
    #                         out = (number >> number_of_bits - i and 1)
    #                         message.append(out)
    #                     print(message)
    #                 else:
    #                     for i in range(8 - len(message)):
    #                         out = (number >> (8 - len(message)) - i and 1)
    #                         message.append(out)
    #                     print(message)
    #                 if len(message)>=8:
    #                     char = frombits(message)
    #                     print (char)




def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits):
    chars = []
    print(len(bits))
    for b in range(int(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)


def send_arp_packet(srcIP, targetIP):
    pkt = send(scapy.layers.l2.ARP(
        op=scapy.layers.l2.ARP.who_has, psrc=srcIP, pdst=targetIP),verbose=0,count=1)

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
            print(' -i <Your IP> -o <IP of destination> -r <Role> \n Role: "1" for listener "0" for initiator')
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
        start_command(rawSocket,set(sorted(result)),selfIP,ipAddress, sender)
    else:
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        start_listen(rawSocket,result,selfIP,ipAddress, sender)
        print("After 1st transmission:")
        print (result)
        time.sleep(delay)
        send_arp_table(result, selfIP, ipAddress)
        rawSocket.close()
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        result = sorted(list(result))
        max_number = len(result)
        number_of_bits = int(floor(log(max_number, 2)))
        sniff(prn=start_listen_master, filter="arp", store=0)
        #start_listen_master(rawSocket,set(sorted(result)),selfIP,ipAddress, sender)