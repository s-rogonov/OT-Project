from struct import *
# to off annoying scapy warnings
# import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.layers.l2
import scapy.layers.all
from scapy.all import *
import socket
from subprocess import *
import time
import sys
import getopt

from math import floor,log

delay = 5
banlist = ("188.130.155.33")
result = str()
message = []
number_of_bits = 0

def start_command(ip_table,selfIP,ipAddress):
    max_number = len(ip_table)
    number_of_bits = int(floor(log(max_number,2)))
    print("Total ip's:",max_number,"Available bytes:",number_of_bits)
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
    if ARP in pkt and pkt[ARP].op in (1, 2) and pkt[ARP].psrc == ipAddress and pkt[ARP].pdst not in banlist:
        number = result.index(pkt[ARP].pdst)
        info = bitfield(number)
        while len(info) < number_of_bits:
            info.insert(0,0)
        message.extend(info[:])
        if len(message) >= 8:
            char = frombits(message[:8])
            message.clear()
            print (char, end='',flush=True)

def tobits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def frombits(bits):
    chars = []
    for b in range(int(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def bitfield(n):
    return [1 if digit=='1' else 0 for digit in bin(n)[2:]]

def send_arp_packet(srcIP, targetIP):
    pkt = send(scapy.layers.l2.ARP(
        op=scapy.layers.l2.ARP.who_has, psrc=srcIP, pdst=targetIP),verbose=1,count=1)

def send_arp_table(ipTableList,selfIP,ipAddress):
    for i in ipTableList:
        if i != ipAddress:
            print (i)
            send_arp_packet(selfIP, i)
    print(ipAddress)
    send_arp_packet(selfIP, ipAddress)

def start_listen(ip_list,selfIP,comIP,sender):
    while True:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
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
                    dest_ip = socket.inet_ntoa(arp_detailed[8])
                    if dest_ip == selfIP:
                        raw_socket.close()
                        break
                    else:
                        print (source_ip)
                        print (dest_ip)
                        ip_list.append(dest_ip)
            else:
                dest_ip = socket.inet_ntoa(arp_detailed[8])
                if dest_ip == selfIP and source_ip == comIP:
                    raw_socket.close()
                    break
                else:
                    ip_list.append(dest_ip)


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
    print("ip n:",result)
    if sender:
        print ("Sender")
        print("Waiting "+ str(delay) + " seconds")
        time.sleep(delay)
        send_arp_table(result, selfIP, ipAddress)
        start_listen (result, selfIP, ipAddress, sender)
        result = sorted(list(set(sorted(result))))
        if selfIP in result:
            result.remove(selfIP)
        if ipAddress in result:
            result.remove(ipAddress)
        print("final")
        print (result)
        start_command(result,selfIP,ipAddress)
    else:
        start_listen(result,selfIP,ipAddress, sender)
        print("After 1st transmission:")
        result = sorted(list(set(sorted(result))))
        print (result)
        time.sleep(delay)
        send_arp_table(result, selfIP, ipAddress)
        result = sorted(list(set(sorted(result))))
        if selfIP in result:
            result.remove(selfIP)
        if ipAddress in result:
            result.remove(ipAddress)
        print("Finish:")
        print(result)
        max_number = len(result)
        number_of_bits = int(floor(log(max_number, 2)))
        sniff(prn=start_listen_master, filter="arp", store=0)
        
        # print ("Source MAC:", binascii.hexlify(arp_detailed[5]))
        # print ("Source IP:", socket.inet_ntoa(arp_detailed[6]))
        # print ("Dest MAC:", binascii.hexlify(arp_detailed[7]))
        # print ("Dest IP:", socket.inet_ntoa(arp_detailed[8]))
        # max_number = len(result)
        # number_of_bits = int(floor(log(max_number, 2)))
        # sniff(prn=start_listen_master, filter="arp", store=0)
