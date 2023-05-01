'''sources:
https://docs.python.org/3/library/argparse.html

Qs:
1. Why the banner grabbing now doesn't work?There's now Raw in Http response somehow
2. The TCP Fin has different result with others
'''

import socket
from scapy.all import *
import time
import argparse
import random

# Normal TCP Scanning 
def norm_scan(target_IP, port):
    # Create a TCP SYN packet
    syn_packet = IP(dst=target_IP)/TCP(dport=port,flags="S")
    # Send the packet and wait for a response
    response = sr1(syn_packet,timeout=2,verbose=False)
    # Print message if there was a response received
    if response:
        # Create a TCP SYN packet
        ack_packet = IP(dst=target_IP)/TCP(dport=port,flags="A", ack=response[TCP].seq + 1)
        send(ack_packet,verbose=False)

        HTTP_request = IP(dst=target_IP)/TCP(dport=port)/Raw(b"GET / HHTP/1.1\r\nHost: " + target_IP.encode() + b"\r\n\r\n")
        HTTP_response = sr1(HTTP_request, timeout=2,verbose=False)

        # Check if the response is an HTTP response and print the banner
        if HTTP_response and HTTP_response.haslayer(TCP) and HTTP_response.haslayer(Raw):
            return HTTP_response[Raw].load
        return True
    else:
        return False

# TCP SYN Scanning (only send the initial SYN Packet and then send RST when client responds with SYN/ACK)
def syn_scan(target_IP, port):
    # Create a TCP SYN packet
    packet = IP(dst=target_IP)/TCP(dport=port,flags="S")
    # Send the packet and wait for a response
    response = sr1(packet,timeout=1,verbose=False)
    # Print message if there was a response received
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            return True
        # Close the connection by RST packet
        send(IP(dst=target_IP)/TCP(dport=response.sport,flags="R"),verbose=False)
    else:
        return False


# TCP Fin Scanning for a single port
def fin_scan(target_IP,port):
    # define randoom source port
    src_port = random.randint(1025,65534)
    # Send Fin to a destination port
    fin_resp = sr1(
        IP(dst=target_IP)/TCP(sport=src_port,dport=port,flags="F"),timeout=1,
        verbose=False,
    )
    # Port is open when no response
    if (fin_resp is None):
        return True
    # Port is closed when response has an RST flag in the TCP
    if fin_resp.haslayer(TCP) and fin_resp.getlayer(TCP).flags == 0x14:
        return False
    return False

target_IP = "131.229.72.13"
# 131.229.72.13
# Create an argument parser for port scanning modes
parser = argparse.ArgumentParser(description="Different modes of port scanning: Normal Port Scanning, TCP SYN Scanning, TCP FIN Scanning")
# parser.add_argument('target', metavar='target', type=str, help='Target IP address')
parser.add_argument('-mode', type=str, help="[normal/syn/fin]")
parser.add_argument('-order', type=str, help="[order/random]")
parser.add_argument('-ports', type=str, help="[all/known]")

# Parse the arguments from the command line
mode = parser.parse_args().mode
ports=parser.parse_args().ports
order=parser.parse_args().order

# set the port list
port_range=[]
if ports=="all":
    port_range=list(range(1,65536))
elif ports=="known":
    port_range=list(range(1,1024))

if order == "random":
    random.shuffle(list(port_range))


# record start time
start_time=time.time()
open_port_list=[]

# scan each port in the list
num_close=0
for port in port_range:
    if mode=="normal":
        if norm_scan(target_IP, port):
            try:
                service = socket.getservbyport(port)
            except:
                service=""
            open_port_list.append([port,service])
        elif norm_scan(target_IP, port)==False:
            num_close+=1

    if mode=="syn":
        if syn_scan(target_IP, port):
            try:
                service = socket.getservbyport(port)
            except:
                service=""
            open_port_list.append([port,service])
        else: num_close+=1

    if mode=="fin":
        if fin_scan(target_IP, port):
            try:
                service = socket.getservbyport(port)
            except:
                service=""
            open_port_list.append([port,service])
        else: num_close+=1

# record end time
end_time=time.time()

# print final results
print("Start port scan at: " + str(start_time))
print("Interesting ports on " + target_IP)
print(f"Not shown:{num_close} closed ports")
print("PORT     STATE     SERVICE")
for p in open_port_list:
    print(f"{p[0]}/tcp    open    {p[1]}")
print(f"scan done! in {target_IP} ({len(open_port_list)} host up) scanned in {str(end_time-start_time)}secs")


