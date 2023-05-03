'''sources:
https://docs.python.org/3/library/argparse.html

Qs:
1. Why the banner grabbing now doesn't work?There's now Raw in Http response somehow
2. The TCP Fin has different result with others
'''

import socket
from scapy.all import *
import datetime
import argparse
import random

# Normal TCP Scanning 
def norm_scan(target_IP, port):
  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    response=s.connect_ex((target_IP, port))
    if response==0:
        banner = s.recv(1024) 
        s.close()
        return banner.decode()
    return None


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
        IP(dst=target_IP)/TCP(sport=src_port,dport=port,flags="F"),timeout=2,
        verbose=False,
    )
    # Port is open when no response
    if (fin_resp is None):
        return True
    return False


def port_scan(target_IP, port_range):
    # record start time
   
    open_port_list=[]
    num_close=0
    for port in port_range:
        if mode=="normal":
            banner=norm_scan(target_IP, port)
            if banner is not None:
                try:
                    service = socket.getservbyport(port)
                except:
                    service=""
                open_port_list.append([port,service,banner])
            else:
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
    return open_port_list, num_close

# Create an argument parser for port scanning modes
parser = argparse.ArgumentParser(description="Different modes of port scanning: Normal Port Scanning, TCP SYN Scanning, TCP FIN Scanning")
# parser.add_argument('target', metavar='target', type=str, help='Target IP address')
parser.add_argument('-mode', type=str, help="[normal/syn/fin]")
parser.add_argument('-order', type=str, help="[order/random]")
parser.add_argument('-ports', type=str, help="[all/known]")
parser.add_argument('target_ip', type=str, help="target ip address")

# Parse the arguments from the command line
mode = parser.parse_args().mode
ports=parser.parse_args().ports
order=parser.parse_args().order
target_IP =parser.parse_args().target_ip

# set the port list
port_range=[]
if ports=="all":
    port_range=list(range(0,65536))
elif ports=="known":
    port_range=list(range(0,30))

if order == "random":
    random.shuffle(list(port_range))

# Send an ICMP echo request packet to the target device
icmp_request_packet = IP(dst=target_IP)/ICMP(type=8)
icmp_response_packet = sr1(icmp_request_packet, timeout=2, verbose=False)

is_alive=False
# If the response packet is not None and has an ICMP type of 0, the target is alive
if icmp_response_packet is not None and icmp_response_packet[ICMP].type == 0:
    is_alive=True

if is_alive:
    start_time= datetime.datetime.now()
    open_port_list, num_close = port_scan(target_IP,port_range)
    # record end time
    end_time= datetime.datetime.now()

    # print final results
    print("Start port scan at: " + str(start_time))
    print("Interesting ports on " + target_IP)
    print(f"Not shown:{num_close} closed ports")
    if mode=="normal":
        print("PORT     STATE     SERVICE       BANNER")
    else:
        print("PORT     STATE     SERVICE")

    for p in open_port_list:
        if mode=="normal":
            print(f"{p[0]}/tcp    open    {p[1]}      {p[2]}")
        else:
            print(f"{p[0]}/tcp    open    {p[1]}")
    print(f"scan done! in {target_IP} ({len(open_port_list)} host up) scanned in {end_time-start_time}secs")
else:
    print("Target IP is not alive")

