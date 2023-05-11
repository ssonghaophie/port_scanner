'''sources:
https://docs.python.org/3/library/argparse.html
https://scapy.readthedocs.io/en/latest/extending.html
https://scapy.readthedocs.io/en/latest/layers/tcp.html
https://docs.python.org/3/library/socket.html

'''

# IP = 131.229.72.13

# To ignore warnings
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

import socket
from scapy.all import *
import datetime
import argparse
import random

# Normal TCP Scanning 
def norm_scan(target_IP, port):
    # Create socket object of IPv4 and TCP
    TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Timeout = 0.5
    TCP_socket.settimeout(0.5)
    # Create a response when connecting to the target IP and port
    response=TCP_socket.connect_ex((target_IP, port))
    # If port is open
    if response==0:
        # Grab banner
        TCP_socket.send(b"GET / HTTP/1.1\r\nHost: "+ bytes(target_IP, 'utf-8')+ b"\r\n\r\n")
        banner = TCP_socket.recv(1024) 
        # Close socket
        TCP_socket.close()
        return banner.decode('utf-8')
    return None


# TCP SYN Scanning 
def syn_scan(target_IP, port):
    # Create a TCP SYN packet
    SYN_packet = IP(dst=target_IP)/TCP(dport=port,flags="S")
    # Send the packet and wait for a response with a timeout of 0.5
    response = sr1(SYN_packet,timeout=0.5,verbose=False)
    # Analyze response
    if response:
        # If the response is SYN/ACK packet
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # Port open
            return True
        # Close the connection by RST packet
        send(IP(dst=target_IP)/TCP(dport=response.sport,flags="R"),verbose=False)
    else:
        # Port closed otherwise
        return False


# TCP Fin Scanning for a single port
def fin_scan(target_IP,port):
    # Define random source port
    #src_port = random.randint(1025,65534)

    # Create a TCP FIN packet
    FIN_packet = IP(dst=target_IP)/TCP(dport=port,flags="F")
    # Send FIN to a destination port
    response = sr1(FIN_packet,timeout=0.5, verbose=False)
    
    # Analyze response
    if response is None:
        # Port open when response is none
        return True
    elif response.haslayer(TCP) and fin_resp.getlayer(TCP).flags == 0x14:
        # Port closed if response is RST packet
        return False
    else:
        # Port open otherwise
        return True

# Port Scanner
def port_scan(target_IP, port_range):
    # List for open ports & counter for the number of closed ports
    open_port_list=[]
    num_close=0

    # Loop through the ports
    for port in port_range:
        # Normal mode
        if mode=="normal":
            banner=norm_scan(target_IP, port)
            # If banner is returned, meaning that port is open
            if banner is not None:
                # Record service
                try:
                    service = socket.getservbyport(port)
                except:
                    service="UNKNOWN"
                # Append to list
                open_port_list.append([port,service,banner])
            # Increment closed port counter if port not open
            else:
                num_close+=1

        # Syn scan
        if mode=="syn":
            # If port open
            if syn_scan(target_IP, port):
                # Record service
                try:
                    service = socket.getservbyport(port)
                except:
                    service="UNKNOWN"
                open_port_list.append([port,service])
            # Increment closed port counter if port not open
            else: num_close+=1

        # Fin scan
        if mode=="fin":
            # If port open
            if fin_scan(target_IP, port):
                # Record service
                try:
                    service = socket.getservbyport(port)
                except:
                    service="UNKNOWN"
                open_port_list.append([port,service])
            # Increment closed port counter if port not open
            else: num_close+=1
    # Return list and counter
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
# Ports
if ports=="all":
    port_range=list(range(0,65536))
elif ports=="known":
    port_range=list(range(0,1024))

# Order
if order == "random":
    random.shuffle(port_range)

# Send an ICMP echo request packet to the target device
icmp_request_packet = IP(dst=target_IP)/ICMP(type=8)
icmp_response_packet = sr1(icmp_request_packet, timeout=2, verbose=False)

# Default
is_alive=False

# If the response packet is not None and has an ICMP type of 0, the target is alive
if icmp_response_packet is not None and icmp_response_packet[ICMP].type == 0:
    is_alive=True

# Scan if target ip is alive
if is_alive:
    # Record start time
    start_time= datetime.datetime.now()
    # Run port scan
    open_port_list, num_close = port_scan(target_IP,port_range)
    # Record end time
    end_time= datetime.datetime.now()

    # Print final results
    print("Start port scan at: " + str(start_time))
    print("Interesting ports on " + target_IP)
    print(f"Not shown: {num_close} closed ports")
    if mode=="normal":
        print("%-10s %-10s %-10s %-10s" % ("PORT", "STATE", "SERVICE", "BANNER"))
    else:
        print("%-10s %-10s %-10s" % ("PORT", "STATE", "SERVICE"))

    for p in open_port_list:
        if mode=="normal":
            print("%-10s %-10s %-10s %-100s" % (str(p[0])+"/tcp","open",p[1],p[2]))
        else:
            print("%-10s %-10s %-10s" % (str(p[0])+"/tcp","open",p[1]))
    print(f"scan done! 1 IP adress: {target_IP} (1 host up) scanned in {end_time-start_time} seconds")
else:
    print("Target IP is not alive")

