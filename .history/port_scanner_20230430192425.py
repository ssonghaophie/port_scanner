'''sources:
https://docs.python.org/3/library/argparse.html

Qs:
1. Runtime too long, is that okay?
2. How to check if Host is alive? Is that different from Port up running?
3. For FIN Scanning, is it only open when the response is NONE? Do we have to care about firewalls or other possible unexpected responses? 
'''





import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket
import argparse

# Create an argument parser for port scanning modes
mode_parser = argparse.ArgumentParser(description="Different modes of port scanning: Normal Port Scanning, TCP SYN Scanning, TCP FIN Scanning")
mode_parser.add_argument('-mode', type=str, help="[normal/syn/fin]")
# Parse the arguments from the command line
mode = mode_parser.parse_args()
# if mode is :

# Create an argument parser for port scanning order
order_parser = argparse.ArgumentParser(description="Different order of port scanning: In Order, Random Order")
order_parser.add_argument('-order', type=str, help="[order/random]")
# Parse the arguments from the command line
order = order_parser.parse_args()
# if order is :

# Create an argument parser for port scanning amount
ports_parser = argparse.ArgumentParser(description="Different number of ports for port scanning: All Ports, Well-known TCP Ports Only")
ports_parser.add_argument('-ports', type=str, help="[all/known]")
# Parse the arguments from the command line
ports = ports_parser.parse_args()
# if order is :

# specify the target IP address
target_IP = "131.229.72.13"

# Check if target host is alive
#modes = input("Which mode? (Normal Port Scanning / TCP SYN Scanning / TCP FIN Scanning): ")
#if modes == 

# create a loop to iterate through all ports
for port in range(65535):
    # create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set a timeout in case the port is not open
    sock.settimeout(1)
    # attempt to connect to the port
    result = sock.connect_ex((target_IP, port))
    # if the port is open, print a message
    if result == 0:
        print(f"Port {port} is open")
    # close the socket
    sock.close()


# TCP SYN Scanning (only send the initial SYN Packet and then send RST when client responds with SYN/ACK)
def syn_scan(target_IP, port):
    # Create a TCP SYN packet
    packet = IP(dst=target_IP)/TCP(dport=port,flags="S")
    # Send the packet and wait for a response
    response = sr1(packet,timeout=1,verbose=0)
    # Print message if there was a response received
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"{port}/tcp    open")
        # Close the connection by RST packet
        send(IP(dst=target_IP)/TCP(dport=response.sport,flags="R"))