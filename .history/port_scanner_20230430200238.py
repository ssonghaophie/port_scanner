'''sources:
https://docs.python.org/3/library/argparse.html
https://thepacketgeek.com/scapy/building-network-tools/part-06/

Qs:
1. Runtime too long, is that okay? Yes, and set timeout every 2 sec for each port
2. How to check if Host is alive? Is that different from Port up running? Send ICMP ping
3. For FIN Scanning, is it only open when the response is NONE? Do we have to care about firewalls or other possible unexpected responses? Don't care about it!
'''

import socket
from scapy import *
from datetime import datetime

# specify the target IP address
# send ICMP ping
target_IP = "131.229.72.13"

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

# Check if target host is alive
# Send ICMP packet 
ping = IP(dst="131.229.72.13")/ICMP()
host_response = sr1(ping, timeout=2)
if int(fin_scan_resp.getlayer(ICMP).code)



# record start time
start_time=str(datetime.now())
print("Start port scan at:" + str(datetime.now()))

# create a loop to iterate through all ports
for i in range(1023):
    # create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set a timeout in case the port is not open
    sock.settimeout(2)
    # attempt to connect to the port
    result = sock.connect_ex((target_IP, i))
    # if the port is open, print a message
    if result == 0:
        print(f"Port {i} is open")
    # close the socket
    sock.close()

# record end time
end_time=str(datetime.now())
print("scan done! in" + start_time-end_time)

# TCP SYN Scanning (only send the initial SYN Packet and then send RST when client responds with SYN/ACK)
def syn_scan(target_IP, port):
    # Create a TCP SYN packet
    packet = IP(dst=target_IP)/TCP(dport=port,flags="S")
    # Send the packet and wait for a response
    response = sr1(packet,timeout=2)
    # Print message if there was a response received
    if response:
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"{port}/tcp    open")
        # Close the connection by RST packet
        send(IP(dst=target_IP)/TCP(dport=response.sport,flags="R"))


# TCP Fin Scanning for a single port
def fin_scan(target_IP,port):
    # define randoom source port
    src_port = random.randint(1025,65534)
    # Send Fin to a destination port
    fin_resp = sr1(
        IP(dst=target_IP)/TCP(sport=src_port,dport=port,flags="F"),timeout=2)
    # Port is open when no response
    if (fin_resp is None):
        return True
    # Port is closed when response has an RST flag in the TCP
    elif fin_resp.haslayer(TCP) and fin_resp.getlayer(TCP).flags == 0x14:
        return False
    # Port is filtered when reponse has a type 3 ICMP packet with code [1,2,3,9,10,13]
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "filtered"
    