import socket

# specify the target IP address
target_IP = "131.229.72.13"

# create a loop to iterate through all ports
for i in range(65535):
    # create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # set a timeout in case the port is not open
    sock.settimeout(1)
    # attempt to connect to the port
    result = sock.connect_ex((target_IP, i))
    # if the port is open, print a message
    if result == 0:
        print(f"Port {i} is open")
    # close the socket
    sock.close()