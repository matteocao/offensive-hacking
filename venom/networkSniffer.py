import socket
import struct
import sys
import os
import subprocess
# network sniffer
if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")
#create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW)

print(s)

# receive a packet
while True:
    # recvfrom does not require the socket to be connected to another one
    data, addr = s.recvfrom(65536) # 16 bit of packets
    print("data:",data , "\nAddress:", addr)
    print("Host address:",socket.gethostbyaddr(addr[0]))

    # ethernet decoding: Packet structure
    #-------------------------------------------------------------------
    #| Ethernet (typically) header | IP header | Your header | payload |
    #-------------------------------------------------------------------
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    payload = data[14:]
    print("host-to-network short: ",socket.htons(proto))
    print("eth0 address of destination: ",":".join(map('{:02x}'.format, dest)).upper())
    print("eth0 address of source: ",":".join(map('{:02x}'.format, src)).upper())
    print("Payload: ",payload)

    struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
# then you have to collect the data and make statistical analyss on it to extract passwords or othher useful information
