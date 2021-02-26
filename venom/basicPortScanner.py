import socket
import sys
'''
Run this script via
```
python basicPortScanner.py localhost 20 200
```
'''
target = socket.gethostbyname(sys.argv[1])
print(sys.argv[1], target)
for port in range(int(sys.argv[2]),int(sys.argv[3])):
    print("Scanning port "+str(port)+"...")
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target,port))
    if result == 0:
        print("We have found an open port: " + str(port))
    else:
        print("next...")
    s.close()
