
import socketserver

import sys
import socket
import warnings

## the expected use is `python simpleProxy.py int_LPORT int_INTERCEPT`
try:
    LPORT = int(sys.argv[1])
except:
    LPORT = 80
try:
    INTERCEPT = int(sys.argv[2])
except:
    INTERCEPT = False
    
LHOST = "0.0.0.0" #proxy server IP
RHOST = "www.example.org" #a default URL
RPORT = 80 #standard HTTP port

def ActivateProxy():
    # create an INET, STREAMing socket
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # bind the socket to a public host, and a well-known port
    serversocket.bind((LHOST, LPORT))
    # become a server socket
    serversocket.listen(5)
    print("Proxy Server is listening at "+LHOST+":"+str(LPORT))
    while True:
        # accept connections from teh client
        (clientsocket, address) = serversocket.accept()
        print("Client address:",address)
        print("Client socket:",clientsocket)
        # now do something with the clientsocket
        # in this case, we'll pretend this is a threaded server
        ct = client_thread(clientsocket)
        server_response = ct.run()
        # send server response back to client
        print("Sending answer back to client...")
        clientsocket.send(server_response)
        #clientsocket.close()
        

class client_thread():
    def __init__(self, clientsocket):
        self.clientsocket = clientsocket

    def run(self):
        global RHOST
        request_text = self.clientsocket.recv(4096).decode("utf-8")
        print("Request to send the RHOST:",request_text)
        if INTERCEPT:
            warnings.warn("put code here to intercept the request")
        # the structure of the request GET http://www.example.com HTTP/1.1\r\n...
        req_type, req_url, req_prot = (request_text.split('\r\n')[0]).split(' ')
        print("-"*100)
        print(req_type, req_url, req_prot)
        print("-"*100)
        
        # extract RHOST from string
        if not req_url.find("http") ==-1:
            RHOST_with_protocol=req_url.replace('/','',1)
            RHOST = RHOST_with_protocol.split('//')[1]
            address = '/'
        else:
            address = req_url
        
        #remove the initial `/` before protocol
        request_text = request_text.replace('/','',1)
        # set the RHOST as Host in the Header
        request_text = request_text.replace('localhost',RHOST,1)
        print("Requested URL:",request_text)
        # put together the remaning headers
        headers = ' '.join(request_text.split(' ')[2:])
        # Here we are sending the request to the server
        try:
            print("Connecting socket to", RHOST)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((RHOST,RPORT))
            msg="GET "+address+" HTTP/1.1\r\nHost: "+RHOST+"\r\n\r\n"
            #sending the request to the server
            #msg = "GET "+address+headers
            s.sendall(msg.encode('utf-8'))# requires byte object
            response = s.recv(4096)#.decode("utf-8")
            whole_response = response
            s.settimeout(1)
            
            # do the whle loop till you get the socket timeout
            while True:
                print(len(response))
                response = s.recv(4096)
                whole_response += response
                #response.decode("utf-8")
        except socket.timeout:
            print("Server Response: ",whole_response)
            s.close()
            if INTERCEPT:
                warnings.warn("put code here to intercept the response")
            return whole_response
        except socket.error as m:
            print(str(m))
            s.close()
            sys.exit(1)
        
if __name__ == "__main__":
    ActivateProxy()

