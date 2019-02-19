
import binascii
import socket as syssock
import struct
import sys

sendPort = 27182
recvPort = 27182

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from

def init(UDPportTx,UDPportRx): 
    global sendPort
    global recvPort
    # Save send and receive ports
    sendPort = int(UDPportTx)
    recvPort = int(UDPportRx)
    
class socket:
    
    def __init__(self, sys = None):
        # Prepare System UDP Socket
        self.syssock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    
    def bind(self,address):
        # Bind - Server will bind on recvPort and wait for incoming connections.
        print address
        print recvPort
        self.syssock.bind((address[0], recvPort))
        return 

    def connect(self,address):
        # Client will connect to address on sendPort and will receive from recvPort.
        print("Binding on " + address[0] + ":" + str(recvPort))
        self.syssock.bind((address[0], recvPort))
        self.syssock.connect((address[0], sendPort))
        #
        # Perform 3-way handshake as client!
        #
        self.syssock.send("SYN")
        data, addr = self.syssock.recvfrom(7)
        print "RECEIVED " + data
        self.syssock.send("ACK")
        return 
    
    def listen(self,backlog):
        # Does nothing - will be more useful for multithreaded socket applications.
        return

    def accept(self):
        # Server accepts incoming connection, performs 3-way handhsake, and connects to sender's sendPort
        #
        # Perform 3-way handshake as server!
        #
        # Handshake part 1 - Receive SYN
        (data, address) = self.syssock.recvfrom(3)
        print ("RECEIVED " + data)
        # Prepare Reverse Direction Connection
        self.syssock.connect((address[0], sendPort))
        # Handshake part 2 - Send SYN/ACK
        self.syssock.send("SYN/ACK")
        # Handshake part 3 - Receive ACK
        (data, address) = self.syssock.recvfrom(3)
        print ("RECEIVED " + data)
        return (self, address)
    
    def close(self): 
        # Tell OS we are done with socket.
        self.syssock.close()
        return 

    def send(self,buffer):
        bytessent = self.syssock.send(buffer)
        print("SENDING: " + buffer)
        return bytessent 

    def recv(self,nbytes):
        data = self.syssock.recv(nbytes)
        print("RECEIVING: " + data)
        return data 


    


