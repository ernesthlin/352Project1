import binascii
import socket as syssock
import struct
import sys

sendPort = 27182
recvPort = 27182

PACKET_SIZE_LIMIT_IN_BYTES = 64000

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
    
    def __init__(self):
        # Prepare System UDP Socket
        self.syssock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    
    def bind(self,address):
        # Bind - Server will bind on recvPort and wait for incoming connections.
        self.syssock.bind((address[0], recvPort))
        return 

    def connect(self,address):
        # Client will connect to address on sendPort and will receive from recvPort.
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

    """
    Send arbitrary buffer of data. This function should break down buffer into a series of 
    RDP packets to transmit through the socket. 
    """
    def send(self,buffer):
        packets = []
        for i in range(0, len(buffer), PACKET_SIZE_LIMIT_IN_BYTES):
            bufferChunk = buffer[i:i + PACKET_SIZE_LIMIT_IN_BYTES]
            # Build packet from buffer chunk

        sendRdpPackets(packets)
        return len(buffer) 

    """
    Receive arbitrary buffer of data. This function should recombine the packets received by 
    the RDP Protocol into the original buffer of data that was transmitted.
    This data should be returned to the caller.
    """
    def recv(self,nbytes):


        # Determine number of packets to receive via RDP Protocol.
        # Call recvRdpPackets(n) to receive packets.
        # Unpack packets back into buffer and return to user.

        return data 


    """
    Send a set of RDP Packets through the socket. This function will also receive Acknowledgement (ACK) 
    packets from the recipient to ensure the data has been received.
    This function will use the Go-Back-N Procedure to re-send any packets that have not been acknowledged. 
    """
    def sendRdpPackets(self, packets):
        # Send packets in order. Start timer to measure timeout for each packet.
        # Listen for ACKs and re-send packets that exceed timeout.
        # Send individual packets using sendSingleRdpPacket(packet)
        pass

    """
    Receive a set of RDP Packets from the socket. This function will also send Acknowledgement (ACK)
    packets to the sender to inform them that the packet has been received.  
    """
    def recvRdpPackets(self, numPackets):
        # Continuously call recvSingleRdpPacket and fill in packets receive.
        # After each received packet, send acknowledgement of latest packet received where all previous
        # packets have also been received.
        # Return set of packets received back to caller.
        pass

    """
    Sends single RDP Packet. All transmissions across UDP Network should use this.
    Packets have a size limit. It may be necessary for the caller to break up 
    the transmitted data into multiple packets and send them in order.

    Once the packet is sent, it is the responsibility of the caller to receive the Acknowledgement (ACK)
    packet from the receiver of the packet.
    """
    def sendSingleRdpPacket(self, packet):
        # Serlialize RDP Packet into raw data.
        # Transmit data through UDP socket.
        pass

    """
    Receives single RDP Packet. All packets should be received using this.
    Packets have a size limit. It may be necessary for the caller to 
    receive multiple packets before they get all the data they want.

    Once the packet is received, it is the responsibility of the caller to send the Acknowledgement (ACK)
    packet back to the sender of the packet.
    """
    def recvSingleRdpPacket(self):
        # Deserialize raw data and rebuild RDP Packet.
        # Return RDP Packet to caller.
        pass

def unpack(header, data):
    headerData = struct.unpack(header)
    return rdpPacketHeader(headerData, data)

class rdpPacket:

    def __init__((version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len), data):
        self.version = version # Should be 1
        self.flags = flags
        self.opt_ptr = opt_ptr # Should be 0
        self.protocol = protocol # Should be 0
        self.header_len = header_len
        self.checksum = checksum
        self.source_port = source_port # Should be 0
        self.dest_port = dest_port # Should be 0
        self.sequence_no = sequence_no
        self.ack_no = ack_no
        self.window = window
        self.payload_len = payload_len
        self.data = data

    def pack():
        return struct.pack("!BBBBHHLLQQLL", self.version, self.flags, self.opt_ptr, self.protocol, self.header_len, self.checksum,
            self.source_port, self.dest_port, self.sequence_no, self.ack_no, self.window, self.payload_len)
