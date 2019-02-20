import binascii
import socket as syssock
import struct
import sys
import select

sendPort = 27182
recvPort = 27182

PACKET_SIZE_LIMIT_IN_BYTES = 64000

# Flag bits
SOCK352_SYN = 0x01
SOCK352_FIN = 0x02
SOCK352_ACK = 0x04
SOCK352_RESET = 0x08
SOCK352_HAS_OPT = 0x10

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
        # Perform 3-way handshake as client
        handshakeComplete = False
        while (not handshakeComplete):
            # Handshake part 1 - Send SYN to server.
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_SYN, 0))
            # Handshake part 2 - Receive SYN/ACK from server.
            packet = self.recvSingleRdpPacket()
            # Verify SYN/ACK
            if (packet.flags != SOCK352_SYN | SOCK352_ACK):
                continue
            # Handshake part 3 - Send ACK to server.
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, 0))
            print "3-way Handshake completed from client side."
            handshakeComplete = True
        return 
    
    def listen(self,backlog):
        # Does nothing - will be more useful for multithreaded socket applications.
        return

    def accept(self):
        # Server accepts incoming connection, performs 3-way handhsake, and connects to sender's sendPort
        # Perform 3-way handshake as server
        handshakeComplete = False
        while (not handshakeComplete):
            # Handshake part 1 - Receive SYN
            packet = self.recvSingleRdpPacket()
            # Verify SYN
            if packet.flags != SOCK352_SYN:
                continue
            address = packet.sender_address
            # Prepare Reverse Direction Connection
            self.syssock.connect((address[0], sendPort))
            # Handshake part 2 - Send SYN/ACK
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_SYN | SOCK352_ACK, 0))
            # Handshake part 3 - Receive ACK
            packet = self.recvSingleRdpPacket()
            # Verify ACK
            if packet.flags != SOCK352_ACK:
                continue
            handshakeComplete = True
        print "3-way Handshake completed from server side."
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
        # Break down buffer into packets of max size 64k.
        for i in range(0, len(buffer), PACKET_SIZE_LIMIT_IN_BYTES):
            bufferChunk = buffer[i:i + PACKET_SIZE_LIMIT_IN_BYTES]
            # Build packet from buffer chunk
            packet = rdpPacket((1, 0, 0, 0, 40, 0, 0, 0, i / PACKET_SIZE_LIMIT_IN_BYTES, i / PACKET_SIZE_LIMIT_IN_BYTES, 0, len(bufferChunk)), bufferChunk)
            packets.append(packet)
        self.sendRdpPackets(packets)
        return len(buffer) 

    """
    Receive arbitrary buffer of data. This function should recombine the packets received by 
    the RDP Protocol into the original buffer of data that was transmitted.
    This data should be returned to the caller.
    """
    def recv(self,nbytes):
        # Determine number of packets to receive via RDP Protocol.
        packets_expected = (nbytes - 1) / PACKET_SIZE_LIMIT_IN_BYTES + 1
        packets = self.recvRdpPackets(packets_expected)
        # Unpack packets back into buffer and return to user.
        buffer = ''
        for packet in packets:
            buffer += packet.data
        return buffer 

    """
    Send a set of RDP Packets through the socket. This function will also receive Acknowledgement (ACK) 
    packets from the recipient to ensure the data has been received.
    This function will use the Go-Back-N Procedure to re-send any packets that have not been acknowledged. 
    """
    def sendRdpPackets(self, packets):
        # Send packets in order. Start timer to measure timeout for each packet.
        # Listen for ACKs and re-send packets that exceed timeout.
        # Send individual packets using sendSingleRdpPacket(packet)
        lastAckReceived = -1
        lastPacketSent = -1
        while(lastAckReceived + 1 < len(packets)):
            # Send next packet
            if lastPacketSent + 1 < len(packets):
                lastPacketSent += 1
                self.sendSingleRdpPacket(packets[lastPacketSent])
            # Check for ACK
            (readableSockets, writableSockets, err) = select.select([self.syssock], [], [], 0)
            if (len(readableSockets) > 0):
                packet = self.recvSingleRdpPacket() # Check if packet is corrupted
                lastAckReceived = max(packet.ack_no, lastAckReceived)
            # Check if packet exceeded timeout
            if lastPacketSent > lastAckReceived:
                nextAckExpected = packets[lastAckReceived + 1]
                if False: # If segment hasn't received ACK after timeout, resend.
                    lastPacketSent = lastAckReceived + 1

    """
    Receive a set of RDP Packets from the socket. This function will also send Acknowledgement (ACK)
    packets to the sender to inform them that the packet has been received.  
    """
    def recvRdpPackets(self, numPackets):
        # Continuously call recvSingleRdpPacket and fill in packets receive.
        # After each received packet, send acknowledgement of latest packet received where all previous
        # packets have also been received.
        # Return set of packets received back to caller.
        ret = [None] * numPackets
        lastAck = -1
        while(lastAck + 1 < numPackets):
            nextPacket = self.recvSingleRdpPacket()
            if (nextPacket.sequence_no == lastAck + 1): # Also need to check if packet is not corrupted
                lastAck += 1
                ret[lastAck] = nextPacket
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, lastAck))
        return ret


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
        rawData = packet.pack()
        self.syssock.send(packet.pack())

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
        # Read one entire datagram.
        (packedPacket, address) = self.syssock.recvfrom(PACKET_SIZE_LIMIT_IN_BYTES + 40)
        header = struct.unpack("!BBBBHHLLQQLL", packedPacket[:40])
        # Last 4 bytes contain payload length.
        payload_len = header[-1]
        data = ''
        if payload_len > 0:
            data = packedPacket[40:]
        ret = rdpPacket(header, data)
        ret.sender_address = address
        return ret


    """
    Generate ACK RDP Packet with no payload
    """
    def generateEmptyPacket(self, flags,ack_no):
        return rdpPacket((1, flags, 0, 0, 40, 0, 0, 0, ack_no, ack_no, 0, 0), '')

class rdpPacket:

    def __init__(self, (version, flags, opt_ptr, protocol, header_len, checksum, source_port, dest_port, sequence_no, ack_no, window, payload_len), data):
        self.version = version # Should be 1
        self.flags = flags
        self.opt_ptr = opt_ptr # Should be 0
        self.protocol = protocol # Should be 0
        self.header_len = header_len # Should be 40
        self.checksum = checksum
        self.source_port = source_port # Should be 0
        self.dest_port = dest_port # Should be 0
        self.sequence_no = sequence_no
        self.ack_no = ack_no
        self.window = window
        self.payload_len = payload_len
        self.data = data

    def pack(self):
        return struct.pack("!BBBBHHLLQQLL", self.version, self.flags, self.opt_ptr, self.protocol, self.header_len, self.checksum,
            self.source_port, self.dest_port, self.sequence_no, self.ack_no, self.window, self.payload_len) + self.data

    def generateChecksum(self):
        pass
