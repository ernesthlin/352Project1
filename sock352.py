import binascii
import socket as syssock
import struct
import sys
import select

sendPort = 27182
recvPort = 27182

PACKET_SIZE_LIMIT_IN_BYTES = 64000

# Flag bits
SOCK352_SYN     = 0b00001  # 0x01 == 1
SOCK352_FIN     = 0b00010  # 0x02 == 2
SOCK352_ACK     = 0b00100  # 0x04 == 4
SOCK352_RESET   = 0b01000  # 0x08 == 8
SOCK352_HAS_OPT = 0b10000  # 0x10 == 16

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
        # TODO - If no SYN/ACK Received after certain time, restart handshake. 
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
        # TODO - If no ACK Received after certain time, restart handshake.
        handshakeComplete = False
        while (not handshakeComplete):
            # Handshake part 1 - Receive SYN
            packet = self.recvSingleRdpPacket()
            # Verify SYN (TODO: Check if packet is corrupted)
            if packet.flags != SOCK352_SYN:
                continue
            address = packet.sender_address
            # Prepare Reverse Direction Connection
            self.syssock.connect((address[0], sendPort))
            # Handshake part 2 - Send SYN/ACK
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_SYN | SOCK352_ACK, 0))
            # Handshake part 3 - Receive ACK
            packet = self.recvSingleRdpPacket()
            # Verify ACK (TODO: Check if packet is corrupted)
            if packet.flags != SOCK352_ACK:
                continue
            handshakeComplete = True
        print "3-way Handshake completed from server side."
        return (self, address)
    
    """
    Closes connection obetween client and server.
    Verifies that both client and server are finished by performing 2-way handshake.
    Client and Server both send a FIN and an ACK for the FIN that they receive.
    """
    def close(self): 
        # 2-way double handshake. Send FIN and wait for ACK.
        # TODO - If First FIN Not Received after timeout, not sure what to do...
        # This either means: The last ACK sent by this socket was not received OR 
        # The FIN that was sent to this socket was lost.
        # In the latter case, it is sufficient to restart the handshake but there is no way
        # to know if the last ACK was received by the sender. 
        # TODO - If ACK Not Received after timeout, restart handshake.
        handshakeComplete = False
        while (not handshakeComplete):
            # Handshake part 1 - Send FIN.
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_FIN, 0))
            # Handshake part 2 - Receive FIN.
            packet = self.recvSingleRdpPacket()
            # Verify FIN (TODO: Check if packet is corrupted)
            if packet.flags != SOCK352_FIN:
                continue
            # Handshake part 3 - Send ACK.
            self.sendSingleRdpPacket(self.generateEmptyPacket(SOCK352_ACK, 0))
            # Handshake part 4 - Receive ACK.
            packet = self.recvSingleRdpPacket()
            # Verify ACK (TODO: Check if packet is corrupted)
            if packet.flags != SOCK352_ACK:
                continue
            handshakeComplete = True

        print "2-way double handshake complete. Closing Socket."
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
        # TODO - If ACK 0 not received after timeout, restart 3-way handshake.
        # TODO - If ACK N > 0 not received after timeout, continue to send from Sequence N.
        lastAckReceived = -1
        lastPacketSent = -1
        while(lastAckReceived + 1 < len(packets)):
            # Send next packet
            if lastPacketSent + 1 < len(packets):
                lastPacketSent += 1
                self.sendSingleRdpPacket(packets[lastPacketSent])
                print "Sent " + str(lastPacketSent) + " and ACKed " + str(lastAckReceived)
            # Check for ACK
            (readableSockets, writableSockets, err) = select.select([self.syssock], [], [], 0)
            if (len(readableSockets) > 0):
                packet = self.recvSingleRdpPacket() # (TODO: Check if packet is corrupted. If so, ignore it).
                print "Packet Received. ACK: " + str(packet.ack_no)
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
        # TODO - If Sequence 0 is not received after timeout, restart 3-way handshake.
        # TODO - If Sequence N > 0 not received after timeout, re-send ACK(N-1)
        ret = [None] * numPackets
        lastAck = -1
        while(lastAck + 1 < numPackets):
            (readableSockets, writableSockets, err) = select.select([self.syssock], [], [], 0)
            nextPacket = self.recvSingleRdpPacket()
            print "Received Sequence no: " + str(nextPacket.sequence_no)
            if (nextPacket.sequence_no == lastAck + 1): # (TODO: Check if packet is corrupted. If so, ignore it).
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
        # Serialize RDP Packet into raw data.
        # Transmit data through UDP socket.
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
    Generate RDP Packet with no payload
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

    def generateChecksum(self, replace = True):
        new_checksum = 0
        num_bytes = WORD_SIZE / 8
        list_words = [self.data[i : i + num_bytes] for i in range(0, len(self.data), num_bytes)]

        for word in list_words:
            if len(word) == 2:
                new_checksum ^= struct.unpack("!H", word)[0]
            elif len(word) == 1:
                new_checksum ^= struct.unpack("!B", word)[0]

        new_checksum = ~new_checksum

        if replace:
            self.checksum = new_checksum
            return None

        return new_checksum
    """
    Returns 0 if packet is not corrupted (checksum was unchanged)
    """
    def check_checksum(self):
        return self.checksum ^ generateChecksum(self, replace = False)
