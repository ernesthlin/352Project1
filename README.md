### CS352: Project 1 (Aaron Kau, Ernest Lin)

This README file contains supplementary details about our code that may not be obvious when looking at it.

Our sock352 socket has a "dropPercentage" field that indicates the percentage of packets we should drop when testing our send and receive methods. Again, this field is only for testing purposes, and by default is 0 (no packets are purposefully dropped). We change the "dropPercentage" field of the socket in our client and server test files. For example, if we wanted the client to drop 20% of packets sent, we would have "name_of_socket.dropPercentage = 20" in the client program. after initializing the sock352 socket. 

Since we were told to assume that no handshake packets are dropped, in our sendSingleRdpPacket() method, we have an optional parameter "handshake" that is by default false, and passed as true only in the accept(), connect() and close() methods since the handshake packets are sent in these methods. This ensures that we do not drop the handshake packets when testing our code.