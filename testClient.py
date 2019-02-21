import sock352

sock352.init(28911, 28912)

socket = sock352.socket()

# Create really long string.
s = ""
for i in range(100000):
	s += str(i)

print len(s)

print "Connecting..."
socket.connect(('localhost', 1010))
print "Connected"

print "Sending TEST"
socket.send(s)

ret = socket.recv(488890)

print "DATA RECEIVED BACK"
print "VALID: " + str(ret == s)

socket.close()

print "Closed socket."