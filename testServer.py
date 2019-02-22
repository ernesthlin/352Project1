import sock352

sock352.init(28912, 28911)

socket = sock352.socket()

print "Binding..."
socket.bind(('', 1010))
print "Listening..."
socket.listen(5)
print "Accepting..."
socket.accept()

print "Receiving..."
data = socket.recv(488890)

print "Sending: " + data[:20] + "..." + data[-20:]
ret = socket.send(data)

print "Sent."
print "Closing socket..."

socket.close()

print "Closed socket."