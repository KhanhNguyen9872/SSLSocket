import SSLSocket

# SSLSocket.log.setOutput(open('log.txt', 'w'))	# Change output write log
# SSLSocket.log.disableError(True)	# Disable Error log
# SSLSocket.log.disableError(False)	# Enable Error log

SSLSocket.installCert()
server = SSLSocket.Server("sslsocket.com")
server.setServer("127.0.0.1", "8080")
server.start()
