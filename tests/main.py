import SSLSocket

SSLSocket.installCert()
server = SSLSocket.Server("khanhdeptrai.wibu")
server.setServer("127.0.0.1", "8080")
server.start()
