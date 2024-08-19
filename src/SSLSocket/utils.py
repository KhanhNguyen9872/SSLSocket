import os
from .exceptions import *

if os.name != 'nt':
    raise DeviceNotSupported("only support Windows!")

import OpenSSL
from pathlib import Path
from threading import Thread
import ssl, socket

certPath = "./cert"
rootCAPath = "/".join("/".join(__file__.split("\\")).split("/")[:-1]) + "/cert"
rootCAPass = "12345678"

def installCert(path = rootCAPath + "/rootCA.crt") -> None:
    os.system("certutil.exe -addstore root {} >NUL 2>&1".format(path))
    print("> if install cert not working, you must install this file [{}] into browser or anything".format(path))
    return

class Server:
    def __init__(self, domain):
        self.__isStart = False
        self.__domain = domain
        self.__sslKey = certPath + "/{}.key".format(self.__domain)
        self.__sslCsr = certPath + "/{}.csr".format(self.__domain)
        self.__sslCrt = certPath + "/{}.crt".format(self.__domain)
        return

    def __prepareSSL(self):
        if not self.__domain:
            raise NameError("domain error")
    
        if not Path(certPath).is_dir():
            os.mkdir(certPath)
        
        # .key
        if Path(self.__sslKey).is_file():
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(self.__sslKey, 'rb').read())
        else:
            key = OpenSSL.crypto.PKey()
            key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
            open(self.__sslKey, 'wb').write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))


        # .csr
        if Path(self.__sslCsr).is_file():
            csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, open(self.__sslCsr, 'rb').read())
        else:
            csr = OpenSSL.crypto.X509Req()
            csrSub = csr.get_subject()
            csrSub.C = "VN"  # Country Name
            csrSub.ST = "Ho Chi Minh"  # State or Province Name
            csrSub.L = "Ho Chi Minh"  # Locality Name
            csrSub.O = "SSLServer"  # Organization Name
            csrSub.OU = "SSLServer"  # Organizational Unit Name
            csrSub.CN = self.__domain  # Common Name
            csrSub.emailAddress = "sslserver@localhost.com"  # Email Address
            
            csr.set_pubkey(key)
            csr.sign(key, "sha256")
            open(self.__sslCsr, 'wb').write(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr))


        # .crt
        if Path(self.__sslCrt).is_file():
            crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(self.__sslCrt, 'rb').read())
        else:
            rootCAPem = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(rootCAPath + "/rootCA.pem", 'rb').read())
            rootCAKey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(rootCAPath + "/rootCA.key", 'rb').read(), passphrase=rootCAPass.encode())
            
            crt = OpenSSL.crypto.X509()
            crt.set_serial_number(1)
            crt.gmtime_adj_notBefore(0)
            crt.gmtime_adj_notAfter(60*60*24*365*10)  # Valid for 10 years
            crt.set_issuer(rootCAPem.get_subject())
            crt.set_subject(csr.get_subject())
            
            crt.add_extensions([
                OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
            ])
            
            crt.add_extensions([
                OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=rootCAPem),
                OpenSSL.crypto.X509Extension(b"keyUsage", False, b"digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment"),
                OpenSSL.crypto.X509Extension(b"subjectAltName", False, "DNS:{}".format(self.__domain).encode()),
            ])
            
            crt.set_pubkey(csr.get_pubkey())
            crt.sign(rootCAKey, "sha256")
            open(self.__sslCrt, 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, crt))
        
        return
    
    def setServer(self, host, port):
        self.__remoteHost = host
        self.__remotePort = port
        return
    
    def __addHosts(self, domain):
        data = open(r"C:\Windows\System32\drivers\etc\hosts", 'rb').read()
        if not "\n127.0.0.1 \t {}\n".format(domain).encode('utf8') in data:
            open(r"C:\Windows\System32\drivers\etc\hosts", "wb").write(data + '\n127.0.0.1 \t {}\n'.format(domain).encode('utf8'))
        return

    def __delHosts(self, domain):
        data = open(r"C:\Windows\System32\drivers\etc\hosts", 'rb').read()
        if "\n127.0.0.1 \t {}\n".format(domain).encode('utf8') in data:
            data_ = b""
            for i in data.split(b'\n'):
                if "127.0.0.1 \t {}".format(domain).encode('utf8') == i:
                    continue
                data_ = data_ + i + b'\n'
            
            open(r"C:\Windows\System32\drivers\etc\hosts", "wb").write(data_)
        return

    def __createSocket(self, isSSL = True):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if isSSL:
            server_socket = ssl.wrap_socket(
                server_socket,
                keyfile=self.__sslKey,
                certfile=self.__sslCrt,
                server_side=True,
                ssl_version=ssl.PROTOCOL_SSLv23
            )
        return server_socket

    def __forward(self, sock_client, sock_dest):
        try:
            string = " "
            while string:
                string = sock_client.recv(8192)
                if string:
                    sock_dest.sendall(string)
                else:
                    sock_client.shutdown(socket.SHUT_RD)
                    sock_dest.shutdown(socket.SHUT_WR)
        except Exception as e:
            print(str(e))
        
        try:
            sock_client.shutdown(socket.SHUT_RD)
            sock_dest.shutdown(socket.SHUT_WR)
        except:
            return
        
        return

    def __prepareForward(self, sock_client):
        sock_dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_dest.connect((self.__remoteHost, int(self.__remotePort)))
        Thread(target=self.__forward, args=(sock_client, sock_dest, )).start()
        Thread(target=self.__forward, args=(sock_dest, sock_client, )).start()
        return
    
    def __sendRedirect(self, sock):
        try:
            url = self.__domain
            data = sock.recv(8192)
            if data:
                url = url + data.split(b' ')[1].decode('utf8')
            
            http_response = (
                "HTTP/1.1 301 Moved Permanently\r\n"
                "Location: https://{0}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).format(url).encode('utf8')
            
            sock.sendall(http_response)
            sock.close()
        except Exception as e:
            print(str(e))
        return
    
    def __getConnection(self, server_socket, isHTTP = False):
        # connection
        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"Connected from {addr}")
                
                if isHTTP:
                    Thread(target=self.__sendRedirect, args=(client_socket, )).start()
                else:
                    Thread(target=self.__prepareForward, args=(client_socket, )).start()
            except Exception as e:
                print(str(e))

    def start(self):
        if self.isRunning():
            raise AlreadyRunning("server already running [{}]".format(self.__domain))
        
        # prepare SSL
        print("> Preparing SSLServer....")
        self.__prepareSSL()
        
        # Server
        print("> Starting server....")
        server_socket_http = self.__createSocket(False)
        server_socket_https = self.__createSocket()
        
        server_socket_http.bind(("127.0.0.1", 80))
        server_socket_https.bind(("127.0.0.1", 443))
        
        server_socket_http.listen(5)
        server_socket_https.listen(5)
        print("> Server started!")
        
        # setup domain (hosts)
        print("> Setting up [{}]....".format(self.__domain))
        self.__addHosts(self.__domain)
        print("> Successfully [{}]".format(self.__domain))

        thread_http = Thread(target=self.__getConnection, args=(server_socket_http, True, ))
        thread_https = Thread(target=self.__getConnection, args=(server_socket_https, ))
        
        thread_http.start()
        thread_https.start()
        return

    def removeDomain(self):
        self.__delHosts(self.__domain)
        
    def isRunning(self) -> bool:
        if self.__isStart:
            return True
        return False

