import os, sys, shutil
from .exceptions import *

def installModule(moduleName):
    if not (os.system("{} -m pip install {}".format(sys.executable, moduleName)) == 0):
        raise CannotInstall("Cannot install {} library! please install it manually!".format(moduleName))
    return

#####
try:
    import OpenSSL
except ModuleNotFoundError:
    installModule("pyOpenSSL")
    import OpenSSL
    
from pathlib import Path
from threading import Thread
import ssl, socket, subprocess

def isWindows() -> bool:
    return os.name == 'nt'

def isLinux() -> bool:
    return (os.name == 'posix') and (shutil.which("bash") != "/data/data/com.termux/files/usr/bin/bash")

if not isWindows() and not isLinux():
    raise DeviceNotSupported("only support Windows and Linux!")

if isWindows():
    from ctypes import windll
    def is_admin():
        try:
            return windll.shell32.IsUserAnAdmin()
        except:
            return False
    if not is_admin():
        raise PermissionDenied("SSLSocket need administrator permission!")

    hostsFile = r"C:\Windows\System32\drivers\etc\hosts"

if isLinux():
    if subprocess.getoutput("whoami") != "root":
        raise PermissionDenied("SSLSocket need root permission!")
    hostsFile = "/etc/hosts"
    
certPath = "./cert"
rootCAPath = "/".join("/".join(__file__.split("\\")).split("/")[:-1]) + "/cert"
rootCAPass = "12345678"

def installCert(path = rootCAPath + "/rootCA.crt") -> None:
    print("> installing certificate....")
    if isWindows():
        output = subprocess.getoutput("certutil.exe -addstore root {} 2>&1".format(path))
        if "completed successfully." in output:
            print("> certificate installed!")
        elif "The requested operation requires elevation." in output:
            raise CannotInstall("install cert requires administrator permission!")
    elif isLinux():
        fileName = "SSLSocket.crt"
        cerPath = "/usr/share/ca-certificates"
        if Path("{}/{}".format(cerPath, fileName)).is_file():
            print("> certificate installed!")
        else:
            if os.system("cp {} {}/{} >/dev/null 2>&1".format(path, cerPath, fileName)) == 0:
                os.system("chmod 644 {}/{} >/dev/null 2>&1".format(cerPath, fileName))
                if (os.system("dpkg-reconfigure ca-certificates >/dev/null 2>&1") == 0):
                    if (os.system("update-ca-certificates >/dev/null 2>&1") == 0):
                        print("> certificate installed!")
                    else:
                        raise CannotInstall("cannot update certificate in system")
                else:
                    raise CannotInstall("cannot reconfigure certificate in system")
            else:
                raise CannotInstall("cannot copy certificate to system")
    else:
        raise DeviceNotSupported("can't install certificate due to device unsupported")

    print("> if install cert not working, you must install this file [{}] into browser or anything".format(path))
    return

def addHost(domain):
    if (isDomain(domain)):
        data = open(hostsFile, 'rb').read()
        if not "\n127.0.0.1 \t {}\n".format(domain).encode('utf8') in data:
            open(hostsFile, "wb").write(data + '\n127.0.0.1 \t {}\n'.format(domain).encode('utf8'))
    return

def delHost(domain):
    if (isDomain(domain)):
        data = open(hostsFile, 'rb').read()
        if "\n127.0.0.1 \t {}\n".format(domain).encode('utf8') in data:
            data_ = b""
            for i in data.split(b'\n'):
                if "127.0.0.1 \t {}".format(domain).encode('utf8') == i:
                    continue
                data_ = data_ + i + b'\n'
            
            open(hostsFile, "wb").write(data_)
    return

def isDomain(domain):
    try:
        if (len(domain.split('.')) == 4):
            [int(x) for x in domain.split('.')]
            return False
        else:
            return True
    except ValueError:
        return True
    
class Server:
    def __init__(self, domain):
        self.__isStart = False
        self.__domain = domain.lower()
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
                OpenSSL.crypto.X509Extension(b"subjectAltName", False, (b"DNS" if isDomain(self.__domain) else b"IP") + ":{}".format(self.__domain).encode()),
            ])
            
            crt.set_pubkey(csr.get_pubkey())
            crt.sign(rootCAKey, "sha256")
            open(self.__sslCrt, 'wb').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, crt))
        
        return
    
    def setServer(self, host, port):
        self.__remoteHost = host
        self.__remotePort = port
        return

    def __createSocket(self, isSSL = True):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if isSSL:
            server_socket = ssl.wrap_socket(
                server_socket,
                keyfile=self.__sslKey,
                certfile=self.__sslCrt,
                server_side=True,
                ssl_version=ssl.PROTOCOL_SSLv23,
                ciphers='DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256'
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
                print(f"Connected from [{addr[0]}:{addr[1]}]")
                
                if isHTTP:
                    print(f"Redirect to https [{addr[0]}:{addr[1]}]")
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
        print("> Starting server [80/443]....")
        server_socket_http = self.__createSocket(False)
        server_socket_https = self.__createSocket()
        
        try:
            server_socket_http.bind(("127.0.0.1", 80))
            server_socket_https.bind(("127.0.0.1", 443))
        except OSError as e:
            if "Address already in use" in str(e) or "Only one usage of each socket address" in str(e) or "An attempt was made to access a socket in a way forbidden by its access permissions" in str(e):
                raise CannotBindPort("Port 80 or 443 is already in use by another program or don't have permission to open port!")
            print(e)
        
        server_socket_http.listen()
        server_socket_https.listen()
        print("> Server started [80/443]")
        
        # setup domain (hosts)
        print("> Setting up [{}]....".format(self.__domain))
        addHost(self.__domain)
        print("> Successfully [{}]".format(self.__domain))

        thread_http = Thread(target=self.__getConnection, args=(server_socket_http, True, ))
        thread_https = Thread(target=self.__getConnection, args=(server_socket_https, ))
        
        thread_http.start()
        thread_https.start()
        
        print("> Now you can browse [https://{}]".format(self.__domain))
        return

    def removeDomain(self):
        delHost(self.__domain)
        
    def isRunning(self) -> bool:
        if self.__isStart:
            return True
        return False

