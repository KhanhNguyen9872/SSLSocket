# SSLSocket
Add self-cert to a http website

# Installation
```bash
pip install SSLSocket
```

# Usage
1. You must have a http website like `http://localhost`, `http://127.0.0.1` or something else
2. Install this library
3. Using this code
```python3
import SSLSocket

# Install self-cert into system
SSLSocket.installCert()

# Replace <DOMAIN> to another domain you want, (ex: sslsocket.com)
server = SSLSocket.Server(<DOMAIN>)  

# Replace IP and PORT with your http website, (ex: IP is '127.0.0.1', and Port is '8080')
server.setServer(<IP>, <PORT>)

# Start server 
server.start()

# Now you can browse your domain with SSL (ex: https://sslsocket.com)
```
