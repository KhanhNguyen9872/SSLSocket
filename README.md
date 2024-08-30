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

# SSLSocket.log.setOutput(open('log.txt', 'w'))	# Change output write log to `log.txt` file
# SSLSocket.log.disableError(True)	# Disable Error log
# SSLSocket.log.disableError(False)	# Enable Error log

# Install self-cert into system
SSLSocket.installCert()

# Replace <DOMAIN> to another domain you want, (ex: sslsocket.com)
server = SSLSocket.Server(<DOMAIN>)  

# Replace IP and PORT with your http website, (ex: IP is '127.0.0.1', and Port is '8080')
server.setServer(<IP>, <PORT>)

# Start server
# In .start() you can use some arg
#    http_port = (int)   # Change http port (default: 80)
#    https_port = (int)  # Change https port (default: 443)
#    delay = (int)  # Delay in second before start server (default: 0)
#    force_https = (bool)  # Force server use https, will be redirect to https:// if user request to http://
server.start()

# Now you can browse your domain with SSL (ex: https://sslsocket.com)
```
