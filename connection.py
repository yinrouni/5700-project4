import RawSocket2
import socket
import sys
from urllib.parse import urlparse

HOST = 'david.choffnes.com'  # Server hostname or IP address
PORT = 80  # Port



def generaterHeader(method, path, cookie, data):
    """The function that generate HTTP Header
    Args:
        method: HTTP Methods 'GET','POST'.
        path: The web page path, e.g. /fakebook/.
        cookie: The data of csrfToken and sessionId.
        data: The data of user's information.
    Returns:
        String return the encoded version of the HTTP Header
    """

    if method == 'POST':
        prefix = "%s %s HTTP/1.0\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded" \
                 "\r\nContent-Length: %s\r\n" % (method, path, HOST, len(data))
    else:
        prefix = "%s %s HTTP/1.0\r\nHost: %s\r\n" % (method, path, HOST) + \
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n" + \
            "Connection: keep-alive\r\n"

    if cookie and data:
        return ("%sCookie: %s\r\n\r\n%s" % (prefix, cookie, data))
    elif not data and cookie:
        return ("%sCookie: %s\r\n\r\n" % (prefix, cookie))

    elif data and not cookie:
        return ("%s\r\n%s" % (prefix, data))

    return ("%s\r\n" % prefix)

def getHostAndPath(url):
    temp = str(url)
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    return host,path


args = sys.argv

if len(args) <= 1:
    exit()

url = args[1]

if 'https://' in url:
    print('This program does not support HTTPS')
    exit()

HOST, path = getHostAndPath(url)
print(HOST)
print(path)
if not path or path == '/':
    path = '/'
    file_name = 'index.html'
else:
    if path.split('/')[-1]:
        file_name = path.split('/')[-1]
    else:
        file_name = 'index.html'

print(file_name)

client_socket = RawSocket2.RawSocket()
server_address = (socket.gethostbyname(HOST), PORT)
client_socket.connect(server_address)

request_header = generaterHeader("GET", path, None, None)
client_socket.send(request_header,file_name)
print('connected')
client_socket.recv(file_name)
client_socket.disconnect()
