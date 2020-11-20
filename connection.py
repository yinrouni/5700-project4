import RawSocket2
import socket

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
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded" \
                 "\r\nContent-Length: %s\r\n" % (method, path, HOST, len(data))
    else:
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n" % (method, path, HOST)

    if cookie and data:
        return ("%sCookie: %s\r\n\r\n%s" % (prefix, cookie, data))
    elif not data and cookie:
        return ("%sCookie: %s\r\n\r\n" % (prefix, cookie))

    elif data and not cookie:
        return ("%s\r\n%s" % (prefix, data))

    return ("%s\r\n" % prefix)

client_socket = RawSocket2.RawSocket()
server_address = (socket.gethostbyname(HOST), PORT)
client_socket.connect(server_address)

request_header = generaterHeader("GET", '/classes/cs4700fa20/project4.php', None, None)
client_socket.send(request_header)
print('connected')
client_socket.recv()
client_socket.disconnect()
