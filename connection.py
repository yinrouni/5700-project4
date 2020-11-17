import RawSocket
import socket

HOST = 'cs5700fa20.ccs.neu.edu'  # Server hostname or IP address
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
        prefix = "%s %s HTTP/1.1\r\nHost: %s\r\n" % (method, path, HOST)

    if cookie and data:
        return ("%sCookie: %s\r\n\r\n%s" % (prefix, cookie, data)).encode()
    elif not data and cookie:
        return ("%sCookie: %s\r\n\r\n" % (prefix, cookie)).encode()

    elif data and not cookie:
        return ("%s\r\n%s" % (prefix, data)).encode()

    return ("%s\r\n" % prefix).encode()


client_socket = RawSocket.RawSocket()
server_address = (socket.gethostbyname(HOST), PORT)
print(server_address)
print(socket.gethostbyname(socket.gethostname()))
client_socket.connect(server_address)
print('connect')

# request_header = generaterHeader("GET", '/accounts/login/?next=/fakebook/', None, None)
# client_socket
