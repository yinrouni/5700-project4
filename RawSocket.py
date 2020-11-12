import socket, sys

class RawSocket:

    def __init__(self):

        # create a raw socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()



    # checksum functions needed for calculation checksum
    def checksum(self, msg):
        s = 0

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)

        # complement and mask to 4 byte short
        s = ~s & 0xffff

        return s

    # IP header

    # TCP header

    # pseudo header for checksum

    # handshake


