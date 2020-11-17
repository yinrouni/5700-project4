# -*- coding: utf-8 -*-
"""
Authors: Jason Teng, Jae Son
"""
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP
import socket
import argparse
import random
import time
from struct import pack, unpack

# parser = argparse.ArgumentParser(description='Client script for Project 4')
# parser.add_argument('url', help='URL')
#
# args = parser.parse_args()
#
# url = args.url

sendSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
recSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
TIMEOUT = 60
recSock.settimeout(TIMEOUT)

# gets the host ip by creating a connection to Google and observing the socket parameters
hostIP = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close())
          for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
print(hostIP)

hostIP_hex = bytes(map(int, hostIP.split('.')))


# takes a HTTP message and returns the raw header and html as separate strings
def parse_response(response):
    s = response.split(b'\r\n\r\n', 1)
    if len(s) < 2:
        return s[0], b''
    return s[0], s[1]


# takes a string of headers and returns a dictionary of the headers
def parse_headers(rawheaders):
    headers = {}
    rawheaders = rawheaders.splitlines()[1:-1]
    for s in rawheaders:
        header = s.split(': ', 1)
        if header[0] in headers:
            headers[header[0]] = headers.get(header[0]) + '\n' + header[1]
        else:
            headers[header[0]] = header[1]
    return headers


ip_header_format = '!BBHHHBBH4s4s'
ip_header_format_1 = '!BBHHHBB'
ip_header_format_2 = '!4s4s'
ip_header_keys = ['ver_ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'proto', 'check', 'src', 'dest']
tcp_temp_header_format = '!HHLLBBHHH'
tcp_header_format = '!HHLLBBH'
tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']
pseudo_header_format = '!4s4sBBH'

# URL trimming to get host name for DEST_ADDR
# trimUrl = url
# if trimUrl.startswith('http://'):
#     trimUrl = url[7:]
#     url = trimUrl
# elif trimUrl.startswith('https://'):
#     print("https websites are not supported")
#     exit()
# if '/' in trimUrl:
#     i = trimUrl.find('/')
#     trimUrl = trimUrl[0:i]
trimUrl = 'cs5700fa20.ccs.neu.edu'
url = 'cs5700fa20.ccs.neu.edu'

# These should be constant for the whole program, while sending packets
# TCP Side
SRC_PORT = random.randint(1024, 65530)
DEST_PORT = 80
OFFSET = 5
AWND = 2000
URG = 0

# IP Side
VERSION = 4
IHL = 5
IHL_VERSION = (VERSION << 4) + IHL
TOS = 0
FRAG_OFF = 0
IP_HDR_LEN = 20
TTL = 255
PROTO = socket.IPPROTO_TCP
SRC_ADDR = socket.inet_aton(hostIP)
DEST_ADDR = socket.inet_aton(socket.gethostbyname(trimUrl))

# Global variables
seq = random.randint(0, 2 ** 32)
ack = 0

# track the seq and ack offsets
SEQ_OFFSET = 0
ACK_OFFSET = 0

# Keeps track of out-of-order packets
lastOrderedSeq = 0
packetBuffer = []


def tcpwrap(seq, ack, flags, data):
    """
    Takes in TCP header parameters and creates the correct TCP header and adds it to the data.
    Returns the new message with the TCP header added. Offset is automatically calculated.
    :param seq: the sequence number of the current packet. += 1 beforehand.
    :param ack: the acknowledgment number
    :param flags: any flags
    :param data: the data to be wrapped
    :return: the packet wrapped with the TCP header
    """

    # Create pseudo-header to calculate checksum
    temp_header = pack(tcp_temp_header_format, SRC_PORT, DEST_PORT, seq, ack, 0x50,
                       flags, AWND, 0, URG)
    total_len = len(temp_header) + len(data)
    pseudo_header = pack(pseudo_header_format, SRC_ADDR, DEST_ADDR, 0, PROTO, total_len)
    check = checksum(pseudo_header + temp_header + data.encode())

    # make the real header
    tcp_header = pack(tcp_header_format, SRC_PORT, DEST_PORT, seq, ack, OFFSET << 4, flags,
                      AWND) + pack('H', check) + pack('!H', URG)
    tcp_packet = tcp_header + data.encode()
    return tcp_packet


def tcpunwrap(tcp_packet):
    """
    Takes a tcp packet and extracts out the header, returning the contained data. Validates the
    :param tcp_packet: the packet to be unwrapped
    :return: a dictionary of the headers and the unwrapped data
    """
    tcp_header_vals = unpack(tcp_header_format, tcp_packet[0:16]) + \
                      unpack('H', tcp_packet[16:18]) + \
                      unpack('!H', tcp_packet[18:20])
    tcp_headers = dict(zip(tcp_header_keys, tcp_header_vals))

    # check for options
    offset = tcp_headers['off_res'] >> 4
    options = b''
    if offset > 5:
        options = tcp_packet[20:4 * offset]
        print('options: ' + str(options))

    tcp_data = tcp_packet[4 * offset:]

    if tcp_headers['dest'] != SRC_PORT:
        raise ValueError("incorrect destination port")

    pseudo_header = pack(pseudo_header_format, DEST_ADDR, SRC_ADDR, 0, PROTO, len(tcp_packet))
    if tcp_verify_checksum(pseudo_header, tcp_header_vals, options, tcp_data):
        return tcp_headers, tcp_data
    else:
        print('tcp checksum has failed. replicate TCP ACK behavior')
        raise ValueError("incorrect TCP checksum")


def ipwrap(tcp_packet):
    """
    Takes in the IP header parameters and constructs a IP header, which is added to the given data and returned.
    :param tcp_packet: the full packet given out by tcpwrap, including payload
    :return: the full IP packet, including the TCP packet
    """
    check = 0  # kernel will fill correct checksum
    pktId = random.randint(0, 65534)
    total_len = len(tcp_packet) + 20
    return pack(ip_header_format_1, IHL_VERSION, TOS, total_len, pktId, FRAG_OFF, TTL, PROTO) + \
           pack('H', check) + pack(ip_header_format_2, SRC_ADDR, DEST_ADDR) + \
           tcp_packet


def ipunwrap(ip_packet):
    """
    Takes an ip packet and extracts the headers and the data
    :param ip_packet: the packet to be unwrapped
    :return: a dictionary of the headers and the unwrapped data
    """
    ip_header_vals = unpack(ip_header_format_1, ip_packet[0:10]) + \
                     unpack('H', ip_packet[10:12]) + \
                     unpack(ip_header_format_2, ip_packet[12:20])
    ip_headers = dict(zip(ip_header_keys, ip_header_vals))

    version = ip_headers['ver_ihl'] >> 4
    if version != 4:
        raise ValueError("not IPv4")
    ihl = ip_headers['ver_ihl'] & 0x0F

    # check that this is the destination
    if ip_headers['dest'] != hostIP_hex:
        print(ip_headers['dest'])
        raise ValueError("invalid destination IP address")

    # check that is tcp packet
    if ip_headers['proto'] != 0x06:
        raise ValueError("Not TCP packet")

    # get the data from the ip packet
    ip_data = ip_packet[4 * ihl:]

    if (ip_verify_checksum(ip_header_vals)):
        return ip_headers, ip_data
    else:
        print('ip checksum has failed. replicate TCP ACK behavior')
        raise ValueError("invalid IP checksum")


# Referenced from Suraj Bisht of Bitforestinfo
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if i == len(msg) - 1:
            w = msg[i]
        else:
            w = (msg[i]) + (msg[i + 1] << 8)
        s = s + w

    while s >> 16 != 0:
        s = (s & 0xffff) + (s >> 16)

    # complement and mask to 2 byte short
    return ~s & 0xffff


def tcp_verify_checksum(pseudo_header, headerVals, opt, data):
    chcksm = headerVals[7]
    headerAndData = pseudo_header + \
                    pack(tcp_temp_header_format, headerVals[0], headerVals[1], headerVals[2],
                         headerVals[3], headerVals[4], headerVals[5], headerVals[6], 0, headerVals[8]) + \
                    opt + data
    calculatedChecksum = checksum(headerAndData)
    return calculatedChecksum == chcksm


def ip_verify_checksum(headerVals):
    chcksm = headerVals[7]
    ipHeader = pack(ip_header_format, headerVals[0], headerVals[1], headerVals[2], headerVals[3], headerVals[4],
                    headerVals[5], headerVals[6], 0, headerVals[8], headerVals[9])
    calculatedChecksum = checksum(ipHeader)
    return calculatedChecksum == chcksm


def tcp_handshake():
    global seq, ack, SEQ_OFFSET, ACK_OFFSET
    # tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

    sendPacket(seq, 0, tcp_flags, '')

    starttime = time.clock()
    while True:
        if time.clock() > starttime + TIMEOUT:
            closeConnection()
            break
        try:
            ip_packet = recSock.recv(65536)
        except socket.timeout:
            closeConnection()
            return
        try:
            ip_headers, ip_data = ipunwrap(ip_packet)
        except ValueError:
            continue
        try:
            tcp_headers, tcp_data = tcpunwrap(ip_data)
            # check for a syn/ack message
            if tcp_headers['flags'] & 0x12 != 0x12:
                continue
            break
        except ValueError:
            continue

    rec_ack = tcp_headers['ack']
    if seq == rec_ack - 1:
        # finish handshake
        # increment sequence number
        seq += 1
        # get the ack number from the SYN/ACK
        rec_seq = tcp_headers['seq']
        ack = rec_seq + 1
        # set the flags to ack
        tcp_flags = 0x10
        sendPacket(seq + SEQ_OFFSET, ack + ACK_OFFSET, tcp_flags, '')

    else:
        print("Handshake failed!")


def change_file_name(myUrl):
    fileName = ''
    lastSlashIndex = myUrl.rfind('/')
    if lastSlashIndex == -1:
        fileName = 'index.html'
    else:
        if lastSlashIndex == len(myUrl) - 1:
            fileName = 'index.html'
        else:
            fileName = myUrl[lastSlashIndex + 1:]
    return fileName


# Use this without messing with IP wrap and TCP wrap, ideally
def sendPacket(seq, ack, flags, data):
    tcpPacket = tcpwrap(seq, ack, flags, data)
    ipPacket = ipwrap(tcpPacket)
    sendSock.sendto(ipPacket, (socket.gethostbyname(trimUrl), DEST_PORT))


def closeConnection():
    print("closing connection")
    global seq, ack

    sendPacket(seq + SEQ_OFFSET, ack + ACK_OFFSET, 0x11, '')

    starttime = time.process_time()
    while True:
        if time.process_time() > starttime + TIMEOUT:
            return
        try:
            ip_packet = recSock.recv(65536)
        except socket.timeout:
            return
        try:
            ip_headers, ip_data = ipunwrap(ip_packet)
        except ValueError:
            continue
        try:
            tcp_headers, tcp_data = tcpunwrap(ip_data)
            # check for a fin/ack message
            if tcp_headers['flags'] & 0x11 != 0x11:
                continue
            break
        except ValueError:
            continue

    rec_ack = tcp_headers['ack']
    if seq + SEQ_OFFSET == rec_ack - 1:
        # finish teardown
        # get the ack number from the SYN/ACK
        rec_seq = tcp_headers['seq']
        fin_ack = rec_seq + 1
        # set the flags to ack
        tcp_flags = 0x10
        sendPacket(seq + SEQ_OFFSET + 1, fin_ack, tcp_flags, '')


#############################################################################
def run():
    global seq, ack, SEQ_OFFSET, ACK_OFFSET
    fileName = change_file_name(url)

    f = open(fileName, 'wb+')
    filesize = 0
    bytes_written = 0

    tcp_handshake()

    # send the HTTP GET request
    # send the ack message, with GET request
    get_request = 'GET http://' + url + ''' HTTP/1.1
Host: ''' + trimUrl + '\r\n\r\n'
    print(get_request)
    sendPacket(seq + SEQ_OFFSET, ack + ACK_OFFSET, 0x10, get_request)
    SEQ_OFFSET += len(get_request)

    done = False
    while not done:
        starttime = time.process_time()
        while True:
            if time.process_time() > starttime + TIMEOUT:
                closeConnection()
                break
            try:
                ip_packet = recSock.recv(65536)
            except socket.timeout:
                closeConnection()
                return
            try:
                ip_headers, ip_data = ipunwrap(ip_packet)
            except ValueError:
                continue
            try:
                tcp_headers, data = tcpunwrap(ip_data)
                break
            except ValueError:
                continue

        # check TCP flag for ack or fin
        if tcp_headers['flags'] & 0x01 > 0:
            done = True
        if tcp_headers['flags'] & 0x10 == 0:
            return

        rec_ack = tcp_headers['ack']
        rec_seq = tcp_headers['seq']
        if seq + SEQ_OFFSET == rec_ack and ack + ACK_OFFSET == rec_seq:
            if len(data) > 0:
                if filesize == 0:
                    try:
                        rawheaders, rawbody = parse_response(data)
                    except UnicodeDecodeError:
                        print('tls packet')
                    try:
                        headers = parse_headers(rawheaders.decode())
                        print('headers: ' + str(headers))
                        filesize = int(headers['Content-Length'])
                        # print('body: ' + str(rawbody))
                        bytes_written += f.write(rawbody)
                    except IndexError:  # still part of an http response, just get the data
                        # print('body: ' + str(data))
                        bytes_written += f.write(data)
                else:
                    bytes_written += f.write(data)
                # check for end of file
                print("File size: " + str(filesize) + " bytes written: " + str(bytes_written) + " len(data): " + str(
                    len(data)))
                if bytes_written >= filesize:
                    return

            # send an ack packet
            tcp_flags = 0x10
            ACK_OFFSET += len(data)
            sendPacket(seq + SEQ_OFFSET, ack + ACK_OFFSET, tcp_flags, '')

        else:
            print("sequence mismatch (out of order or other error)")
            # retransmit the most recent ACK
            sendPacket(seq + SEQ_OFFSET, ack + ACK_OFFSET, 0x10, '')

    f.close()


run()
closeConnection()