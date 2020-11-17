import math
import random
import socket
import sys
import time
from struct import *

RESEND_THRESHOLD = 60


# TCP flags
def getTCPFlags(flag):
    tcp_fin = 0
    tcp_syn = 0
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0

    if flag == 'SYN':
        tcp_syn = 1
    elif flag == 'ACK':
        tcp_ack = 1
    elif flag == 'FIN':
        tcp_fin = 1
    elif flag == 'PSH-ACK':
        tcp_psh = 1
        tcp_ack = 1
    elif flag == 'FIN-ACK':
        tcp_ack = 1
        tcp_fin = 1

    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    return tcp_flags


# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s


def setFileName(url):
    filename = ''
    slash_index = url.rfind('/')
    if slash_index == 6 or slash_index == len(url) - 1:
        filename = "index.html"
    else:
        filename = url[slash_index + 1:]

    return filename


def ip_verify_checksum(headerVals):
    chcksm = headerVals[7]
    ipHeader = pack('!BBHHHBBH4s4s', headerVals[0], headerVals[1], headerVals[2], headerVals[3], headerVals[4],
                    headerVals[5], headerVals[6], 0, headerVals[8], headerVals[9])
    calculatedChecksum = checksum(ipHeader)
    return calculatedChecksum == chcksm


def tcp_verify_checksum(pseudo_header, tcp_header_vals, options, tcp_data):
    chcksm = tcp_header_vals[7]
    headerAndData = pseudo_header + \
                    pack('!HHLLBBHHH', tcp_header_vals[0], tcp_header_vals[1], tcp_header_vals[2],
                         tcp_header_vals[3], tcp_header_vals[4], tcp_header_vals[5], tcp_header_vals[6], 0,
                         tcp_header_vals[8]) + \
                    options + tcp_data
    calculatedChecksum = checksum(headerAndData)
    return calculatedChecksum == chcksm


class RawSocket:

    def __init__(self):
        self.source_ip = ''
        self.dest_ip = ''
        self.source_port = random.randint(1024, 65530)
        self.dest_port = ''
        self.seq_number = random.randint(0, math.pow(2, 31))
        self.seq_ack_num = 0

        # create a raw socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error as msg:
            print('Send socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

        try:
            self.rcv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print('Receive socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

    # IP header
    def getIPHeader(self):
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill the correct total length
        ip_id = 54321  # Id of this packet
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # kernel will fill the correct checksum
        ip_saddr = socket.inet_aton(self.source_ip)  # Spoof the source ip address if you want to
        ip_daddr = socket.inet_aton(self.dest_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto,
                         ip_check, ip_saddr, ip_daddr)

        return ip_header

    # TCP header
    def getTCPHeader(self, tcp_seq, tcp_ack_seq, user_data, flag):
        # tcp header fields
        tcp_source = self.source_port  # source port
        tcp_dest = self.dest_port  # destination port

        tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes

        tcp_window = socket.htons(5840)  # maximum allowed window size
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_check = 0
        tcp_urg_ptr = 0

        # tcp flags
        tcp_flags = getTCPFlags(flag)

        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window, tcp_check, tcp_urg_ptr)

        tcp_check = self.checkPseudoHeader(tcp_header, user_data)
        tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                          tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

        return tcp_header

    # pseudo header for checksum
    def checkPseudoHeader(self, tcp_header, user_data):
        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)

        psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)

        psh = psh + tcp_header + user_data.encode()

        tcp_check = checksum(psh)

        return tcp_check

    # unpack packet to get ip header and verification
    def unpackIP(self, packet):
        ip_header_keys = ['ver_ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'proto', 'check', 'src', 'dest']
        ip_header_vals = unpack('!BBHHHBB', packet[0:10]) + \
                         unpack('H', packet[10:12]) + \
                         unpack('!4s4s', packet[12:20])
        ip_headers = dict(zip(ip_header_keys, ip_header_vals))

        version = ip_headers['ver_ihl'] >> 4
        if version != 4:
            print('not ipv4')
            raise ValueError("not IPv4")
        ihl = ip_headers['ver_ihl'] & 0x0F

        # check that this is the destination
        print(ip_headers['dest'], self.dest_ip)
        if ip_headers['dest'] != self.dest_ip:
            print("invalid destination IP address")
            raise ValueError("invalid destination IP address")

        # check that is tcp packet
        if ip_headers['proto'] != 0x06:
            print('not tcp packet')
            raise ValueError("Not TCP packet")

        # get the data from the ip packet
        ip_data = packet[4 * ihl:]

        if ip_verify_checksum(ip_header_vals):
            return ip_headers, ip_data
        else:
            print('ip checksum has failed. replicate TCP ACK behavior')
            raise ValueError("invalid IP checksum")

    def sendPacket(self, seq_number, seq_ack_num, user_data, flags):
        ip_header = self.getIPHeader()
        tcp_header = self.getTCPHeader(seq_number, seq_ack_num, user_data, flags)

        packet = ip_header + tcp_header + user_data.encode()
        self.socket.sendto(packet, (self.dest_ip, self.dest_port))

    # handshake
    def handshake(self):

        # send first SYN
        self.sendPacket(self.seq_number, self.seq_ack_num, '', 'SYN')
        start = time.process_time()
        print('sent SYN at ' + str(start))

        # receive SYN_ACK
        # TODO: retry and timeout
        while True:
            print('enter loop')
            recv_packet = self.rcv_socket.recv(65565)

            print('received SYN-ACK at' + str(time.process_time()))
            print(recv_packet)

            try:
                ip_header, ip_data = self.unpackIP(recv_packet)
            except ValueError:
                print('ip verify fails')
                continue
            try:
                tcp_header, tcp_data = self.unpackTCP(ip_data)

                # check syn-ack
                if tcp_header['flags'] & 0x12 != 0x12:
                    continue
                break

            except ValueError:
                continue

        # send ACK
        recv_ack = tcp_header['ack']
        if self.seq_number + 1 == recv_ack:
            self.seq_number += 1
            self.seq_ack_num = tcp_header['seq'] + 1

            self.sendPacket(self.seq_number, self.seq_ack_num, '', 'ACK')
        else:
            print('handshake fail')

    # connect
    def connect(self, address_tuple):
        hostname = address_tuple[0]
        self.dest_port = address_tuple[1]
        self.dest_ip = socket.gethostbyname(hostname)

        # API to get IP of source machine
        self.source_ip = socket.gethostbyname(socket.gethostname())

        self.handshake()

    #  disconnect

    # send
    def send(self, request):
        self.sendPacket(self.seq_number, self.seq_ack_num, request, 'PSH-ACK')
        self.seq_number += len(request)

    # get Response
    def recv(self):
        f = open('demo.txt', 'a')

        done = False
        while not done:
            while True:
                recv_packet = self.rcv_socket.recvfrom(65565)

                try:
                    ip_header, ip_data = self.unpackIP(recv_packet)
                except ValueError:
                    continue

                try:
                    tcp_header, tcp_data = self.unpackTCP(ip_data)
                    break
                except ValueError:
                    continue

            # check tcp flags:
            if tcp_header['flags'] & 0x01 > 0:
                # fin: stop accepting resp and sending ack
                done = True

            if tcp_header['flags'] & 0x10 == 0:
                # no ack
                break

            recv_seq = tcp_header['seq']
            recv_ack = tcp_header['ack']

            if recv_ack == self.seq_number and recv_seq == self.seq_ack_num:
                if len(tcp_data) > 0:
                    # has resp
                    f.write(tcp_data)



                    self.seq_ack_num += len(data)
                    self.sendPacket(self.seq_number, self.seq_ack_num, '', 'ACK')
                else:
                    continue
            else:
                # retransmit
                self.sendPacket(self.seq_number, self.seq_ack_num, '', 'ACK')
        f.close()
        self.teardown()

    def teardown(self):
        self.sendPacket(self.seq_number, self.seq_ack_num, '', 'FIN-ACK')

        while True:
            recv_packet = self.rcv_socket.recvfrom(65565)

            try:
                ip_header, ip_data = self.unpackIP(recv_packet)
            except ValueError:
                continue

            try:
                tcp_header, tcp_data = self.unpackTCP(ip_data)
                if tcp_header['flags'] & 0x11 != 0x11:  # if not fin-ack
                    continue
                break
            except ValueError:
                continue

        recv_ack = tcp_header['ack']
        if recv_ack == self.seq_number + 1:
            recv_seq = tcp_header['seq']
            self.sendPacket(recv_ack, recv_seq + 1, '', 'ACK')

    def unpackTCP(self, ip_data):
        tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']
        tcp_header_vals = unpack('!HHLLBBH', ip_data[0:16]) + \
                          unpack('H', ip_data[16:18]) + \
                          unpack('!H', ip_data[18:20])
        tcp_headers = dict(zip(tcp_header_keys, tcp_header_vals))

        # check for options
        offset = tcp_headers['off_res'] >> 4
        options = b''
        if offset > 5:
            options = ip_data[20:4 * offset]
            print('options: ' + str(options))

        tcp_data = ip_data[4 * offset:]

        if tcp_headers['dest'] != self.source_port:
            raise ValueError("incorrect destination port")

        source_address = socket.inet_aton(self.source_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP

        pseudo_header = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, len(ip_data))
        if tcp_verify_checksum(pseudo_header, tcp_header_vals, options, tcp_data):
            return tcp_headers, tcp_data
        else:
            print('tcp checksum has failed. replicate TCP ACK behavior')
            raise ValueError("incorrect TCP checksum")

    def disconnect(self):
        self.teardown()
        self.socket.close()
        self.rcv_socket.close()