import math
import random
import socket
import sys
import time
from struct import *
import subprocess
import os

# TCP flags
def getTCPFlags(flag):
    """
    generate TCP flags using types of them
    :param flag:  name of flag, e.g. SYN, SYN-ACK
    :return
    the corresponding flag as a int
    """
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

def parse_header_body(tcp_data):
    """
    Split the header and body in the http/GET response by \r\n\r\n
    :param tcp_data: http/GET response in byte
    :return: header, body
    """
    body = tcp_data.split(bytes('\r\n\r\n', 'utf-8'), 1)
    if len(body) == 1:
        return body[0], ''
    return body[0], body[1]


def calculate_checksum(msg):
    """
    Calculate the checksum using the given header in byte
    :param msg: the given IP or pseudo header in byte
    :return: the calculated checksum
    """
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if i == len(msg)-1:
            w = msg[i]
        else :
            w = msg[i] + (msg[i + 1] << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def create_file(file_name):
    """
    Create the file used for the response for the http/GET
    :param file_name: the name of file
    """
    local_file_name = file_name
    temp_file = open(local_file_name, 'w+')
    temp_file.close()

PACK_ID = random.randint(15000, 65535)
TCP_WINDOW = 2048
SOCK_PROTOTYPE = socket.IPPROTO_TCP
TIME_OUT = 60


class RawSocket:
    """
    This is socket used to send and recv http/GET via TCP/IP. It provides following methods for users:
    connect(address_tuple): connect local host and remote server.
    send(request): send a http/GET request, and the name of file for the outpu
    recv(filename): recv the response from the http/GET sent before, and save in the file named filename
    close(): close the socket
    """

    def __init__(self):
        """
        Initialize the socket using essential settings
        """

        # the base seq and ack number in tcp, and offset used to help the change of seq and ack
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.ack = 0
        self.seq_offset = 0
        self.ack_offset = 0

        self.cwnd = 1

        self.DEST_IP = ''
        self.DEST_PORT = 80
        # API to get IP of local machine
        self.SRC_IP = subprocess.getoutput("hostname -I")
        self.SRC_PORT = random.randint(1024, 65535)
        self.SRC_ADDR = ''
        self.DEST_ADDR = ''

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.last_ack_time = time.process_time()

    def createIPHeader(self, payload_length):
        """
        generated an IP header by setting up the essential fields in the header. Generate temp IP header using 0 as
        checksum,then replace the checksum calculated by it and repack the returned IP header
        :param payload_length: the length of the payload in the IP header
        :return: the packed IP header
        """
        ip_version = 4
        ip_header_length = 5
        packet_id = PACK_ID
        first_byte = ip_header_length + (ip_version << 4)
        service_type = 0
        total_length = payload_length + 20
        identification = packet_id
        flags = 0
        fragment_offset = 0
        fragment_bytes = fragment_offset + (flags << 3)
        ttl = 255
        protocol = socket.IPPROTO_TCP

        ip_header = pack('!BBHHHBBH4s4s', first_byte, service_type, total_length, identification, fragment_bytes,
                         ttl, protocol, 0, self.SRC_ADDR, self.DEST_ADDR)
        header_checksum = calculate_checksum(ip_header)
        ip_header = pack('!BBHHHBBH4s4s', first_byte, service_type, total_length, identification, fragment_bytes,
                         ttl, protocol, header_checksum, self.SRC_ADDR, self.DEST_ADDR)
        return ip_header

    def createTCPPacket(self, seq_no, ack_no, flags, data):
        """
        generated an TCP header by setting up the essential fields in the header. Generate pseudo header using 0 as
        checksum,then replace the checksum calculated by it and repack the returned TCP header
        :param seq_no: seq of the packet
        :param ack_no: ack of the packet
        :param flags: value of the flag
        :param data: the payload
        :return: packed TCP header
        """

        urgent_pointer = 0
        tcp_checksum = 0
        window = TCP_WINDOW
        tcp_header_length = 5
        offset_reserve = (tcp_header_length << 4) + 0
        tcp_dummy = pack('!HHLLBBHHH', self.SRC_PORT, self.DEST_PORT, seq_no, ack_no, offset_reserve, flags, window,
                         tcp_checksum,
                         urgent_pointer)
        tcp_packet_length = len(tcp_dummy) + len(data)
        pseudo_header = pack('!4s4sBBH', self.SRC_ADDR, self.DEST_ADDR,
                             0, socket.IPPROTO_TCP, tcp_packet_length)
        pseudo_packet = pseudo_header + tcp_dummy + bytes(data, 'utf-8')
        tcp_checksum = calculate_checksum(pseudo_packet)
        tcp_packet = pack('!HHLLBBH', self.SRC_PORT, self.DEST_PORT, seq_no, ack_no, offset_reserve, flags,
                          window) + pack('H',tcp_checksum) + pack('!H', urgent_pointer)

        return tcp_packet

    def send_packet(self, seq, ack, flags, data):
        """
        Generate a packet (packet = ip_header + tcp_header + user_data) using the created IP and TCP header. Send the
        packet to the remote server
        :param seq: seq in the TCP header
        :param ack: ack in the TCP header
        :param flags: value of flag in the TCP header
        :param data: user data
        :return: null
        """

        packet = self.createIPHeader(len(data)) + self.createTCPPacket(seq, ack, getTCPFlags(flags), data) + bytes(
            data, 'utf-8')
        self.send_sock.sendto(packet, (self.DEST_IP, 0))

    def unpackTCP(self,tcp_packet):
        """
        Unpacks incoming TCP packet and  performs validations. Its destination port should be the port if the local
        machine,
        and validate the checksum.
        :param tcp_packet: the tcp packted to be unpacked
        :return: tcp headers and user data in it
        """
        tcp_header_values = unpack('!HHLLBBH', tcp_packet[0:16]) + \
                            unpack('H', tcp_packet[16:18]) + \
                            unpack('!H', tcp_packet[18:20])

        tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']
        tcp_headers = dict(zip(tcp_header_keys, tcp_header_values))

        if tcp_headers['dest'] != self.SRC_PORT:
            raise ValueError('TCP: invalid port')

        offset = tcp_headers['off_res'] >> 4

        options = ''.encode()
        if offset > 5:
            options = tcp_packet[20:4 * offset]

        tcp_data = tcp_packet[4 * offset:]

        header1 = pack('!4s4sBBH', self.DEST_ADDR, self.SRC_ADDR, 0, SOCK_PROTOTYPE, len(tcp_packet))
        c_sum = tcp_header_values[7]
        header1_data = header1 + pack('!HHLLBBHHH',
                                      tcp_header_values[0],
                                      tcp_header_values[1],
                                      tcp_header_values[2],
                                      tcp_header_values[3],
                                      tcp_header_values[4],
                                      tcp_header_values[5],
                                      tcp_header_values[6],
                                      0,
                                      tcp_header_values[8]) \
                       + options + tcp_data
        actual_c_sum = calculate_checksum(header1_data)

        if c_sum != actual_c_sum:
            print("Invalid packet")
            raise ValueError
        return tcp_headers, tcp_data

    def unpackIP(self, ip_packet):
        """
        Unpacks the incoming IP packet and performs validations. Its destination address should be the address if the
        local machine,and validate the protocol type and checksum.
        :param ip_packet: the incoming IP packet
        :return: IP headers and tcp packets
        """
        ip_header_values = unpack('!BBHHHBBH4s4s', ip_packet[:20])
        tcp_packet = ip_packet[20:]
        # print(ip_header_values)

        ip_header_keys = ['ver_ihl', 'service_type', 'total_length', 'pkt_id', 'frag_off', 'ttl', 'proto', 'checksum',
                          'src', 'dest']
        ip_headers = dict(zip(ip_header_keys, ip_header_values))

        if ip_headers['dest'] != self.SRC_ADDR:
            raise ValueError('IP: invalid addr')

        if ip_headers['proto'] != SOCK_PROTOTYPE:
            print("NOT TCP Protocol")
            raise ValueError

        return ip_headers, tcp_packet

    def handshake(self):
        """
        Set up the connect by handshaking. Start with sending a SYN to server. Unpack and validate the incoming
        SYN-ACK packet. Send a ACK for it. Handshake done.

        client ---------------------- server
        ----------- SYN seq = x ----------->
        <-- SYN, ACK seq = y, ack = x + 1 --
        --- ACK seq = x + 1, ack = y + 1 --->

        :return: null
        """

        # Send a SYN
        self.send_packet(self.seq, 0, 'SYN', '')
        print('handshake sent', self.seq, 0, 'SYN', 0)

        # receive a SYN-ACK. if the incoming packet fails the verification and it's invalid, discard it and try to
        # receive another.
        ip_packet = self.recv_sock.recv(65536)
        while ip_packet:
            try:
                ip_headers, ip_data = self.unpackIP(ip_packet)
                tcp_headers, tcp_data = self.unpackTCP(ip_data)
            except ValueError:
                ip_packet = self.recv_sock.recv(65536)
                continue

            if tcp_headers['flags'] != 0x12:
                ip_packet = self.recv_sock.recv(65536)
                continue
            response_ack = tcp_headers['ack']
            print('handshake recv', tcp_headers['seq'], tcp_headers['ack'],
                    'SYN-ACK', 0)

            # verify the ack of incoming SYN-ACK with the SYN sent. If succeed, send a ACK for it, and handshake
            # done. otherwise, handshake fails.
            if self.seq + 1 == response_ack:
                self.seq = response_ack
                response_seq = tcp_headers['seq']
                self.ack = response_seq + 1
                self.send_packet(self.seq, self.ack, 'ACK', '')
                print('handshake sent', self.seq, self.ack, 'ACK', 0)
                print("handshake done")
                break
            else:
                print("handshake fails")
                raise ValueError("handshake fails")


    def send(self, get_request_data):
        """
        Send request after handshake. Unpack and validate the incoming ACK packet. If it fails validation,
        resend the request.

        client -------------------------------- server
        - PSH-ACK seq = x + 1, ack = y + 1, len = z ->
        <----- ACK seq = y + 1, ack = x + 1 + z ------

        :param get_request_data: http request
        :return: null
        """

        print("start to download")
        while True:
            try:
                self.handshake()
                break
            except ValueError:
                continue

        self.send_packet(self.seq, self.ack, 'PSH-ACK', get_request_data)
        print('get sent', self.seq, self.ack, 'PSH-ACK', len(get_request_data))

        while self.rev_ack():
            self.send_packet(self.seq, self.ack, 'PSH-ACK', get_request_data)
            print('get sent', self.seq, self.ack, 'PSH-ACK', len(get_request_data))

        self.seq_offset += len(get_request_data)

    def rev_ack(self, fin = 0):
        """
        Handle the incoming ACK for PSH-ACK when sending http request, and FIN when client wants to end the connection.
        If there's valid ACK within 1 min, assume the sent packet is lost and retransmit. If it does not receive any
        data for 3 min, client start to tear down the connection.
        :param fin: flag for whether it should be a ACK for a FIN
        :return: whether the incoming ACK is valid
        """

        start_time = time.process_time()
        now = start_time
        while now - start_time < TIME_OUT:
            try:
                ip_packet = self.recv_sock.recv(65536)
                ip_headers, ip_data = self.unpackIP(ip_packet)
                tcp_headers, tcp_response = self.unpackTCP(ip_data)
                break
            except ValueError:
                now = time.process_time()
                continue
        if time.process_time() - self.last_ack_time > 3 * TIME_OUT:
            self.disconnect()
            return False

        if now - start_time > TIME_OUT:
            self.cwnd = 1
            return False
        rec_ack = tcp_headers['ack']
        rec_seq = tcp_headers['seq']

        # ACK for FIN/FIN-ACK
        if fin and rec_ack == self.seq + self.seq_offset + 1 and tcp_headers['flags'] == 16:
            self.last_ack_time = time.process_time()
            self.cwnd = min(self.cwnd, 999) + 1
            self.ack_offset += len(tcp_response)

            print('dis recv', tcp_headers['seq'], tcp_headers['ack'], 'ACK', len(tcp_response))
            return True

        # ACK for PSH-ACK
        if self.seq + self.seq_offset == rec_ack and self.ack + self.ack_offset == rec_seq\
                and tcp_headers['flags'] == 16 and not fin:
            self.last_ack_time = time.process_time()
            self.cwnd = min(self.cwnd, 999) + 1
            self.ack_offset += len(tcp_response)

            print('get recv', tcp_headers['seq'], tcp_headers['ack'], 'ACK', len(tcp_response))
            return True
        return False

    def recv(self,file_name):
        """
        Receive the response of the request. Keep receiving ACK with content from server, and send back ACK for each
        of them. If there's valid ACK within 1 min, assume the sent packet is lost and retransmit. If it does not
        receive any data for 3 min, client start to tear down the connection. When receiving a packet marked FIN,
        reply to the request from server to end the connection.

        client -------------------------------- server
        <- ACK seq = y + 1, ack = x + 1 + z, len = k -
        --- ACK seq = x + 1 + z, ack = y + 1 + k ---->
                            ...

        :param file_name: file for response
        :return: null
        """

        # init the output file
        create_file(file_name)
        local_file_name = file_name
        local_file = open(local_file_name, 'r+b')

        # Flag for the first packet containing http response header
        tcp_header_and_body_flag = 0
        ok = 1
        while True:
            start_time = time.process_time()
            now = start_time
            while now - start_time < TIME_OUT:
                try:
                    ip_packet = self.recv_sock.recv(65536)
                    ip_headers, ip_data = self.unpackIP(ip_packet)
                    tcp_headers, tcp_response = self.unpackTCP(ip_data)
                    break
                except ValueError:
                    now = time.process_time()
                    continue
            if time.process_time() - self.last_ack_time > 3 * TIME_OUT:
                self.disconnect()
                return

            # timeout, reset the cwnd
            if now - start_time > TIME_OUT:
                self.cwnd = 1

            # keep the order of packets using seq and ack
            rec_ack = tcp_headers['ack']
            rec_seq = tcp_headers['seq']
            if self.seq + self.seq_offset == rec_ack and self.ack + self.ack_offset == rec_seq:
                self.last_ack_time = time.process_time()
                self.cwnd = min(self.cwnd, 999) + 1
                self.ack_offset += len(tcp_response)
                if not tcp_header_and_body_flag:
                    headers, body = parse_header_body(tcp_response)
                    if not headers.startswith(b'HTTP/1.1 200 OK'):
                        ok = 0
                        break
                    else:
                        ok = 1

                    if len(body) > 0:
                        local_file.write(body)
                        tcp_header_and_body_flag = 1
                else:
                    local_file.write(tcp_response)
                print('get recv', rec_seq, rec_ack, tcp_headers['flags'], len(tcp_response))

            else:
                # packet lost, cwnd reset
                self.cwnd = 1
            if tcp_headers['flags'] % 2 == 1:
                # FIN from server, reply to the request from server to end the connection.
                self.reply_disconnect()
                break
            else:
                # send ACK for the received packets
                self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset, 'ACK', '')
                print('get sent', self.seq + self.seq_offset, self.ack + self.ack_offset, 'ACK', '')
            if not ok:
                print('not 200 ------ disconnect')
                self.disconnect()
                os.system('rm -rf %s' % file_name)
                return
       # self.disconnect()
        local_file.close()
        print("DOWNLOAD DONE TO :" + local_file_name)

    def reply_disconnect(self):
        """
        When receive a FIN from server, reply to this request to tear down the connection, by sending a FIN-ACK. Then
        receive an ACK from server and tear down the connection

        client ------------------------------ server
        <-- PSH,FIN,ACK seq = m, ack = n, len = k --
        ---- FIN, ACK seq = n, ack = m + k + 1 ---->
         <---- ACK seq = m + k + 1, ack = n + 1 ----
        :return:null
        """
        self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset + 1, 'FIN-ACK', '')
        print('dis sent', self.seq + self.seq_offset, self.ack + self.ack_offset + 1, 'FIN-ACK', 0)
        ret = self.rev_ack(fin = 1)
        self.close()

    def disconnect(self):
        """
        Client wants to end the connection.

        client ------------------------- server
        -------- FIN seq = m, ack = n -------->
        <----- ACK seq = k , ack = m + 1 ------
        <---- FIN-ACK seq = w, ack = m + 1 ----
        ---- ACK seq = m + 1 , ack = w + 1 ---->
        :return: null
        """
        self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset, 'FIN', '')
        print('dis sent', self.seq + self.seq_offset, self.ack + self.ack_offset, 'FIN', 0)

        while self.rev_ack(fin=1):
            self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset, 'FIN', '')
            print('dis sent', self.seq + self.seq_offset, self.ack + self.ack_offset, 'FIN', 0)
        while True:
            start_time = time.process_time()
            now = time.process_time()
            tcp_headers = {}
            while now - start_time <= TIME_OUT:
                try:
                    ip_packet = self.recv_sock.recv(65536)
                    ip_headers, ip_data = self.unpackIP(ip_packet)
                    tcp_headers, tcp_data = self.unpackTCP(ip_data)
                    if tcp_headers['flags'] == 17: #FIN-ACK
                        break
                except:
                    continue
                now = time.process_time()
            if now - start_time > TIME_OUT:
                # retry
                self.disconnect()
            response_ack = tcp_headers['ack']
            if self.seq + self.seq_offset + 1 == response_ack:
                print('dis recv', tcp_headers['seq'],tcp_headers['ack'], tcp_headers['flags'], 0)
                response_ack = tcp_headers['seq']
                self.send_packet(self.seq + self.seq_offset + 1, response_ack + 1, 'ACK', '')
                print('dis sent', self.seq + self.seq_offset + 1, response_ack + 1, 'ACK', '')
                break
            self.close()
            return

    def connect(self, address):
        """
        Set up the IP and port of the remote server
        :param address:
        :return: null
        """
        self.DEST_IP = address[0]
        self.DEST_PORT = address[1]

        self.SRC_ADDR = socket.inet_aton(self.SRC_IP)
        self.DEST_ADDR = socket.inet_aton(self.DEST_IP)

    def close(self):
        """
        Close the socket (both send and recv)
        :return: null
        """
        self.send_sock.close()
        self.recv_sock.close()