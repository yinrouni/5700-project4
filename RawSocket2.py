import math
import random
import socket
import sys
import time
from struct import *
import subprocess

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

def parse_header_body(tcp_data):
    body = tcp_data.split(bytes('\r\n\r\n', 'utf-8'), 1)
    if len(body) == 1:
        return body[0], ''
    return body[0], body[1]

def calculate_checksum(msg):
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

PACK_ID = random.randint(15000, 65535)
TCP_WINDOW = 1024
SOCK_PROTOTYPE = socket.IPPROTO_TCP
TIME_OUT = 60

class RawSocket:

    def __init__(self):
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.ack = 0

        self.DEST_IP = ''
        self.DEST_PORT = 80
        self.cwnd = 1

        self.SRC_IP = subprocess.getoutput("hostname -I")
        self.SRC_PORT = random.randint(1024, 65535)

        self.SRC_ADDR = ''
        self.DEST_ADDR = ''
        self.seq_offset = 0
        self.ack_offset = 0
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        self.last_ack_time = time.process_time()

    # generated an IP header
    def createIPHeader(self, payload_length):
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

        packet = self.createIPHeader(len(data)) + self.createTCPPacket(seq, ack, getTCPFlags(flags), data) + bytes(
            data, 'utf-8')
        self.send_sock.sendto(packet, (self.DEST_IP, 0))

    # unpacks the Transport layer packet and  performs checks
    def unpackTCP(self,tcp_packet):
        tcp_header_values = unpack('!HHLLBBH', tcp_packet[0:16]) + \
                            unpack('H', tcp_packet[16:18]) + \
                            unpack('!H', tcp_packet[18:20])

        tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']
        tcp_headers = dict(zip(tcp_header_keys, tcp_header_values))

        if tcp_headers['dest'] != self.SRC_PORT:
            # print("TCP destination port != SRC_PORT!!")
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

    # unpacks the transport layer packet and performs checks
    def unpackIP(self, ip_packet):
        ip_header_values = unpack('!BBHHHBBH4s4s', ip_packet[:20])
        tcp_packet = ip_packet[20:]
        # print(ip_header_values)

        ip_header_keys = ['ver_ihl', 'service_type', 'total_length', 'pkt_id', 'frag_off', 'ttl', 'proto', 'checksum',
                          'src', 'dest']
        ip_headers = dict(zip(ip_header_keys, ip_header_values))

        # print("tcp data",tcp_packet)
        if ip_headers['dest'] != self.SRC_ADDR:
            raise ValueError('IP: invalid addr')

        if ip_headers['proto'] != SOCK_PROTOTYPE:
            print("NOT TCP Protocol")
            raise ValueError

        return ip_headers, tcp_packet

    def handshake(self):
        self.send_packet(self.seq, 0, 'SYN', '')
        print('handshake sent', self.seq, 0, 'SYN', 0)
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

            if self.seq + 1 == response_ack:
                self.seq = response_ack
                response_seq = tcp_headers['seq']
                self.ack = response_seq + 1
                self.send_packet(self.seq, self.ack, 'ACK', '')
                print('handshake sent', self.seq, self.ack, 'ACK', 0)
                # print("hands shook well")
                break
            else:
                # print("handshake fails")
                raise ValueError("handshake fails")


    def send(self, get_request_data):
        print("STARTED DOWNLOADING")
        self.handshake()
        # index = local_file_name.rfind("/")
        # if index == len(local_file_name) - 1 or index == -1:
        #     local_file_name = 'index.html'
        # else:
        #     local_file_name = local_file_name[index + 1:]
        # # print("WRITING DATA TO::::", local_file_name)
        # temp_file = open(local_file_name, 'w+')
        # temp_file.close()

        self.send_packet(self.seq, self.ack, 'PSH-ACK', get_request_data)
        print('get sent', self.seq, self.ack, 'PSH-ACK', len(get_request_data))

        while self.rev_ack():
            self.send_packet(self.seq, self.ack, 'PSH-ACK', get_request_data)
            print('get sent', self.seq, self.ack, 'PSH-ACK', len(get_request_data))

        self.seq_offset += len(get_request_data)
    
    def rev_ack(self):
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
        if self.seq + self.seq_offset == rec_ack and self.ack + self.ack_offset == rec_seq\
                and tcp_headers['flags'] == 16:
            self.last_ack_time = time.process_time()
            self.cwnd = min(self.cwnd, 999) + 1
            self.ack_offset += len(tcp_response)
            
            print('get recv', tcp_headers['seq'], tcp_headers['ack'], 'ACK', len(tcp_response))
            return True
        return False

    def recv(self):

        local_file_name = 'file.txt'
        local_file = open(local_file_name, 'r+b') 
        tcp_header_and_body_flag = 0
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

            if now - start_time > TIME_OUT:
                self.cwnd = 1
            rec_ack = tcp_headers['ack']
            rec_seq = tcp_headers['seq']
            if self.seq + self.seq_offset == rec_ack and self.ack + self.ack_offset == rec_seq:
                self.last_ack_time = time.process_time()
                self.cwnd = min(self.cwnd, 999) + 1
                self.ack_offset += len(tcp_response)
                if not tcp_header_and_body_flag:
                    headers, body = parse_header_body(tcp_response)
                    if len(body) > 0:
                        local_file.write(body)
                        tcp_header_and_body_flag = 1
                else:
                    local_file.write(tcp_response)
                print('get recv', rec_seq, rec_ack, tcp_headers['flags'], len(tcp_response))
            else:
                self.cwnd = 1
            self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset, 'ACK', '')
            print('get sent', self.seq + self.seq_offset, self.ack + self.ack_offset, 'ACK', '')
            if tcp_headers['flags'] % 2 == 1:
                break
        local_file.close()
        print("DOWNLOAD SUCCESSFUL TO::" + local_file_name)

    def disconnect(self):
        self.send_packet(self.seq + self.seq_offset, self.ack + self.ack_offset, 'FIN', '')

        start_time = time.process_time()
        now = time.process_time()
        tcp_headers = {}
        while now - start_time <= TIME_OUT:
            try:
                ip_packet = self.recv_sock.recv(65536)
                ip_headers, ip_data = self.unpackIP(ip_packet)
                tcp_headers, tcp_data = self.unpackTCP(ip_data)
                if tcp_headers['flags'] % 2 == 1:
                    break
            except:
                continue
            now = time.process_time()
        if now - start_time > TIME_OUT:
            # retry
            self.disconnect()
        response_ack = tcp_headers['ack']
        if self.seq + self.seq_offset + 1 == response_ack:
            response_ack = tcp_headers['seq']
            self.send_packet(self.seq + self.seq_offset + 1, response_ack + 1, 'ACK', '')
        self.send_sock.close()
        self.recv_sock.close()
        return

    def connect(self, address):
        self.DEST_IP = address[0]
        self.DEST_PORT = address[1]

        self.SRC_ADDR = socket.inet_aton(self.SRC_IP)
        self.DEST_ADDR = socket.inet_aton(self.DEST_IP)
