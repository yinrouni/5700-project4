import math
import random
import socket
import sys
import time
from struct import *
import subprocess

def fin_flag(tcp_headers):
    return tcp_headers['flags'] % 2 == 1

def get_body_and_headers_from_tcp_data(tcp_data):
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
TCP_WINDOW = socket.htons(8192)
SOCK_PROTOTYPE = socket.IPPROTO_TCP
TIME_OUT = 60

class RawSocket:

    def __init__(self):
        self.seq = random.randint(0, 2 ** 32 - 1)
        self.ack = 0

        # print("DOMAIN", domain_url)
        self.DEST_IP = ''
        self.DEST_PORT = 80
        self.cwnd = 1

        self.SRC_IP = subprocess.getoutput("hostname -I")
        self.SRC_PORT = random.randint(1024, 65535)

        self.SRC_ADDR = ''
        self.DEST_ADDR = ''
        self.seq_addr = 0
        self.ack_addr = 0
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
        header_checksum = 0
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
        pseudo_header = pack('!4s4sBBH', SRC_ADDR, DEST_ADDR,
                             0, socket.IPPROTO_TCP, tcp_packet_length)
        pseudo_packet = pseudo_header + tcp_dummy + bytes(data, 'utf-8')
        tcp_checksum = calculate_checksum(pseudo_packet)
        tcp_packet = pack('!HHLLBBH', self.SRC_PORT, self.DEST_PORT, seq_no, ack_no, offset_reserve, flags,
                          window) + pack('H',tcp_checksum) + pack('!H', urgent_pointer)

        return tcp_packet

    def send_packet(self, seq, ack, flags, data):
        packet = self.createIPHeader(len(data)) + self.createTCPPacket(seq, ack, flags, data) + bytes(data, 'utf-8')
        self.send_sock.sendto(packet, (self.DEST_IP, 0))

    # unpacks the Transport layer packet and  performs checks
    def unpack_tcp_packet(self,tcp_packet):
        tcp_header_values = unpack('!HHLLBBH', tcp_packet[0:16]) + \
                            unpack('H', tcp_packet[16:18]) + \
                            unpack('!H', tcp_packet[18:20])
        tcp_headers = {}
        tcp_headers['src'] = tcp_header_values[0]
        tcp_headers['dest'] = tcp_header_values[1]
        tcp_headers['seq'] = tcp_header_values[2]
        tcp_headers['ack'] = tcp_header_values[3]
        tcp_headers['off_res'] = tcp_header_values[4]
        tcp_headers['flags'] = tcp_header_values[5]
        tcp_headers['awnd'] = tcp_header_values[6]
        tcp_headers['chksm'] = tcp_header_values[7]
        tcp_headers['urg'] = tcp_header_values[8]

        # print("dadadddda", tcp_headers)
        if tcp_headers['dest'] != self.SRC_PORT:
            # print("TCP destination port != SRC_PORT!!")
            raise ValueError
        # else:
        #     print('src', tcp_headers['src'])
        #     print('dest', tcp_headers['dest'])
        #     print('ack', tcp_headers['ack'])
        #     print('flags', tcp_headers['flags'])

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
    def unpack_ip_packet(self, ip_packet):
        ip_header_values = unpack('!BBHHHBBH4s4s', ip_packet[:20])
        tcp_packet = ip_packet[20:]
        # print(ip_header_values)

        ip_headers = {}
        ip_headers['ver_ihl'] = ip_header_values[0]
        ip_headers['service_type'] = ip_header_values[1]
        ip_headers['total_length'] = ip_header_values[2]
        ip_headers['pkt_id'] = ip_header_values[3]
        ip_headers['frag_off'] = ip_header_values[4]
        ip_headers['ttl'] = ip_header_values[5]
        ip_headers['proto'] = ip_header_values[6]
        ip_headers['checksum'] = ip_header_values[7]
        ip_headers['src'] = ip_header_values[8]
        ip_headers['dest'] = ip_header_values[9]

        # print("tcp data",tcp_packet)
        if ip_headers['dest'] != self.SRC_ADDR:
            # print(ip_headers['dest'], SRC_ADDR)
            # print("IP packet not from SRC")
            raise ValueError
        # else:
        #     print('IP packet from', socket.inet_ntoa(ip_headers['src']))
        #     print('IP packet to', socket.inet_ntoa(ip_headers['dest']))

        #
        if ip_headers['proto'] != SOCK_PROTOTYPE:
            print("NOT TCP Protocol")
            raise ValueError

        return ip_headers, tcp_packet

    def handshake(self):
        self.send_packet(self.seq, 0, 0x02, '')
        ip_packet = self.recv_sock.recv(65536)
        # packet = createIPHeader(0) + createTCPPacket(0, 0, 2, '')
        # send_sock.sendto(packet, (DEST_IP, 0))
        packet_sent_time = time.process_time()
        # return packet_sent_time
        st_time = time.process_time()
        tcp_headers = {}
        while ip_packet:
            ip_headers, ip_data = self.unpack_ip_packet(ip_packet)
            tcp_headers, tcp_data = self.unpack_tcp_packet(ip_data)
            # print("FLAGSSSS:::", tcp_headers['flags'])
            if tcp_headers['flags'] != 0x12:
                ip_packet = self.recv_sock.recv(65536)
                continue
            response_ack = tcp_headers['ack']
            # print("resp:", response_ack, seq)
            if self.seq + 1 == response_ack:
                self.seq = response_ack
                response_seq = tcp_headers['seq']
                self.ack = response_seq + 1
                self.send_packet(self.seq, self.ack, 0x10, '')
                # print("hands shook well")
                break
            else:
                print("hands did not shake well")
                raise ValueError
        else:
            print("NONEE")


    def send(self, get_request_data):
        print("STARTED DOWNLOADING")
        global seq, ack, URL, seq_addr, ack_addr
        self.handshake()
        local_file_name = 'file.txt'
        # index = local_file_name.rfind("/")
        # if index == len(local_file_name) - 1 or index == -1:
        #     local_file_name = 'index.html'
        # else:
        #     local_file_name = local_file_name[index + 1:]
        # # print("WRITING DATA TO::::", local_file_name)
        # temp_file = open(local_file_name, 'w+')
        # temp_file.close()
        local_file = open(local_file_name, 'r+b')

        self.send_packet(self.seq, self.ack, 0x18, get_request_data)
        self.seq_addr += len(get_request_data)
        self.recv(local_file)
        print("DOWNLOAD SUCCESSFUL TO::" + local_file_name)

    def recv(self,local_file):
        # print("vacha")
        tcp_header_and_body_flag = 0
        while True:
            start_time = time.process_time()
            now = start_time
            while now - start_time < TIME_OUT:
                try:
                    ip_packet = self.recv_sock.recv(65536)
                    ip_headers, ip_data = self.unpack_ip_packet(ip_packet)
                    tcp_headers, tcp_response = self.unpack_tcp_packet(ip_data)
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
            if self.seq + self.seq_addr == rec_ack and self.ack + self.ack_addr == rec_seq:
                self.last_ack_time = time.process_time()
                self.cwnd = min(self.cwnd, 999) + 1
                self.ack_addr += len(tcp_response)
                if not tcp_header_and_body_flag:
                    headers, body = get_body_and_headers_from_tcp_data(tcp_response)
                    if len(body) > 0:
                        local_file.write(body)
                        tcp_header_and_body_flag = 1
                else:
                    local_file.write(tcp_response)
            else:
                self.cwnd = 1
            self.send_packet(self.seq + self.seq_addr, self.ack + self.ack_addr, 0x10, '')
            if fin_flag(tcp_headers):
                break
        local_file.close()

    def disconnect(self):
        self.send_packet(self.seq + self.seq_addr, self.ack + self.ack_addr, 0x01, '')

        start_time = time.process_time()
        now = time.process_time()
        tcp_headers = {}
        while now - start_time <= TIME_OUT:
            try:
                ip_packet = self.recv_sock.recv(65536)
                ip_headers, ip_data = self.unpack_ip_packet(ip_packet)
                tcp_headers, tcp_data = self.unpack_tcp_packet(ip_data)
                if fin_flag(tcp_headers):
                    break
            except:
                continue
            now = time.process_time()
        if now - start_time > TIME_OUT:
            print("TEAR DOWN LO PROBLEM RAAAA::::")
            self.disconnect()
        response_ack = tcp_headers['ack']
        if self.seq + self.seq_addr + 1 == response_ack:
            response_ack = tcp_headers['seq']
            self.send_packet(self.seq + self.seq_addr + 1, response_ack + 1, 0x10, '')
        self.send_sock.close()
        self.recv_sock.close()
        return

    def connect(self, address):
        self.DEST_IP = address[0]
        self.DEST_PORT = address[1]

        self.SRC_ADDR = socket.inet_aton(self.SRC_IP)
        self.DEST_ADDR = socket.inet_aton(self.DEST_IP)


