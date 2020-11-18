#!/usr/bin/env python3
import socket
import random
from struct import pack, unpack
import array
import time
import sys


# gets the IP of the host system
def getSourceIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("cs5700f16.ccs.neu.edu", 80))
    return s.getsockname()[0]


# checksum calculator
def calculate_checksum(data):
    s = 0
    if len(data) % 2 != 0:
        w = array.array('h', (data + b'\0'))
    else:
        w = array.array('h', data)
    for wd in w:
        wd = wd & 0xffff
        s += wd
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


# generated an IP header
def createIPHeader(payload_length):
    global SRC_IP, DEST_IP, SRC_ADDR, DEST_ADDR
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
                     ttl, protocol, 0, SRC_ADDR, DEST_ADDR)
    header_checksum = calculate_checksum(ip_header)
    ip_header = pack('!BBHHHBBH4s4s', first_byte, service_type, total_length, identification, fragment_bytes,
                     ttl, protocol, header_checksum, SRC_ADDR, DEST_ADDR)
    return ip_header


# creates a TCP header
def createTCPPacket(seq_no, ack_no, flags, data):
    global TCP_WINDOW, SRC_PORT, DEST_PORT, SRC_IP, DEST_IP
    urgent_pointer = 0
    tcp_checksum = 0
    window = TCP_WINDOW
    tcp_header_length = 5
    offset_reserve = (tcp_header_length << 4) + 0
    tcp_dummy = pack('!HHLLBBHHH', SRC_PORT, DEST_PORT, seq_no, ack_no, offset_reserve, flags, window,
                     tcp_checksum,
                     urgent_pointer)
    tcp_packet_length = len(tcp_dummy) + len(data)
    pseudo_header = pack('!4s4sBBH', SRC_ADDR, DEST_ADDR,
                         0, socket.IPPROTO_TCP, tcp_packet_length)
    pseudo_packet = pseudo_header + tcp_dummy + bytes(data, 'utf-8')
    tcp_checksum = calculate_checksum(pseudo_packet)
    tcp_packet = pack('!HHLLBBH', SRC_PORT, DEST_PORT, seq_no, ack_no, offset_reserve, flags, window) + pack('H',
                                                                                                             tcp_checksum) + pack(
        '!H', urgent_pointer)

    return tcp_packet


# sends a Transport layer packet to the DESTINATION IP
def send_packet(seq, ack, flags, data):
    global DEST_IP
    packet = createIPHeader(len(data)) + createTCPPacket(seq, ack, flags, data) + bytes(data, 'utf-8')
    send_sock.sendto(packet, (DEST_IP, 0))


# three way handshake
def handshake():
    global seq, recv_sock, ack, TIME_OUT
    send_packet(seq, 0, 0x02, '')
    ip_packet = recv_sock.recv(65536)
    # packet = createIPHeader(0) + createTCPPacket(0, 0, 2, '')
    # send_sock.sendto(packet, (DEST_IP, 0))
    packet_sent_time = time.time()
    # return packet_sent_time
    st_time = time.time()
    tcp_headers = {}
    while ip_packet:
        ip_headers, ip_data = unpack_ip_packet(ip_packet)
        tcp_headers, tcp_data = unpack_tcp_packet(ip_data)
        # print("FLAGSSSS:::", tcp_headers['flags'])
        if tcp_headers['flags'] != 0x12:
            ip_packet = recv_sock.recv(65536)
            continue
        response_ack = tcp_headers['ack']
        # print("resp:", response_ack, seq)
        if seq + 1 == response_ack:
            seq = response_ack
            response_seq = tcp_headers['seq']
            ack = response_seq + 1
            send_packet(seq, ack, 0x10, '')
            # print("hands shook well")
            break
        else:
            print("hands did not shake well")
            raise ValueError
    else:
        print("NONEE")


# unpacks the Transport layer packet and  performs checks
def unpack_tcp_packet(tcp_packet):
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
    if tcp_headers['dest'] != SRC_PORT:
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

    header1 = pack('!4s4sBBH', DEST_ADDR, SRC_ADDR, 0, SOCK_PROTOTYPE, len(tcp_packet))
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
def unpack_ip_packet(ip_packet):
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
    if ip_headers['dest'] != SRC_ADDR:
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


def get_host_name():
    global URL
    domain_name = URL
    index = domain_name.find('http://')
    if index >= 0:
        domain_name = domain_name[len('http://'):]
    index = domain_name.find('/')
    if index >= 0:
        domain_name = domain_name[:index]
    return domain_name


def http_get_data():
    global URL, domain_url

    # return "GET http://cs5700sp20.ccs.neu.edu/accounts/login/?next=/fakebook/ HTTP/1.0\r\nHost: cs5700sp20.ccs.neu.edu\r\nConnection: keep-alive\r\n\r\n"
    # request_data = 'GET http://' + URL + ''' HTTP/1.1
    # Host: ''' + URL + '\r\n\r\n'
    # http: // david.choffnes.com/classes/cs4700sp17/2MB.log
    # return "GET cs5700sp20.ccs.neu.edu/accounts/login/?next=/fakebook/ HTTP/1.1\r\nHost: cs5700sp20.ccs.neu.edu/\r\n\r\n"
    # return "GET http://david.choffnes.com/ HTTP/1.0\r\nHost: david.choffnes.com\r\n\r\n"

    if URL[:len('http://')] == 'http://':
        get_temp = "GET "
    else:
        get_temp = "GET HTTP://" + URL[:len('http://')]
    return get_temp + URL + " HTTP/1.0\r\nHost: " + domain_url + "\r\nConnection: keep-alive\r\n\r\n"


def fin_flag(tcp_headers):
    return tcp_headers['flags'] % 2 == 1


def get_body_and_headers_from_tcp_data(tcp_data):
    body = tcp_data.split(bytes('\r\n\r\n', 'utf-8'), 1)
    if len(body) == 1:
        return body[0], ''
    return body[0], body[1]


def download_file_helper(local_file):
    global ack, seq, seq_addr, ack_addr, TIME_OUT, cwnd, last_ack_time
    # print("vacha")
    tcp_header_and_body_flag = 0
    while True:
        start_time = time.time()
        now = start_time
        while now - start_time < TIME_OUT:
            try:
                ip_packet = recv_sock.recv(65536)
                ip_headers, ip_data = unpack_ip_packet(ip_packet)
                tcp_headers, tcp_response = unpack_tcp_packet(ip_data)
                break
            except ValueError:
                now = time.time()
                continue
        if time.time() - last_ack_time > 3 * TIME_OUT:
            tear_down_connection()
            return

        if now - start_time > TIME_OUT:
            cwnd = 1
        rec_ack = tcp_headers['ack']
        rec_seq = tcp_headers['seq']
        if seq + seq_addr == rec_ack and ack + ack_addr == rec_seq:
            last_ack_time = time.time()
            cwnd = min(cwnd, 999) + 1
            ack_addr += len(tcp_response)
            if not tcp_header_and_body_flag:
                headers, body = get_body_and_headers_from_tcp_data(tcp_response)
                if len(body) > 0:
                    local_file.write(body)
                    tcp_header_and_body_flag = 1
            else:
                local_file.write(tcp_response)
        else:
            cwnd = 1
        send_packet(seq + seq_addr, ack + ack_addr, 0x10, '')
        if fin_flag(tcp_headers):
            break
    local_file.close()


def tear_down_connection():
    global seq, ack, seq_addr, ack_addr, TIME_OUT, send_sock, recv_sock
    send_packet(seq + seq_addr, ack + ack_addr, 0x01, '')

    start_time = time.time()
    now = time.time()
    tcp_headers = {}
    while now - start_time <= TIME_OUT:
        try:
            ip_packet = recv_sock.recv(65536)
            ip_headers, ip_data = unpack_ip_packet(ip_packet)
            tcp_headers, tcp_data = unpack_tcp_packet(ip_data)
            if fin_flag(tcp_headers):
                break
        except:
            continue
        now = time.time()
    if now - start_time > TIME_OUT:
        print("TEAR DOWN LO PROBLEM RAAAA::::")
        tear_down_connection()
    response_ack = tcp_headers['ack']
    if seq + seq_addr + 1 == response_ack:
        response_ack = tcp_headers['seq']
        send_packet(seq + seq_addr + 1, response_ack + 1, 0x10, '')
    send_sock.close()
    recv_sock.close()
    return


def download_file():
    print("STARTED DOWNLOADING")
    global seq, ack, URL, seq_addr, ack_addr
    handshake()
    local_file_name = URL
    index = local_file_name.rfind("/")
    if index == len(local_file_name) - 1 or index == -1:
        local_file_name = 'index.html'
    else:
        local_file_name = local_file_name[index + 1:]
    # print("WRITING DATA TO::::", local_file_name)
    temp_file = open(local_file_name, 'w+')
    temp_file.close()
    local_file = open(local_file_name, 'r+b')
    get_request_data = http_get_data()
    send_packet(seq, ack, 0x18, get_request_data)
    seq_addr += len(get_request_data)
    download_file_helper(local_file)
    print("DOWNLOAD SUCCESSFUL TO::" + local_file_name)


URL = 'http://david.choffnes.com/classes/cs4700fa20/2MB.log'
# args = sys.argv
#
# if len(args) <= 1:
#     exit()
#
# URL = args[1]
if 'https://' in URL:
    print("NO HTTPS PLEASE")
    exit()

seq = random.randint(0, 2 ** 32 - 1)
PACK_ID = random.randint(15000, 65535)
TCP_WINDOW = socket.htons(8192)
ack = 0

domain_url = get_host_name()
# print("DOMAIN", domain_url)
DEST_IP = socket.gethostbyname(domain_url)
SOCK_PROTOTYPE = socket.IPPROTO_TCP
DEST_PORT = 80
cwnd = 1

SRC_IP = getSourceIP()
SRC_PORT = random.randint(1024, 65535)

SRC_ADDR = socket.inet_aton(SRC_IP)
DEST_ADDR = socket.inet_aton(DEST_IP)
seq_addr = 0
ack_addr = 0
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
TIME_OUT = 60

last_ack_time = time.time()
# handshake()
download_file()
tear_down_connection()

# packet = recv_sock.recv(65000)
# print(packet)
# unpack_ip_packet(packet)