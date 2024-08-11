
# CodeAlpha_CyberSecurity_Internship_Task01_NetworkPacketSniffer_Raghav

import socket
import struct

# Creating raw socket
def create_socket():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return conn

# Unpacking Ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    dest_mac = format_mac(dest_mac)
    src_mac = format_mac(src_mac)
    proto = socket.htons(proto)
    data = data[14:]
    return dest_mac, src_mac, proto, data

# Formatting MAC address
def format_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpacking IPv4 packet
def unpack_ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src = format_ipv4(src)
    target = format_ipv4(target)
    data = data[header_length:]
    return ttl, proto, src, target, data

# Formatting IPv4 address
def format_ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacking ICMP packet
def unpack_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    data = data[4:]
    return icmp_type, code, checksum, data

# Unpacking TCP segment
def unpack_tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

# Unpacking UDP segment
def unpack_udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    data = data[8:]
    return src_port, dest_port, size, data

#  Calling main function to capture and analyze network packets
def main():
    conn = create_socket()
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print(f"\nEthernet Frame: ")
        print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

        if eth_proto == 8: # IPv4
            ttl, proto, src, target, data = unpack_ipv4_packet(data)
            print(f"IPv4 Packet: ")
            print(f"TTL: {ttl}, Protocol: {proto}, Source: {src}, Target: {target}")

            if proto == 1:
                icmp_type, code, checksum, data = unpack_icmp_packet(data)
                print(f"ICMP Packet: ")
                print(f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp_segment(data)
                print(f"TCP Segment: ")
                print(f"Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"Flags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
            elif proto == 17:
                src_port, dest_port, size, data = unpack_udp_segment(data)
                print(f"UDP Segment: ")
                print(f"Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}")

if __name__ == "__main__":
    main()