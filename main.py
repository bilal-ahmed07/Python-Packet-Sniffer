import socket
import struct

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3));

raw_packt, addr = conn.recvfrom(65536)

for i in range(20):
    # raw packet break down
    eth_header = raw_packt[:14];
    ip_header = raw_packt[14:34];
    tcp_header = raw_packt[34:54];
    udp_header = raw_packt[34:42];

    #ethernet header breakdown
    dest_raw_mac, src_raw_mac, eth_raw_protocol = struct.unpack("!6s6sH", eth_header)

    # Converting Mac Addresses and Protocol 
    dest_mac = ":".join(format(i, "02x") for i in dest_raw_mac);
    src_mac = ":".join(format(i, "02x") for i in src_raw_mac);
    eth_protocol = socket.ntohs(eth_raw_protocol);

    #IP header breakdown
    ip_parts = struct.unpack("!BBHHHBBH4s4s", ip_header);

    # >> indexing ip headers parts

    # ip_parts = (
    #     version_ihl,
    #     tos,
    #     total_length,
    #     id,
    #     flags,
    #     ttl,
    #     protocol,
    #     checksum,
    #     src_ip,
    #     dst_ip
    # )
    # use accordingly to your requirement

    protocol = ip_parts[6];
    src_raw_ip = ip_parts[8];
    dest_raw_ip = ip_parts[9];
    
    # print("TCP" if (protocol==6) else "UDP")

    #Converting IP Addresses
    src_ip = socket.inet_ntoa(src_raw_ip);
    dest_ip = socket.inet_ntoa(dest_raw_ip);

    # TCP/UDP breakdown
    if (protocol == 6):
        #TCP parts breakdown
        tcp_parts = struct.unpack("!HHLLHHHH", tcp_header)

        #Indexing UDP parts

        # tcp_parts = (
        #   src_port,
        #   dst_port,
        #   seq_number,
        #   ack_number,
        #   flags_info,
        #   window_size,
        #   checksum,
        #   urgent_pointer
        # )

        tcp_src_ports = tcp_parts[0];
        tcp_dest_ports = tcp_parts[1];

        # print("SRC TCP:",tcp_src_ports)
        # print("DEST TCP:",tcp_dest_ports)


    elif (protocol == 17):
        #UDP parts breakdown
        udp_parts = struct.unpack("!HHHH", udp_header)

        #Indexing UPD parts

        # udp_parts = (
        #     src_port,
        #     dst_port,
        #     length,
        #     checksum
        # )

        udp_src_port = udp_parts[0];
        udp_dest_port = udp_parts[1];
        udp_length = udp_parts[2]

        # print("SRC UDP:",udp_src_port)
        # print("DEST UDP:",udp_dest_port)