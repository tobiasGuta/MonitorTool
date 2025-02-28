import socket
import struct
import ipaddress
import argparse
import time

def capture_network_traffic(interface="eth0", output_file="capture.pcap"):
    """
    Captures network traffic, prints information, and saves to a pcap file.
    Continuously listens until interrupted.

    Args:
        interface (str): The network interface to capture on.
        output_file (str): The filename for the pcap output.
    """

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))

        print(f"Listening on interface {interface} and saving to {output_file}...")

        with open(output_file, 'wb') as pcap_file:
            # Write pcap global header
            pcap_global_header = struct.pack("!IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            pcap_file.write(pcap_global_header)

            while True:
                try:
                    raw_data, addr = sock.recvfrom(65535)

                    eth_length = 14
                    eth_header = raw_data[:eth_length]
                    eth_unpacked = struct.unpack("!6s6sH", eth_header)
                    eth_protocol = socket.ntohs(eth_unpacked[2])

                    if eth_protocol == 8:  # IPv4
                        ip_header = raw_data[eth_length:eth_length + 20]
                        ip_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
                        version_ihl = ip_unpacked[0]
                        version = version_ihl >> 4
                        ihl = version_ihl & 0xF
                        iph_length = ihl * 4

                        ttl = ip_unpacked[5]
                        protocol = ip_unpacked[6]
                        s_addr = socket.inet_ntoa(ip_unpacked[8])
                        d_addr = socket.inet_ntoa(ip_unpacked[9])

                        print(f"Protocol: IPv4, Source: {s_addr}, Destination: {d_addr}, Protocol Number: {protocol}")

                        if protocol == 6:  # TCP
                            tcp_header = raw_data[eth_length + iph_length:eth_length + iph_length + 20]
                            tcp_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
                            source_port = tcp_unpacked[0]
                            dest_port = tcp_unpacked[1]
                            print(f"  TCP, Source Port: {source_port}, Destination Port: {dest_port}")

                        elif protocol == 17:  # UDP
                            udp_header = raw_data[eth_length + iph_length:eth_length + iph_length + 8]
                            udp_unpacked = struct.unpack("!HHHH", udp_header)
                            source_port = udp_unpacked[0]
                            dest_port = udp_unpacked[1]
                            print(f"  UDP, Source Port: {source_port}, Destination Port: {dest_port}")

                        elif protocol == 1:  # ICMP
                            print("  ICMP packet")

                    elif eth_protocol == 1544:  # ARP
                        arp_header = raw_data[eth_length:eth_length + 28]
                        arp_unpacked = struct.unpack("!HHBBH6s4s6s4s", arp_header)
                        arp_opcode = arp_unpacked[4]

                        if arp_opcode == 1:
                            print("ARP Request")
                            src_ip = socket.inet_ntoa(arp_unpacked[6])
                            target_ip = socket.inet_ntoa(arp_unpacked[8])
                            print(f"  Source IP: {src_ip}, Target IP: {target_ip}")
                        elif arp_opcode == 2:
                            print("ARP Reply")
                            src_ip = socket.inet_ntoa(arp_unpacked[6])
                            target_ip = socket.inet_ntoa(arp_unpacked[8])
                            print(f"  Source IP: {src_ip}, Target IP: {target_ip}")

                    # Write pcap packet header and data
                    ts_sec, ts_usec = map(int, str(time.time()).split('.'))
                    packet_length = len(raw_data)
                    pcap_packet_header = struct.pack("!IIII", ts_sec, ts_usec, packet_length, packet_length)
                    pcap_file.write(pcap_packet_header)
                    pcap_file.write(raw_data)

                except KeyboardInterrupt:
                    print("\nCapture interrupted by user.")
                    break
    except PermissionError:
        print("Error: You need root privileges to run this script.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture network traffic.")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to capture on.")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output pcap filename.")
    args = parser.parse_args()

    capture_network_traffic(args.interface, args.output)
