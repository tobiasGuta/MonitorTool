import socket
import struct
import time
import argparse

def capture_network_traffic(interface="any", output_file="capture.pcap"):
    """
    Captures network traffic from a specified interface or all interfaces if 'any' is selected.
    Prints packet details and saves them to a pcap file.
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        if interface != "any":
            sock.bind((interface, 0))
            print(f"listening on {interface}, link-type EN10MB (Ethernet), snapshot length 262144 bytes")
        else:
            print("Listening on ALL available interfaces...")

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
                        ihl = version_ihl & 0xF
                        iph_length = ihl * 4

                        protocol = ip_unpacked[6]
                        s_addr = socket.inet_ntoa(ip_unpacked[8])
                        d_addr = socket.inet_ntoa(ip_unpacked[9])

                        if protocol == 17:  # UDP
                            udp_header = raw_data[eth_length + iph_length:eth_length + iph_length + 8]
                            udp_unpacked = struct.unpack("!HHHH", udp_header)
                            source_port = udp_unpacked[0]
                            dest_port = udp_unpacked[1]

                            # Format time
                            current_time = time.time()
                            time_struct = time.localtime(current_time)
                            microseconds = int((current_time - int(current_time)) * 1000000)
                            formatted_time = f"{time_struct.tm_hour:02}:{time_struct.tm_min:02}:{time_struct.tm_sec:02}.{microseconds:06}"

                            print(f"{formatted_time} IP {s_addr}.{source_port} > {d_addr}.{dest_port}: UDP, length {len(raw_data) - eth_length - iph_length - 8}")

                        elif protocol == 6:  # TCP
                            tcp_header = raw_data[eth_length + iph_length:eth_length + iph_length + 20]
                            tcp_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
                            source_port = tcp_unpacked[0]
                            dest_port = tcp_unpacked[1]

                            current_time = time.time()
                            time_struct = time.localtime(current_time)
                            microseconds = int((current_time - int(current_time)) * 1000000)
                            formatted_time = f"{time_struct.tm_hour:02}:{time_struct.tm_min:02}:{time_struct.tm_sec:02}.{microseconds:06}"

                            print(f"{formatted_time} IP {s_addr}.{source_port} > {d_addr}.{dest_port}: TCP, length {len(raw_data) - eth_length - iph_length - 20}")

                        elif protocol == 1:  # ICMP
                            current_time = time.time()
                            time_struct = time.localtime(current_time)
                            microseconds = int((current_time - int(current_time)) * 1000000)
                            formatted_time = f"{time_struct.tm_hour:02}:{time_struct.tm_min:02}:{time_struct.tm_sec:02}.{microseconds:06}"

                            print(f"{formatted_time} IP {s_addr} > {d_addr}: ICMP, length {len(raw_data) - eth_length - iph_length}")

                    elif eth_protocol == 1544:  # ARP
                        current_time = time.time()
                        time_struct = time.localtime(current_time)
                        microseconds = int((current_time - int(current_time)) * 1000000)
                        formatted_time = f"{time_struct.tm_hour:02}:{time_struct.tm_min:02}:{time_struct.tm_sec:02}.{microseconds:06}"

                        print(f"{formatted_time} ARP Packet")

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
    parser.add_argument("-i", "--interface", default="any", help="Network interface to capture on. Use 'any' for all interfaces.")
    parser.add_argument("-o", "--output", default="capture.pcap", help="Output pcap filename.")
    args = parser.parse_args()

    capture_network_traffic(args.interface, args.output)
