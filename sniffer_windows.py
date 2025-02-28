import socket
import os
import argparse
import struct

# Protocol numbers mapping
PROTOCOL_MAP = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

def create_raw_socket(host):
    """Creates a raw socket and binds it to the public interface."""
    try:
        # Use IPPROTO_IP to capture all IP packets
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_sock.bind((host, 0))
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        if os.name == "nt":  # Windows
            raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        return raw_sock
    except Exception as e:
        print(f"[!] Error creating raw socket: {e}")
        return None

def read_packets(raw_sock):
    """Continuously reads packets from the raw socket."""
    try:
        print("[+] Listening for incoming packets. Press Ctrl+C to stop.")
        while True:
            packet, addr = raw_sock.recvfrom(65535)
            src_ip, dest_ip, proto = parse_ip_header(packet[:20])
            protocol_name = PROTOCOL_MAP.get(proto, f"Unknown ({proto})")
            print(f"[+] Packet: {src_ip} -> {dest_ip} (Protocol: {protocol_name})")
    except KeyboardInterrupt:
        print("\n[+] Stopping packet capture.")
    except Exception as e:
        print(f"[!] Error reading packet: {e}")

def parse_ip_header(data):
    """Parses the IP header to extract source and destination IP addresses and protocol."""
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', data)
    src_ip = socket.inet_ntoa(unpacked_data[8])
    dest_ip = socket.inet_ntoa(unpacked_data[9])
    proto = unpacked_data[6]
    return src_ip, dest_ip, proto

def main():
    parser = argparse.ArgumentParser(description="Network Sniffer Tool")
    parser.add_argument("-H", "--host", required=True, help="Host IP to bind the raw socket")
    args = parser.parse_args()
    
    raw_sock = create_raw_socket(args.host)
    if raw_sock:
        read_packets(raw_sock)
        
        if os.name == "nt":  # Turn off promiscuous mode on Windows
            raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        raw_sock.close()
        print("[+] Scan complete.")

if __name__ == "__main__":
    main()
