import os
import sys
import time
import socket
import struct
import threading
import ipaddress

# ICMP packet structure
def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF
        count += 2

    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xFFFFFFFF

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer

def create_icmp_packet():
    header = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    data = b'PINGTEST'
    chksum = checksum(header + data)
    header = struct.pack("!BBHHH", 8, 0, chksum, 1, 1)
    return header + data

def ping_host(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1)
        packet = create_icmp_packet()
        start_time = time.time()
        sock.sendto(packet, (host, 1))

        while True:
            data, addr = sock.recvfrom(1024)
            if addr[0] == host:  # Ensure response is from target
                icmp_header = data[20:28]
                icmp_type, code, checksum, packet_id, sequence = struct.unpack("!BBHHH", icmp_header)
                if icmp_type == 0:  # Echo Reply
                    rtt = (time.time() - start_time) * 1000
                    print(f"{host} is alive | RTT: {rtt:.2f} ms")
                    return
    except socket.timeout:
        print(f"{host} is unreachable")
    except PermissionError:
        print("[!] Run the script as root/admin to send ICMP packets.")
        return
    except Exception as e:
        print(f"[!] Error pinging {host}: {e}")
    finally:
        if 'sock' in locals():
            sock.close()

def scan_subnet(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        threads = []
        for ip in network.hosts():  # Skip network and broadcast addresses
            thread = threading.Thread(target=ping_host, args=(str(ip),))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

    except ValueError as e:
        print(f"[!] Invalid subnet: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 fping.py <IP address> OR <Subnet (e.g., ip/23)>")
        sys.exit(1)

    target = sys.argv[1]

    if "/" in target:  # Check if it's a subnet
        print(f"Scanning subnet {target} ...")
        scan_subnet(target)
    else:
        ping_host(target)
