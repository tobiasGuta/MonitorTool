import psutil
import argparse

# Set up argument parsing
parser = argparse.ArgumentParser(description='Monitor processes with optional filtering')
parser.add_argument('--process', '-p', help='Filter by process name (case-insensitive)')
parser.add_argument('--ip', '-i', help='Filter by IP address (local or remote)')
args = parser.parse_args()

# Open a log file in write mode
log_file_path = "process_log.txt"
with open(log_file_path, "w") as log_file:
    # List all running processes
    header = f"{'PID':<10} {'Name':<25} {'Status':<15} {'Username':<20} {'Local Address':<25} {'Remote Address':<25} {'Connection Status':<20} {'Path':<50}"
    print(header)  # Print header to console
    log_file.write(header + "\n")  # Write header to log file
    print("-" * 150)  # Print separator to console
    log_file.write("-" * 150 + "\n")  # Write separator to log file

    for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or "N/A"
            status = proc.info['status'] or "N/A"
            username = proc.info['username'] or "N/A"
            
            # Apply process name filter if specified
            if args.process and args.process.lower() not in name.lower():
                continue
            
            # Get the executable path of the process
            path = proc.exe() if proc.exe() else "N/A"
            
            # Get network connections associated with the process
            connections = proc.net_connections(kind='inet')

            # Skip if IP filter is specified and process has no connections
            if args.ip and not connections:
                continue

            # For each connection, display the relevant information
            connection_found = False
            for conn in connections:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connection_status = conn.status or "N/A"
                
                # Apply IP filter if specified
                if args.ip:
                    local_ip = conn.laddr.ip if conn.laddr else ""
                    remote_ip = conn.raddr.ip if conn.raddr else ""
                    if args.ip not in (local_ip, remote_ip):
                        continue
                    connection_found = True
                
                # Print to console
                output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {local_address:<25} {remote_address:<25} {connection_status:<20} {path:<50}"
                print(output)
                
                # Write to log file
                log_file.write(output + "\n")

            # If no IP filter or no connections, show process info
            if not args.ip or (not connections and not args.ip):
                output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {'N/A':<25} {'N/A':<25} {'N/A':<20} {path:<50}"
                print(output)
                log_file.write(output + "\n")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

print(f"Log saved to {log_file_path}")
