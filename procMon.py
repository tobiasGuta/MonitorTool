import psutil

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
            
            # Get the executable path of the process
            path = proc.exe() if proc.exe() else "N/A"
            
            # Get network connections associated with the process
            connections = proc.net_connections(kind='inet')

            # For each connection, display the relevant information
            for conn in connections:
                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                connection_status = conn.status or "N/A"
                
                # Print to console
                output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {local_address:<25} {remote_address:<25} {connection_status:<20} {path:<50}"
                print(output)
                
                # Write to log file
                log_file.write(output + "\n")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

print(f"Log saved to {log_file_path}")
