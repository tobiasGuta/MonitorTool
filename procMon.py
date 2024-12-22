import psutil
import argparse
import curses

# Set up argument parsing
parser = argparse.ArgumentParser(description='Monitor processes with optional filtering')
parser.add_argument('--process', '-p', help='Filter by process name (case-insensitive)')
parser.add_argument('--ip', '-i', help='Filter by IP address (local or remote)')
args = parser.parse_args()

def main(stdscr):
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(1)  # Make getch() non-blocking
    stdscr.timeout(500)  # Refresh every 500 milliseconds

    while True:
        stdscr.clear()  # Clear the screen
        height, width = stdscr.getmaxyx()  # Get the size of the terminal window

        # List all running processes
        header = f"{'PID':<10} {'Name':<25} {'Status':<15} {'Username':<20} {'Local Address':<25} {'Remote Address':<25} {'Connection Status':<20} {'Path':<50}"
        if len(header) > width:
            header = header[:width-1]
        stdscr.addstr(0, 0, header)  # Print header to screen
        stdscr.addstr(1, 0, "-" * (width-1))  # Print separator to screen

        row = 2
        for proc in psutil.process_iter(['pid', 'name', 'status', 'username']):
            if row >= height:
                break  # Stop if we exceed the terminal height
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
                for conn in connections:
                    if row >= height:
                        break  # Stop if we exceed the terminal height
                    local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                    remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    connection_status = conn.status or "N/A"
                    
                    # Apply IP filter if specified
                    if args.ip:
                        local_ip = conn.laddr.ip if conn.laddr else ""
                        remote_ip = conn.raddr.ip if conn.raddr else ""
                        if args.ip not in (local_ip, remote_ip):
                            continue
                    
                    # Print to screen
                    output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {local_address:<25} {remote_address:<25} {connection_status:<20} {path:<50}"
                    if len(output) > width:
                        output = output[:width-1]
                    stdscr.addstr(row, 0, output)
                    row += 1

                # If no IP filter or no connections, show process info
                if not args.ip or (not connections and not args.ip):
                    if row >= height:
                        break  # Stop if we exceed the terminal height
                    output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {'N/A':<25} {'N/A':<25} {'N/A':<20} {path:<50}"
                    if len(output) > width:
                        output = output[:width-1]
                    stdscr.addstr(row, 0, output)
                    row += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        stdscr.refresh()  # Refresh the screen

        if stdscr.getch() == ord('q'):  # Exit on 'q' key press
            break

curses.wrapper(main)
