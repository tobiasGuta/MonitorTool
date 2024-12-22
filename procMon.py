import psutil
import argparse
import curses

# Set up argument parsing
parser = argparse.ArgumentParser(description='Monitor processes with optional filtering')
parser.add_argument('--process', '-p', help='Filter by process name (case-insensitive)')
parser.add_argument('--ip', '-i', help='Filter by IP address (local or remote)')
args = parser.parse_args()

sort_field = 'pid'
scroll_offset = 0

def main(stdscr):
    global sort_field, scroll_offset
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(1)  # Make getch() non-blocking
    stdscr.timeout(100)  # Refresh every 100 milliseconds

    # Initialize color pairs
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)

    while True:
        stdscr.erase()  # Clear the screen more efficiently
        height, width = stdscr.getmaxyx()  # Get the size of the terminal window

        # List all running processes
        header = f"{'PID':<10} {'Name':<25} {'Status':<15} {'Username':<20} {'Local Address':<25} {'Remote Address':<25} {'Connection Status':<20} {'Path':<50}"
        if len(header) > width:
            header = header[:width-1]
        stdscr.addstr(0, 0, header)  # Print header to screen
        stdscr.addstr(1, 0, "-" * (width-1))  # Print separator to screen

        row = 2
        processes = sorted(psutil.process_iter(['pid', 'name', 'status', 'username']), key=lambda p: p.info.get(sort_field, ''))
        processes = processes[scroll_offset:]  # Apply scroll offset
        for proc in processes:
            if row >= height - 3:
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
                    if row >= height - 3:
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
                    if row >= height - 3:
                        break  # Stop if we exceed the terminal height
                    output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {'N/A':<25} {'N/A':<25} {'N/A':<20} {path:<50}"
                    if len(output) > width:
                        output = output[:width-1]
                    stdscr.addstr(row, 0, output)
                    row += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Display the bottom bar with options
        bottom_bar = "F1: Sort Options | F2: Kill by PID | Up/Down: Scroll | q: Quit"
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(height - 2, 0, bottom_bar[:width-1])
        stdscr.attroff(curses.color_pair(1))

        stdscr.refresh()  # Refresh the screen

        key = stdscr.getch()
        if key == ord('q'):  # Exit on 'q' key press
            break
        elif key == curses.KEY_F1:
            stdscr.nodelay(0)  # Make getch() blocking
            sort_options = "Sort by: 1: PID | 2: Name | 3: Status | 4: Username | 5: Local Address | 6: Remote Address | 7: Path"
            stdscr.addstr(height - 1, 0, sort_options[:width-1])
            stdscr.refresh()
            sort_key = stdscr.getch()
            if sort_key == ord('1'):
                sort_field = 'pid'
            elif sort_key == ord('2'):
                sort_field = 'name'
            elif sort_key == ord('3'):
                sort_field = 'status'
            elif sort_key == ord('4'):
                sort_field = 'username'
            elif sort_key == ord('5'):
                sort_field = 'local_address'
            elif sort_key == ord('6'):
                sort_field = 'remote_address'
            elif sort_key == ord('7'):
                sort_field = 'path'
            stdscr.nodelay(1)  # Make getch() non-blocking again
        elif key == curses.KEY_F2:
            curses.echo()
            stdscr.nodelay(0)  # Make getch() blocking
            stdscr.addstr(height - 1, 0, "Enter PID to kill: ")
            stdscr.clrtoeol()  # Clear to the end of the line
            stdscr.refresh()
            pid = stdscr.getstr().decode('utf-8')
            if pid.isdigit():
                try:
                    psutil.Process(int(pid)).kill()
                    stdscr.addstr(height - 1, 0, f"Process {pid} killed successfully. Press any key to continue.")
                except Exception as e:
                    stdscr.addstr(height - 1, 0, f"Failed to kill process {pid}: {e}. Press any key to continue.")
            else:
                stdscr.addstr(height - 1, 0, "Invalid PID. Press any key to continue.")
            stdscr.clrtoeol()  # Clear to the end of the line
            stdscr.refresh()
            stdscr.getch()
            curses.noecho()
            stdscr.nodelay(1)  # Make getch() non-blocking again
        elif key == curses.KEY_UP:
            scroll_offset = max(0, scroll_offset - 1)
        elif key == curses.KEY_DOWN:
            scroll_offset += 1

curses.wrapper(main)
