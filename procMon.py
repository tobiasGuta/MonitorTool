import psutil
import argparse
import curses
import os
import logging
import time
from functools import wraps
from pathlib import Path

# Set up logging
log_dir = Path.home() / '.procmon'
log_dir.mkdir(exist_ok=True)
logging.basicConfig(
    filename=log_dir / 'procmon.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Rate limiting decorator
def rate_limit(limit_seconds):
    last_called = {}
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            if func.__name__ in last_called:
                if current_time - last_called[func.__name__] < limit_seconds:
                    logging.warning(f"Rate limit exceeded for {func.__name__}")
                    return None
            last_called[func.__name__] = current_time
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Security checks
def check_privileges():
    try:
        admin_access = os.geteuid() == 0
        logging.info(f"Privilege check: Admin access = {admin_access}")
        return admin_access
    except AttributeError:
        # Windows systems
        import ctypes
        admin_access = ctypes.windll.shell32.IsUserAnAdmin() != 0
        logging.info(f"Privilege check: Admin access = {admin_access}")
        return admin_access

def is_root_process(proc):
    try:
        return proc.username() == 'root'
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

# Secure process termination
@rate_limit(3)  # Limit to one kill operation every 3 seconds
def secure_kill_process(pid):
    try:
        proc = psutil.Process(pid)
        
        # Check if trying to kill root process
        if is_root_process(proc) and not check_privileges():
            logging.warning(f"Unauthorized attempt to kill root process {pid}")
            return False, "Cannot kill root process without root privileges"
            
        # Check if we have permission to kill this process
        if proc.username() == psutil.Process().username() or check_privileges():
            proc.kill()
            logging.info(f"Process {pid} terminated successfully")
            return True, "Process terminated successfully"
        else:
            logging.warning(f"Unauthorized attempt to kill process {pid}")
            return False, "Permission denied"
    except psutil.NoSuchProcess:
        logging.error(f"No such process: {pid}")
        return False, "Process not found"
    except psutil.AccessDenied:
        logging.error(f"Access denied to process: {pid}")
        return False, "Access denied"

# Set up argument parsing
parser = argparse.ArgumentParser(description='Monitor processes with optional filtering')
parser.add_argument('--process', '-p', help='Filter by process name (case-insensitive)')
parser.add_argument('--ip', '-i', help='Filter by IP address (local or remote)')
parser.add_argument('--stats', '-s', action='store_true', help='Show process memory and CPU usage')
args = parser.parse_args()

sort_field = 'pid'
scroll_offset = 0

def main(stdscr):
    global sort_field, scroll_offset
    
    # Check privileges at startup
    is_admin = check_privileges()
    logging.info(f"Process monitor started (admin access: {is_admin})")
    
    curses.curs_set(0)  # Hide the cursor
    stdscr.nodelay(0)  # Make getch() blocking
    curses.halfdelay(1)  # Set half-delay mode to wait for 100ms for a key press

    # Initialize color pairs
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)

    while True:
        try:
            stdscr.erase()  # Clear the screen more efficiently
            height, width = stdscr.getmaxyx()  # Get the size of the terminal window

            # List all running processes
            if args.stats:
                header = f"{'PID':<10} {'Name':<25} {'Status':<15} {'Username':<20} {'Memory %':<10} {'CPU %':<10} {'Path':<50}"
            else:
                header = f"{'PID':<10} {'Name':<25} {'Status':<15} {'Username':<20} {'Path':<50}"
            if len(header) > width:
                header = header[:width-1]
            stdscr.addstr(0, 0, header)  # Print header to screen
            stdscr.addstr(1, 0, "-" * (width-1))  # Print separator to screen

            row = 2
            processes = sorted(psutil.process_iter(['pid', 'name', 'status', 'username', 'memory_percent', 'cpu_percent']), key=lambda p: p.info.get(sort_field, ''))
            filtered_processes = []
            for proc in processes:
                try:
                    pid = proc.info['pid']
                    name = proc.info['name'] or "N/A"
                    status = proc.info['status'] or "N/A"
                    username = proc.info['username'] or "N/A"
                    memory_percent = f"{proc.info['memory_percent']:.2f}" if args.stats else "N/A"
                    cpu_percent = f"{proc.info['cpu_percent']:.2f}" if args.stats else "N/A"
                    
                    # Apply process name filter if specified
                    if args.process and args.process.lower() not in name.lower():
                        continue
                    
                    # Get the executable path of the process
                    path = proc.exe() if proc.exe() else "N/A"
                    
                    # Add to filtered processes list
                    filtered_processes.append((pid, name, status, username, memory_percent, cpu_percent, path))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            # Apply scroll offset and limit to screen height
            visible_processes = filtered_processes[scroll_offset:scroll_offset + height - 3]
            for proc in visible_processes:
                pid, name, status, username, memory_percent, cpu_percent, path = proc
                if args.stats:
                    output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {memory_percent:<10} {cpu_percent:<10} {path:<50}"
                else:
                    output = f"{pid:<10} {name:<25} {status:<15} {username:<20} {path:<50}"
                if len(output) > width:
                    output = output[:width-1]
                
                # Highlight root processes in red
                if username == 'root':
                    stdscr.attron(curses.color_pair(2))
                    stdscr.addstr(row, 0, output)
                    stdscr.attroff(curses.color_pair(2))
                else:
                    stdscr.addstr(row, 0, output)
                row += 1

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
                sort_options = "Sort by: 1: PID | 2: Name | 3: Status | 4: Username | 5: Memory % | 6: CPU % | 7: Path"
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
                    sort_field = 'memory_percent'
                elif sort_key == ord('6'):
                    sort_field = 'cpu_percent'
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
                    success, message = secure_kill_process(int(pid))
                    stdscr.addstr(height - 1, 0, f"{message}. Press any key to continue.")
                else:
                    logging.warning("Invalid PID input attempted")
                    stdscr.addstr(height - 1, 0, "Invalid PID. Press any key to continue.")
                
                stdscr.clrtoeol()  # Clear to the end of the line
                stdscr.refresh()
                stdscr.getch()
                curses.noecho()
                stdscr.nodelay(1)  # Make getch() non-blocking again
            elif key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(scroll_offset + 1, len(filtered_processes) - (height - 3))

        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            continue

try:
    curses.wrapper(main)
except Exception as e:
    logging.critical(f"Application crashed: {str(e)}")
    raise