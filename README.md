# Process Logger Tool

This Python-based tool allows you to monitor and log details of running processes on your system, including network connections and the executable paths of the processes. It helps track real-time system activity and can be useful for debugging, performance monitoring, and security assessments.

## Usage

To run the tool, use the following command:

```bash
py .\proMon.py
```
![tool](https://github.com/user-attachments/assets/41853a49-0c0e-4f70-9c46-90b6ffd03845)

You can also filter by IP address:

```bash
py .\proMon.py -i 0.0.0.0
```
![Screenshot 2024-12-11 180128](https://github.com/user-attachments/assets/e91bea9f-0c09-4018-ab6b-eda9c8549116)

Or filter by process name:

```bash
py .\proMon.py -p svchost.exe
```
![Screenshot 2024-12-11 180238](https://github.com/user-attachments/assets/4644d996-edd6-437f-93fd-5c425656cb5a)

## Features

- **Real-Time Monitoring**: Continuously updates the list of running processes and their details.
- **Process Details**: Lists all currently running processes, including:
  - PID (Process ID)
  - Name of the process
  - Status (Running, Sleeping, etc.)
  - Username of the process owner
  - Path to the executable
- **Network Connections**: Displays network connections related to each process:
  - Local IP address and port
  - Remote IP address and port
  - Connection status (e.g., `ESTABLISHED`, `LISTEN`, `CLOSE_WAIT`)
- **Interactive Interface**: Provides an interactive interface with options to:
  - Sort processes by various fields (PID, Name, Status, etc.)
  - Kill a process by PID
  - Scroll through the list of processes
- **Log File**: Writes all process and network connection details to a log file (`process_log.txt`), enabling future reference and analysis.
- **Filtering**: Allows filtering the output based on specific criteria, such as process name and IP address.

## Security Features

### Process Protection
- Root processes are highlighted in red
- Root processes can only be terminated when running the tool with root/admin privileges
- Regular users can only terminate processes they own
- Built-in protection against unauthorized process termination

### Rate Limiting
- Process termination is rate-limited to prevent abuse
- Maximum of one kill operation every 3 seconds

### Logging
- All actions are logged to `~/.procmon/procmon.log`
- Logs include:
  - Process termination attempts
  - Unauthorized access attempts
  - Application starts/stops
  - Error conditions
  - Privilege level changes

### Privilege Levels
- Regular user mode:
  - Can view all processes
  - Can only terminate owned processes
  - Cannot terminate root/system processes
- Root/Admin mode:
  - Full process termination rights
  - Can terminate any process
  - Required for system/root process management

### Security Best Practices
- Run with regular user privileges for routine monitoring
- Only use root/admin privileges when necessary
- Monitor the log file for unauthorized access attempts
- Review process ownership before termination

## Use Cases

- **System Monitoring**: Monitor the processes and network activity running on your machine.
- **Security Auditing**: Identify any suspicious or unexpected processes, network connections, or services.
- **Debugging**: Track down processes that may be consuming excessive resources or misbehaving.
- **Penetration Testing**: Use the tool to gather insights into processes running on a target machine during a red team exercise.

## Requirements

- Python 3.x
- `psutil` Python library

To install `psutil`, run:

```bash
pip install psutil
```

## Installation

Clone the repository:

```bash
git clone https://github.com/tobiasGuta/SysMonitorTool.git
```

## How It Works

- **Process Iteration**: The script iterates through all running processes on your system using the `psutil.process_iter()` function.
- **Network Connections**: For each process, it fetches network connections associated with the process using `proc.net_connections(kind='inet')`.
- **Executable Path**: The script checks the path to the executable for each process using `proc.exe()`.
- **Logging**: All relevant information (PID, name, status, username, network connections, and executable path) is printed to the console and saved to a log file (`process_log.txt`).

## Interactive Interface

The tool provides an interactive interface with the following options:

- **F1**: Display sorting options (PID, Name, Status, Username, Local Address, Remote Address, Path)
- **F2**: Kill a process by PID
- **Up/Down Arrows**: Scroll through the list of processes
- **q**: Quit the tool

The bottom menu is highlighted in light green for better visibility.

## Screenshots

![tool](https://github.com/user-attachments/assets/41853a49-0c0e-4f70-9c46-90b6ffd03845)
![Screenshot 2024-12-11 180128](https://github.com/user-attachments/assets/e91bea9f-0c09-4018-ab6b-eda9c8549116)
![Screenshot 2024-12-11 180238](https://github.com/user-attachments/assets/4644d996-edd6-437f-93fd-5c425656cb5a)
