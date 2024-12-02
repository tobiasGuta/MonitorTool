# Process Logger Tool

This Python-based tool allows you to monitor and log details of running processes on your system, including network connections and the executable paths of the processes. It helps track real-time system activity and can be useful for debugging, performance monitoring, and security assessments.

## Features

- **Process Details**: The tool lists all currently running processes on your system, including:
  - PID (Process ID)
  - Name of the process
  - Status (Running, Sleeping, etc.)
  - Username of the process owner
  - Path to the executable

- **Network Connections**: The tool fetches and displays network connections related to each process:
  - Local IP address and port
  - Remote IP address and port
  - Connection status (e.g., `ESTABLISHED`, `LISTEN`, `CLOSE_WAIT`)

- **Log File**: The tool writes all process and network connection details to a log file (`process_log.txt`), enabling future reference and analysis.

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
