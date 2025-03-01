# Process Logger Tool

This Python-based tool allows you to monitor and log details of running processes on your system, including network connections and the executable paths of the processes. It helps track real-time system activity and can be useful for debugging, performance monitoring, and security assessments.

# real-time monitoring

```bash
py .\proMon.py
```
![tool](https://github.com/user-attachments/assets/41853a49-0c0e-4f70-9c46-90b6ffd03845)

Note: You can use this with --interval or -t to refresh every second, for example, -t 10

# Filter by IP using -i
```bash
py .\proMon.py -i 0.0.0.0
```
![Screenshot 2024-12-11 180128](https://github.com/user-attachments/assets/e91bea9f-0c09-4018-ab6b-eda9c8549116)

# Filter by process name using -p
```bash
py .\proMon.py -p svchost.exe
```
![Screenshot 2024-12-11 180238](https://github.com/user-attachments/assets/4644d996-edd6-437f-93fd-5c425656cb5a)

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

- **Filtering**: You can filter the output based on specific criteria, for now **process name** and **IP address** are supported.

## ProcChangeLogger.py
Monitoring for Process Command Lines
continuously monitoring process changes on a Windows machine, checking for new processes that start and old ones that stop. Monitoring for Process Command Lines
It collects process command lines every two seconds, compares them with the previous snapshot, and displays any changes detected.

![Screenshot 2025-02-16 105955](https://github.com/user-attachments/assets/fa58c7dd-8a7c-4abf-92a6-e1fba3be28e1)

## Use Cases

- **System Monitoring**: Monitor the processes and network activity running on your machine.
- **Security Auditing**: Identify any suspicious or unexpected processes, network connections, or services.
- **Debugging**: Track down processes that may be consuming excessive resources or misbehaving.
- **Penetration Testing**: Use the tool to gather insights into processes running on a target machine during a red team exercise.

## sniffer_windows.py

This Python-based network sniffer tool is used to capture and analyze raw IP packets from the network. It creates a raw socket that listens for incoming network traffic and displays information about the source and destination IP addresses, as well as the protocol being used (ICMP, TCP, UDP, etc.).

```bash
python sniffer.py -H 192.168.1.1
```

![image](https://github.com/user-attachments/assets/9173bd7c-5e25-417b-aa83-613839323ab9)

## sniffer_linux.py

```bash
sudo python3 sniffer.py -i ens33 -o checking.pcap
```

![image](https://github.com/user-attachments/assets/b2625c4b-c3aa-4d8e-8033-d48126e13b6a)

## fping.py

```bash
sudo python3 fping.py 192.168.232.0/24 -a
```

![image](https://github.com/user-attachments/assets/e8eff5e4-3690-48c3-bb39-c97ecbe1eceb)


## Installation

```bash
git clone https://github.com/tobiasGuta/SysMonitorTool.git
```




## How It Works
- Process Iteration: The script iterates through all running processes on your system using the psutil.process_iter() function.
- Network Connections: For each process, it fetches network connections associated with the process using proc.net_connections(kind='inet').
- Executable Path: The script checks the path to the executable for each process using proc.exe().
- Logging: All relevant information (PID, name, status, username, network connections, and executable path) is printed to the console and saved to a log file (process_log.txt).
