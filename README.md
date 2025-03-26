# NetShark - Visual Network Scanner

NetShark is a powerful GUI-based network scanning and visualization tool that helps you discover and monitor devices on your network. With its modern dark UI theme and interactive network graph, you can easily identify and analyze devices, services, and potential security issues on your network.

![NetShark Screenshot](https://github.com/phantom-kali/netshark/raw/main/docs/images/netshark-screenshot.png)

## Features

- **Interactive Network Visualization**: See your network topology with color-coded device types
- **Real-time Device Discovery**: Watch as devices are discovered during scanning
- **Multi-threaded Scanning**: Fast parallel scanning of multiple devices
- **MAC Vendor Identification**: Automatically identify device manufacturers
- **Port Visualization**: Visual representation of open ports and services
- **Continuous Monitoring**: Track devices joining and leaving your network
- **Persistent Database**: Store scan results for historical comparison
- **Dark Theme UI**: Easy on the eyes for security professionals

## Requirements

- Python 3.8+
- PyQt5
- matplotlib
- networkx
- scapy
- python-nmap
- requests

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/phantom-kali/netshark.git
   cd netshark
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install required packages:
   ```
   pip install -r requirements.txt
   ```

4. Make sure you have nmap installed on your system:
   - Ubuntu/Debian: `sudo apt install nmap`
   - Fedora/RHEL: `sudo dnf install nmap`
   - Arch Linux: `sudo pacman -S nmap`
   - Windows: Download and install from [nmap.org](https://nmap.org/download.html)

## Usage

NetShark requires root/administrator privileges to perform network scanning operations.

### Running the application:

