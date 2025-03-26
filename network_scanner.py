#!/usr/bin/env python3
import sys
import ipaddress
import threading
import time
import socket
import logging
from datetime import datetime
from scapy.all import ARP, Ether, srp
import nmap

class NetworkScanner:
    """Core scanning engine for discovering network devices"""
    
    def __init__(self, db_manager=None, mac_lookup=None):
        self.devices = {}  # IP -> device_info
        self.scan_thread = None
        self.stop_scan = False
        self.db_manager = db_manager
        self.mac_lookup = mac_lookup
        self.logger = logging.getLogger('NetworkScanner')
        self.use_vendor_lookup = True
        
    def discover_network(self, ip_range="192.168.1.0/24"):
        """Perform ARP scan to discover devices on network"""
        self.logger.info(f"Starting network discovery on {ip_range}")
        
        # Create ARP request packet
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast
        packet = ether/arp
        
        try:
            # Send packet and capture responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Process responses
            devices = []
            for sent, received in result:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'time_discovered': datetime.utcnow(),
                    'last_seen': datetime.utcnow()
                }
                devices.append(device)
                
            return devices
        except Exception as e:
            self.logger.error(f"Error during network discovery: {e}")
            return []
    
    def scan_device(self, ip_address):
        """Detailed scan of a specific device"""
        device_info = {'ip': ip_address}
        
        # Initialize nmap scanner
        nm = nmap.PortScanner()
        
        try:
            # Basic scan with OS detection and service version detection
            nm.scan(ip_address, arguments='-O -sV')
            
            # Extract basic information
            if ip_address in nm.all_hosts():
                host = nm[ip_address]
                device_info['state'] = host.state()
                
                # Get hostname if available
                try:
                    device_info['hostname'] = socket.gethostbyaddr(ip_address)[0]
                except socket.herror:
                    device_info['hostname'] = 'Unknown'
                
                # Get MAC address if available
                if 'mac' in host['addresses']:
                    mac = host['addresses']['mac']
                    device_info['mac'] = mac
                    
                    # Lookup vendor information if enabled
                    if self.use_vendor_lookup and self.mac_lookup and mac:
                        vendor = self.mac_lookup.lookup_vendor(mac)
                        if vendor:
                            device_info['vendor'] = vendor
                
                # Get OS information
                if 'osmatch' in host and len(host['osmatch']) > 0:
                    device_info['os'] = host['osmatch'][0]['name']
                else:
                    device_info['os'] = 'Unknown'
                
                # Get open ports and services
                device_info['ports'] = []
                if 'tcp' in host:
                    for port, port_info in host['tcp'].items():
                        device_info['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        })
                
                # Determine device type based on open ports, OS and vendor
                device_info['type'] = self._determine_device_type(device_info)
                
                return device_info
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Error scanning device {ip_address}: {e}")
            return device_info
    
    def _determine_device_type(self, device_info):
        """Determine device type based on open ports, OS information and vendor"""
        # Simple heuristics for device type identification
        os = device_info.get('os', '').lower()
        ports = device_info.get('ports', [])
        port_numbers = [p['port'] for p in ports]
        vendor = device_info.get('vendor', '').lower()
        
        # Check vendor information first
        if vendor:
            if any(router_vendor in vendor for router_vendor in ['cisco', 'netgear', 'tp-link', 'asus', 'linksys', 'd-link']):
                return 'router'
            elif any(mobile_vendor in vendor for mobile_vendor in ['apple', 'samsung', 'huawei', 'xiaomi', 'oppo']):
                # Check if it's likely a mobile device vs a laptop
                if 'mac' in os.lower() or 'darwin' in os.lower():
                    return 'mac'
                return 'mobile'
            elif any(iot_vendor in vendor for iot_vendor in ['nest', 'ring', 'ecobee', 'amazon']):
                return 'web-device'
        
        # Check based on OS and ports
        if 'router' in os or 'linux' in os and (80 in port_numbers or 443 in port_numbers):
            return 'router'
        elif 'windows' in os:
            return 'windows-pc'
        elif 'linux' in os:
            return 'linux-server' if 22 in port_numbers else 'linux-pc'
        elif 'mac' in os or 'darwin' in os:
            return 'mac'
        elif 'android' in os:
            return 'mobile'
        elif 8080 in port_numbers or 80 in port_numbers:
            return 'web-device'
        else:
            return 'unknown'
    
    def start_continuous_scan(self, ip_range="192.168.1.0/24", interval=60):
        """Start a background thread that continuously scans the network"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.logger.warning("Scan already in progress")
            return False
        
        self.stop_scan = False
        self.scan_thread = threading.Thread(target=self._continuous_scan_worker, 
                                           args=(ip_range, interval))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        return True
        
    def _continuous_scan_worker(self, ip_range, interval):
        """Worker thread function for continuous scanning"""
        while not self.stop_scan:
            try:
                # Discover devices
                devices = self.discover_network(ip_range)
                
                # Update our device list
                new_devices = []
                for device in devices:
                    ip = device['ip']
                    if ip not in self.devices:
                        # New device found, perform detailed scan
                        detailed_info = self.scan_device(ip)
                        if detailed_info:
                            self.devices[ip] = detailed_info
                            new_devices.append(detailed_info)
                    else:
                        # Update last_seen timestamp for existing device
                        self.devices[ip]['last_seen'] = datetime.utcnow()
                
                # Save to database if available
                if self.db_manager and new_devices:
                    self.db_manager.save_devices(new_devices)
                
                # Sleep for the specified interval
                time.sleep(interval)
                
            except Exception as e:
                self.logger.error(f"Error in continuous scan: {e}")
                time.sleep(interval)
    
    def stop_continuous_scan(self):
        """Stop the continuous scan thread"""
        self.stop_scan = True
        if self.scan_thread:
            self.scan_thread.join(timeout=1.0)
            self.scan_thread = None

if __name__ == "__main__":
    # Simple command line test
    logging.basicConfig(level=logging.INFO)
    scanner = NetworkScanner()
    
    if len(sys.argv) > 1:
        ip_range = sys.argv[1]
    else:
        ip_range = "192.168.1.0/24"
        
    print(f"Scanning network: {ip_range}")
    devices = scanner.discover_network(ip_range)
    
    print(f"Found {len(devices)} devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
        detailed = scanner.scan_device(device['ip'])
        if detailed and 'hostname' in detailed:
            print(f"Hostname: {detailed['hostname']}")
        if detailed and 'os' in detailed:
            print(f"OS: {detailed['os']}")
        if detailed and 'ports' in detailed:
            print(f"Open ports: {len(detailed['ports'])}")
            for port in detailed['ports'][:5]:  # Show only first 5 ports
                print(f"  {port['port']}/{port['service']}")
        print("-" * 40)