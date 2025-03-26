#!/usr/bin/env python3
import sqlite3
import json
import logging
from datetime import datetime

class DatabaseManager:
    """Manages persistent storage of network data"""
    
    def __init__(self, db_path='network_scanner.db'):
        self.db_path = db_path
        self.logger = logging.getLogger('DatabaseManager')
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database with required tables if they don't exist"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create devices table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT,
                hostname TEXT,
                device_type TEXT,
                os TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                details TEXT,
                UNIQUE(ip, mac)
            )
            ''')
            
            # Create scan_history table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP,
                ip_range TEXT,
                devices_count INTEGER
            )
            ''')
            
            # Create port_history table to track changes in open ports
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                scan_time TIMESTAMP,
                port INTEGER,
                state TEXT,
                service TEXT,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info("Database initialized successfully")
            
        except sqlite3.Error as e:
            self.logger.error(f"Error initializing database: {e}")
    
    def save_devices(self, devices):
        """Save or update device information in the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for device in devices:
                ip = device.get('ip')
                mac = device.get('mac', '')
                hostname = device.get('hostname', '')
                device_type = device.get('type', 'unknown')
                os = device.get('os', '')
                current_time = datetime.utcnow().isoformat()
                
                # Convert ports and other details to JSON
                details = json.dumps({k: v for k, v in device.items() 
                                     if k not in ['ip', 'mac', 'hostname', 'type', 'os']})
                
                # Check if device exists
                cursor.execute(
                    "SELECT id, first_seen FROM devices WHERE ip = ? AND (mac = ? OR mac = '')",
                    (ip, mac)
                )
                result = cursor.fetchone()
                
                if result:
                    # Update existing device
                    device_id, first_seen = result
                    cursor.execute('''
                    UPDATE devices SET 
                        mac = ?,
                        hostname = ?,
                        device_type = ?,
                        os = ?,
                        last_seen = ?,
                        details = ?
                    WHERE id = ?
                    ''', (mac, hostname, device_type, os, current_time, details, device_id))
                else:
                    # Insert new device
                    cursor.execute('''
                    INSERT INTO devices 
                        (ip, mac, hostname, device_type, os, first_seen, last_seen, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (ip, mac, hostname, device_type, os, current_time, current_time, details))
                    device_id = cursor.lastrowid
                
                # Save port information if available
                if 'ports' in device:
                    for port_info in device['ports']:
                        cursor.execute('''
                        INSERT INTO port_history
                            (device_id, scan_time, port, state, service)
                        VALUES (?, ?, ?, ?, ?)
                        ''', (device_id, current_time, port_info['port'], 
                             port_info['state'], port_info['service']))
            
            conn.commit()
            conn.close()
            self.logger.info(f"Saved {len(devices)} devices to database")
            
        except sqlite3.Error as e:
            self.logger.error(f"Error saving devices to database: {e}")
    
    def get_all_devices(self):
        """Retrieve all devices from the database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, ip, mac, hostname, device_type, os, first_seen, last_seen, details
            FROM devices
            ''')
            
            devices = []
            for row in cursor.fetchall():
                device = dict(row)
                # Parse JSON details
                device['details'] = json.loads(device['details']) if device['details'] else {}
                devices.append(device)
            
            conn.close()
            return devices
            
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving devices from database: {e}")
            return []
    
    def get_device_history(self, device_id):
        """Get historical data for a specific device"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get port history
            cursor.execute('''
            SELECT scan_time, port, state, service
            FROM port_history
            WHERE device_id = ?
            ORDER BY scan_time DESC
            ''', (device_id,))
            
            history = []
            for row in cursor.fetchall():
                history.append(dict(row))
            
            conn.close()
            return history
            
        except sqlite3.Error as e:
            self.logger.error(f"Error retrieving device history: {e}")
            return []