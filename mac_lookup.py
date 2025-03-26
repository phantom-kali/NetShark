#!/usr/bin/env python3
import requests
import json
import time
import logging
import os
from datetime import datetime, timedelta

class MacLookup:
    """Class for looking up MAC address vendor information"""
    
    def __init__(self, cache_file="mac_vendors_cache.json", cache_duration=30):
        """
        Initialize MAC lookup service
        
        Args:
            cache_file: Path to the cache file
            cache_duration: Cache duration in days
        """
        self.cache_file = cache_file
        self.cache_duration = timedelta(days=cache_duration)
        self.cache = {}
        self.logger = logging.getLogger('MacLookup')
        
        # Load cache from file if available
        self._load_cache()
    
    def _load_cache(self):
        """Load vendor cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    
                    # Convert timestamp strings to datetime objects
                    for mac, entry in data.items():
                        if isinstance(entry, dict) and 'timestamp' in entry:
                            entry['timestamp'] = datetime.fromisoformat(entry['timestamp'])
                    
                    self.cache = data
                    self.logger.info(f"Loaded {len(self.cache)} MAC vendor entries from cache")
        except Exception as e:
            self.logger.error(f"Error loading MAC vendor cache: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Save vendor cache to file"""
        try:
            # Convert datetime objects to strings for JSON serialization
            serializable_cache = {}
            for mac, entry in self.cache.items():
                if isinstance(entry, dict) and 'timestamp' in entry:
                    serializable_entry = entry.copy()
                    serializable_entry['timestamp'] = entry['timestamp'].isoformat()
                    serializable_cache[mac] = serializable_entry
                else:
                    serializable_cache[mac] = entry
            
            with open(self.cache_file, 'w') as f:
                json.dump(serializable_cache, f, indent=2)
                
            self.logger.info(f"Saved {len(self.cache)} MAC vendor entries to cache")
        except Exception as e:
            self.logger.error(f"Error saving MAC vendor cache: {e}")
    
    def lookup_vendor(self, mac_address):
        """
        Look up vendor for a MAC address
        
        Args:
            mac_address: MAC address to look up
        
        Returns:
            Vendor name or None if not found
        """
        # Normalize MAC address
        mac = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
        mac_prefix = mac[:6]  # First 6 characters (OUI)
        
        # Check cache first
        if mac_prefix in self.cache:
            cache_entry = self.cache[mac_prefix]
            
            # Check if entry is a dict with timestamp
            if isinstance(cache_entry, dict) and 'timestamp' in cache_entry:
                # Check if cache is still valid
                if datetime.now() - cache_entry['timestamp'] < self.cache_duration:
                    return cache_entry.get('vendor')
            else:
                # Old format cache entry (just string)
                return cache_entry
        
        # Not in cache or cache expired, perform API lookup
        vendor = self._api_lookup(mac_prefix)
        
        # Update cache with new entry
        if vendor:
            self.cache[mac_prefix] = {
                'vendor': vendor,
                'timestamp': datetime.now()
            }
            
            # Save updated cache
            self._save_cache()
            
        return vendor
    
    def _api_lookup(self, mac_prefix):
        """
        Look up vendor using API
        
        We'll use macvendors.co API which is free
        """
        try:
            # Sleep a little to avoid hitting rate limits
            time.sleep(0.5)
            
            url = f"https://macvendors.co/api/{mac_prefix}"
            headers = {"User-Agent": "NetworkScannerTool/1.0"}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if 'result' in data and 'company' in data['result']:
                    return data['result']['company']
            
            return None
        except Exception as e:
            self.logger.error(f"Error looking up MAC vendor: {e}")
            return None

if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)
    lookup = MacLookup()
    
    test_macs = [
        "00:50:56:C0:00:08",  # VMware
        "00:0C:29:9A:E8:5D",  # VMware
        "00:14:22:01:23:45",  # Dell
        "AC:DE:48:00:11:22"   # Apple
    ]
    
    for mac in test_macs:
        print(f"{mac} -> {lookup.lookup_vendor(mac)}")
