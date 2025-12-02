"""
Relay Directory (RD) Management
Loads hardcoded relay topology from network_topology.json
"""

import json
import time
import threading
from typing import Dict, List, Optional


class RelayDirectory:
    """
    Relay Directory - stores information about available relay nodes
    Loads from network_topology.json for simulation
    """
    
    def __init__(self, topology_file: str = None):
        """
        Initialize Relay Directory
        
        Args:
            topology_file: Path to network_topology.json (optional)
        """
        self.relays: Dict[str, Dict] = {}  # address -> relay_info
        self.lock = threading.Lock()
        
        # Load from topology file if provided
        if topology_file:
            self.load_from_topology(topology_file)
    
    def load_from_topology(self, topology_file: str):
        """
        Load relay addresses from network_topology.json
        
        Args:
            topology_file: Path to network_topology.json
        """
        try:
            with open(topology_file, 'r') as f:
                topology = json.load(f)
            
            with self.lock:
                for node in topology.get('nodes', []):
                    address = node['network_address']
                    
                    # Initialize with default values
                    # Public key will be updated when nodes gossip
                    self.relays[address] = {
                        'address': address,
                        'public_key': None,  # Will be filled via gossip
                        'current_load': 0.0,
                        'uptime_score': 0.0,
                        'relay_reputation': 0.0,
                        'last_update': time.time()
                    }
            
            print(f"[RD] Loaded {len(self.relays)} relay addresses from topology file")
        
        except Exception as e:
            print(f"[RD] Error loading topology: {e}")
    
    def add_relay(self, address: str, public_key: str,
                  current_load: float = 0.0, uptime_score: float = 0.0):
        """
        Add or update relay in directory
        
        Args:
            address: "ip:port" format
            public_key: Base64-encoded public key
            current_load: 0.0 (idle) to 1.0 (maxed)
            uptime_score: 0.0 to 1.0
        """
        with self.lock:
            relay_reputation = (uptime_score * 0.5) + ((1.0 - current_load) * 0.5)
            
            self.relays[address] = {
                'address': address,
                'public_key': public_key,
                'current_load': current_load,
                'uptime_score': uptime_score,
                'relay_reputation': relay_reputation,
                'last_update': time.time()
            }
    
    def update_relay_from_gossip(self, address: str, public_key: str, 
                                  current_load: float, uptime_score: float):
        """
        Update relay info from gossip message
        
        Args:
            address: Relay address
            public_key: Relay's public key
            current_load: Current load
            uptime_score: Uptime score
        """
        with self.lock:
            if address in self.relays:
                # Update existing relay
                relay_reputation = (uptime_score * 0.5) + ((1.0 - current_load) * 0.5)
                self.relays[address].update({
                    'public_key': public_key,
                    'current_load': current_load,
                    'uptime_score': uptime_score,
                    'relay_reputation': relay_reputation,
                    'last_update': time.time()
                })
            else:
                # Add new relay (in case topology file doesn't have it)
                self.add_relay(address, public_key, current_load, uptime_score)
    
    def cleanup_stale_relays(self, timeout: int = 600):
        """
        Remove relays that haven't updated in timeout seconds
        
        Args:
            timeout: Seconds before considering relay stale (default 10 minutes)
        """
        current_time = time.time()
        with self.lock:
            stale_relays = [addr for addr, rinfo in self.relays.items()
                          if current_time - rinfo['last_update'] > timeout]
            for addr in stale_relays:
                del self.relays[addr]
            
            if stale_relays:
                print(f"[RD] Removed {len(stale_relays)} stale relays")
                
    def get_relay_by_address(self, address: str) -> Optional[Dict]:
        """Get relay information by address"""
        with self.lock:
            return self.relays.get(address)
    
    def get_all_relays(self) -> List[Dict]:
        """Get list of all relays"""
        with self.lock:
            return list(self.relays.values())
    
    def get_high_reputation_relays(self, min_reputation: float = 0.6) -> List[Dict]:
        """Get relays with reputation above threshold"""
        with self.lock:
            return [r for r in self.relays.values() 
                   if r['relay_reputation'] >= min_reputation]
    
    def get_guards(self, count: int = 3, min_reputation: float = 0.7) -> List[Dict]:
        """Get suitable guard relays"""
        candidates = self.get_high_reputation_relays(min_reputation)
        # Sort by reputation (descending) and take top N
        candidates.sort(key=lambda x: x['relay_reputation'], reverse=True)
        return candidates[:count]
    
    def get_random_peers(self, count: int, exclude_addresses: List[str] = None) -> List[Dict]:
        """
        Get random relays for gossip forwarding
        
        Args:
            count: Number of peers to return
            exclude_addresses: List of addresses to exclude
        
        Returns:
            List of relay info dicts
        """
        import random
        
        exclude_addresses = exclude_addresses or []
        with self.lock:
            candidates = [r for r in self.relays.values() 
                         if r['address'] not in exclude_addresses]
            return random.sample(candidates, min(count, len(candidates)))
    
    def print_directory(self):
        """Print directory contents (for debugging)"""
        with self.lock:
            print(f"\n[RD] Relay Directory ({len(self.relays)} relays):")
            for idx, (addr, info) in enumerate(self.relays.items(), 1):
                pk_short = info['public_key'][:8] if info['public_key'] else "None"
                print(f"  Relay {idx}: {addr} "
                      f"PK={pk_short}... "
                      f"rep={info['relay_reputation']:.2f} "
                      f"load={info['current_load']:.2f}")


# Self-test
if __name__ == "__main__":
    print("Testing RelayDirectory...")
    
    # Test 1: Load from topology file
    rd = RelayDirectory(topology_file="/home/ai-mas/ai-mas-node/config/network_topology.json")
    rd.print_directory()
    
    # Test 2: Update via gossip
    rd.update_relay_from_gossip(
        address="192.168.56.101:8001",
        public_key="pubkey-abc123",
        current_load=0.3,
        uptime_score=0.9
    )
    
    print("\nAfter gossip update:")
    rd.print_directory()
    
    # Test 3: Get random peers
    peers = rd.get_random_peers(count=2)
    print(f"\nRandom 2 peers: {[p['address'] for p in peers]}")
    
    print("\nAll tests passed!")