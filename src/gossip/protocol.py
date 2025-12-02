
"""
Gossip Protocol Implementation
Push gossip with message prioritization and de-duplication
"""

import json
import time
import threading
import uuid
from typing import Set, Dict, Callable, Optional
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.crypto.crypto_utils import CryptoUtils
from src.gossip.relay_directory import RelayDirectory


class GossipProtocol:
    """
    Push gossip protocol with fanout k=3
    Handles relay announcements, capability updates, and network state
    """
    
    FANOUT = 3  # Number of peers to forward to
    TTL_DEFAULT = 10  # Default time-to-live
    
    PRIORITY_CRITICAL = "CRITICAL"
    PRIORITY_HIGH = "HIGH"
    PRIORITY_NORMAL = "NORMAL"
    PRIORITY_LOW = "LOW"
    
    def __init__(self, node_id: str, private_key, public_key, 
                 relay_directory: RelayDirectory, send_callback: Callable):
        """
        Initialize gossip protocol
        
        Args:
            node_id: This node's ID
            private_key: Ed25519 private key for signing
            public_key: Ed25519 public key
            relay_directory: RelayDirectory instance
            send_callback: Function to send UDP messages, signature: send(msg, host, port)
        """
        self.node_id = node_id
        self.private_key = private_key
        self.public_key = public_key
        self.public_key_b64 = CryptoUtils.serialize_public_key(public_key)
        self.relay_directory = relay_directory
        self.send_callback = send_callback
        
        # De-duplication
        self.seen_messages: Set[str] = set()
        self.seen_lock = threading.Lock()
        
        # Cleanup thread
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    def stop(self):
        """Stop gossip protocol"""
        self.running = False
    
    def create_relay_update(self, address: str, current_load: float, 
                           uptime_score: float, priority: str = PRIORITY_NORMAL) -> Dict:
        """
        Create relay update message
        
        Args:
            address: This node's "ip:port"
            current_load: 0.0 to 1.0
            uptime_score: 0.0 to 1.0
            priority: Message priority
        
        Returns:
            Signed gossip message dict
        """
        relay_reputation = (uptime_score * 0.5) + ((1.0 - current_load) * 0.5)
        
        message = {
            'type': 'RELAY_UPDATE',
            'priority': priority,
            'node_id': self.node_id,
            'network_address': address,
            'current_load': current_load,
            'uptime_score': uptime_score,
            'relay_reputation': relay_reputation,
            'public_key': self.public_key_b64,
            'timestamp': int(time.time() * 1000),  # milliseconds
            'message_id': str(uuid.uuid4()),
            'ttl': self.TTL_DEFAULT,
            'seen_by': []
        }
        
        # Sign message (exclude signature field)
        message_str = json.dumps(message, sort_keys=True)
        message['signature'] = CryptoUtils.sign_message(self.private_key, message_str)
        
        return message
    
    def gossip_relay_update(self, address: str, current_load: float, uptime_score: float):
        """
        Gossip relay update to k random peers
        
        Args:
            address: This node's "ip:port"
            current_load: Current load (0.0 to 1.0)
            uptime_score: Uptime score (0.0 to 1.0)
        """
        message = self.create_relay_update(address, current_load, uptime_score)
        
        # Add to seen set
        with self.seen_lock:
            self.seen_messages.add(message['message_id'])
        
        # Forward to k random peers
        self._forward_to_peers(message, exclude=[])
        
        print(f"[{self.node_id}] Gossiped relay update (load={current_load:.2f}, uptime={uptime_score:.2f})")
    
    def handle_gossip_message(self, message: Dict, sender_addr: tuple) -> bool:
        """
        Handle received gossip message
        
        Args:
            message: Gossip message dict
            sender_addr: (ip, port) of sender
        
        Returns:
            True if message processed, False if dropped
        """
        message_id = message.get('message_id')
        
        # Check if already seen
        with self.seen_lock:
            if message_id in self.seen_messages:
                return False  # Drop duplicate
            self.seen_messages.add(message_id)
        
        # Verify signature
        if not self._verify_message_signature(message):
            print(f"[{self.node_id}] Invalid signature from {sender_addr}")
            return False
        
        # Process based on message type
        if message['type'] == 'RELAY_UPDATE':
            self._handle_relay_update(message)
        else:
            print(f"[{self.node_id}] Unknown gossip type: {message['type']}")
            return False
        
        # Forward to peers if TTL > 0
        if message['ttl'] > 0:
            message['ttl'] -= 1
            message['seen_by'].append(self.node_id)
            self._forward_to_peers(message, exclude=message['seen_by'])
        
        return True
    
    def _handle_relay_update(self, message: Dict):
        """Process relay update message"""
        self.relay_directory.add_relay(
            relay_id=message['node_id'],
            address=message['network_address'],
            public_key=message['public_key'],
            current_load=message['current_load'],
            uptime_score=message['uptime_score']
        )
        print(f"[{self.node_id}] Updated RD: {message['node_id']} @ {message['network_address']}")
    
    def _forward_to_peers(self, message: Dict, exclude: list):
        """
        Forward message to k random peers
        
        Args:
            message: Message to forward
            exclude: List of node_ids to exclude
        """
        peers = self.relay_directory.get_random_peers(self.FANOUT, exclude=exclude)
        
        for peer in peers:
            try:
                # Parse address
                host, port = peer['address'].split(':')
                port = int(port)
                
                # Send via UDP
                self.send_callback(message, host, port)
            except Exception as e:
                print(f"[{self.node_id}] Failed to forward to {peer['relay_id']}: {e}")
    
    def _verify_message_signature(self, message: Dict) -> bool:
        """Verify message signature"""
        try:
            signature = message.pop('signature')
            message_str = json.dumps(message, sort_keys=True)
            public_key = CryptoUtils.deserialize_public_key(message['public_key'])
            is_valid = CryptoUtils.verify_signature(public_key, message_str, signature)
            message['signature'] = signature  # Restore
            return is_valid
        except Exception as e:
            print(f"Signature verification error: {e}")
            return False
    
    def _cleanup_loop(self):
        """Periodic cleanup of seen messages and stale relays"""
        while self.running:
            time.sleep(60)  # Every minute
            
            # Clean up seen messages (keep last 1000)
            with self.seen_lock:
                if len(self.seen_messages) > 1000:
                    # Remove oldest (convert to list, sort by insertion order not possible)
                    # Simple approach: clear all if too many
                    self.seen_messages.clear()
            
            # Clean up stale relays (no update in 10 minutes)
            self.relay_directory.cleanup_stale_relays(timeout=600)


# # Self-test
# if __name__ == "__main__":
#     print("Testing GossipProtocol...")
    
#     # Mock send callback
#     def mock_send(message, host, port):
#         print(f"  SEND to {host}:{port} - {message['type']}")
    
#     # Create keys
#     private_key, public_key = CryptoUtils.generate_ed25519_keypair()
    
#     # Create relay directory
#     rd = RelayDirectory("TestNode")
#     rd.add_relay("Peer1", "192.168.1.101:9001", "pubkey1", 0.3, 0.9)
#     rd.add_relay("Peer2", "192.168.1.102:9002", "pubkey2", 0.2, 0.95)
    
#     # Create gossip protocol
#     gossip = GossipProtocol("TestNode", private_key, public_key, rd, mock_send)
    
#     # Test gossip relay update
#     print("\nGossiping relay update...")
#     gossip.gossip_relay_update("192.168.1.100:8001", current_load=0.4, uptime_score=0.85)
    
#     # Test handling received message
#     print("\nSimulating received gossip...")
#     message = gossip.create_relay_update("192.168.1.103:8003", 0.5, 0.8)
#     result = gossip.handle_gossip_message(message, ("192.168.1.103", 8003))
#     print(f"Message processed: {result}")
    
#     # Test duplicate detection
#     print("\nTesting duplicate detection...")
#     result2 = gossip.handle_gossip_message(message, ("192.168.1.103", 8003))
#     print(f"Duplicate dropped: {not result2}")
    
#     # Print final directory
#     rd.print_directory()
    
#     gossip.stop()
#     print("\nAll tests passed!")
