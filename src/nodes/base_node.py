"""
Base UDP Node for AI-MAS network
Provides UDP socket communication, message handling, and Tor routing
"""

import socket
import json
import threading
import time
import logging
from typing import Callable, Optional, Dict, Any


class UDPNode:
    """
    Base class for all AI-MAS nodes
    Handles UDP communication, message routing, and basic networking
    """
    
    def __init__(self, node_id: str, host: str, port: int, node_type: str = "base"):
        """
        Initialize UDP node
        
        Args:
            node_id: Unique node identifier (e.g., "Agent-Text-1")
            host: IP address to bind to (e.g., "192.168.56.101")
            port: UDP port to listen on (e.g., 8001)
            node_type: Node type (agent, fog, orchestrator)
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        self.node_type = node_type
        self.running = False
        
        # UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        
        # Message handler callback
        self.message_handler: Optional[Callable] = None
        
        # Logging
        logging.basicConfig(
            level=logging.INFO,
            format=f'[{node_id}] %(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        self.logger = logging.getLogger(node_id)
        
        # Statistics
        self.stats = {
            'messages_received': 0,
            'messages_sent': 0,
            'bytes_received': 0,
            'bytes_sent': 0,
            'start_time': time.time()
        }
    
    def start(self):
        """Start UDP listener thread"""
        self.running = True
        listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
        listener_thread.start()
        self.logger.info(f"Started on {self.host}:{self.port} (type: {self.node_type})")
    
    def stop(self):
        """Stop UDP listener"""
        self.running = False
        self.sock.close()
        self.logger.info("Stopped")
    
    def _listen_loop(self):
        """Main UDP listening loop"""
        self.sock.settimeout(1.0)  # 1 second timeout for checking self.running
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)  # Max UDP packet size
                self.stats['messages_received'] += 1
                self.stats['bytes_received'] += len(data)
                
                # Decode message
                try:
                    message = json.loads(data.decode('utf-8'))
                    self._handle_message(message, addr)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Invalid JSON from {addr}: {e}")
                except Exception as e:
                    self.logger.error(f"Error handling message from {addr}: {e}")
                    
            except socket.timeout:
                continue  # Check self.running and continue
            except Exception as e:
                if self.running:
                    self.logger.error(f"Socket error: {e}")
    
    def _handle_message(self, message: Dict[str, Any], addr: tuple):
        """
        Handle received message
        
        Args:
            message: Decoded JSON message
            addr: (ip, port) tuple of sender
        """
        if self.message_handler:
            self.message_handler(message, addr)
        else:
            self.logger.debug(f"Received {message.get('type', 'UNKNOWN')} from {addr}")
    
    def send_message(self, message: Dict[str, Any], dest_host: str, dest_port: int):
        """
        Send JSON message via UDP
        
        Args:
            message: Dictionary to send (will be JSON-encoded)
            dest_host: Destination IP
            dest_port: Destination port
        """
        try:
            data = json.dumps(message).encode('utf-8')
            self.sock.sendto(data, (dest_host, dest_port))
            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data)
        except Exception as e:
            self.logger.error(f"Failed to send to {dest_host}:{dest_port}: {e}")
    
    def set_message_handler(self, handler: Callable):
        """
        Set callback for handling received messages
        
        Args:
            handler: Function with signature handler(message: dict, addr: tuple)
        """
        self.message_handler = handler
    
    def get_stats(self) -> Dict[str, Any]:
        """Get node statistics"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'messages_per_second': self.stats['messages_received'] / max(uptime, 1)
        }
    
    def print_stats(self):
        """Print node statistics"""
        stats = self.get_stats()
        self.logger.info(f"Statistics: RX={stats['messages_received']} TX={stats['messages_sent']} "
                        f"Uptime={stats['uptime_seconds']:.1f}s")


# Self-test
# if __name__ == "__main__":
#     print("Testing UDPNode...")
    
#     # Create two nodes
#     node1 = UDPNode("TestNode1", "127.0.0.1", 9001, "test")
#     node2 = UDPNode("TestNode2", "127.0.0.1", 9002, "test")
    
#     # Set up message handler for node2
#     def node2_handler(message, addr):
#         print(f"Node2 received: {message}")
#         # Echo back
#         node2.send_message({"type": "ECHO", "original": message}, addr[0], addr[1])
    
#     node2.set_message_handler(node2_handler)
    
#     # Start both nodes
#     node1.start()
#     node2.start()
    
#     # Send test message
#     time.sleep(0.5)
#     node1.send_message({"type": "TEST", "content": "Hello Node2!"}, "127.0.0.1", 9002)
    
#     # Wait for response
#     time.sleep(1)
    
#     # Print stats
#     node1.print_stats()
#     node2.print_stats()
    
#     # Stop nodes
#     node1.stop()
#     node2.stop()
    
#     print("\nTest complete!")


# Expected output:
# Testing UDPNode...
# [TestNode1] ... - INFO - Started on 127.0.0.1:9001 (type: test)
# [TestNode2] ... - INFO - Started on 127.0.0.1:9002 (type: test)
# Node2 received: {'type': 'TEST', 'content': 'Hello Node2!'}
# [TestNode1] ... - INFO - Statistics: RX=1 TX=1 Uptime=1.0s
# [TestNode2] ... - INFO - Statistics: RX=1 TX=1 Uptime=1.0s
# Test complete!