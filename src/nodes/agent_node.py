
"""
AI Agent Node Implementation
Handles task execution with SLM inference
"""

import time
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.nodes.base_node import UDPNode
from src.crypto.crypto_utils import CryptoUtils
from src.gossip.relay_directory import RelayDirectory
from src.gossip.protocol import GossipProtocol


class AgentNode(UDPNode):
    """
    AI Agent Node - executes tasks with SLM inference
    """
    
    def __init__(self, node_id: str, host: str, port: int, specialty: str, 
                 inference_time_ms: int):
        """
        Initialize agent node
        
        Args:
            node_id: Agent identifier
            host: IP to bind
            port: Port to listen
            specialty: Agent specialty (e.g., "code-generation")
            inference_time_ms: Expected inference time (for reputation)
        """
        super().__init__(node_id, host, port, node_type="agent")
        
        self.specialty = specialty
        self.inference_time_ms = inference_time_ms

        # Generate cryptographic keys
        # Load cryptographic keys from file
        key_prefix = node_id.lower().replace(" ", "-")  # "Agent-Code" -> "agent-code"
        self.private_key, self.public_key = self.load_keys_from_file(key_prefix)
        
        # Relay Directory
        self.relay_directory = RelayDirectory(
    topology_file="/home/ai-mas/ai-mas-node/config/network_topology.json"
)
        
        # Gossip Protocol
        self.gossip = GossipProtocol(
            node_id, 
            self.private_key, 
            self.public_key,
            self.relay_directory,
            self.send_message
        )
        
        # Current load (simulated)
        self.current_load = 0.0
        self.uptime_score = 0.0
        self.tasks_completed = 0
        
        # Set message handler
        self.set_message_handler(self._handle_message)
        
        # Gossip update thread
        self.gossip_running = True
        import threading
        self.gossip_thread = threading.Thread(target=self._gossip_loop, daemon=True)
        self.gossip_thread.start()

    def load_keys_from_file(self,key_prefix: str):
        """
        Load private and public keys from PEM files
        
        Args:
            key_prefix: Prefix for key files (e.g., "agent-code")
        
        Returns:
            tuple: (private_key, public_key)
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        key_dir = "/home/ai-mas/ai-mas-node/keys"
        private_key_path = f"{key_dir}/{key_prefix}-private.pem"
        public_key_path = f"{key_dir}/{key_prefix}-public.pem"
        
        # Load private key
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Load public key
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        return private_key, public_key
    
    def _handle_message(self, message: dict, addr: tuple):
        """Handle incoming UDP messages"""
        msg_type = message.get('type')
        
        if msg_type == 'RELAY_UPDATE':
            self.gossip.handle_gossip_message(message, addr)
        
        elif msg_type == 'TOR_PACKET':
            self._handle_tor_packet(message, addr)
        
        elif msg_type == 'TASK':
            self._execute_task(message)
        
        else:
            self.logger.debug(f"Unknown message type: {msg_type}")
    
    def _handle_tor_packet(self, packet: dict, addr: tuple):
        """Handle Tor circuit packet"""
        # TODO: Implement Tor packet handling
        self.logger.info(f"Received Tor packet from {addr}")
    
    def _execute_task(self, task: dict):
        """
        Execute AI task - simplified version

        Args:
            task: Task dict with 'description', 'task_id', 'language'
        """
        task_id = task.get('task_id', 'unknown')
        description = task.get('description', '')
        language = task.get('language', 'python')

        self.logger.info(f"Executing task {task_id}: {description}")

        # Simulate latency (optional)
        if self.inference_time_ms > 0:
            time.sleep(self.inference_time_ms / 1000.0)

        # Simple static response
        out = "agent code replied"

        self.tasks_completed += 1

        self.logger.info(f"Task {task_id} completed ({self.tasks_completed} total)")

        return {
            "task_id": task_id,
            "result": out,
            "language": language
        }
    
    def _gossip_loop(self):
        """Periodic gossip of relay updates"""
        while self.gossip_running:
            time.sleep(300)  # Every 5 minutes
            
            # Update uptime score (simple: increment up to 1.0)
            self.uptime_score = min(1.0, self.uptime_score + 0.1)
            
            # Gossip relay update
            address = f"{self.host}:{self.port}"
            self.gossip.gossip_relay_update(address, self.current_load, self.uptime_score)
    
    def stop(self):
        """Stop agent node"""
        self.gossip_running = False
        self.gossip.stop()
        super().stop()



# # Self-test
# if __name__ == "__main__":
#     print("Testing AgentNode...")
    
#     agent = AgentNode(
#         node_id="Agent-Code",
#         host="192.168.1.88",
#         port=8001,
#         specialty="Coding in Python",
#         inference_time_ms=500
#     )
    
#     agent.start()
    
#     # Simulate task execution
#     time.sleep(1)
#     task = {
#         'type': 'TASK',
#         'task_id': 'task-001',
#         'description': 'Write a Python function to compute Fibonacci numbers recursively.',
#     }
#     agent._execute_task(task)
    
#     # Wait for gossip
#     time.sleep(2)
    
#     agent.print_stats()
#     agent.stop()
    
#     print("\nAgent deployment complete!")
