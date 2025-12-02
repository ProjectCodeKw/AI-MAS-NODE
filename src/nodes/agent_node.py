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

        # Load cryptographic keys from file
        key_prefix = node_id.lower().replace(" ", "-")
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

    def load_keys_from_file(self, key_prefix: str):
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
        """
        Handle Tor circuit packet
        Two cases:
        1. Final destination (Layer 1 decrypts) → Process task_json
        2. Intermediate relay (Layer 1 fails) → Forward to next_hop
        """
        self.logger.info(f"Received Tor packet from {addr}")
        
        # Case 1: Packet already contains plaintext task_json (simplified for testing)
        if 'task_json' in packet:
            self.logger.info("Received plaintext task_json - processing")
            self._process_task_json(packet['task_json'])
            return
        
        # Case 2: Full Tor packet with Layer 1 encryption
        if 'layer1' in packet:
            # Try to decrypt Layer 1 with our agent_id
            try:
                my_key = CryptoUtils.derive_key_from_agent_id(self.node_id)
                layer1_data = packet['layer1']
                
                decrypted = CryptoUtils.decrypt_aes_gcm(
                    my_key,
                    layer1_data['nonce'],
                    layer1_data['ciphertext']
                )
                
                # SUCCESS - we can see plaintext!
                task_json = json.loads(decrypted)
                self.logger.info("✓ Layer 1 decrypted - I'm the final destination")
                self._process_task_json(task_json)
                return
                
            except Exception as e:
                # FAILED - we're just a relay, forward it
                self.logger.info("✗ Cannot decrypt Layer 1 - acting as relay")
                self._relay_tor_packet(packet)
                return
        
        self.logger.warning("Unknown Tor packet structure")

    def _process_task_json(self, task_json: dict):
        """
        Process task JSON - try to decrypt all keys to find our task
        JSON SIZE NEVER CHANGES - only replace task data with result data
        
        Args:
            task_json: JSON with encrypted tasks (size stays constant)
        """
        self.logger.info(f"Processing task JSON with {len(task_json)} entries")
        
        # Try to decrypt each entry to find our task
        my_task = None
        my_key_hash = None
        
        for key_hash, encrypted_data in list(task_json.items()):
            # Skip fuzz entries
            if key_hash.startswith("fuzz_"):
                continue
            
            # Try to decrypt with our agent_id
            try:
                my_agent_key = CryptoUtils.derive_key_from_agent_id(self.node_id)
                
                # Decrypt
                decrypted = CryptoUtils.decrypt_aes_gcm(
                    my_agent_key,
                    encrypted_data['nonce'],
                    encrypted_data['ciphertext']
                )
                
                # Parse decrypted data
                task_data = json.loads(decrypted)
                
                # Check if this is a task (not a result)
                if 'task' in task_data:
                    # Successfully found our task!
                    my_task = task_data
                    my_key_hash = key_hash
                    self.logger.info(f"✓ Found my task under key: {key_hash}")
                    break
                
            except Exception as e:
                # Not our task, continue trying
                continue
        
        if not my_task:
            self.logger.error("Could not find my task in JSON!")
            return
        
        # Extract task details
        description = my_task.get('task')
        next_addr = my_task.get('next_addr')
        nonce = my_task.get('nonce')
        timestamp = my_task.get('TS')
        
        self.logger.info(f"Executing task: {description}")
        
        # Execute task
        start_time = time.time()
        time.sleep(self.inference_time_ms / 1000.0)  # Simulate inference
        
        # Generate result based on specialty
        if self.specialty == "code-generation":
            result = "def find_smallest(lst):\n    return min(lst)"
        elif self.specialty == "text-generation":
            result = "UDP (User Datagram Protocol) is a connectionless transport protocol."
        elif self.specialty == "graph-visualization":
            result = "[Graph visualization data]"
        else:
            result = f"Result from {self.node_id}"
        
        execution_time = time.time() - start_time
        self.tasks_completed += 1
        
        self.logger.info(f"✓ Task completed in {execution_time:.2f}s")
        
        print(f"\n{'='*60}")
        print(f"[{self.node_id}] TASK EXECUTED")
        print(f"{'='*60}")
        print(f"Task: {description}")
        print(f"Result: {result[:200]}...")
        print(f"Execution Time: {execution_time:.2f}s")
        print(f"{'='*60}\n")
        
        # REPLACE task data with result data (JSON size stays same!)
        result_data = {
            'result': result,
            'nonce': nonce,
            'next_addr': next_addr,
            'TS': int(time.time() * 1000),
            'execution_time': execution_time
        }
        
        # Re-encrypt with same key
        my_agent_key = CryptoUtils.derive_key_from_agent_id(self.node_id)
        encrypted_result = CryptoUtils.encrypt_aes_gcm(
            my_agent_key,
            json.dumps(result_data)
        )
        
        # REPLACE in JSON (not add, not remove - REPLACE)
        task_json[my_key_hash] = encrypted_result
        
        self.logger.info(f"Replaced task with result under {my_key_hash}")
        
        # Forward to next_addr
        if next_addr:
            self.logger.info(f"Forwarding modified task JSON to {next_addr}")
            self._forward_via_tor(task_json, next_addr)
        else:
            self.logger.warning("No next_addr specified!")

    def _forward_via_tor(self, task_json: dict, dest_addr: str):
        """
        Wrap task JSON in NEW Tor circuit and forward
        
        Args:
            task_json: Modified task JSON (SAME SIZE as received)
            dest_addr: Destination address (next agent or orchestrator)
        """
        host, port = dest_addr.split(':')
        port = int(port)
        
        message = {
            'type': 'TOR_PACKET',
            'task_json': task_json
        }
        
        self.send_message(message, host, port)
        self.logger.info(f"✓ Forwarded task JSON (size: {len(task_json)} entries) to {dest_addr}")

    def _relay_tor_packet(self, packet: dict):
        """
        Forward Tor packet as intermediate relay (cannot decrypt)
        
        Args:
            packet: Tor packet with next_hop address
        """
        next_hop = packet.get('next_hop')
        
        if not next_hop:
            self.logger.error("No next_hop in packet - cannot relay")
            return
        
        self.logger.info(f"Relaying packet to {next_hop}")
        
        # Parse destination
        host, port = next_hop.split(':')
        port = int(port)
        
        # Forward packet unchanged
        self.send_message(packet, host, port)
        self.logger.info(f"✓ Packet relayed to {next_hop}")

        
        # Modify task JSON
        # 1. Remove our encrypted task
        del task_json[my_key_hash]
        
        # 2. Add our result
        if sk_key:
            # Dependent task - encrypt result with SK for next agent
            sk_hash = f"H(SK_{sk_key})"
            sk_bytes = CryptoUtils.derive_key_from_agent_id(sk_key)
            encrypted_result = CryptoUtils.encrypt_aes_gcm(sk_bytes, result)
            task_json[sk_hash] = encrypted_result
            self.logger.info(f"Added encrypted result under {sk_hash}")
        else:
            # Single agent task - add result directly
            task_json['result'] = result
            task_json['agent_id'] = self.node_id
            task_json['execution_time'] = execution_time
            task_json['task_id'] = task_id
        
        # Forward to next_addr
        if next_addr:
            self.logger.info(f"Forwarding modified task JSON to {next_addr}")
            self._forward_via_tor(task_json, next_addr)
        else:
            self.logger.warning("No next_addr specified - task chain incomplete!")
    
    
    
    def _execute_task(self, task: dict):
        """
        Execute AI task - legacy method for direct task messages
        
        Args:
            task: Task dict with 'description', 'task_id'
        """
        task_id = task.get('task_id', 'unknown')
        description = task.get('description', '')

        self.logger.info(f"Executing direct task {task_id}: {description}")

        # Simulate inference
        if self.inference_time_ms > 0:
            time.sleep(self.inference_time_ms / 1000.0)

        # Simple static response
        out = f"[{self.node_id}] Completed: {description}"

        self.tasks_completed += 1
        self.logger.info(f"Task {task_id} completed ({self.tasks_completed} total)")

        return {
            "task_id": task_id,
            "result": out
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