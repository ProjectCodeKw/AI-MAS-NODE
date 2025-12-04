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

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        # Load cryptographic keys from file
        private_key_path = f"/home/ai-mas/ai-mas-node/keys/agent-code-private.pem"
        public_key_path = f"/home/ai-mas/ai-mas-node/keys/agent-code-public.pem"
        with open(private_key_path, "rb") as f:
            priv_pem = f.read()
            self.private_key = serialization.load_pem_private_key(
                priv_pem,
                password=None,
                backend=default_backend()
            )

        with open(public_key_path, "rb") as f:
            pub_pem = f.read()
            self.public_key = serialization.load_pem_public_key(
                pub_pem,
                backend=default_backend()
            )

        
        # Relay Directory
        self.relay_directory = RelayDirectory(
            topology_file="/home/ai-mas/ai-mas-node/config/network_topology.json"
        )

        # Populate relay_keys from topology file (TEST-ONLY symmetric keys)
        # Priority: if a node entry contains `symmetric_key` use it (test-only),
        # otherwise deterministically derive a 32-byte key from `public_key` via SHA-256.
        # NOTE: This is only for simulation/testing. Do NOT use in production.
        self.relay_keys = {}
        try:
            import hashlib, base64
            topo_path = "/home/ai-mas/ai-mas-node/config/network_topology.json"
            with open(topo_path, 'r') as f:
                topo = json.load(f)
                for node in topo.get('nodes', []):
                    addr = node.get('network_address')
                    if not addr:
                        continue

                    # If a symmetric testing key is provided explicitly in topology, use it.
                    sym = node.get('symmetric_key')
                    if sym:
                        key_bytes = None
                        # Try base64 decode
                        try:
                            key_bytes = base64.b64decode(sym)
                        except Exception:
                            pass
                        # Try hex decode
                        if key_bytes is None:
                            try:
                                key_bytes = bytes.fromhex(sym)
                            except Exception:
                                pass
                        # Fallback: hash the provided string to 32 bytes
                        if key_bytes is None:
                            key_bytes = hashlib.sha256(sym.encode('utf-8')).digest()

                        # Ensure 32 bytes
                        if len(key_bytes) != 32:
                            key_bytes = hashlib.sha256(key_bytes).digest()

                        self.relay_keys[addr] = key_bytes
                        continue

                    # Use the public_key field directly as the symmetric AES key
                    # (TEST-ONLY): decode base64 and truncate/pad to 32 bytes as needed.
                    pub = node.get('public_key')
                    if pub:
                        try:
                            # Attempt base64 decode of the public_key string
                            key_bytes = base64.b64decode(pub)
                        except Exception:
                            # If it's not base64, fall back to raw bytes of the string
                            key_bytes = pub.encode('utf-8')

                        # Ensure exactly 32 bytes for AES-256-GCM
                        if len(key_bytes) < 32:
                            key_bytes = key_bytes.ljust(32, b"\0")
                        elif len(key_bytes) > 32:
                            key_bytes = key_bytes[:32]

                        self.relay_keys[addr] = key_bytes
        except Exception as e:
            # If topology isn't available, leave relay_keys empty and fall back to random keys
            self.logger.debug(f"Could not populate relay_keys from topology: {e}")
        # Ensure this node's own relay key is set from its public key file (use public_key_path)
        try:
            import hashlib
            self_addr = f"{self.host}:{self.port}"
            # Derive 32-byte AES key from this node's public key PEM (TEST-ONLY)
            if 'pub_pem' in locals():
                self.relay_keys[self_addr] = hashlib.sha256(pub_pem).digest()
                self.logger.debug(f"Set relay key for self ({self_addr}) from public_key_path")
        except Exception as e:
            self.logger.debug(f"Could not set self relay key from public_key_path: {e}")
        
        # Gossip Protocol
        self.gossip = GossipProtocol(
            node_id, 
            self.private_key, 
            self.public_key,
            self.relay_directory,
            self.send_message
        )
        
        # Current load (calculated from CPU usage)
        import psutil
        self.psutil = psutil
        self.uptime_score = 0.0
        
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
        Handle Tor circuit packet (generic structure - no layer names)
        Two cases:
        1. Final destination (decrypt succeeds) → Process task_json
        2. Intermediate relay (decrypt fails) → Forward to next_hop
        """
        from cryptography.hazmat.primitives import serialization

        print(f"\n{'='*80}")
        print(f"[{self.node_id}] RECEIVED TOR PACKET")
        print(f"{'='*80}")
        print(f"From: {addr[0]}:{addr[1]}")
        print(f"To: {self.host}:{self.port}")

        # Case 1: Packet already contains plaintext task_json (simplified for testing)
        if 'task_json' in packet and 'encrypted' not in packet:
            print(f"Status: Plaintext task_json (no encryption)")
            print(f"{'='*80}\n")
            self._process_task_json(packet['task_json'])
            return

        # Case 2: Encrypted packet - try to decrypt with our key
        if 'encrypted' not in packet:
            self.logger.warning(f"Unknown packet structure: {list(packet.keys())}")
            return

        encrypted_data = packet['encrypted']

        # Derive our key from public key (DER format, truncated to 32 bytes)
        try:
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self_key = pub_bytes[:32] if len(pub_bytes) >= 32 else pub_bytes.ljust(32, b"\0")
        except Exception as e:
            self.logger.error(f"Failed to derive key: {e}")
            return

        # Try to decrypt
        try:
            decrypted_json = CryptoUtils.decrypt_aes_gcm(
                self_key, encrypted_data['nonce'], encrypted_data['ciphertext']
            )
            decrypted = json.loads(decrypted_json)
            print(f"Status: Decrypted successfully")

            # Check if this has another encrypted layer (relay) or is final payload
            if 'encrypted' in decrypted:
                # Still has more layers - forward to next hop
                next_hop = decrypted.get('next_hop')
                if next_hop:
                    host, port = next_hop.split(':')
                    forward_packet = {'type': 'TOR_PACKET', **decrypted}
                    self.send_message(forward_packet, host, int(port))
                    print(f"Forwarded to: {next_hop}")
                    print(f"{'='*80}\n")
                    self.logger.info(f"Relayed packet to {next_hop}")
                return

            # Final destination - process the payload
            print(f"Status: Final destination")
            print(f"{'='*80}\n")
            self._process_task_json(decrypted)
            return

        except Exception as e:
            # Decryption failed - we're an intermediate relay
            next_hop = packet.get('next_hop')
            if next_hop:
                print(f"Status: Relay (cannot decrypt)")
                print(f"Forwarding to: {next_hop}")
                print(f"{'='*80}\n")
                host, port = next_hop.split(':')
                self.send_message(packet, host, int(port))
                self.logger.info(f"Relayed packet to {next_hop}")
            else:
                self.logger.error(f"Cannot decrypt and no next_hop: {e}")

    def _process_task_json(self, task_json: dict):
        """
        Process task JSON - try to decrypt all keys to find our task
        JSON SIZE NEVER CHANGES - only replace task data with result data

        Args:
            task_json: Wrapper dict or actual task JSON with encrypted tasks
        """
        # Extract actual task JSON if wrapped
        if 'task_json' in task_json:
            actual_task_json = task_json['task_json']
        else:
            actual_task_json = task_json

        self.logger.info(f"Processing task JSON with {len(actual_task_json)} entries")

        # Debug: Print all keys in task_json and our expected key
        print(f"\n{'='*80}")
        print(f"[{self.node_id}] TASK JSON DECRYPTION DEBUG")
        print(f"{'='*80}")
        print(f"Keys in task_json: {list(actual_task_json.keys())}")
        print(f"Our node_id: {self.node_id}")
        our_expected_key = CryptoUtils.hash_agent_id(self.node_id, length=16)
        print(f"Our expected_key hash: {our_expected_key}")
        print(f"Match found: {our_expected_key in actual_task_json}")
        print(f"{'='*80}\n")

        # Try to decrypt each entry to find our task
        my_task = None
        my_key_hash = None

        for key_hash, encrypted_data in list(actual_task_json.items()):
            # Skip fuzz entries
            if key_hash.startswith("fuzz_"):
                continue
            
            # Try to decrypt with our agent_id (derive 32-byte AES key)
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
                    self.logger.info(f"Found my task under key: {key_hash}")
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
        
        # Generate result based on specialty (STATIC RESPONSE FOR TESTING)
        if self.specialty == "code-generation":
            result = "def find_smallest(lst):\n    return min(lst)"
        elif self.specialty == "text-generation":
            result = "UDP (User Datagram Protocol) is a connectionless transport protocol."
        elif self.specialty == "graph-visualization":
            result = "[Graph visualization data]"
        else:
            result = f"Result from {self.node_id}"

        execution_time = time.time() - start_time
        self.logger.info(f"Task completed in {execution_time:.2f}s")
        
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
        actual_task_json[my_key_hash] = encrypted_result

        self.logger.info(f"Replaced task with result under {my_key_hash}")

        # Forward to next_addr via Tor circuit
        if next_addr:
            self.logger.info(f"Forwarding modified task JSON to {next_addr}")
            # Extract task_id if available (from the original wrapper)
            task_id = task_json.get('task_id', 'unknown') if 'task_id' in task_json else 'unknown'
            self._send_task_json_via_tor(actual_task_json, next_addr, task_id)
        else:
            self.logger.warning("No next_addr specified!")

    def _send_task_json_via_tor(self, task_json: dict, dest_addr: str, task_id: str):
        """
        Build and send a 4-layer Tor packet for task_json.
        All 4 layers use same key derivation: DER-encoded public key from topology, truncated to 32 bytes.

        Args:
            task_json: The task payload (dict) to send
            dest_addr: Destination address (IP:port format)
            task_id: Identifier for logging/debug
        """
        import random
        from src.tor.packet import TorPacket

        # Filter relays by reputation threshold (>= 0.6)
        REPUTATION_THRESHOLD = 0.6
        all_relays = self.relay_directory.get_all_relays()
        qualified = [r for r in all_relays if r.get('relay_reputation', 0) >= REPUTATION_THRESHOLD]

        if len(qualified) < 3:
            self.logger.error(f"Not enough qualified relays ({len(qualified)}/3). Aborting.")
            return

        # Select 3 distinct relays by reputation
        qualified.sort(key=lambda r: r.get('relay_reputation', 0), reverse=True)
        guard = random.choice(qualified[:3])
        remaining = [r for r in qualified if r['address'] != guard['address']]
        middle = random.choice(remaining[:3])
        remaining = [r for r in remaining if r['address'] != middle['address']]
        exit_relay = random.choice(remaining[:3])

        guard_addr = guard['address']
        middle_addr = middle['address']
        exit_addr = exit_relay['address']

        # Get keys from topology (all layers use same method)
        relay_keys = getattr(self, 'relay_keys', {})
        guard_key = relay_keys.get(guard_addr, os.urandom(32))
        middle_key = relay_keys.get(middle_addr, os.urandom(32))
        exit_key = relay_keys.get(exit_addr, os.urandom(32))
        dest_key = relay_keys.get(dest_addr, os.urandom(32))  # Destination key from topology

        # Build payload
        plaintext = json.dumps({'type': 'TOR_PACKET', 'task_json': task_json, 'task_id': task_id})

        # Build 4-layer packet (dest_key for innermost layer, same method as all others)
        packet = TorPacket.build_4_layer_packet(
            plaintext=plaintext,
            dest_key=dest_key,
            guard_key=guard_key,
            middle_key=middle_key,
            exit_key=exit_key,
            guard_addr=guard_addr,
            middle_addr=middle_addr,
            exit_addr=exit_addr,
            dest_addr=dest_addr
        )

        print(f"\n[{self.node_id}] Sending via Tor: {guard_addr} → {middle_addr} → {exit_addr} → {dest_addr}")

        # Send to guard
        host, port = guard_addr.split(':')
        self.send_message(packet, host, int(port))
        self.logger.info(f"Sent task {task_id} via Tor circuit")

    def _relay_tor_packet(self, packet: dict):
        """Forward Tor packet as intermediate relay (cannot decrypt)"""
        next_hop = packet.get('next_hop')
        if not next_hop:
            self.logger.error("No next_hop in packet - cannot relay")
            return

        print(f"[{self.node_id}] Relaying to {next_hop}")
        host, port = next_hop.split(':')
        self.send_message(packet, host, int(port))
    
    
    
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

        self.logger.info(f"Task {task_id} completed")

        return {
            "task_id": task_id,
            "result": out
        }
    
    def get_current_load(self) -> float:
        """
        Calculate current CPU load as percentage (0.0 to 1.0)

        Returns:
            float: CPU usage from 0.0 (idle) to 1.0 (fully loaded)
        """
        try:
            # Get CPU usage percentage (0-100) and convert to 0.0-1.0
            cpu_percent = self.psutil.cpu_percent(interval=0.1)
            return cpu_percent / 100.0
        except Exception as e:
            self.logger.warning(f"Failed to get CPU load: {e}")
            return 0.0

    def _gossip_loop(self):
        """Periodic gossip of relay updates"""
        while self.gossip_running:
            time.sleep(300)  # Every 5 minutes

            # Gossip relay update using current load only
            address = f"{self.host}:{self.port}"
            current_load = self.get_current_load()
            self.gossip.gossip_relay_update(address, current_load)
    
    def stop(self):
        """Stop agent node"""
        self.gossip_running = False
        self.gossip.stop()
        super().stop()