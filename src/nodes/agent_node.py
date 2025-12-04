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
        Handle Tor circuit packet
        Two cases:
        1. Final destination (Layer 1 decrypts) → Process task_json
        2. Intermediate relay (Layer 1 fails) → Forward to next_hop
        """
        print(f"\n{'='*80}")
        print(f"[{self.node_id}] RECEIVED TOR PACKET")
        print(f"{'='*80}")
        print(f"From: {addr[0]}:{addr[1]}")
        print(f"To: {self.host}:{self.port}")
        print(f"Packet type: {packet.get('type', 'UNKNOWN')}")

        # Case 1: Packet already contains plaintext task_json (simplified for testing)
        if 'task_json' in packet:
            print(f"\nPacket contains: Plaintext task_json")
            print(f"Task JSON entries: {len(packet['task_json'])}")
            print(f"Status: Final destination (no encryption)")
            print(f"{'='*80}\n")
            self.logger.info("Received plaintext task_json - processing")
            self._process_task_json(packet['task_json'])
            return

        # If this packet contains an outer encrypted layer (layer4/layer3/layer2),
        # attempt to decrypt using known relay keys, print the decrypted payload,
        # and forward the peeled payload to its `next_hop`/`dest`.
        for outer_layer in ('layer4', 'layer3', 'layer2'):
            if outer_layer in packet:
                layer_data = packet[outer_layer]
                decrypted_payload = None

                # Derive symmetric key from this node's public key (TEST-ONLY)
                # Must match sender's derivation: DER encoding truncated/padded to 32 bytes
                from cryptography.hazmat.primitives import serialization

                try:
                    # Serialize to DER format (not PEM) to match topology encoding
                    pub_bytes = self.public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    # Truncate/pad to 32 bytes (same as sender does)
                    if len(pub_bytes) < 32:
                        self_key = pub_bytes.ljust(32, b"\0")
                    elif len(pub_bytes) > 32:
                        self_key = pub_bytes[:32]
                    else:
                        self_key = pub_bytes
                except Exception as e:
                    self.logger.error(f"Failed to derive key from public key: {e}")
                    break

                try:
                    decrypted_json = CryptoUtils.decrypt_aes_gcm(
                        self_key,
                        layer_data['nonce'],
                        layer_data['ciphertext']
                    )
                    decrypted_payload = json.loads(decrypted_json)
                except Exception as e:
                    self.logger.debug(f"Failed to decrypt {outer_layer} with this node's key: {e}")
                    # If decryption fails with the node's key, do not try other keys (security model)
                    break

                if decrypted_payload is None:
                    # Could not decrypt with available keys
                    self.logger.debug(f"Received {outer_layer} but could not decrypt with available keys")
                    # Do not treat as final; fallback to existing relay behavior
                    break

                # Print decrypted payload for inspection
                print(f"\nDecrypted {outer_layer} payload:")
                try:
                    print(json.dumps(decrypted_payload, indent=2))
                except Exception:
                    print(str(decrypted_payload))

                # Forward the peeled payload to its next hop (if present)
                next_hop = decrypted_payload.get('next_hop') or decrypted_payload.get('dest')
                if next_hop:
                    try:
                        host, port = next_hop.split(':')
                        port = int(port)
                        forward_packet = {'type': 'TOR_PACKET', **decrypted_payload}
                        self.send_message(forward_packet, host, port)
                        self.logger.info(f"Forwarded peeled {outer_layer} to {next_hop}")
                    except Exception as e:
                        self.logger.error(f"Failed forwarding peeled {outer_layer}: {e}")
                else:
                    self.logger.warning(f"Decrypted {outer_layer} has no next_hop/dest; not forwarding")

                # Stop processing after handling the outer layer
                return

        # Case 2: Full Tor packet with Layer 1 encryption
        if 'layer1' in packet:
            layer1_data = packet['layer1']
            print(f"\nPacket contains: Encrypted Layer 1")
            print(f"Layer 1 nonce: {layer1_data.get('nonce', 'N/A')[:16]}...")
            print(f"Layer 1 ciphertext size: {len(layer1_data.get('ciphertext', ''))} bytes")
            print(f"\nAttempting to decrypt with agent_id: {self.node_id}")

            # Try to decrypt Layer 1 with our agent_id
            try:
                my_key = CryptoUtils.derive_key_from_agent_id(self.node_id)

                decrypted = CryptoUtils.decrypt_aes_gcm(
                    my_key,
                    layer1_data['nonce'],
                    layer1_data['ciphertext']
                )

                # SUCCESS - we can see plaintext!
                print(f"\nDecryption SUCCESS!")
                print(f"Status: Final destination")

                # Parse decrypted content. Some builders wrap the actual payload
                # under a 'plaintext' key (string). Unwrap if present.
                parsed = None
                try:
                    parsed = json.loads(decrypted)
                except Exception:
                    # If it isn't valid JSON, treat decrypted as raw plaintext
                    parsed = decrypted

                # If wrapper present, try to extract inner plaintext
                if isinstance(parsed, dict) and 'plaintext' in parsed:
                    inner = parsed.get('plaintext')
                    try:
                        task_json = json.loads(inner)
                    except Exception:
                        task_json = inner
                else:
                    task_json = parsed

                # Log and dispatch to task processor if it's the expected task JSON
                try:
                    if isinstance(task_json, dict):
                        print(f"Decrypted task_json entries: {len(task_json)}")
                    else:
                        print("Decrypted payload (non-dict)")
                except Exception:
                    pass

                print(f"{'='*80}\n")
                self.logger.info("Layer 1 decrypted - I'm the final destination")
                self._process_task_json(task_json)
                return

            except Exception as e:
                # FAILED - we're just a relay, forward it
                print(f"\nDecryption FAILED: {str(e)[:50]}")
                print(f"Status: Intermediate relay (not for me)")
                next_hop = packet.get('next_hop') or packet.get('dest') or 'NOT SPECIFIED'
                print(f"Next hop: {next_hop}")
                print(f"{'='*80}\n")
                self.logger.info("Cannot decrypt Layer 1 - acting as relay")
                self._relay_tor_packet(packet)
                return

        print(f"\nUnknown Tor packet structure")
        print(f"Available keys: {list(packet.keys())}")
        print(f"{'='*80}\n")

        # Also log the full packet structure (truncated) and pretty-print for debugging
        try:
            packet_str = json.dumps(packet, default=str)
        except Exception:
            packet_str = str(packet)

        # Truncate to avoid excessively large log entries
        truncated = packet_str[:2000]
        self.logger.warning(f"Unknown Tor packet structure - keys={list(packet.keys())} - packet(truncated)={truncated}")

        try:
            import pprint
            pprint.pprint(packet)
        except Exception:
            # Fallback to printing the truncated JSON string
            print(truncated)

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

        # Log the encrypted JSON being sent
        print(f"\n{'='*80}")
        print(f"[{self.node_id}] FORWARDING VIA TOR")
        print(f"{'='*80}")
        print(f"Destination: {dest_addr}")
        print(f"Packet Type: {message['type']}")
        print(f"Task JSON entries: {len(task_json)}")
        print(f"\nEncrypted JSON Keys:")
        for idx, (key_hash, encrypted_data) in enumerate(list(task_json.items())[:5], 1):
            if isinstance(encrypted_data, dict) and 'nonce' in encrypted_data:
                print(f"  {idx}. {key_hash}: nonce={encrypted_data['nonce'][:16]}..., "
                      f"ciphertext_size={len(encrypted_data['ciphertext'])} bytes")
            else:
                print(f"  {idx}. {key_hash}: {str(encrypted_data)[:60]}...")
        if len(task_json) > 5:
            print(f"  ... and {len(task_json) - 5} more entries")

        packet_size = len(json.dumps(message))
        print(f"\nTotal packet size: {packet_size} bytes")
        print(f"Sending from: {self.host}:{self.port}")
        print(f"Sending to: {dest_addr}")
        print(f"{'='*80}\n")

        self.send_message(message, host, port)
        self.logger.info(f"Forwarded task JSON (size: {len(task_json)} entries) to {dest_addr}")

    def _send_task_json_via_tor(self, task_json: dict, dest_addr: str, task_id: str):
        """
        Build and send a 4-layer Tor packet for `task_json` using relay-selection policy:
        - Guards are chosen from `get_guards(count=5)` (top reputations).
        - Guard, middle, exit each selected randomly from their top-3 pools (or fewer if not available).
        - Layer-1 is encrypted with THIS agent's key (self.node_id), so recipient knows which agent sent it.

        Args:
            task_json: The task payload (dict) to send (will be serialized as plaintext layer1)
            dest_addr: Destination address (IP:port format)
            task_id: Identifier for logging/debug
        """
        import random
        try:
            from src.tor.packet import TorPacket
        except Exception:
            self.logger.error("TorPacket module not available; cannot build Tor packet")
            return

        # Gather relay lists - FILTER by reputation threshold (>= 0.6)
        all_relays = self.relay_directory.get_all_relays()
        REPUTATION_THRESHOLD = 0.6
        qualified_relays = [r for r in all_relays if r.get('relay_reputation', 0) >= REPUTATION_THRESHOLD]

        if len(qualified_relays) < 3:
            self.logger.error(f"Not enough qualified relays (reputation >= {REPUTATION_THRESHOLD}) to build circuit. "
                            f"Found {len(qualified_relays)}, need 3. Aborting send.")
            return

        # 1) Prepare guard candidates (prefer top guards from qualified relays only)
        guard_candidates = [r for r in self.relay_directory.get_guards(count=5)
                           if r.get('relay_reputation', 0) >= REPUTATION_THRESHOLD]
        if not guard_candidates:
            # Fallback: use qualified relays sorted by reputation desc
            guard_candidates = sorted(qualified_relays, key=lambda r: r.get('relay_reputation', 0), reverse=True)

        # Sort and take top-3 (or fewer)
        guard_candidates.sort(key=lambda r: r.get('relay_reputation', 0), reverse=True)
        guard_pool = guard_candidates[:3] if len(guard_candidates) >= 1 else guard_candidates

        # Select guard randomly from guard_pool
        guard_relay = random.choice(guard_pool)
        guard_addr = guard_relay['address']

        # Remove chosen guard from available relays for next picks
        chosen_addrs = {guard_addr}

        # 2) Middle relay selection from remaining QUALIFIED relays by reputation
        remaining = [r for r in qualified_relays if r['address'] not in chosen_addrs]
        if not remaining:
            self.logger.error("No available qualified middle relays after selecting guard; aborting")
            return

        remaining.sort(key=lambda r: r.get('relay_reputation', 0), reverse=True)
        middle_pool = remaining[:3] if len(remaining) >= 1 else remaining
        middle_relay = random.choice(middle_pool)
        middle_addr = middle_relay['address']
        chosen_addrs.add(middle_addr)

        # 3) Exit relay selection from remaining QUALIFIED relays by reputation
        remaining2 = [r for r in qualified_relays if r['address'] not in chosen_addrs]
        if not remaining2:
            self.logger.error("No available qualified exit relays after selecting guard/middle; aborting")
            return

        remaining2.sort(key=lambda r: r.get('relay_reputation', 0), reverse=True)
        exit_pool = remaining2[:3] if len(remaining2) >= 1 else remaining2
        exit_relay = random.choice(exit_pool)
        exit_addr = exit_relay['address']

        # Ensure distinct addresses (defensive)
        if len({guard_addr, middle_addr, exit_addr}) < 3:
            self.logger.error("Unable to select three distinct qualified relays; aborting")
            return

        # Lookup relay keys (preserve existing pattern; use getattr to avoid KeyError)
        relay_keys = getattr(self, 'relay_keys', {})
        guard_key = relay_keys.get(guard_addr, os.urandom(32))
        middle_key = relay_keys.get(middle_addr, os.urandom(32))
        exit_key = relay_keys.get(exit_addr, os.urandom(32))

        # Log chosen relays and reputations (non-identifying, show address+rep)
        self.logger.info(f"Selected circuit for task {task_id}: Guard={guard_addr} (rep={guard_relay.get('relay_reputation', 0):.2f}), "
                         f"Middle={middle_addr} (rep={middle_relay.get('relay_reputation', 0):.2f}), "
                         f"Exit={exit_addr} (rep={exit_relay.get('relay_reputation', 0):.2f})")

        # Build Tor packet (wrap task_json with metadata)
        plaintext_payload = json.dumps({
            'type': 'TOR_PACKET',
            'task_json': task_json,
            'task_id': task_id
        })

        # Layer 1 encrypted with THIS agent's key (self.node_id)
        # Recipient will decrypt with derive_key_from_agent_id(current_agent_id)
        packet = TorPacket.build_4_layer_packet(
            plaintext=plaintext_payload,
            recipient_agent_id=self.node_id,  # Use current agent's key for Layer 1
            guard_key=guard_key,
            middle_key=middle_key,
            exit_key=exit_key,
            guard_addr=guard_addr,
            middle_addr=middle_addr,
            exit_addr=exit_addr,
            dest_addr=dest_addr  # Final destination (orchestrator or next agent)
        )

        # Log circuit details before sending
        print(f"\n{'='*80}")
        print(f"[{self.node_id}] SENDING RESPONSE VIA TOR CIRCUIT")
        print(f"{'='*80}")
        print(f"Task ID: {task_id}")
        print(f"Destination: {dest_addr}")
        print(f"\nCIRCUIT SELECTED:")
        print(f"  Guard:  {guard_addr}")
        print(f"  Middle: {middle_addr}")
        print(f"  Exit:   {exit_addr}")
        print(f"\nLAYER 1 ENCRYPTION:")
        print(f"  Encrypted with agent key: {self.node_id}")
        print(f"  Task JSON entries: {len(task_json)}")
        print(f"{'='*80}\n")

        # Send packet to first hop (guard)
        try:
            host, port = guard_addr.split(':')
            port = int(port)
            self.send_message(packet, host, port)
            self.logger.info(f"Sent Tor packet for task {task_id} to guard {guard_addr}")
        except Exception as e:
            self.logger.error(f"Failed to send Tor packet to guard {guard_addr}: {e}")

    def _relay_tor_packet(self, packet: dict):
        """
        Forward Tor packet as intermediate relay (cannot decrypt)

        Args:
            packet: Tor packet with next_hop address
        """
        # Accept either 'next_hop' or legacy/alternate 'dest' field
        next_hop = packet.get('next_hop') or packet.get('dest')

        if not next_hop:
            self.logger.error("No next_hop/dest in packet - cannot relay")
            return

        # Log traffic forwarding details
        print(f"\n{'='*80}")
        print(f"[{self.node_id}] RELAYING TOR TRAFFIC (Cannot Decrypt)")
        print(f"{'='*80}")
        print(f"Acting as: Intermediate Relay")
        print(f"Current node: {self.host}:{self.port}")
        print(f"Next hop: {next_hop}")

        # Show encrypted layers
        if 'layer4' in packet:
            layer_data = packet['layer4']
            print(f"\nEncrypted Layer 4 (outermost):")
            print(f"  Nonce: {layer_data.get('nonce', 'N/A')[:16]}...")
            print(f"  Ciphertext size: {len(layer_data.get('ciphertext', ''))} bytes")
        elif 'layer3' in packet:
            layer_data = packet['layer3']
            print(f"\nEncrypted Layer 3:")
            print(f"  Nonce: {layer_data.get('nonce', 'N/A')[:16]}...")
            print(f"  Ciphertext size: {len(layer_data.get('ciphertext', ''))} bytes")
        elif 'layer2' in packet:
            layer_data = packet['layer2']
            print(f"\nEncrypted Layer 2:")
            print(f"  Nonce: {layer_data.get('nonce', 'N/A')[:16]}...")
            print(f"  Ciphertext size: {len(layer_data.get('ciphertext', ''))} bytes")
        elif 'layer1' in packet:
            layer_data = packet['layer1']
            print(f"\nEncrypted Layer 1 (innermost):")
            print(f"  Nonce: {layer_data.get('nonce', 'N/A')[:16]}...")
            print(f"  Ciphertext size: {len(layer_data.get('ciphertext', ''))} bytes")

        packet_size = len(json.dumps(packet))
        print(f"\nPacket size: {packet_size} bytes")
        print(f"Traffic flow: [Previous Hop] → [{self.node_id}] → [{next_hop}]")
        print(f"{'='*80}\n")

        self.logger.info(f"Relaying packet to {next_hop}")

        # Parse destination
        host, port = next_hop.split(':')
        port = int(port)

        # Forward packet unchanged
        self.send_message(packet, host, port)
        self.logger.info(f"Packet relayed to {next_hop}")
    
    
    
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