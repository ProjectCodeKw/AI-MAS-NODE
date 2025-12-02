"""
4-Layer Tor Packet Construction
Implements custom Tor-over-UDP with 4 encryption layers
"""

import json
import sys
import os
from typing import Optional
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.crypto.crypto_utils import CryptoUtils


class TorPacket:
    """
    4-Layer Tor packet structure:
    Layer 4 (outermost): Guard relay encryption
    Layer 3: Middle relay encryption
    Layer 2: Exit relay encryption
    Layer 1 (innermost): Agent-to-agent encryption (recipient agent_id key)
    """
    
    @staticmethod
    def build_4_layer_packet(plaintext: str, recipient_agent_id: str,
                            guard_key: bytes, middle_key: bytes, exit_key: bytes,
                            guard_addr: str, middle_addr: str, exit_addr: str,
                            dest_addr: str) -> dict:
        """
        Build 4-layer encrypted Tor packet
        
        Args:
            plaintext: Message to send
            recipient_agent_id: Destination agent ID (for Layer 1 key derivation)
            guard_key: Shared key with guard relay (Layer 4)
            middle_key: Shared key with middle relay (Layer 3)
            exit_key: Shared key with exit relay (Layer 2)
            guard_addr: "ip:port" of guard
            middle_addr: "ip:port" of middle
            exit_addr: "ip:port" of exit
            dest_addr: "ip:port" of final destination
        
        Returns:
            dict: 4-layer encrypted packet ready to send to guard
        """
        
        # Layer 1: Encrypt with recipient's agent_id-derived key
        layer1_key = CryptoUtils.derive_key_from_agent_id(recipient_agent_id)
        layer1_payload = {
            'plaintext': plaintext,
            'recipient': recipient_agent_id
        }
        layer1_encrypted = CryptoUtils.encrypt_aes_gcm(layer1_key, json.dumps(layer1_payload))
        
        # Layer 2: Encrypt Layer 1 + destination address with exit relay key
        layer2_payload = {
            'layer1': layer1_encrypted,
            'next_hop': dest_addr
        }
        layer2_encrypted = CryptoUtils.encrypt_aes_gcm(exit_key, json.dumps(layer2_payload))
        
        # Layer 3: Encrypt Layer 2 + exit address with middle relay key
        layer3_payload = {
            'layer2': layer2_encrypted,
            'next_hop': exit_addr
        }
        layer3_encrypted = CryptoUtils.encrypt_aes_gcm(middle_key, json.dumps(layer3_payload))
        
        # Layer 4: Encrypt Layer 3 + middle address with guard relay key
        layer4_payload = {
            'layer3': layer3_encrypted,
            'next_hop': middle_addr
        }
        layer4_encrypted = CryptoUtils.encrypt_aes_gcm(guard_key, json.dumps(layer4_payload))
        
        # Final packet to send to guard
        packet = {
            'type': 'TOR_PACKET',
            'layer4': layer4_encrypted,
            'dest': guard_addr  # First hop
        }
        
        return packet
    
    @staticmethod
    def peel_layer(encrypted_layer: dict, relay_key: bytes) -> dict:
        """
        Peel one layer of Tor encryption
        
        Args:
            encrypted_layer: dict with 'nonce' and 'ciphertext'
            relay_key: This relay's shared key
        
        Returns:
            dict with 'next_hop' and next encrypted layer (or plaintext if final)
        
        Raises:
            ValueError: If decryption fails
        """
        decrypted_json = CryptoUtils.decrypt_aes_gcm(
            relay_key,
            encrypted_layer['nonce'],
            encrypted_layer['ciphertext']
        )
        return json.loads(decrypted_json)
    
    @staticmethod
    def try_decrypt_layer1(encrypted_layer: dict, agent_id: str) -> Optional[dict]:
        """
        Attempt to decrypt Layer 1 (final destination check)
        
        Args:
            encrypted_layer: dict with 'nonce' and 'ciphertext'
            agent_id: This agent's ID
        
        Returns:
            dict with plaintext if successful, None if not final destination
        """
        try:
            key = CryptoUtils.derive_key_from_agent_id(agent_id)
            decrypted_json = CryptoUtils.decrypt_aes_gcm(
                key,
                encrypted_layer['nonce'],
                encrypted_layer['ciphertext']
            )
            payload = json.loads(decrypted_json)
            
            # Check if this is actually for us
            if payload.get('recipient') == agent_id:
                return payload
            else:
                return None
        except:
            # Decryption failed - not final destination
            return None


# Self-test
# if __name__ == "__main__":
#     print("Testing 4-Layer Tor Packet...")
    
#     # Simulate shared keys (in real implementation, these come from key exchange)
#     guard_key = os.urandom(32)
#     middle_key = os.urandom(32)
#     exit_key = os.urandom(32)
    
#     # Build packet
#     packet = TorPacket.build_4_layer_packet(
#         plaintext="Secret message from Agent A to Agent B",
#         recipient_agent_id="Agent-B",
#         guard_key=guard_key,
#         middle_key=middle_key,
#         exit_key=exit_key,
#         guard_addr="192.168.56.101:9001",
#         middle_addr="192.168.56.102:9001",
#         exit_addr="192.168.56.103:9001",
#         dest_addr="192.168.56.104:8001"
#     )
    
#     print(f"Packet type: {packet['type']}")
#     print(f"Packet size: {len(json.dumps(packet))} bytes")
    
#     # Simulate Guard relay peeling Layer 4
#     print("\n[Guard Relay] Peeling Layer 4...")
#     layer4_data = packet['layer4']
#     layer3_data = TorPacket.peel_layer(layer4_data, guard_key)
#     print(f"Next hop: {layer3_data['next_hop']}")
    
#     # Simulate Middle relay peeling Layer 3
#     print("\n[Middle Relay] Peeling Layer 3...")
#     layer2_data = TorPacket.peel_layer(layer3_data['layer3'], middle_key)
#     print(f"Next hop: {layer2_data['next_hop']}")
    
#     # Simulate Exit relay peeling Layer 2
#     print("\n[Exit Relay] Peeling Layer 2...")
#     layer1_data = TorPacket.peel_layer(layer2_data['layer2'], exit_key)
#     print(f"Next hop: {layer1_data['next_hop']}")
#     print(f"Exit relay sees encrypted Layer 1 (cannot read)")
    
#     # Simulate final destination trying to decrypt Layer 1
#     print("\n[Agent-B] Attempting to decrypt Layer 1...")
#     final_payload = TorPacket.try_decrypt_layer1(layer1_data['layer1'], "Agent-B")
    
#     if final_payload:
#         print(f"SUCCESS! Plaintext: {final_payload['plaintext']}")
#     else:
#         print("FAILED: Not the final destination")
    
#     # Test wrong recipient
#     print("\n[Agent-C] Attempting to decrypt Layer 1...")
#     wrong_payload = TorPacket.try_decrypt_layer1(layer1_data['layer1'], "Agent-C")
#     if wrong_payload:
#         print("ERROR: Should not decrypt!")
#     else:
#         print("Correctly rejected (not intended recipient)")
    
#     print("\nAll tests passed!")