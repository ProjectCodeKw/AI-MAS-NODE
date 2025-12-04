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
    4-Layer Tor packet. All layers use same encryption method (AES-256-GCM with 32-byte key).
    Keys derived from public_key in topology (DER-encoded, truncated to 32 bytes).
    """

    @staticmethod
    def build_4_layer_packet(plaintext: str, dest_key: bytes,
                            guard_key: bytes, middle_key: bytes, exit_key: bytes,
                            guard_addr: str, middle_addr: str, exit_addr: str,
                            dest_addr: str) -> dict:
        """
        Build 4-layer encrypted Tor packet. All layers use same key derivation method.

        Args:
            plaintext: Message to send (JSON string)
            dest_key: 32-byte key for destination (same method as relay keys)
            guard_key: 32-byte key for guard relay
            middle_key: 32-byte key for middle relay
            exit_key: 32-byte key for exit relay
            guard_addr, middle_addr, exit_addr, dest_addr: "ip:port" addresses
        """
        # Build from inside out - all layers use same structure
        # Inner layer (destination)
        inner = CryptoUtils.encrypt_aes_gcm(dest_key, plaintext)

        # Exit layer wraps inner + dest address
        exit_payload = json.dumps({'encrypted': inner, 'next_hop': dest_addr})
        exit_layer = CryptoUtils.encrypt_aes_gcm(exit_key, exit_payload)

        # Middle layer wraps exit + exit address
        middle_payload = json.dumps({'encrypted': exit_layer, 'next_hop': exit_addr})
        middle_layer = CryptoUtils.encrypt_aes_gcm(middle_key, middle_payload)

        # Guard layer wraps middle + middle address
        guard_payload = json.dumps({'encrypted': middle_layer, 'next_hop': middle_addr})
        guard_layer = CryptoUtils.encrypt_aes_gcm(guard_key, guard_payload)

        return {'type': 'TOR_PACKET', 'encrypted': guard_layer, 'next_hop': guard_addr}

    @staticmethod
    def try_decrypt(encrypted_data: dict, key: bytes) -> tuple:
        """
        Try to decrypt an encrypted layer.

        Args:
            encrypted_data: dict with 'nonce' and 'ciphertext'
            key: 32-byte AES key

        Returns:
            (success: bool, payload: str or None)
        """
        try:
            decrypted = CryptoUtils.decrypt_aes_gcm(key, encrypted_data['nonce'], encrypted_data['ciphertext'])
            return True, decrypted
        except:
            return False, None


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