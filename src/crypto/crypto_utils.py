"""
Cryptographic utilities for AI-MAS network
Provides AES-256-GCM encryption and Ed25519 signing
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import base64


class CryptoUtils:
    """Cryptographic operations for Tor over UDP"""
    
    @staticmethod
    def derive_key_from_agent_id(agent_id: str, salt: bytes = b'ai-mas-2025') -> bytes:
        """
        Derive AES-256 key from agent_id using HKDF-SHA256
        This is used for Layer 1 encryption in 4-layer Tor
        
        Args:
            agent_id: Unique agent identifier (e.g., "Agent-Text-1")
            salt: Salt for key derivation
        
        Returns:
            32-byte AES-256 key
        """
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            info=b'agent-key-derivation'
        )
        return kdf.derive(agent_id.encode('utf-8'))
    
    @staticmethod
    def encrypt_aes_gcm(key: bytes, plaintext: str) -> dict:
        """
        Encrypt plaintext using AES-256-GCM
        
        Args:
            key: 32-byte AES key
            plaintext: String to encrypt
        
        Returns:
            dict with 'nonce' and 'ciphertext' (both base64 encoded)
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    @staticmethod
    def decrypt_aes_gcm(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
        """
        Decrypt ciphertext using AES-256-GCM
        
        Args:
            key: 32-byte AES key
            nonce_b64: Base64-encoded nonce
            ciphertext_b64: Base64-encoded ciphertext
        
        Returns:
            Decrypted plaintext string
        
        Raises:
            ValueError: If decryption fails (wrong key or tampered data)
        """
        try:
            aesgcm = AESGCM(key)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    @staticmethod
    def generate_ed25519_keypair():
        """
        Generate Ed25519 key pair for signing
        
        Returns:
            tuple: (private_key, public_key)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def sign_message(private_key, message: str) -> str:
        """
        Sign message with Ed25519 private key
        
        Args:
            private_key: Ed25519PrivateKey object
            message: String message to sign
        
        Returns:
            Base64-encoded signature
        """
        signature = private_key.sign(message.encode('utf-8'))
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key, message: str, signature_b64: str) -> bool:
        """
        Verify Ed25519 signature
        
        Args:
            public_key: Ed25519PublicKey object
            message: Original message
            signature_b64: Base64-encoded signature
        
        Returns:
            True if signature valid, False otherwise
        """
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, message.encode('utf-8'))
            return True
        except:
            return False
    
    @staticmethod
    def hash_sha256(data: str) -> str:
        """
        Compute SHA-256 hash
        
        Args:
            data: String to hash
        
        Returns:
            Hex-encoded hash (64 characters)
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def hash_agent_id(agent_id: str, length: int = 16) -> str:
        """
        Hash agent_id for task chain lookup
        
        Args:
            agent_id: Agent identifier
            length: Number of hex characters to return
        
        Returns:
            Truncated hex hash (e.g., "7a3f9c2b" for length=8)
        """
        full_hash = CryptoUtils.hash_sha256(agent_id)
        return full_hash[:length]
    
    @staticmethod
    def serialize_public_key(public_key) -> str:
        """
        Serialize Ed25519 public key to base64
        
        Args:
            public_key: Ed25519PublicKey object
        
        Returns:
            Base64-encoded public key
        """
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(public_bytes).decode('utf-8')
    
    @staticmethod
    def deserialize_public_key(public_key_b64: str):
        """
        Deserialize base64 public key to Ed25519PublicKey
        
        Args:
            public_key_b64: Base64-encoded public key
        
        Returns:
            Ed25519PublicKey object
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_bytes = base64.b64decode(public_key_b64)
        return Ed25519PublicKey.from_public_bytes(public_bytes)

# Self-test
# if __name__ == "__main__":
#     print("Testing CryptoUtils...")
    
#     # Test key derivation
#     key = CryptoUtils.derive_key_from_agent_id("Agent-Test-1")
#     print(f"Derived key length: {len(key)} bytes")
#     assert len(key) == 32
    
#     # Test encryption/decryption
#     plaintext = "Hello, AI-MAS network!"
#     encrypted = CryptoUtils.encrypt_aes_gcm(key, plaintext)
#     print(f"Encrypted: {encrypted['ciphertext'][:32]}...")
    
#     decrypted = CryptoUtils.decrypt_aes_gcm(key, encrypted['nonce'], encrypted['ciphertext'])
#     print(f"Decrypted: {decrypted}")
#     assert decrypted == plaintext
    
#     # Test signing/verification
#     private_key, public_key = CryptoUtils.generate_ed25519_keypair()
#     message = "Test message for signing"
#     signature = CryptoUtils.sign_message(private_key, message)
#     print(f"Signature: {signature[:32]}...")
    
#     is_valid = CryptoUtils.verify_signature(public_key, message, signature)
#     print(f"Signature valid: {is_valid}")
#     assert is_valid
    
#     # Test hashing
#     agent_hash = CryptoUtils.hash_agent_id("Agent-Test-1", length=16)
#     print(f"Agent hash: {agent_hash}")
#     assert len(agent_hash) == 16
    
#     print("\nAll tests passed!")