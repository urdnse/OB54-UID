import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from config import AES_CONFIG

class AESUtils:
    def __init__(self):
        # Load configuration from config.py
        if AES_CONFIG["use_base64"]:
            self.key_base64 = AES_CONFIG["key_base64"]
            self.iv_base64 = AES_CONFIG["iv_base64"]
        else:
            # Convert hex to base64
            key_bytes = bytes.fromhex(AES_CONFIG["key_hex"])
            iv_bytes = bytes.fromhex(AES_CONFIG["iv_hex"])
            self.key_base64 = base64.b64encode(key_bytes).decode()
            self.iv_base64 = base64.b64encode(iv_bytes).decode()
    
    def get_key(self):
        """Get the AES key from base64"""
        return base64.b64decode(self.key_base64)
    
    def get_iv(self):
        """Get the IV from base64"""
        return base64.b64decode(self.iv_base64)
    
    def encrypt_aes_cbc(self, data):
        """
        Encrypt data using AES CBC mode
        Args:
            data: bytes to encrypt
        Returns:
            encrypted bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        key = self.get_key()
        iv = self.get_iv()
        
        # Add PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted
    
    def decrypt_aes_cbc(self, hex_data):
        """
        Decrypt hex string using AES CBC mode
        Args:
            hex_data: hex string to decrypt
        Returns:
            decrypted bytes
        """
        # Convert hex to bytes
        if isinstance(hex_data, str):
            encrypted_data = bytes.fromhex(hex_data)
        else:
            encrypted_data = hex_data
        
        key = self.get_key()
        iv = self.get_iv()
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()
        
        return data

# Test function to verify our implementation
def test_aes_utils():
    """Test the AESUtils implementation"""
    aes = AESUtils()
    
    # Test data
    test_data = b"Hello World Test Data"
    print(f"Original data: {test_data}")
    
    # Encrypt
    encrypted = aes.encrypt_aes_cbc(test_data)
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    # Decrypt
    decrypted = aes.decrypt_aes_cbc(encrypted.hex())
    print(f"Decrypted: {decrypted}")
    
    # Verify
    assert test_data == decrypted, "Encryption/Decryption failed!"
    print("✅ AES encryption/decryption test passed!")

if __name__ == "__main__":
    test_aes_utils()
