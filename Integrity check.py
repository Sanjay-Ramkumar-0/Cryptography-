import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import json
import base64

class IntegrityProtectedCrypto:
    def __init__(self, key_size_bits=256):
        self.key_size_bits = key_size_bits
        self.key_size_bytes = key_size_bits // 8
        self.supported_hash_functions = {
            'SHA256': hashlib.sha256,
            'SHA512': hashlib.sha512,
            'SHA3-256': hashlib.sha3_256,
            'SHA3-512': hashlib.sha3_512,
            'BLAKE2b': lambda: hashlib.blake2b(digest_size=32),
            'BLAKE2s': lambda: hashlib.blake2s(digest_size=32)
        }
    
    def pad_to_16_bytes(self, data):
        """Pad data to 16-byte multiple for AES"""
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode('utf-8'))
        padded_data += padder.finalize()
        return padded_data
    
    def unpad_data(self, padded_data):
        """Remove padding from decrypted data"""
        try:
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data)
            data += unpadder.finalize()
            return data.decode('utf-8')
        except Exception:
            cleaned_data = padded_data.rstrip(b'\x00')
            return cleaned_data.decode('utf-8', errors='ignore')
    
    def generate_hash(self, data, hash_function_name='SHA256'):
        """Generate hash of data using specified hash function"""
        if hash_function_name not in self.supported_hash_functions:
            raise ValueError(f"Unsupported hash function: {hash_function_name}")
        
        hash_func = self.supported_hash_functions[hash_function_name]()
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode('utf-8')
        
        hash_func.update(data)
        return hash_func.digest()
    
    def generate_hmac(self, data, key, hash_function_name='SHA256'):
        """Generate HMAC for data using specified hash function"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode('utf-8')
        
        if hash_function_name == 'SHA256':
            return hmac.new(key, data, hashlib.sha256).digest()
        elif hash_function_name == 'SHA512':
            return hmac.new(key, data, hashlib.sha512).digest()
        elif hash_function_name == 'SHA3-256':
            return hmac.new(key, data, hashlib.sha3_256).digest()
        elif hash_function_name == 'SHA3-512':
            return hmac.new(key, data, hashlib.sha3_512).digest()
        else:
            # For BLAKE2, use SHA256 as fallback for HMAC
            return hmac.new(key, data, hashlib.sha256).digest()
    
    def verify_hash(self, data, expected_hash, hash_function_name='SHA256'):
        """Verify hash integrity"""
        computed_hash = self.generate_hash(data, hash_function_name)
        return hmac.compare_digest(computed_hash, expected_hash)
    
    def verify_hmac(self, data, key, expected_hmac, hash_function_name='SHA256'):
        """Verify HMAC integrity"""
        computed_hmac = self.generate_hmac(data, key, hash_function_name)
        return hmac.compare_digest(computed_hmac, expected_hmac)
    
    def aes_encrypt(self, plaintext, key):
        """AES CBC encryption"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self.pad_to_16_bytes(plaintext)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv
    
    def aes_decrypt(self, ciphertext, key, iv):
        """AES CBC decryption"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return self.unpad_data(padded_plaintext)
    
    def twofish_simulate_encrypt(self, data, key):
        """Simulate Twofish encryption"""
        iv = os.urandom(16)
        if len(key) >= 32:
            aes_key = key[:32]
        elif len(key) >= 24:
            aes_key = key[:24]
        else:
            aes_key = (key + b'\x00' * 16)[:16]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if len(data) % 16 != 0:
            padding_len = 16 - (len(data) % 16)
            data = data + bytes([padding_len] * padding_len)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, iv
    
    def twofish_simulate_decrypt(self, ciphertext, key, iv):
        """Simulate Twofish decryption"""
        if len(key) >= 32:
            aes_key = key[:32]
        elif len(key) >= 24:
            aes_key = key[:24]
        else:
            aes_key = (key + b'\x00' * 16)[:16]
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        if len(padded_data) > 0:
            padding_len = padded_data[-1]
            if padding_len <= 16 and padding_len > 0:
                return padded_data[:-padding_len]
        return padded_data
    
    def chacha20_encrypt(self, data, key):
        """ChaCha20 encryption"""
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, nonce
    
    def chacha20_decrypt(self, ciphertext, key, nonce):
        """ChaCha20 decryption"""
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def encrypt_with_integrity(self, sentence, n, hash_function='SHA256', use_hmac=True):
        """Complete encryption with integrity protection"""
        # Generate keys
        aes_key = os.urandom(32)
        twofish_key = os.urandom(max(64, self.key_size_bytes))
        chacha20_key = os.urandom(32)
        integrity_key = os.urandom(32)
        
        n = min(n, len(twofish_key) - 1)
        
        # Step 1: AES encryption
        aes_ciphertext, aes_iv = self.aes_encrypt(sentence, aes_key)
        
        # Step 2: Twofish encryption of AES key
        twofish_encrypted_aes_key, twofish_iv = self.twofish_simulate_encrypt(aes_key, twofish_key)
        
        # Step 3: ChaCha20 encryption
        first_n_bytes = twofish_key[:n]
        chacha20_encrypted_bytes, nonce = self.chacha20_encrypt(first_n_bytes, chacha20_key)
        
        # Step 4: Create encrypted data bundle
        encrypted_bundle = {
            'aes_ciphertext': base64.b64encode(aes_ciphertext).decode('utf-8'),
            'aes_iv': base64.b64encode(aes_iv).decode('utf-8'),
            'twofish_encrypted_aes_key': base64.b64encode(twofish_encrypted_aes_key).decode('utf-8'),
            'twofish_iv': base64.b64encode(twofish_iv).decode('utf-8'),
            'modified_twofish_key': base64.b64encode(twofish_key[n:]).decode('utf-8'),
            'chacha20_encrypted_bytes': base64.b64encode(chacha20_encrypted_bytes).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'hash_function': hash_function,
            'use_hmac': use_hmac
        }
        
        # Step 5: Generate integrity check
        if use_hmac:
            integrity_digest = self.generate_hmac(encrypted_bundle, integrity_key, hash_function)
        else:
            integrity_digest = self.generate_hash(encrypted_bundle, hash_function)
        
        # Add integrity digest to bundle
        encrypted_bundle['integrity_digest'] = base64.b64encode(integrity_digest).decode('utf-8')
        
        return {
            'encrypted_bundle': encrypted_bundle,
            'chacha20_key': chacha20_key,
            'integrity_key': integrity_key if use_hmac else None
        }
    
    def decrypt_with_integrity_check(self, encrypted_data, n):
        """Complete decryption with integrity verification"""
        encrypted_bundle = encrypted_data['encrypted_bundle']
        chacha20_key = encrypted_data['chacha20_key']
        integrity_key = encrypted_data['integrity_key']
        
        # Step 1: Verify integrity
        expected_digest = base64.b64decode(encrypted_bundle['integrity_digest'])
        bundle_without_digest = encrypted_bundle.copy()
        del bundle_without_digest['integrity_digest']
        
        if encrypted_bundle['use_hmac'] and integrity_key:
            is_valid = self.verify_hmac(bundle_without_digest, integrity_key, 
                                       expected_digest, encrypted_bundle['hash_function'])
        else:
            is_valid = self.verify_hash(bundle_without_digest, expected_digest, 
                                       encrypted_bundle['hash_function'])
        
        if not is_valid:
            raise ValueError("Integrity check failed! Data may have been tampered with.")
        
        # Step 2: Decrypt ChaCha20
        chacha20_encrypted_bytes = base64.b64decode(encrypted_bundle['chacha20_encrypted_bytes'])
        nonce = base64.b64decode(encrypted_bundle['nonce'])
        first_n_bytes = self.chacha20_decrypt(chacha20_encrypted_bytes, chacha20_key, nonce)
        
        # Step 3: Reconstruct Twofish key
        modified_twofish_key = base64.b64decode(encrypted_bundle['modified_twofish_key'])
        reconstructed_twofish_key = first_n_bytes + modified_twofish_key
        
        # Step 4: Decrypt AES key with Twofish
        twofish_encrypted_aes_key = base64.b64decode(encrypted_bundle['twofish_encrypted_aes_key'])
        twofish_iv = base64.b64decode(encrypted_bundle['twofish_iv'])
        decrypted_aes_key_raw = self.twofish_simulate_decrypt(twofish_encrypted_aes_key, 
                                                            reconstructed_twofish_key, twofish_iv)
        aes_key = decrypted_aes_key_raw[:32] if len(decrypted_aes_key_raw) >= 32 else decrypted_aes_key_raw + b'\x00' * (32 - len(decrypted_aes_key_raw))
        
        # Step 5: Decrypt sentence with AES
        aes_ciphertext = base64.b64decode(encrypted_bundle['aes_ciphertext'])
        aes_iv = base64.b64decode(encrypted_bundle['aes_iv'])
        original_sentence = self.aes_decrypt(aes_ciphertext, aes_key, aes_iv)
        
        return original_sentence, True  # True indicates integrity check passed


def test_integrity_protection():
    """Test integrity protection functionality"""
    print("Testing Integrity Protection...")
    
    crypto = IntegrityProtectedCrypto(256)
    test_sentence = "This is a test message for integrity verification."
    n = 16
    
    hash_functions = ['SHA256', 'SHA512', 'SHA3-256', 'BLAKE2b']
    
    for hash_func in hash_functions:
        print(f"\n--- Testing with {hash_func} ---")
        
        # Test normal encryption/decryption
        encrypted_data = crypto.encrypt_with_integrity(test_sentence, n, hash_func, use_hmac=True)
        decrypted_sentence, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        
        print(f"Original:  {test_sentence}")
        print(f"Decrypted: {decrypted_sentence}")
        print(f"Integrity Valid: {integrity_valid}")
        print(f"Match: {test_sentence == decrypted_sentence}")
        
        # Test tampering detection
        print("Testing tampering detection...")
        tampered_data = encrypted_data.copy()
        tampered_bundle = tampered_data['encrypted_bundle'].copy()
        
        # Tamper with the ciphertext
        tampered_aes_ciphertext = base64.b64decode(tampered_bundle['aes_ciphertext'])
        tampered_aes_ciphertext = tampered_aes_ciphertext[:-1] + b'\x00'  # Change last byte
        tampered_bundle['aes_ciphertext'] = base64.b64encode(tampered_aes_ciphertext).decode('utf-8')
        tampered_data['encrypted_bundle'] = tampered_bundle
        
        try:
            crypto.decrypt_with_integrity_check(tampered_data, n)
            print("❌ Failed to detect tampering!")
        except ValueError as e:
            print(f"✅ Successfully detected tampering: {e}")


def test_multiple_scenarios():
    """Test different scenarios"""
    print("\n" + "="*50)
    print("Testing Multiple Scenarios")
    print("="*50)
    
    crypto = IntegrityProtectedCrypto(256)
    test_cases = [
        ("Short message", 8),
        ("Medium length message for testing purposes", 16),
        ("Very long message " * 10, 24),
        ("Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?", 12)
    ]
    
    for message, n in test_cases:
        print(f"\nTesting: '{message[:30]}...' with n={n}")
        
        # Test with HMAC
        encrypted_data = crypto.encrypt_with_integrity(message, n, 'SHA256', use_hmac=True)
        decrypted_message, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        
        print(f"HMAC - Integrity Valid: {integrity_valid}, Match: {message == decrypted_message}")
        
        # Test with Hash only
        encrypted_data = crypto.encrypt_with_integrity(message, n, 'SHA256', use_hmac=False)
        decrypted_message, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        
        print(f"Hash - Integrity Valid: {integrity_valid}, Match: {message == decrypted_message}")


if __name__ == "__main__":
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("Please install required package:")
        print("pip install cryptography")
        exit(1)
    
    test_integrity_protection()
    test_multiple_scenarios()
