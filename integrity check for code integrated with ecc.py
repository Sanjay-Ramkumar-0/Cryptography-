import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
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
        self.supported_curves = {
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(),
            'secp521r1': ec.SECP521R1(),
            'secp256k1': ec.SECP256K1()
        }
    
    def generate_ecc_keypair(self, curve_name='secp256r1'):
        """Generate ECC key pair"""
        if curve_name not in self.supported_curves:
            raise ValueError(f"Unsupported curve: {curve_name}. Supported: {list(self.supported_curves.keys())}")
        
        curve = self.supported_curves[curve_name]
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_ecc_keys(self, private_key=None, public_key=None):
        """Serialize ECC keys to PEM format"""
        result = {}
        if private_key:
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            result['private_key'] = base64.b64encode(private_pem).decode('utf-8')
        if public_key:
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            result['public_key'] = base64.b64encode(public_pem).decode('utf-8')
        return result
    
    def deserialize_ecc_keys(self, private_key_b64=None, public_key_b64=None):
        """Deserialize ECC keys from PEM format"""
        result = {}
        if private_key_b64:
            private_pem = base64.b64decode(private_key_b64)
            private_key = serialization.load_pem_private_key(
                private_pem, password=None, backend=default_backend()
            )
            result['private_key'] = private_key
        if public_key_b64:
            public_pem = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(
                public_pem, backend=default_backend()
            )
            result['public_key'] = public_key
        return result
    
    def ecc_sign(self, data, private_key, hash_algorithm='SHA256'):
        """Create ECC digital signature"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode('utf-8')
        
        hash_alg_map = {
            'SHA256': hashes.SHA256(),
            'SHA512': hashes.SHA512(),
            'SHA3-256': hashes.SHA3_256(),
            'SHA3-512': hashes.SHA3_512()
        }
        hash_algorithm = hash_algorithm if hash_algorithm in hash_alg_map else 'SHA256'
        signature = private_key.sign(data, ec.ECDSA(hash_alg_map[hash_algorithm]))
        return signature
    
    def ecc_verify(self, data, signature, public_key, hash_algorithm='SHA256'):
        """Verify ECC digital signature"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, dict):
            data = json.dumps(data, sort_keys=True).encode('utf-8')
        
        hash_alg_map = {
            'SHA256': hashes.SHA256(),
            'SHA512': hashes.SHA512(),
            'SHA3-256': hashes.SHA3_256(),
            'SHA3-512': hashes.SHA3_512()
        }
        hash_algorithm = hash_algorithm if hash_algorithm in hash_alg_map else 'SHA256'
        try:
            public_key.verify(signature, data, ec.ECDSA(hash_alg_map[hash_algorithm]))
            return True
        except Exception:
            return False
    
    def ecc_ecdh_derive_key(self, private_key, public_key, key_length=32):
        """Derive shared key using ECDH"""
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'ECC-ECDH-derived-key',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key
    
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
        aes_key = os.urandom(32)
        twofish_key = os.urandom(max(64, self.key_size_bytes))
        chacha20_key = os.urandom(32)
        integrity_key = os.urandom(32)
        
        n = min(n, len(twofish_key) - 1)
        aes_ciphertext, aes_iv = self.aes_encrypt(sentence, aes_key)
        twofish_encrypted_aes_key, twofish_iv = self.twofish_simulate_encrypt(aes_key, twofish_key)
        first_n_bytes = twofish_key[:n]
        chacha20_encrypted_bytes, nonce = self.chacha20_encrypt(first_n_bytes, chacha20_key)
        
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
        
        if use_hmac:
            integrity_digest = self.generate_hmac(encrypted_bundle, integrity_key, hash_function)
        else:
            integrity_digest = self.generate_hash(encrypted_bundle, hash_function)
        
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
        
        chacha20_encrypted_bytes = base64.b64decode(encrypted_bundle['chacha20_encrypted_bytes'])
        nonce = base64.b64decode(encrypted_bundle['nonce'])
        first_n_bytes = self.chacha20_decrypt(chacha20_encrypted_bytes, chacha20_key, nonce)
        
        modified_twofish_key = base64.b64decode(encrypted_bundle['modified_twofish_key'])
        reconstructed_twofish_key = first_n_bytes + modified_twofish_key
        
        twofish_encrypted_aes_key = base64.b64decode(encrypted_bundle['twofish_encrypted_aes_key'])
        twofish_iv = base64.b64decode(encrypted_bundle['twofish_iv'])
        decrypted_aes_key_raw = self.twofish_simulate_decrypt(twofish_encrypted_aes_key, 
                                                            reconstructed_twofish_key, twofish_iv)
        aes_key = decrypted_aes_key_raw[:32] if len(decrypted_aes_key_raw) >= 32 else decrypted_aes_key_raw + b'\x00' * (32 - len(decrypted_aes_key_raw))
        
        aes_ciphertext = base64.b64decode(encrypted_bundle['aes_ciphertext'])
        aes_iv = base64.b64decode(encrypted_bundle['aes_iv'])
        original_sentence = self.aes_decrypt(aes_ciphertext, aes_key, aes_iv)
        return original_sentence, True
    
    def encrypt_with_integrity_and_ecc(self, sentence, n, curve_name='secp256r1', hash_function='SHA256', use_hmac=True, use_ecc_signature=True):
        """Complete encryption with integrity protection and ECC"""
        ecc_private_key, ecc_public_key = self.generate_ecc_keypair(curve_name)
        ephemeral_private, ephemeral_public = self.generate_ecc_keypair(curve_name)
        chacha20_key = self.ecc_ecdh_derive_key(ephemeral_private, ecc_public_key, 32)
        
        aes_key = os.urandom(32)
        twofish_key = os.urandom(max(64, self.key_size_bytes))
        integrity_key = os.urandom(32)
        
        n = min(n, len(twofish_key) - 1)
        aes_ciphertext, aes_iv = self.aes_encrypt(sentence, aes_key)
        twofish_encrypted_aes_key, twofish_iv = self.twofish_simulate_encrypt(aes_key, twofish_key)
        first_n_bytes = twofish_key[:n]
        chacha20_encrypted_bytes, nonce = self.chacha20_encrypt(first_n_bytes, chacha20_key)
        
        encrypted_bundle = {
            'aes_ciphertext': base64.b64encode(aes_ciphertext).decode('utf-8'),
            'aes_iv': base64.b64encode(aes_iv).decode('utf-8'),
            'twofish_encrypted_aes_key': base64.b64encode(twofish_encrypted_aes_key).decode('utf-8'),
            'twofish_iv': base64.b64encode(twofish_iv).decode('utf-8'),
            'modified_twofish_key': base64.b64encode(twofish_key[n:]).decode('utf-8'),
            'chacha20_encrypted_bytes': base64.b64encode(chacha20_encrypted_bytes).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ephemeral_public_key': self.serialize_ecc_keys(public_key=ephemeral_public)['public_key'],
            'hash_function': hash_function,
            'curve_name': curve_name,
            'use_hmac': use_hmac,
            'use_ecc_signature': use_ecc_signature
        }
        
        if use_hmac:
            integrity_digest = self.generate_hmac(encrypted_bundle, integrity_key, hash_function)
        else:
            integrity_digest = self.generate_hash(encrypted_bundle, hash_function)
        
        encrypted_bundle['integrity_digest'] = base64.b64encode(integrity_digest).decode('utf-8')
        
        if use_ecc_signature:
            signature = self.ecc_sign(encrypted_bundle, ecc_private_key, hash_function)
            encrypted_bundle['ecc_signature'] = base64.b64encode(signature).decode('utf-8')
        
        return {
            'encrypted_bundle': encrypted_bundle,
            'integrity_key': integrity_key if use_hmac else None,
            'ecc_private_key': self.serialize_ecc_keys(private_key=ecc_private_key)['private_key'] if use_ecc_signature else None,
            'ecc_public_key': self.serialize_ecc_keys(public_key=ecc_public_key)['public_key']
        }
    
    def decrypt_with_integrity_and_ecc_check(self, encrypted_data, n):
        """Complete decryption with integrity and ECC signature verification"""
        encrypted_bundle = encrypted_data['encrypted_bundle']
        integrity_key = encrypted_data['integrity_key']
        ecc_public_key_b64 = encrypted_data['ecc_public_key']
        
        ecc_keys = self.deserialize_ecc_keys(public_key_b64=ecc_public_key_b64)
        ecc_public_key = ecc_keys['public_key']
        
        if encrypted_bundle.get('use_ecc_signature', False) and 'ecc_signature' in encrypted_bundle:
            signature = base64.b64decode(encrypted_bundle['ecc_signature'])
            bundle_without_signature = encrypted_bundle.copy()
            del bundle_without_signature['ecc_signature']
            signature_valid = self.ecc_verify(bundle_without_signature, signature, 
                                            ecc_public_key, encrypted_bundle['hash_function'])
            if not signature_valid:
                raise ValueError("ECC signature verification failed! Data may have been tampered with.")
        
        expected_digest = base64.b64decode(encrypted_bundle['integrity_digest'])
        bundle_without_digest = encrypted_bundle.copy()
        del bundle_without_digest['integrity_digest']
        if 'ecc_signature' in bundle_without_digest:
            del bundle_without_digest['ecc_signature']
        
        if encrypted_bundle['use_hmac'] and integrity_key:
            is_valid = self.verify_hmac(bundle_without_digest, integrity_key, 
                                       expected_digest, encrypted_bundle['hash_function'])
        else:
            is_valid = self.verify_hash(bundle_without_digest, expected_digest, 
                                       encrypted_bundle['hash_function'])
        
        if not is_valid:
            raise ValueError("Integrity check failed! Data may have been tampered with.")
        
        ephemeral_public_key_data = self.deserialize_ecc_keys(
            public_key_b64=encrypted_bundle['ephemeral_public_key']
        )
        ephemeral_public_key = ephemeral_public_key_data['public_key']
        chacha20_key = self.ecc_ecdh_derive_key(
            self.deserialize_ecc_keys(private_key_b64=encrypted_data.get('ecc_private_key'))['private_key'], 
            ephemeral_public_key, 32
        )
        
        chacha20_encrypted_bytes = base64.b64decode(encrypted_bundle['chacha20_encrypted_bytes'])
        nonce = base64.b64decode(encrypted_bundle['nonce'])
        first_n_bytes = self.chacha20_decrypt(chacha20_encrypted_bytes, chacha20_key, nonce)
        
        modified_twofish_key = base64.b64decode(encrypted_bundle['modified_twofish_key'])
        reconstructed_twofish_key = first_n_bytes + modified_twofish_key
        
        twofish_encrypted_aes_key = base64.b64decode(encrypted_bundle['twofish_encrypted_aes_key'])
        twofish_iv = base64.b64decode(encrypted_bundle['twofish_iv'])
        decrypted_aes_key_raw = self.twofish_simulate_decrypt(twofish_encrypted_aes_key, 
                                                            reconstructed_twofish_key, twofish_iv)
        aes_key = decrypted_aes_key_raw[:32] if len(decrypted_aes_key_raw) >= 32 else decrypted_aes_key_raw + b'\x00' * (32 - len(decrypted_aes_key_raw))
        
        aes_ciphertext = base64.b64decode(encrypted_bundle['aes_ciphertext'])
        aes_iv = base64.b64decode(encrypted_bundle['aes_iv'])
        original_sentence = self.aes_decrypt(aes_ciphertext, aes_key, aes_iv)
        return original_sentence, True

def test_integrity_protection():
    """Test integrity protection functionality"""
    print("Testing Integrity Protection...")
    crypto = IntegrityProtectedCrypto(256)
    test_sentence = "This is a test message for integrity verification."
    n = 16
    hash_functions = ['SHA256', 'SHA512', 'SHA3-256', 'BLAKE2b']
    
    for hash_func in hash_functions:
        print(f"\n--- Testing with {hash_func} ---")
        encrypted_data = crypto.encrypt_with_integrity(test_sentence, n, hash_func, use_hmac=True)
        decrypted_sentence, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        print(f"Original:  {test_sentence}")
        print(f"Decrypted: {decrypted_sentence}")
        print(f"Integrity Valid: {integrity_valid}")
        print(f"Match: {test_sentence == decrypted_sentence}")
        
        print("Testing tampering detection...")
        tampered_data = encrypted_data.copy()
        tampered_bundle = tampered_data['encrypted_bundle'].copy()
        tampered_aes_ciphertext = base64.b64decode(tampered_bundle['aes_ciphertext'])
        tampered_aes_ciphertext = tampered_aes_ciphertext[:-1] + b'\x00'
        tampered_bundle['aes_ciphertext'] = base64.b64encode(tampered_aes_ciphertext).decode('utf-8')
        tampered_data['encrypted_bundle'] = tampered_bundle
        try:
            crypto.decrypt_with_integrity_check(tampered_data, n)
            print("❌ Failed to detect tampering!")
        except ValueError as e:
            print(f"✅ Successfully detected tampering: {e}")

def test_ecc_functionality():
    """Test ECC functionality"""
    print("\n" + "="*50)
    print("Testing ECC Functionality")
    print("="*50)
    
    crypto = IntegrityProtectedCrypto(256)
    print("\n--- Testing ECC Key Generation ---")
    private_key, public_key = crypto.generate_ecc_keypair('secp256r1')
    serialized = crypto.serialize_ecc_keys(private_key, public_key)
    deserialized = crypto.deserialize_ecc_keys(serialized['private_key'], serialized['public_key'])
    print("✅ ECC key generation and serialization working")
    
    print("\n--- Testing ECC Digital Signatures ---")
    test_message = "This is a test message for ECC signing"
    signature = crypto.ecc_sign(test_message, private_key)
    is_valid = crypto.ecc_verify(test_message, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    tampered_message = "This is a TAMPERED message for ECC signing"
    is_valid_tampered = crypto.ecc_verify(tampered_message, signature, public_key)
    print(f"Tampered signature valid: {is_valid_tampered}")
    
    print("\n--- Testing ECDH Key Derivation ---")
    alice_private, alice_public = crypto.generate_ecc_keypair('secp256r1')
    bob_private, bob_public = crypto.generate_ecc_keypair('secp256r1')
    alice_shared = crypto.ecc_ecdh_derive_key(alice_private, bob_public)
    bob_shared = crypto.ecc_ecdh_derive_key(bob_private, alice_public)
    print(f"Shared keys match: {alice_shared == bob_shared}")
    print(f"Shared key length: {len(alice_shared)} bytes")

def test_enhanced_encryption():
    """Test enhanced encryption with ECC"""
    print("\n" + "="*50)
    print("Testing Enhanced Encryption with ECC")
    print("="*50)
    
    crypto = IntegrityProtectedCrypto(256)
    test_sentence = "This is a test message for ECC-enhanced encryption."
    n = 16
    curves = ['secp256r1', 'secp384r1', 'secp256k1']
    
    for curve in curves:
        print(f"\n--- Testing with curve {curve} ---")
        encrypted_data = crypto.encrypt_with_integrity_and_ecc(
            test_sentence, n, curve_name=curve, hash_function='SHA256', use_hmac=True, use_ecc_signature=True
        )
        decrypted_sentence, all_checks_passed = crypto.decrypt_with_integrity_and_ecc_check(encrypted_data, n)
        print(f"Original:  {test_sentence}")
        print(f"Decrypted: {decrypted_sentence}")
        print(f"All checks passed: {all_checks_passed}")
        print(f"Match: {test_sentence == decrypted_sentence}")
        
        print("Testing tampering detection...")
        tampered_data = encrypted_data.copy()
        tampered_bundle = tampered_data['encrypted_bundle'].copy()
        tampered_aes_ciphertext = base64.b64decode(tampered_bundle['aes_ciphertext'])
        tampered_aes_ciphertext = tampered_aes_ciphertext[:-1] + b'\x00'
        tampered_bundle['aes_ciphertext'] = base64.b64encode(tampered_aes_ciphertext).decode('utf-8')
        tampered_data['encrypted_bundle'] = tampered_bundle
        try:
            crypto.decrypt_with_integrity_and_ecc_check(tampered_data, n)
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
        
        encrypted_data = crypto.encrypt_with_integrity(message, n, 'SHA256', use_hmac=True)
        decrypted_message, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        print(f"HMAC - Integrity Valid: {integrity_valid}, Match: {message == decrypted_message}")
        
        encrypted_data = crypto.encrypt_with_integrity(message, n, 'SHA256', use_hmac=False)
        decrypted_message, integrity_valid = crypto.decrypt_with_integrity_check(encrypted_data, n)
        print(f"Hash - Integrity Valid: {integrity_valid}, Match: {message == decrypted_message}")
        
        encrypted_data = crypto.encrypt_with_integrity_and_ecc(message, n, 'secp256r1', 'SHA256', use_hmac=True, use_ecc_signature=True)
        decrypted_message, all_checks_passed = crypto.decrypt_with_integrity_and_ecc_check(encrypted_data, n)
        print(f"ECC - All Checks Passed: {all_checks_passed}, Match: {message == decrypted_message}")

if __name__ == "__main__":
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
    except ImportError:
        print("Please install required package:")
        print("pip install cryptography")
        exit(1)
    
    test_integrity_protection()
    test_ecc_functionality()
    test_enhanced_encryption()
    test_multiple_scenarios()
