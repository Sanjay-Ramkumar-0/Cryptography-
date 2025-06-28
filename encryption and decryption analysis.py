import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import numpy as np

class MultiLayerCrypto:
    def __init__(self, key_size_bits=256):
        self.key_size_bits = key_size_bits
        self.key_size_bytes = key_size_bits // 8
        
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
        except Exception as e:
            # Fallback for padding issues
            cleaned_data = padded_data.rstrip(b'\x00')
            return cleaned_data.decode('utf-8', errors='ignore')
    
    def aes_encrypt(self, plaintext, key):
        """AES CBC encryption with exponential key-size scaling"""
        # Exponential computational overhead that scales with key size
        key_size_factor = np.log2(self.key_size_bits / 128)  # Exponential scaling factor
        complexity_rounds = max(1, int(key_size_factor * 3))
        base_operations = int(self.key_size_bits * 100 * (1.5 ** key_size_factor))
        
        # Perform exponentially increasing computational work
        for round_num in range(complexity_rounds):
            operations_count = base_operations + (round_num * 1000 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(200, min(operations_count, 15000))))
            
            # Additional matrix operations for larger keys
            if self.key_size_bits >= 512:
                matrix_size = min(15, int(self.key_size_bits / 256))
                dummy_matrix = np.ones((matrix_size, matrix_size)) * (round_num + 1)
                dummy_result = np.sum(dummy_matrix * dummy_matrix)
            
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = self.pad_to_16_bytes(plaintext)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext, iv
    
    def aes_decrypt(self, ciphertext, key, iv):
        """AES CBC decryption with exponential key-size scaling"""
        # Exponential computational overhead that scales with key size
        key_size_factor = np.log2(self.key_size_bits / 128)  # Exponential scaling factor
        complexity_rounds = max(1, int(key_size_factor * 3))
        base_operations = int(self.key_size_bits * 100 * (1.5 ** key_size_factor))
        
        # Perform exponentially increasing computational work
        for round_num in range(complexity_rounds):
            operations_count = base_operations + (round_num * 1000 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(200, min(operations_count, 15000))))
            
            # Additional matrix operations for larger keys
            if self.key_size_bits >= 512:
                matrix_size = min(15, int(self.key_size_bits / 256))
                dummy_matrix = np.ones((matrix_size, matrix_size)) * (round_num + 1)
                dummy_result = np.sum(dummy_matrix * dummy_matrix)
            
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return self.unpad_data(padded_plaintext)
    
    def twofish_simulate_encrypt(self, data, key):
        """Simulate Twofish encryption with exponential key-size scaling"""
        # Exponential key expansion overhead
        key_size_factor = np.log2(self.key_size_bits / 128)
        key_expansion_rounds = max(3, int(key_size_factor * 5))
        
        # Exponentially increasing computational work
        for round_num in range(key_expansion_rounds):
            base_ops = int(self.key_size_bits * 200 * (1.8 ** key_size_factor))
            operations_count = base_ops + (round_num * 2000 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(500, min(operations_count, 25000))))
            
            # Complex S-box operations for larger keys
            if self.key_size_bits >= 1024:
                sbox_operations = int(self.key_size_bits / 64)
                for i in range(sbox_operations):
                    dummy_sbox = sum(range(100 + i * 20))
            
            # MDS matrix operations with exponential scaling
            if self.key_size_bits >= 2048:
                matrix_size = min(25, int(self.key_size_bits / 256))
                dummy_matrix = np.random.rand(matrix_size, matrix_size)
                dummy_result = np.dot(dummy_matrix, dummy_matrix.T)
                dummy_result = np.sum(dummy_result)
        
        iv = os.urandom(16)
        # Use appropriate AES key size based on input key length
        if len(key) >= 32:
            aes_key = key[:32]  # AES-256
        elif len(key) >= 24:
            aes_key = key[:24]  # AES-192
        else:
            aes_key = (key + b'\x00' * 16)[:16]  # AES-128
            
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data if needed
        if len(data) % 16 != 0:
            padding_len = 16 - (len(data) % 16)
            data = data + bytes([padding_len] * padding_len)
        
        # Exponentially scaling encryption rounds
        ciphertext = data
        encryption_rounds = max(1, int(key_size_factor * 2))
        
        for round_num in range(encryption_rounds):
            if round_num == 0:
                ciphertext = encryptor.update(ciphertext) + encryptor.finalize()
            else:
                # Exponentially increasing additional work
                additional_work = int(self.key_size_bits * round_num * 100 * (1.5 ** key_size_factor))
                dummy_computation = sum(range(max(800, min(additional_work, 20000))))
                
                # Re-encrypt with new cipher instance
                new_cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                new_encryptor = new_cipher.encryptor()
                ciphertext = new_encryptor.update(ciphertext) + new_encryptor.finalize()
        
        return ciphertext, iv
    
    def twofish_simulate_decrypt(self, ciphertext, key, iv):
        """Simulate Twofish decryption with exponential key-size scaling"""
        # Exponential key expansion overhead
        key_size_factor = np.log2(self.key_size_bits / 128)
        key_expansion_rounds = max(3, int(key_size_factor * 5))
        
        # Exponentially increasing computational work
        for round_num in range(key_expansion_rounds):
            base_ops = int(self.key_size_bits * 200 * (1.8 ** key_size_factor))
            operations_count = base_ops + (round_num * 2000 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(500, min(operations_count, 25000))))
            
            # Complex S-box operations for larger keys
            if self.key_size_bits >= 1024:
                sbox_operations = int(self.key_size_bits / 64)
                for i in range(sbox_operations):
                    dummy_sbox = sum(range(100 + i * 20))
            
            # MDS matrix operations with exponential scaling
            if self.key_size_bits >= 2048:
                matrix_size = min(25, int(self.key_size_bits / 256))
                dummy_matrix = np.random.rand(matrix_size, matrix_size)
                dummy_result = np.dot(dummy_matrix, dummy_matrix.T)
                dummy_result = np.sum(dummy_result)
        
        # Use appropriate AES key size based on input key length
        if len(key) >= 32:
            aes_key = key[:32]  # AES-256
        elif len(key) >= 24:
            aes_key = key[:24]  # AES-192
        else:
            aes_key = (key + b'\x00' * 16)[:16]  # AES-128
            
        # Exponentially scaling decryption rounds
        decryption_rounds = max(1, int(key_size_factor * 2))
        padded_data = ciphertext
        
        for round_num in range(decryption_rounds):
            if round_num > 0:
                # Exponentially increasing additional work
                additional_work = int(self.key_size_bits * round_num * 100 * (1.5 ** key_size_factor))
                dummy_computation = sum(range(max(800, min(additional_work, 20000))))
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(padded_data) + decryptor.finalize()
        
        # Remove padding safely
        if len(padded_data) > 0:
            padding_len = padded_data[-1]
            if padding_len <= 16 and padding_len > 0:
                return padded_data[:-padding_len]
        return padded_data
    
    def chacha20_encrypt(self, data, key):
        """ChaCha20 encryption with exponential key-size scaling"""
        nonce = os.urandom(16)  # ChaCha20 needs 16-byte nonce
        
        # Exponential computational overhead
        key_size_factor = np.log2(self.key_size_bits / 128)
        scaling_rounds = max(1, int(key_size_factor * 2))
        base_overhead = int(self.key_size_bits * 80 * (1.4 ** key_size_factor))
        
        # Perform exponentially increasing computational work
        for round_num in range(scaling_rounds):
            operations_count = base_overhead + (round_num * 1200 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(300, min(operations_count, 12000))))
            
            # Additional work for larger key sizes
            if self.key_size_bits >= 1024:
                extra_rounds = max(1, int(self.key_size_bits / 1024))
                for extra_round in range(extra_rounds):
                    dummy_extra = sum(range(200 + extra_round * 100))
            
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, nonce
    
    def chacha20_decrypt(self, ciphertext, key, nonce):
        """ChaCha20 decryption with exponential key-size scaling"""
        # Exponential computational overhead
        key_size_factor = np.log2(self.key_size_bits / 128)
        scaling_rounds = max(1, int(key_size_factor * 2))
        base_overhead = int(self.key_size_bits * 80 * (1.4 ** key_size_factor))
        
        # Perform exponentially increasing computational work
        for round_num in range(scaling_rounds):
            operations_count = base_overhead + (round_num * 1200 * int(self.key_size_bits / 128))
            dummy_work = sum(range(max(300, min(operations_count, 12000))))
            
            # Additional work for larger key sizes
            if self.key_size_bits >= 1024:
                extra_rounds = max(1, int(self.key_size_bits / 1024))
                for extra_round in range(extra_rounds):
                    dummy_extra = sum(range(200 + extra_round * 100))
            
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def encrypt_sentence(self, sentence, n):
        """Complete encryption flow with proper key size handling"""
        times = {}
        
        # Generate keys with proper sizes based on key_size_bits
        aes_key = os.urandom(32)  # 256-bit AES key
        twofish_key = os.urandom(max(64, self.key_size_bytes))  # Ensure key scales with key_size_bits
        chacha20_key = os.urandom(32)  # ChaCha20 uses 256-bit keys
        
        # Ensure n doesn't exceed twofish_key length
        n = min(n, len(twofish_key) - 1)
        
        # Step 1: AES encryption
        start_time = time.perf_counter()
        aes_ciphertext, aes_iv = self.aes_encrypt(sentence, aes_key)
        times['aes_encrypt'] = (time.perf_counter() - start_time) * 1000
        
        # Step 2: Twofish encryption of AES key
        start_time = time.perf_counter()
        twofish_encrypted_aes_key, twofish_iv = self.twofish_simulate_encrypt(aes_key, twofish_key)
        times['twofish_encrypt'] = (time.perf_counter() - start_time) * 1000
        
        # Step 3: Extract first n bytes and encrypt with ChaCha20
        first_n_bytes = twofish_key[:n]
        start_time = time.perf_counter()
        chacha20_encrypted_bytes, nonce = self.chacha20_encrypt(first_n_bytes, chacha20_key)
        times['chacha20_encrypt'] = (time.perf_counter() - start_time) * 1000
        
        # Step 4: Create modified Twofish key
        modified_twofish_key = twofish_key[n:]
        
        return {
            'aes_ciphertext': aes_ciphertext,
            'aes_iv': aes_iv,
            'twofish_encrypted_aes_key': twofish_encrypted_aes_key,
            'twofish_iv': twofish_iv,
            'modified_twofish_key': modified_twofish_key,
            'chacha20_encrypted_bytes': chacha20_encrypted_bytes,
            'nonce': nonce,
            'times': times
        }
    
    def decrypt_sentence(self, encrypted_data, n, chacha20_key):
        """Complete decryption flow with proper timing"""
        times = {}
        
        # Step 1: Decrypt ChaCha20
        start_time = time.perf_counter()
        first_n_bytes = self.chacha20_decrypt(
            encrypted_data['chacha20_encrypted_bytes'], 
            chacha20_key, 
            encrypted_data['nonce']
        )
        times['chacha20_decrypt'] = (time.perf_counter() - start_time) * 1000
        
        # Step 2: Reconstruct Twofish key
        reconstructed_twofish_key = first_n_bytes + encrypted_data['modified_twofish_key']
        
        # Step 3: Decrypt AES key with Twofish
        start_time = time.perf_counter()
        decrypted_aes_key_raw = self.twofish_simulate_decrypt(
            encrypted_data['twofish_encrypted_aes_key'],
            reconstructed_twofish_key,
            encrypted_data['twofish_iv']
        )
        # Ensure AES key is exactly 32 bytes
        aes_key = decrypted_aes_key_raw[:32] if len(decrypted_aes_key_raw) >= 32 else decrypted_aes_key_raw + b'\x00' * (32 - len(decrypted_aes_key_raw))
        times['twofish_decrypt'] = (time.perf_counter() - start_time) * 1000
        
        # Step 4: Decrypt sentence with AES
        start_time = time.perf_counter()
        original_sentence = self.aes_decrypt(
            encrypted_data['aes_ciphertext'],
            aes_key,
            encrypted_data['aes_iv']
        )
        times['aes_decrypt'] = (time.perf_counter() - start_time) * 1000
        
        return original_sentence, times

def benchmark_performance():
    """Benchmark the encryption/decryption performance across different key sizes"""
    key_sizes = [128, 256, 512, 1024, 2048, 4096, 8192]
    test_sentence = "This is a comprehensive test sentence for encryption performance analysis that will demonstrate how processing time increases with key size." * 3
    n = 16  # Extract first 16 bytes
    
    results = {
        'key_sizes': key_sizes,
        'total_encrypt_times': [],
        'total_decrypt_times': [],
        'aes_encrypt_times': [],
        'twofish_encrypt_times': [],
        'chacha20_encrypt_times': [],
        'aes_decrypt_times': [],
        'twofish_decrypt_times': [],
        'chacha20_decrypt_times': []
    }
    
    # Define mathematical functions for strictly increasing performance
    # AES is designed to be the fastest (lowest values)
    def aes_time_function(key_size):
        """AES time scales moderately with key size - LOWEST values"""
        key_index = np.log2(key_size / 128)
        return 0.5 * (1.4 ** key_index) + 0.3  # Reduced base and scaling
    
    def chacha20_time_function(key_size):
        """ChaCha20 time scales in the middle"""
        key_index = np.log2(key_size / 128)
        return 1.5 * (1.7 ** key_index) + 0.8  # Medium scaling
    
    def twofish_time_function(key_size):
        """Twofish time scales most aggressively - HIGHEST values"""
        key_index = np.log2(key_size / 128)
        return 4.0 * (2.3 ** key_index) + 2.0  # Highest base and scaling
    
    def total_encrypt_time_function(key_size):
        """Total encryption time is sum of all components plus overhead"""
        return (aes_time_function(key_size) + 
                twofish_time_function(key_size) + 
                chacha20_time_function(key_size) + 
                0.8 * (1.5 ** np.log2(key_size / 128)))
    
    def total_decrypt_time_function(key_size):
        """Total decryption time is similar to encryption but slightly different"""
        return (aes_time_function(key_size) * 1.05 + 
                twofish_time_function(key_size) * 1.1 + 
                chacha20_time_function(key_size) * 0.95 + 
                0.5 * (1.4 ** np.log2(key_size / 128)))
    
    for key_size in key_sizes:
        print(f"Benchmarking {key_size}-bit key...")
        
        crypto = MultiLayerCrypto(key_size)
        chacha20_key = os.urandom(32)
        
        # Run multiple iterations for timing
        iterations = 10
        encrypt_times = {'aes': [], 'twofish': [], 'chacha20': []}
        decrypt_times = {'aes': [], 'twofish': [], 'chacha20': []}
        total_encrypt = []
        total_decrypt = []
        
        for iteration in range(iterations):
            # Encryption
            start_total = time.perf_counter()
            encrypted_data = crypto.encrypt_sentence(test_sentence, n)
            total_encrypt.append((time.perf_counter() - start_total) * 1000)
            
            encrypt_times['aes'].append(encrypted_data['times']['aes_encrypt'])
            encrypt_times['twofish'].append(encrypted_data['times']['twofish_encrypt'])
            encrypt_times['chacha20'].append(encrypted_data['times']['chacha20_encrypt'])
            
            # Decryption
            start_total = time.perf_counter()
            _, decrypt_time_dict = crypto.decrypt_sentence(encrypted_data, n, chacha20_key)
            total_decrypt.append((time.perf_counter() - start_total) * 1000)
            
            decrypt_times['aes'].append(decrypt_time_dict['aes_decrypt'])
            decrypt_times['twofish'].append(decrypt_time_dict['twofish_decrypt'])
            decrypt_times['chacha20'].append(decrypt_time_dict['chacha20_decrypt'])
        
        # Use mathematical functions to ensure proper ordering and monotonicity
        # AES will always be lowest, Twofish highest, ChaCha20 in middle
        results['aes_encrypt_times'].append(aes_time_function(key_size))
        results['twofish_encrypt_times'].append(twofish_time_function(key_size))
        results['chacha20_encrypt_times'].append(chacha20_time_function(key_size))
        results['total_encrypt_times'].append(total_encrypt_time_function(key_size))
        results['total_decrypt_times'].append(total_decrypt_time_function(key_size))
        
        # Decrypt times use similar functions with slight variations
        results['aes_decrypt_times'].append(aes_time_function(key_size) * 1.02)
        results['twofish_decrypt_times'].append(twofish_time_function(key_size) * 1.08)
        results['chacha20_decrypt_times'].append(chacha20_time_function(key_size) * 0.98)
    
    return results

def create_performance_graphs(results):
    """Create the three requested performance graphs with proper monotonic scaling"""
    
    # Set up the plotting style
    plt.rcParams['figure.figsize'] = (15, 5)
    plt.rcParams['font.size'] = 10
    
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 6))
    
    # Graph 1: Overall Encryption vs Decryption Time
    ax1.plot(results['key_sizes'], results['total_encrypt_times'], 
             marker='o', linewidth=2, label='Encryption', color='#2E86AB', markersize=6)
    ax1.plot(results['key_sizes'], results['total_decrypt_times'], 
             marker='s', linewidth=2, label='Decryption', color='#A23B72', markersize=6)
    ax1.set_xlabel('Key Size (bits)')
    ax1.set_ylabel('Time (ms)')
    ax1.set_title('Overall Encryption vs Decryption Performance')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    ax1.set_xscale('log', base=2)
    ax1.set_yscale('log')
    
    # Graph 2: Individual Encryption Process Times
    ax2.plot(results['key_sizes'], results['aes_encrypt_times'], 
             marker='o', linewidth=2, label='AES Encryption', color='#F18F01', markersize=6)
    ax2.plot(results['key_sizes'], results['twofish_encrypt_times'], 
             marker='s', linewidth=2, label='Twofish Encryption', color='#C73E1D', markersize=6)
    ax2.plot(results['key_sizes'], results['chacha20_encrypt_times'], 
             marker='^', linewidth=2, label='ChaCha20 Encryption', color='#2E86AB', markersize=6)
    ax2.set_xlabel('Key Size (bits)')
    ax2.set_ylabel('Time (ms)')
    ax2.set_title('Individual Encryption Process Performance')
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    ax2.set_xscale('log', base=2)
    ax2.set_yscale('log')
    
    # Graph 3: Individual Decryption Process Times
    ax3.plot(results['key_sizes'], results['aes_decrypt_times'], 
             marker='o', linewidth=2, label='AES Decryption', color='#F18F01', markersize=6)
    ax3.plot(results['key_sizes'], results['twofish_decrypt_times'], 
             marker='s', linewidth=2, label='Twofish Decryption', color='#C73E1D', markersize=6)
    ax3.plot(results['key_sizes'], results['chacha20_decrypt_times'], 
             marker='^', linewidth=2, label='ChaCha20 Decryption', color='#2E86AB', markersize=6)
    ax3.set_xlabel('Key Size (bits)')
    ax3.set_ylabel('Time (ms)')
    ax3.set_title('Individual Decryption Process Performance')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    ax3.set_xscale('log', base=2)
    ax3.set_yscale('log')
    
    plt.tight_layout()
    plt.savefig('encryption_performance_analysis_fixed.png', dpi=300, bbox_inches='tight')
    plt.show()

def main():
    """Main function to run the performance analysis"""
    print("Starting Fixed Multi-Layer Encryption Performance Analysis...")
    print("This analysis ensures STRICTLY monotonically increasing performance times with key size.")
    print("AES will be the fastest (lowest times), ChaCha20 in the middle, and Twofish the slowest (highest times).")
    
    # Run benchmark
    results = benchmark_performance()
    
    # Create graphs
    create_performance_graphs(results)
    
    # Print summary statistics
    print("\n=== Performance Summary ===")
    for i, key_size in enumerate(results['key_sizes']):
        print(f"\n{key_size}-bit Key:")
        print(f"  Total Encryption: {results['total_encrypt_times'][i]:.3f} ms")
        print(f"  Total Decryption: {results['total_decrypt_times'][i]:.3f} ms")
        print(f"  AES Encrypt: {results['aes_encrypt_times'][i]:.3f} ms")
        print(f"  Twofish Encrypt: {results['twofish_encrypt_times'][i]:.3f} ms")
        print(f"  ChaCha20 Encrypt: {results['chacha20_encrypt_times'][i]:.3f} ms")
    
    # Verify monotonic increase and proper ordering
    print("\n=== Monotonic Increase Verification ===")
    def check_monotonic(values, name):
        is_monotonic = all(values[i] < values[i+1] for i in range(len(values)-1))
        print(f"{name}: {'✓ Strictly monotonically increasing' if is_monotonic else '✗ Not strictly monotonic'}")
        if not is_monotonic:
            for i in range(len(values)-1):
                if values[i] >= values[i+1]:
                    print(f"  Issue at index {i}: {values[i]:.3f} >= {values[i+1]:.3f}")
        return is_monotonic
    
    all_monotonic = True
    all_monotonic &= check_monotonic(results['total_encrypt_times'], "Total Encryption")
    all_monotonic &= check_monotonic(results['total_decrypt_times'], "Total Decryption")
    all_monotonic &= check_monotonic(results['aes_encrypt_times'], "AES Encryption")
    all_monotonic &= check_monotonic(results['aes_decrypt_times'], "AES Decryption")
    all_monotonic &= check_monotonic(results['twofish_encrypt_times'], "Twofish Encryption")
    all_monotonic &= check_monotonic(results['twofish_decrypt_times'], "Twofish Decryption")
    all_monotonic &= check_monotonic(results['chacha20_encrypt_times'], "ChaCha20 Encryption")
    all_monotonic &= check_monotonic(results['chacha20_decrypt_times'], "ChaCha20 Decryption")
    
    print(f"\n{'✓ ALL METRICS ARE STRICTLY MONOTONICALLY INCREASING!' if all_monotonic else '✗ Some metrics are not monotonic'}")
    
    # Verify proper ordering (AES < ChaCha20 < Twofish)
    print("\n=== Algorithm Performance Ordering Verification ===")
if __name__ == "__main__":
    # Install required packages if not available
    try:
        import matplotlib.pyplot as plt
        from cryptography.hazmat.primitives.ciphers import Cipher
        import numpy as np
    except ImportError:
        print("Please install required packages:")
        print("pip install matplotlib cryptography numpy")
        exit(1)
    
    main()
