IntegrityProtectedCrypto
Python
License: MIT
Cryptography Library
A Four-Layer Hybrid Cryptosystem with ECC-Based Key Derivation, Tunable n-Byte Key Splitting, and Comprehensive Integrity Protection
This repository implements IntegrityProtectedCrypto, a novel hybrid encryption system combining symmetric ciphers (AES-256-CBC, simulated Twofish, ChaCha20) with elliptic curve cryptography (ECDH for key derivation, optional ECDSA signatures) to achieve confidentiality, integrity, authenticity, tamper resistance, and perfect forward secrecy.
The standout feature is the tunable n-byte key-splitting mechanism: only the first n bytes of the Twofish key are encrypted using ChaCha20 (with an ECDH-derived key), while the remainder is sent in cleartext — exponentially increasing security as n grows.
🚀 Key Features

Four-Layer Encryption Pipeline:
AES-256-CBC for payload encryption
Simulated Twofish for AES key wrapping
ChaCha20 + ECDH/HKDF for protecting first n bytes of Twofish key
HMAC-SHA256/512 (or hash) + optional ECDSA signatures for bundle integrity/authenticity

Tunable Security: Adjust n (8–256 bytes) to balance security vs bandwidth
Perfect Forward Secrecy: Ephemeral ECDH keys discarded after use
100% Tamper Detection: Bundle-wide integrity checks
Multiple ECC Curves: secp256r1, secp384r1, secp521r1, secp256k1
Pure Python: Only uses the battle-tested cryptography library

📊 Visual Overview
Encryption Pipeline
Encryption Flowchart
The process begins with padding and AES encryption, followed by Twofish key wrapping, n-byte extraction and ChaCha20 protection, and final bundle creation with integrity tag.
Decryption Pipeline
Decryption Flowchart
Decryption verifies integrity first, derives the ChaCha20 key via ECDH, reconstructs the Twofish key, recovers the AES key, and decrypts the payload — rejecting any tampering immediately.
Security Analysis Graphs
Security Analysis Graphs
These graphs illustrate:

Left: Cracking time (log scale) vs n-parameter — exponential growth, reaching infeasible levels (>10¹⁰ years) at moderate n
Center: Bar chart showing individual contributions of each layer (AES, Twofish simulation, ChaCha20 protection, n-parameter entropy)
Right: Total effective security for fixed n=32 across key sizes — demonstrating multi-layer defense in depth

Performance Analysis Graphs
Performance Graphs
These graphs show:

Left: Overall encryption/decryption time vs message size — near-linear scaling
Center/Right: Per-algorithm breakdown — ChaCha20 fastest, AES dominant for large payloads, minimal overhead from key management

🛠️ Installation
Bashgit clone https://github.com/Sanjay-Ramkumar-0/Cryptography-.git
cd Cryptography-
pip install cryptography
🔒 Quick Usage Example
Pythonfrom integrity_protected_crypto import IntegrityProtectedCrypto

crypto = IntegrityProtectedCrypto()

# Encrypt
encrypted = crypto.encrypt_with_integrity_and_ecc(
    "Secret message", n=32, curve_name='secp256r1', use_ecc_signature=True
)

# Decrypt (recipient uses their private key)
decrypted, valid = crypto.decrypt_with_integrity_and_ecc_check(encrypted, n=32)
print(decrypted)  # "Secret message"
print(valid)      # True
📈 Experimental Results Summary

Test Environment: Intel i5-7200U, 8 GB RAM, Windows 11
Tamper Detection: 100% across 124 test cases
Security: >10¹⁰ years cracking time at n=32
Performance: ~42 ms encryption / 45 ms decryption per 1 MB

🤝 Contributing
Contributions are welcome! Please:

Fork and create a feature branch
Add tests for new features
Follow PEP8 style
Submit a pull request

📄 License
This project is licensed under the MIT License - see LICENSE for details.
🙏 Acknowledgments

Built with the excellent cryptography library
Inspired by modern protocols and hybrid encryption research


Stars and feedback appreciated! ⭐
For questions: sanjay.r2024c@vitstudent.ac.in
Last updated: December 26, 2025
