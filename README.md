# crypt

A collection of tools and helpers for handling sensitive data. This project is currently focused on an AES-CBC-HMAC Encryptor.
Important: As this is a personal project, carefully review the code for correctness and security before using it.
If you happen to see and review this code your are welcome to leave your feadback. 

## AES-CBC-HMAC Encryptor
Implements encryption and integrity protection using AES-CBC cipher mode and HMAC.
- Secure Encryption: Utilizes AES-CBC mode for robust encryption.
- Data Integrity: Employs HMAC (HMAC-SHA256 or similar) for ensuring data hasn't been tampered with.
- Associated Data Support: Allows inclusion of unencrypted associated data (AD) that needs authentication along with the ciphertext.
- Customizable HMAC: The HMAC algorithm can be configured during setup.

### Message Format
The encrypted message package has the following structure:
[ MAC | AD-Length (2 bytes) | AD | Initialization Vector | Block 1 | Block 2 | ... ]

### When to Use
- You need both encryption and integrity protection.
- Avoiding nonce collisions presents challenges in your use case (e.g., high-volume systems, distributed environments, or scenarios with persistent storage of encrypted data).

### Important Considerations
- Memory Constraints: Since the HMAC calculation requires the entire cipher to be in memory, it might not be ideal for very large messages.
- Key Management: Ensure secure key generation, storage, and rotation practices. Separate encryption and integrity keys are essential.
- Nonce/IV Generation: This implementation uses `rand.Reader`.

# Contributions
Contributions are welcome! Feel free to open issues or submit pull requests.
