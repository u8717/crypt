# crypt (WiP)

A collection of tools and helpers for handling sensitive data. As this is a personal project, please carefully review the code for correctness and security before using it.

**Note:** If you happen to see and review this code, you are welcome to leave your feedback.

## libcipher

### AES-CBC-HMAC

Located in `libcipher`, this module implements encryption and integrity protection using AES-CBC cipher mode and HMAC.

- **Secure Encryption:** Utilizes AES-CBC mode for robust encryption.
- **Data Integrity:** Employs HMAC (HMAC-SHA256 or similar) to ensure data hasn't been tampered with.
- **Associated Data Support:** Allows inclusion of unencrypted associated data (AD) that needs authentication along with the ciphertext.
- **Customizable HMAC:** The HMAC algorithm can be configured during setup.

**Message Format:**
The encrypted message package has the following structure:
`[MAC | AD-Length (2 bytes) | AD | Initialization Vector | Block 1 | Block 2 | ...]`

#### When to Use AES-CBC-HMAC

- You need both encryption and integrity protection.
- Avoiding nonce collisions presents challenges in your use case (e.g., high-volume systems, distributed environments, or scenarios with persistent storage of encrypted data).

#### Considerations for AES-CBC-HMAC

- **Memory Constraints:** Since the HMAC calculation requires the entire cipher to be in memory, it might not be ideal for very large messages.
- **Key Management:** Ensure secure key generation, storage, and rotation practices. Separate encryption and integrity keys are essential.
- **Nonce/IV Generation:** This implementation recommends using `rand.Reader`.

### AES-GCM

AES-GCM implements encryption, integrity, and authenticity using AES-GCM mode via a single operation.

**Message Format:**
`[Nonce] | AD-Length (2 bytes) | AD | [Ciphertext] | [Authentication Tag]`

#### When to Use AES-GCM

- When dealing with non-persisted, short-lived, and not distributed data.
- When performance is critical.
- When the encrypted content-size per entry is not very large.
- When you are able to prevent nonce reuse.

#### Considerations for AES-GCM

- **Memory Constraints:** The current implementation requires the entire cipher to be in memory, but this should be fine since it is not useful for large messages anyway.
- **Key Management:** Ensure secure key generation, storage, and rotation practices. Separate encryption and integrity keys are not needed.
- **Nonce/IV Generation:** This implementation recommends using `rand.Reader`.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests.
