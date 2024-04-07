## How LSIG Works

LSIG is a simple implementation of Lamport signatures designed for quantum-resistant digital signatures. Here's how it operates:

1. **Private Key Generation**:
   - A private key is randomly generated
2. **Public Key Derivation**:

   - The public key is derived by hashing the private key using a secure hash function.
   - This ensures that the public key is securely derived from the private key, providing a one-way mapping.

3. **Message Signing**:

   - To sign a message, it is first hashed using a secure hash function (e.g., SHA-256).
   - The hash value is then used to reveal preimages based on the bit representation of the message.

   - These preimages serve as the signature blocks.

4. **Signature Verification**:
   - To verify a signature, each block of the signature is hashed.
   - The resulting hash values are compared against the corresponding blocks of the public key.
   - If the hash values match, the signature is considered valid, confirming the authenticity of the message.

## Limitations

- **Key Reuse**: Using the same key pair to sign multiple messages may lead to revealing a significant portion of the private key.
