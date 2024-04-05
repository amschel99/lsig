//! LSIG is a straightforward implementation of Lamport signatures designed for quantum-resistant digital signatures.
//! Private and public key pairs can be created.
//! A message can be signed using the private key to generate a signature, and then the message can be verified using the signature and the public key.
mod signature;
pub use signature::*;
