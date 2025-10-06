use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use thiserror::Error;


/// A container for the user's identity fingerprint.
pub struct SafetyNumber {
    /// For display to the user, e.g., "12345 67890 11121 31415".
    pub display_string: String,
    /// The full hash for QR code generation or exact matching.
    pub full_hex: String,
}

#[derive(Error, Debug)]
pub enum SafetyNumberError {
    #[error("Public key is empty.")]
    EmptyPublicKey,
    #[error("Failed to generate safety number.")]
    GenerationFailed,
}
/// Generates a safety number from a user's OpenMLS Credential.
///
/// This function hashes the public key within the credential to create a stable,
/// verifiable fingerprint for out-of-band authentication.
pub fn generate_safety_number(public_key: &VerifyingKey) -> Result<SafetyNumber, SafetyNumberError> {
    // Convert the public key to bytes
    let public_key_bytes = public_key.to_bytes();

    if public_key_bytes.is_empty() {
        return Err(SafetyNumberError::EmptyPublicKey);
    }

    // 2. Hash the public key using SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let hash_result = hasher.finalize();

    // 3. Encode the hash into human-readable formats.

    // Format 1: A numeric string for reading aloud.
    // We take the first 8 bytes of the hash (64 bits) and format it
    // into four 5-digit groups for easier reading.
    let mut number_chunk = [0u8; 8];
    number_chunk.copy_from_slice(&hash_result[0..8]);
    let numeric_value = u64::from_be_bytes(number_chunk);

    let g1 = numeric_value % 100_000;
    let g2 = (numeric_value / 100_000) % 100_000;
    let g3 = (numeric_value / 10_000_000_000) % 100_000;
    let g4 = (numeric_value / 1_000_000_000_000_000) % 100_000;

    let display_string = format!("{:05} {:05} {:05} {:05}", g4, g3, g2, g1);

    // Format 2: A full hex string for QR codes.
    let full_hex = hex::encode(hash_result);

    Ok(SafetyNumber {
        display_string,
        full_hex,
    })
}
