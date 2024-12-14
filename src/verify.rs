use crate::types::FrostKeys;
use frost_dalek::signature::ThresholdSignature;
use frost_dalek::{compute_message_hash, GroupKey};
use std::fs::File;
use std::io::BufReader;

pub fn validate_signature(
    message: &str,
    key_file: &str,
    signature_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Load the signature from file
    let signature_file = File::open(signature_file)?;
    let signature_reader = BufReader::new(signature_file);
    let signature_vec: Vec<u8> = serde_json::from_reader(signature_reader)?;
    if signature_vec.len() != 64 {
        return Err("Invalid length for threshold signature".into());
    }
    let signature_bytes: [u8; 64] = signature_vec
        .try_into()
        .map_err(|_| "Failed to convert to [u8; 64]")?;

    // Deserialize the signature
    let threshold_signature = ThresholdSignature::from_bytes(signature_bytes)
        .map_err(|_| "Failed to deserialize ThresholdSignature")?;

    // Step 2: Load the public group key from the key file
    let key_file = File::open(key_file)?;
    let key_reader = BufReader::new(key_file);
    let frost_keys: FrostKeys = serde_json::from_reader(key_reader)?;

    let group_key =
        GroupKey::from_bytes(frost_keys.group_key).map_err(|_| "Invalid group public key")?;

    // Step 3: Compute the message hash
    let context = b"THRESHOLD SIGNING CONTEXT";
    let message_bytes = message.as_bytes();
    let message_hash = compute_message_hash(&context[..], &message_bytes[..]);

    // Step 4: Verify the threshold signature
    threshold_signature
        .verify(&group_key, &message_hash)
        .map_err(|_| "Signature verification failed")?;

    println!("Signature is valid!");
    Ok(())
}
