//! Module for signing messages using threshold cryptography.
//! This function demonstrates the threshold signing process.

use crate::types::FrostKeys;
use frost_dalek::signature::SecretKey as SignatureSecretKey;
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, GroupKey, Parameters,
    SignatureAggregator,
};
use serde_json::from_reader;
use std::fs::File;
use std::io::BufReader;
use rand::rngs::OsRng;

/// Signs a message using threshold signing.
///
/// # Arguments
/// - `message`: The message to be signed.
/// - `t`: The signing threshold (minimum participants required).
/// - `n`: The total number of participants.
/// - `key_file`: Path to the file containing the generated keys.
/// - `signature_file`: Path to save the generated signature.
///
/// # Errors
/// Returns an error if loading keys, generating commitment shares, or signing fails.
pub fn sign_message(
    message: &str,
    t: u32,
    n: u32,
    key_file: &str,
    signature_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Load keys from file
    let file = File::open(key_file)?;
    let reader = BufReader::new(file);
    let frost_keys: FrostKeys = from_reader(reader)?;

    // Step 2: Set up signing parameters
    let params = Parameters { t, n };

    // Step 3: Load the group public key
    let group_key =
        GroupKey::from_bytes(frost_keys.group_key).map_err(|_| "Invalid group public key")?;

    // Step 4: Reconstruct secret keys from the key file
    let mut secret_keys = Vec::new();
    for (key_bytes, index) in &frost_keys.private_shares {
        let secret_key = SignatureSecretKey::from_bytes(*index, *key_bytes)
            .map_err(|_| "Invalid private key bytes")?;
        secret_keys.push(secret_key);
    }

    // Step 5: Choose `t` signers for threshold signing
    let signers = &secret_keys[0..(t as usize)];

    // Step 6: Generate commitment shares for the chosen signers
    let mut public_comshares = Vec::new();
    let mut secret_comshares = Vec::new();
    for signer in signers {
        let (pub_com, sec_com) = generate_commitment_share_lists(&mut OsRng, signer.get_index(), 1);
        public_comshares.push((signer.get_index(), pub_com));
        secret_comshares.push((signer.get_index(), sec_com));
    }

    // Step 7: Hash the message to create a signing context
    let context = b"THRESHOLD SIGNING CONTEXT";
    let message_bytes = message.as_bytes();
    let message_hash = compute_message_hash(&context[..], &message_bytes[..]);

    // Step 8: Initialize a signature aggregator
    let mut aggregator =
        SignatureAggregator::new(params, group_key, &context[..], &message_bytes[..]);

    // Step 9: Include signers and their commitment shares in the aggregator
    for (signer, (index, pub_com)) in signers.iter().zip(public_comshares.iter()) {
        let public_key = signer.to_public();
        aggregator.include_signer(*index, pub_com.commitments[0], public_key);
    }

    // Step 10: Get the list of participating signers
    let signers = aggregator.get_signers().clone();

    // Step 11: Create and include partial signatures
    for (secret_key, (_, sec_com)) in secret_keys.iter().zip(secret_comshares.iter_mut()) {
        let partial_sig = secret_key.sign(&message_hash, &group_key, sec_com, 0, &signers)?;
        aggregator.include_partial_signature(partial_sig);
    }

    // Step 12: Finalize and aggregate the threshold signature
    let aggregator = aggregator.finalize().map_err(|err| {
        let error_message = format!("Failed to finalize aggregator: {:?}", err);
        Box::<dyn std::error::Error>::from(error_message)
    })?;

    let threshold_signature = aggregator.aggregate().map_err(|err| {
        let error_message = format!("Failed to aggregate signature: {:?}", err);
        Box::<dyn std::error::Error>::from(error_message)
    })?;

    // Step 13: Save the signature as a JSON file
    let file = File::create(signature_file)?;
    serde_json::to_writer_pretty(file, &threshold_signature.to_bytes().to_vec())?;

    println!("Threshold signature saved to: {}", signature_file);
    Ok(())
}
