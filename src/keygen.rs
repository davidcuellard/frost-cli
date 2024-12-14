//! Generates a public key and private key shares using FROST.
//!
//! # Parameters
//! - `t`: Threshold value, the minimum number of participants required to reconstruct the private key.
//! - `n`: Total number of participants (key shares).
//!
//! # Returns
//! - Saves the keys to `./results/frost_keys.json` in JSON format.

use crate::types::FrostKeys;
use frost_dalek::{DistributedKeyGeneration, Parameters, Participant};
use std::fs::File;

/// Generates the public key and private key shares.
pub fn generate_keys(t: u32, n: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the parameters for the key generation.
    let params = Parameters { t, n };

    // Step 1: Create participants and their polynomial coefficients.
    let mut participants = Vec::new();
    let mut coefficients = Vec::new();
    for i in 1..=n {
        let (participant, coeff) = Participant::new(&params, i);
        participants.push(participant);
        coefficients.push(coeff);
    }

    // Step 2: Verify zero-knowledge proof of secret keys for all participants.
    for participant in &participants {
        participant
            .proof_of_secret_key
            .verify(&participant.index, &participant.public_key().unwrap())
            .map_err(|_| {
                format!(
                    "Proof of secret key verification failed for participant {}",
                    participant.index
                )
            })?;
    }
    println!("All participants verified their proofs of secret keys!");

    // Step 3: Perform the first round of Distributed Key Generation (DKG).
    let mut dkg_states = Vec::new();
    let mut all_secret_shares = Vec::new();
    for (i, participant) in participants.iter().enumerate() {
        let mut other_participants = participants.clone();
        other_participants.remove(i);

        let participant_state = DistributedKeyGeneration::<_>::new(
            &params,
            &participant.index,
            &coefficients[i],
            &mut other_participants,
        )
        .map_err(|err| {
            format!(
                "DistributedKeyGeneration failed for participant: {}: {:?}",
                &participant.index, err
            )
        })?;

        let participant_their_secret_shares = participant_state
            .their_secret_shares()
            .map_err(|_| {
                format!(
                    "Secret shares retrieval failed for participant {}",
                    participant.index
                )
            })?
            .to_vec();

        dkg_states.push(participant_state);
        all_secret_shares.push(participant_their_secret_shares);
    }
    println!("DKG Round 1 complete");

    // Step 4: Share secret shares and complete Round 2 of DKG.
    let mut dkg_states_round_two = Vec::new();
    for (i, dkg_state) in dkg_states.into_iter().enumerate() {
        let my_secret_shares: Vec<_> = all_secret_shares
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .filter_map(|(j, shares)| {
                let pos = if i < j { i } else { i - 1 };
                shares.get(pos).cloned()
            })
            .collect();

        // Ensure the correct number of shares are received.
        if my_secret_shares.len() != (params.n - 1) as usize {
            return Err(format!(
                "Participant {} received incorrect number of shares: expected {}, got {}",
                participants[i].index,
                params.n - 1,
                my_secret_shares.len()
            )
            .into());
        }

        let round_two_state = dkg_state
            .to_round_two(my_secret_shares)
            .map_err(|_| format!("Round 2 failed for participant {}", participants[i].index))?;

        dkg_states_round_two.push(round_two_state);
    }
    println!("Share secret shares Round 2 complete");

    // Step 5: Finalize DKG and save the keys.
    let mut group_keys = Vec::new();
    let mut private_shares = Vec::new();
    for (i, dkg_state) in dkg_states_round_two.iter().enumerate() {
        let (dkg_group_key, dkg_secret_key) = dkg_state
            .clone()
            .finish(participants[i].public_key().unwrap())
            .map_err(|_| {
                format!(
                    "Failed to finish DKG for participant {}",
                    participants[i].index
                )
            })?;

        group_keys.push(dkg_group_key);
        private_shares.push(dkg_secret_key.to_bytes());

        // Ensure all group keys are identical.
        if i > 0 {
            assert_eq!(dkg_group_key, group_keys[i - 1]);
        }
    }

    // Combine group key and private shares into a single structure.
    let frost_keys = FrostKeys {
        group_key: group_keys[0].to_bytes(),
        private_shares,
    };

    // Save the keys to a JSON file.
    let file = File::create("./results/frost_keys.json")?;
    serde_json::to_writer_pretty(file, &frost_keys)?;

    println!("Generated {} shares with threshold {}. Keys saved.", n, t);
    Ok(())
}
