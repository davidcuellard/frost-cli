use clap::{Parser, Subcommand};
use frost_dalek::signature::SecretKey as SignatureSecretKey;
use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, GroupKey,
    Parameters, Participant, SignatureAggregator,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::from_reader;
use std::fs::File;
use std::io::BufReader;

#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "CLI for FROST threshold signatures", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize)]
struct FrostKeys {
    group_key: [u8; 32],
    private_shares: Vec<([u8; 32], u32)>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a public key and private key shares
    Generate {
        #[arg(short, long, default_value = "3")]
        t: u32,
        #[arg(short, long, default_value = "5")]
        n: u32,
    },
    /// Sign a message using private key shares
    Sign {
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "3")]
        t: u32,
        #[arg(short, long, default_value = "5")]
        n: u32,
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        key_file: String,
    },
    /// Verify a signature using the public key
    Verify {
        #[arg(short, long)]
        message: String,
        #[arg(short, long)]
        signature_file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate { t, n } => {
            println!("Generating keys...");
            generate_keys(*t, *n)?;
        }
        Commands::Sign {
            message,
            t,
            n,
            key_file,
        } => {
            println!("Signing message: {}", message);
            sign_message(&message, *t, *n, key_file)?;
        }
        Commands::Verify {
            message,
            signature_file,
        } => {
            println!("Verifying signature for message: {}", message);
            println!("Using signature file: {}", signature_file);
        }
    }

    Ok(())
}

fn generate_keys(t: u32, n: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Define parameters
    let params = Parameters { t, n };

    // Step 1: Generate participants and coefficients
    let mut participants = Vec::new();
    let mut coefficients = Vec::new();

    for i in 1..=n {
        let (participant, coeff) = Participant::new(&params, i);
        participants.push(participant);
        coefficients.push(coeff);
    }

    // Step 2: Verify zk proof of secret keys
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

    // Step 3: Perform Distributed Key Generation (Round 1)
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

    // Step 4: Share Secret Shares (Round 2)
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

    // Step 5: Finish DKG and save keys
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

        if i > 0 {
            assert_eq!(dkg_group_key, group_keys[i - 1]);
        }
    }

    let frost_keys = FrostKeys {
        group_key: group_keys[0].to_bytes(),
        private_shares,
    };

    let file = File::create("./results/frost_keys.json")?;
    serde_json::to_writer_pretty(file, &frost_keys)?;

    println!("Generated {} shares with threshold {}. Keys saved.", n, t);
    Ok(())
}

fn sign_message(
    message: &str,
    t: u32,
    n: u32,
    key_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Load keys from file
    let file = File::open(key_file)?;
    let reader = BufReader::new(file);
    let frost_keys: FrostKeys = from_reader(reader)?;

    // Step 2: Reconstruct parameters
    let params = Parameters { t, n };

    // Step 3: Reconstruct the group public key
    let group_key =
        GroupKey::from_bytes(frost_keys.group_key).map_err(|_| "Invalid group public key")?;

    // Step 4: Reconstruct individual secret keys
    let mut secret_keys = Vec::new();
    for (key_bytes, index) in &frost_keys.private_shares {
        let secret_key = SignatureSecretKey::from_bytes(*index, *key_bytes)
            .map_err(|_| "Invalid private key bytes")?;
        secret_keys.push(secret_key);
    }
    // Step 5: Select the first `t` participants as signers
    let signers = &secret_keys[0..(t as usize)];

    // Step 6: Generate commitment shares for each signer
    let mut public_comshares = Vec::new();
    let mut secret_comshares = Vec::new();
    for signer in signers {
        let (pub_com, sec_com) = generate_commitment_share_lists(&mut OsRng, signer.get_index(), 1);
        public_comshares.push((signer.get_index(), pub_com));
        secret_comshares.push((signer.get_index(), sec_com));
    }

    // Step 7: Define a context and compute the message hash
    let context = b"THRESHOLD SIGNING CONTEXT";
    let message_bytes = message.as_bytes();
    let message_hash = compute_message_hash(&context[..], &message_bytes[..]);

    // Step 8: Initialize the SignatureAggregator
    let mut aggregator =
        SignatureAggregator::new(params, group_key, &context[..], &message_bytes[..]);

    // Step 9: Include each signer in the aggregator
    for (signer, (index, pub_com)) in signers.iter().zip(public_comshares.iter()) {
        let public_key = signer.to_public();
        aggregator.include_signer(*index, pub_com.commitments[0], public_key);
    }

    // Step 10: Get the final list of signers from the aggregator
    let signers = aggregator.get_signers().clone();

    // Step 11: Create partial signatures
    for (secret_key, (_, sec_com)) in secret_keys.iter().zip(secret_comshares.iter_mut()) {
        let partial_sig = secret_key.sign(&message_hash, &group_key, sec_com, 0, &signers)?;
        aggregator.include_partial_signature(partial_sig);
    }

    // Step 12: Finalize and aggregate the signature
    let aggregator = aggregator.finalize().map_err(|err| {
        let error_message = format!("Failed to finalize aggregator: {:?}", err);
        Box::<dyn std::error::Error>::from(error_message)
    })?;

    let threshold_signature = aggregator.aggregate().map_err(|err| {
        let error_message = format!("Failed to aggregate signature: {:?}", err);
        Box::<dyn std::error::Error>::from(error_message)
    })?;

    // Step 13: Verify the signature
    threshold_signature
        .verify(&group_key, &message_hash)
        .map_err(|_| "Signature verification failed")?;

    println!("Threshold signature is valid!");

    Ok(())
}
