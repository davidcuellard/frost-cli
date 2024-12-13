use clap::{Parser, Subcommand};
use frost_dalek::{DistributedKeyGeneration, Parameters, Participant};
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "CLI for FROST threshold signatures", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Serialize, Deserialize)]
struct FrostKeys {
    group_key: Vec<u8>,
    private_shares: Vec<Vec<u8>>,
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
        Commands::Sign { message } => {
            println!("Signing message: {}", message);
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

        let public_key_bytes = dkg_secret_key
            .to_public()
            .share
            .compress()
            .to_bytes()
            .to_vec();

        group_keys.push(dkg_group_key);
        private_shares.push(public_key_bytes);

        if i > 0 {
            assert_eq!(dkg_group_key, group_keys[i - 1]);
        }
    }

    let frost_keys = FrostKeys {
        group_key: group_keys[0].to_bytes().to_vec(),
        private_shares: private_shares,
    };

    let file = File::create("./results/frost_keys.json")?;
    serde_json::to_writer_pretty(file, &frost_keys)?;

    println!("Generated {} shares with threshold {}. Keys saved.", n, t);
    Ok(())
}
