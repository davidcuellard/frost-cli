//! A CLI utility for demonstrating FROST threshold signatures.
//!
//! This tool supports:
//! - Generating a public key and private key shares.
//! - Signing a message using a threshold of private key shares.
//! - Verifying a signature using the public key.

use clap::{Parser, Subcommand};
use frost_cli::{generate_keys, sign_message, validate_signature};

/// Defines the structure for the CLI interface.
#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "CLI for FROST threshold signatures", long_about = None)]
struct Cli {
    /// Subcommand to execute (generate, sign, or verify).
    #[command(subcommand)]
    command: Commands,
}

/// Enum representing available CLI commands.
#[derive(Subcommand)]
enum Commands {
    /// Generate a public key and private key shares.
    Generate {
        /// Threshold value for key shares.
        #[arg(short, long, default_value = "3")]
        t: u32,
        /// Total number of key shares to generate.
        #[arg(short, long, default_value = "5")]
        n: u32,
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        output_key_file: String,
    },
    /// Sign a message using a threshold of private key shares.
    Sign {
        /// The message to sign.
        #[arg(short, long)]
        message: String,
        /// Threshold value for signing.
        #[arg(short, long, default_value = "3")]
        t: u32,
        /// Total number of participants.
        #[arg(short, long, default_value = "5")]
        n: u32,
        /// Path to the JSON file containing key shares.
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        key_file: String,
        /// Path to save the resulting signature.
        #[arg(short, long, default_value = "./results/signature.json")]
        signature_file: String,
    },
    /// Verify a signature using the public key.
    Verify {
        /// The signed message to verify.
        #[arg(short, long)]
        message: String,
        /// Path to the JSON file containing the public key.
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        key_file: String,
        /// Path to the JSON file containing the signature.
        #[arg(short, long, default_value = "./results/signature.json")]
        signature_file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate {
            t,
            n,
            output_key_file,
        } => {
            generate_keys(*t, *n, output_key_file).expect("Failed to generate keys");
        }
        Commands::Sign {
            message,
            t,
            n,
            key_file,
            signature_file,
        } => {
            sign_message(message, *t, *n, key_file, signature_file)
                .expect("Failed to sign message");
        }
        Commands::Verify {
            message,
            key_file,
            signature_file,
        } => {
            validate_signature(message, key_file, signature_file)
                .expect("Failed to verify signature");
        }
    }
}
