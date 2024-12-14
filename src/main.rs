//! A CLI utility for demonstrating FROST threshold signatures.
//! 
//! This tool supports:
//! - Generating a public key and private key shares.
//! - Signing a message using a threshold of private key shares.
//! - Verifying a signature using the public key.

mod keygen;
mod sign;
mod verify;
mod types;

use clap::{Parser, Subcommand};
use keygen::generate_keys;
use sign::sign_message;
use verify::validate_signature;

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

/// Entry point for the CLI utility.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments.
    let cli = Cli::parse();

    match &cli.command {
        // Handle key generation command.
        Commands::Generate { t, n } => {
            println!("Generating keys...");
            generate_keys(*t, *n)?;
        }
        // Handle message signing command.
        Commands::Sign {
            message,
            t,
            n,
            key_file,
            signature_file,
        } => {
            println!("Signing message: {}", message);
            sign_message(&message, *t, *n, key_file, signature_file)?;
        }
        // Handle signature verification command.
        Commands::Verify {
            message,
            key_file,
            signature_file,
        } => {
            println!("Verifying signature for message: {}", message);
            println!("Using signature file: {}", signature_file);
            validate_signature(&message, key_file, signature_file)?;
        }
    }

    Ok(())
}
