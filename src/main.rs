mod keygen;
mod sign;
mod verify;
mod types;

use clap::{Parser, Subcommand};
use keygen::generate_keys;
use sign::sign_message;
use verify::validate_signature;

#[derive(Parser)]
#[command(name = "frost-cli")]
#[command(about = "CLI for FROST threshold signatures", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        #[arg(short, long, default_value = "3")]
        t: u32,
        #[arg(short, long, default_value = "5")]
        n: u32,
    },
    Sign {
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "3")]
        t: u32,
        #[arg(short, long, default_value = "5")]
        n: u32,
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        key_file: String,
        #[arg(short, long, default_value = "./results/signature.json")]
        signature_file: String,
    },
    Verify {
        #[arg(short, long)]
        message: String,
        #[arg(short, long, default_value = "./results/frost_keys.json")]
        key_file: String,
        #[arg(short, long, default_value = "./results/signature.json")]
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
            signature_file,
        } => {
            println!("Signing message: {}", message);
            sign_message(&message, *t, *n, key_file, signature_file)?;
        }
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
