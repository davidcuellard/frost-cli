# FROST DALEK CLI

## Overview
This CLI utility demonstrates the use of the FROST threshold signature library. 

This project uses a fork from `https://github.com/isislovecruft/frost-dalek`

It provides the following functionality:

1. **Key Generation**: Generates a group public key and shares of the private key.
2. **Message Signing**: Signs a message using a threshold number of private key shares.
3. **Signature Verification**: Validates a signature using the group public key.

This tool is intended for demonstration purposes and runs all operations on a single machine.

## Prerequisites
- Rust toolchain installed ([instructions](https://www.rust-lang.org/tools/install)).

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/davidcuellard/frost-cli
   cd frost-cli
   ```

2. Build the project:
   ```bash
   cargo build
   ```

## Usage

### Example Program
Run the example program provided with the library to explore its API:
```bash
cargo run --example frost_api_example
```

### Commands

#### 1. Generate Keys
Generates a group public key and `n` private key shares with a threshold of `t` participants required to sign.
```bash
cargo run -- generate --t 3 --n 5
```
- **Options**:
  - `--t`: Threshold number of participants required to sign (default: 3).
  - `--n`: Total number of participants (default: 5).
- **Output**:
  - A JSON file `frost_keys.json` in the `results` folder containing the group public key and private key shares.

#### 2. Sign a Message
Signs a message using the threshold `t` of private key shares.
```bash
cargo run -- sign --message "hi, this is a test" --t 3 --n 5 --key-file "./results/frost_keys.json" --signature-file "./results/signature.json"
```
- **Options**:
  - `--message`: The message to be signed.
  - `--t`: Threshold number of participants (default: 3).
  - `--n`: Total number of participants (default: 5).
  - `--key-file`: Path to the JSON file containing the keys (default: `./results/frost_keys.json`).
  - `--signature-file`: Path to save the generated signature (default: `./results/signature.json`).
- **Output**:
  - A JSON file `signature.json` in the `results` folder containing the threshold signature.

#### 3. Verify a Signature
Verifies the validity of a signature for a given message using the group public key.
```bash
cargo run -- verify --message "hi, this is a test" --key-file "./results/frost_keys.json" --signature-file "./results/signature.json"
```
- **Options**:
  - `--message`: The message whose signature needs to be validated.
  - `--key-file`: Path to the JSON file containing the keys (default: `./results/frost_keys.json`).
  - `--signature-file`: Path to the JSON file containing the signature (default: `./results/signature.json`).
- **Output**:
  - Prints `Signature is valid!` if the verification is successful.

## Use Cases
- **Demonstration**: Learn how FROST threshold signatures work.
- **Testing**: Validate the FROST library by generating keys, signing messages, and verifying signatures.
- **Educational**: Understand the cryptographic concepts of threshold signatures.

## Example Workflow
1. Generate keys:
   ```bash
   cargo run -- generate --t 3 --n 5 --output-key-file "./results/frost_keys.json"
   ```
2. Sign a message:
   ```bash
   cargo run -- sign --message "hi, this is a test" --t 3 --n 5 --key-file "./results/frost_keys.json" --signature-file "./results/signature.json"
   ```
3. Verify the signature:
   ```bash
   cargo run -- verify --message "hi, this is a test" --key-file "./results/frost_keys.json" --signature-file "./results/signature.json"
   ```

## Project Structure
- `src/main.rs`: CLI entry point.
- `src/lib.rs`: Logic for Key generation, Message signing and Signature verification.
- `tests/test.rs`: Unit testing for key generation, message signing, and signature verification, ensuring the functionality works as expected.

# Docs
Run
   ```bash
    cargo doc --open
  ```


## Changes to `isislovecruft/frost-dalek`

- The `SecretKey` struct has been modified to include serialization and deserialization support.
  - The `index` and `key` fields are private (pub(crate)), preventing direct serialization or reconstruction outside the module.
  The following methods have been added to facilitate serialization and deserialization:

    - `to_bytes`: Serializes the `SecretKey` to bytes, returning a tuple containing the scalar key as bytes and the index.
    - `from_bytes`: Deserializes the `SecretKey` from bytes, taking an index and scalar key bytes as input and returning a `Result` with the `SecretKey` or an error message.
    - `get_index`: A getter method for retrieving the participant index.