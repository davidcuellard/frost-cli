//! Module defining data structures used across the application.

use serde::{Deserialize, Serialize};

/// Represents the key material for threshold cryptography.
///
/// This structure contains the group public key and the private key shares
/// for all participants.
///
/// # Fields
/// - `group_key`: The shared public key for the group.
/// - `private_shares`: A vector of tuples containing:
///   - The private key share (as an array of 32 bytes).
///   - The index of the participant owning the share.
#[derive(Serialize, Deserialize)]
pub struct FrostKeys {
    /// The shared public key for the group.
    pub group_key: [u8; 32],
    /// The private key shares for all participants.
    pub private_shares: Vec<([u8; 32], u32)>,
}
