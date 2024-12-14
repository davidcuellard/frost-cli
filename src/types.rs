use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FrostKeys {
    pub group_key: [u8; 32],
    pub private_shares: Vec<([u8; 32], u32)>,
}
