use std::borrow::Cow;

use candid::CandidType;
use ic_stable_structures::Storable;
use serde::{Deserialize, Serialize};



#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub password_hash: String,
}

impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(bincode::serialize(self).expect("Serialization failed"))
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        bincode::deserialize(&bytes).expect("Deserialization failed")
    }

    const BOUND: ic_stable_structures::storable::Bound = ic_stable_structures::storable::Bound::Bounded {
        max_size: 1024,
        is_fixed_size: false,
    };
}