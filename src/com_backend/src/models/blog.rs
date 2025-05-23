use candid::CandidType;
use ic_stable_structures::{storable::Bound, Storable};
use serde::{Deserialize, Serialize};



#[derive(Debug, Serialize, Deserialize, Clone, CandidType)]
pub struct Blog {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub published: bool,
    pub created_by: u64,
    pub created_at: u64, 
    pub deleted_at: Option<u64>,
}

impl Storable for Blog{
   fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        candid::encode_one(self)
            .map(|bytes| bytes.into())
            .expect("Failed to serialize Blog")
    }

    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to deserialize Blog")
    }
    
    const BOUND: Bound = Bound::Bounded {
        max_size: 4096, 
        is_fixed_size: false,
    };
}