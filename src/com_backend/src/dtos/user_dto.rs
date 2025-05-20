use candid::CandidType;
use serde::{Deserialize, Serialize};



#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct UserResponseDto {
    pub id: u64,
    pub username: String,
}