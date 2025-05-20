use candid::CandidType;
use serde::{Deserialize, Serialize};


#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct AuthResponseDto {
    pub token: String,
}