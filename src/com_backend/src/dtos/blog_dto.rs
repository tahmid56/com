use candid::CandidType;
use serde::{Deserialize, Serialize};



#[derive(Debug, Serialize, Deserialize, CandidType)]
pub struct BlogResponseDto {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub published: bool,
    pub created_by: u64,
    pub created_at: u64,
    pub categories: Option<String>,
}