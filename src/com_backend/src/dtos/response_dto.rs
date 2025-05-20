use candid::CandidType;
use serde::{Serialize, Deserialize};

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum ResponseDto<T> {
    Ok(T),
    Err(T),
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct GenericResponseDto<T> {
    pub data: T,
    pub message: String,
    pub status: u16,
}