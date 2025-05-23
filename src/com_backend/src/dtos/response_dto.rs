use candid::CandidType;
use serde::{Serialize, Deserialize};

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum ResponseDto<T, E> {
    Ok(T),
    Err(E),
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct GenericResponseDto<T> {
    pub data: T,
    pub message: String,
    pub status: u16,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct ErrorResponseDto {
    pub message: String,
    pub status: u16,
}