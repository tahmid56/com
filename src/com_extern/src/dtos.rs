use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponseDto {
    pub message: String,
    pub status: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponseDto {
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericResponseDtoAuth {
    pub data: AuthResponseDto,
    pub message: String,
    pub status: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ResponseDtoAuth {
    Ok(GenericResponseDtoAuth),
    Err(ErrorResponseDto),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlogResponseDto {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub published: bool,
    pub created_by: u64,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericResponseDtoBlog {
    pub data: BlogResponseDto,
    pub message: String,
    pub status: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ResponseDtoBlog {
    Ok(GenericResponseDtoBlog),
    Err(ErrorResponseDto),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBlogRequest {
    pub token: String,
    pub title: String,
    pub content: String,
    pub published: bool,
}