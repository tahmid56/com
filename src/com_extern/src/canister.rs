use candid::{self, CandidType, Principal};
use candid::Deserialize as CandidDeserialize;
use ic_agent::{Agent, AgentError};

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct GenericResponseDtoString {
    pub status: u16,
    pub data: String,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct ErrorResponseDto {
    pub status: u16,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub enum ResponseDtoString {
    Ok(GenericResponseDtoString),
    Err(ErrorResponseDto),
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct BlogResponseDto {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub published: bool,
    pub created_at: u64,
    pub created_by: u64,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct GenericResponseDtoBlog {
    pub status: u16,
    pub data: BlogResponseDto,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub enum ResponseDtoBlog {
    Ok(GenericResponseDtoBlog),
    Err(ErrorResponseDto),
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct UserResponseDto {
    pub id: u64,
    pub username: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct GenericResponseDtoUserVec {
    pub status: u16,
    pub data: Vec<UserResponseDto>,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub enum ResponseDtoUserVec {
    Ok(GenericResponseDtoUserVec),
    Err(ErrorResponseDto),
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct GenericResponseDtoBlogVec {
    pub status: u16,
    pub data: Vec<BlogResponseDto>,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub enum ResponseDtoBlogVec {
    Ok(GenericResponseDtoBlogVec),
    Err(ErrorResponseDto),
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct AuthResponseDto {
    pub token: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub struct GenericResponseDtoAuth {
    pub status: u16,
    pub data: AuthResponseDto,
    pub message: String,
}

#[derive(CandidType, CandidDeserialize, Debug)]
pub enum ResponseDtoAuth {
    Ok(GenericResponseDtoAuth),
    Err(ErrorResponseDto),
}

pub struct Service {
    pub agent: Agent,
    pub canister_id: Principal,
}

impl Service {
    pub fn new(agent: Agent, canister_id: Principal) -> Self {
        Service { agent, canister_id }
    }

    pub async fn signin(&self, username: String, password: String) -> Result<ResponseDtoAuth, AgentError> {
        let args = candid::encode_args((username, password)).expect("Failed to encode args");
        let response = self
            .agent
            .update(&self.canister_id, "signin")
            .with_arg(args)
            .call_and_wait()
            .await?;
        let result: (ResponseDtoAuth,) = candid::decode_args(&response).expect("Failed to decode response");
        Ok(result.0)
    }

    pub async fn create_blog(&self, token: String, title: String, content: String, published: bool) -> Result<ResponseDtoBlog, AgentError> {
        let args = candid::encode_args((token, title, content, published)).expect("Failed to encode args");
        let response = self
            .agent
            .update(&self.canister_id, "create_blog")
            .with_arg(args)
            .call_and_wait()
            .await?;
        let result: (ResponseDtoBlog,) = candid::decode_args(&response).expect("Failed to decode response");
        Ok(result.0)
    }
}