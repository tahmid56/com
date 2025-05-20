
use dtos::{GenericResponseDto, UserResponseDto};
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

use hmac::{Hmac, Mac};
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
mod dtos;
mod models;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

thread_local! {
    static USER_STORAGE: RefCell<StableBTreeMap<String, models::User, DefaultMemoryImpl>> =
        RefCell::new(StableBTreeMap::init(DefaultMemoryImpl::default()));
    static USER_ID_COUNTER: RefCell<u64> = const { RefCell::new(1) };
}

const JWT_SECRET: &str = "my-secret-key-123";

#[init]
fn init() {}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {}

#[update]
async fn signup(
    username: String,
    password: String,
) -> dtos::ResponseDto<dtos::GenericResponseDto<String>> {
    if username.is_empty() || password.is_empty() {
        return dtos::ResponseDto::Err(dtos::GenericResponseDto {
            data: "Username or password is empty".to_string(),
            message: "Username or password is empty".to_string(),
            status: 400,
        });
    }

    let user_id = USER_ID_COUNTER.with(|counter| {
        let mut counter = counter.borrow_mut();
        let id = *counter;
        *counter += 1;
        id
    });

    let salted_password = format!("salt123{}", password);
    let mut hasher = Sha256::new();
    hasher.update(salted_password);
    let hashed = hex::encode(hasher.finalize());

    let user = models::User {
        id: user_id,
        username: username.clone(),
        password_hash: hashed,
    };

    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.contains_key(&username) {
            dtos::ResponseDto::Err(GenericResponseDto {
                data: "User Already Exists".to_string(),
                message: "User Already Exists".to_string(),
                status: 400,
            })
        } else {
            storage.insert(username.clone(), user);
            dtos::ResponseDto::Ok(GenericResponseDto {
                data: "User created".to_string(),
                message: "User created".to_string(),
                status: 200,
            })
        }
    })
}

#[query]
fn signin(
    username: String,
    password: String,
) -> dtos::ResponseDto<GenericResponseDto<dtos::AuthResponseDto>> {
    let salted_password = format!("salt123{}", password);
    let mut hasher = Sha256::new();
    hasher.update(salted_password);
    let hashed = hex::encode(hasher.finalize());

    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();
        match storage.get(&username) {
            Some(user) => {
                if user.password_hash == hashed {
                    let claims = Claims {
                        sub: user.id.to_string(),
                        exp: (ic_cdk::api::time() / 1_000_000_000) as usize + 3600,
                    };
                    let header = Header {
                        algorithm: jwt::AlgorithmType::Hs256,
                        ..Default::default()
                    };
                    let token = Token::new(header, claims);
                    let key = Hmac::<Sha256>::new_from_slice(JWT_SECRET.as_bytes()).map_err(|_| {
                        dtos::ResponseDto::Err(dtos::GenericResponseDto {
                            data: dtos::AuthResponseDto { token: "Failed to generate token".to_string() },
                            message: "Failed to generate token".to_string(),
                            status: 500,
                        })
                    });
                    let key = match key {
                        Ok(key) => key,
                        Err(e) => return e,
                    };
                    let signed_token = token.sign_with_key(&key).map_err(|_| {
                        dtos::ResponseDto::Err(dtos::GenericResponseDto {
                            data: dtos::AuthResponseDto { token: "Failed to generate token".to_string() },
                            message: "Failed to generate token".to_string(),
                            status: 500,
                        })
                    });
                    match signed_token {
                        Ok(signed_token) => dtos::ResponseDto::Ok(dtos::GenericResponseDto {
                            data: dtos::AuthResponseDto {
                                token: signed_token.as_str().to_string(),
                            },
                            message: "Success".to_string(),
                            status: 200,
                        }),
                        Err(e) => {
                            dtos::ResponseDto::Err(dtos::GenericResponseDto {
                                data: dtos::AuthResponseDto { token: "Failed to generate token".to_string() },
                                message: "Failed to generate token".to_string(),
                                status: 500,
                            })
                        }
                    }
                } else {
                    dtos::ResponseDto::Err(dtos::GenericResponseDto {
                        data: dtos::AuthResponseDto { token: "Invalid credentials".to_string() },
                        message: "Invalid credentials".to_string(),
                        status: 401,
                    })
                }
            }
            None => dtos::ResponseDto::Err(dtos::GenericResponseDto {
                data: dtos::AuthResponseDto { token: "User not found".to_string() },
                message: "User not found".to_string(),
                status: 404,
            }),
        }
    })
}

fn validate_token(token: &str) -> bool {
    let key = match Hmac::<Sha256>::new_from_slice(JWT_SECRET.as_bytes()) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let token: Token<Header, Claims, _> = match Token::parse_unverified(token) {
        Ok(token) => token,
        Err(_) => return false,
    };

    let verified_claims = match token.verify_with_key(&key) {
        Ok(claims) => claims,
        Err(_) => return false,
    };

    let current_time = (ic_cdk::api::time() / 1_000_000_000) as usize;
    verified_claims.claims().exp >= current_time
}

#[query]
fn protected_endpoint(
    token: String,
) -> dtos::ResponseDto<GenericResponseDto<String>> {
    if validate_token(&token) {
        dtos::ResponseDto::Ok(GenericResponseDto {
            data: "Access granted".to_string(),
            message: "Authenticated successfully".to_string(),
            status: 200,
        })
    } else {
        dtos::ResponseDto::Err(GenericResponseDto {
            data: "Token not valid".to_string(),
            message: "Token not valid".to_string(),
            status: 401,
        })
    }
}

#[query]
fn list_user(token: String) -> dtos::ResponseDto<GenericResponseDto<Vec<UserResponseDto>>> {
    if validate_token(&token) {
        USER_STORAGE.with(|storage| {
            let storage = storage.borrow();
            let users: Vec<UserResponseDto> = storage
                .iter()
                .map(|(_, user)| {
                    UserResponseDto {
                        id: user.id,
                        username: user.username.clone(),
                    }
                })
                .collect();
            dtos::ResponseDto::Ok(GenericResponseDto {
                data: users,
                message: "Users retrieved successfully".to_string(),
                status: 200,
            })
        })
    } else {
        dtos::ResponseDto::Err(GenericResponseDto {
            data: Vec::new(),
            message: "Token not valid".to_string(),
            status: 401,
        })
    }
}

#[query]
fn debug_user_storage() -> dtos::ResponseDto<GenericResponseDto<Vec<String>>> {
    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let keys: Vec<String> = storage.iter().filter_map(|(key, _)| Some(key.clone())).collect();
        dtos::ResponseDto::Ok(GenericResponseDto {
            data: keys,
            message: "Storage keys retrieved".to_string(),
            status: 200,
        })
    })
}

#[update]
fn clear_user_storage() -> dtos::ResponseDto<GenericResponseDto<String>> {
    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        *storage = StableBTreeMap::init(DefaultMemoryImpl::default());
        dtos::ResponseDto::Ok(GenericResponseDto {
            data: "Storage cleared".to_string(),
            message: "User storage cleared successfully".to_string(),
            status: 200,
        })
    })
}

#[query]
fn debug_storage_keys() -> dtos::ResponseDto<GenericResponseDto<Vec<String>>> {
    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let keys: Vec<String> = storage
            .range(..)
            .map(|(key, _)| key.clone())
            .collect();
        dtos::ResponseDto::Ok(GenericResponseDto {
            data: keys,
            message: "Storage keys retrieved".to_string(),
            status: 200,
        })
    })
}