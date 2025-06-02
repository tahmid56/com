use candid::CandidType;
use dtos::{
    AuthResponseDto, BlogResponseDto, ErrorResponseDto, GenericResponseDto, ResponseDto,
    UserResponseDto,
};
use ic_cdk::{init, post_upgrade, pre_upgrade, query, storage, update};
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableBTreeMap,
};
use models::Blog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

use hmac::{Hmac, Mac};
use jwt::{Header, SignWithKey, Token, Verified, VerifyWithKey};
mod dtos;
mod models;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

type BlogStorage = StableBTreeMap<u64, models::Blog, VirtualMemory<DefaultMemoryImpl>>;
type UserStorage = StableBTreeMap<u64, models::User, VirtualMemory<DefaultMemoryImpl>>;

thread_local! {
    static MEMORY_MANAGER: MemoryManager<DefaultMemoryImpl> =
        MemoryManager::init(DefaultMemoryImpl::default());

    // Use unique memory IDs for each map
    static BLOG_STORAGE: RefCell<BlogStorage> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.get(MemoryId::new(0)))
        )
    );

    static USER_STORAGE: RefCell<UserStorage> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.get(MemoryId::new(1)))
        )
    );

    static BLOG_ID_COUNTER: RefCell<u64> = RefCell::new(0);
    static USER_ID_COUNTER: RefCell<u64> = RefCell::new(0);

}

const JWT_SECRET: &str = "my-secret-key-123";

#[init]
fn init() {}

#[pre_upgrade]
fn pre_upgrade() {
    use crate::models::{Blog, User}; // Adjust based on actual module

    let blogs: Vec<(u64, Blog)> = BLOG_STORAGE.with(|storage| storage.borrow().iter().collect());
    let users: Vec<(u64, User)> = USER_STORAGE.with(|storage| storage.borrow().iter().collect());

    let blog_id_counter = BLOG_ID_COUNTER.with(|counter| *counter.borrow());
    let user_id_counter = USER_ID_COUNTER.with(|counter| *counter.borrow());

    #[derive(CandidType, Serialize, Deserialize)]
    struct State {
        blogs: Vec<(u64, Blog)>,
        users: Vec<(u64, User)>,
        blog_id_counter: u64,
        user_id_counter: u64,
    }

    let state = State {
        blogs,
        users,
        blog_id_counter,
        user_id_counter,
    };

    ic_cdk::storage::stable_save((state,)).expect("Stable save failed");
}

#[post_upgrade]
fn post_upgrade() {
    use crate::models::{Blog, User}; // Adjust based on actual module

    #[derive(CandidType, Serialize, Deserialize)]
    struct State {
        blogs: Vec<(u64, Blog)>,
        users: Vec<(u64, User)>,
        blog_id_counter: u64,
        user_id_counter: u64,
    }

    let state = match ic_cdk::storage::stable_restore::<(State,)>() {
        Ok((state,)) => state,
        Err(e) => {
            ic_cdk::println!("Stable restore failed: {:?}", e);
            State {
                blogs: vec![],
                users: vec![],
                blog_id_counter: 0,
                user_id_counter: 0,
            }
        }
    };

    // Reinitialize BLOG_STORAGE and USER_STORAGE
    BLOG_STORAGE.with(|s| {
        let mut storage = s.borrow_mut();
        *storage = StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.get(MemoryId::new(0))));
    });

    USER_STORAGE.with(|s| {
        let mut storage = s.borrow_mut();
        *storage = StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.get(MemoryId::new(1))));
    });

    // Restore blogs
    BLOG_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        for (id, blog) in state.blogs {
            let b = Blog {
                id,
                title: blog.title,
                content: blog.content,
                published: blog.published,
                created_by: blog.created_by,
                created_at: blog.created_at,
                deleted_at: blog.deleted_at,
                categories: blog.categories.or(None),
                updated_at: blog.updated_at.or(None),
                updated_by: blog.updated_by.or(None),
            };
            storage.insert(id, b);
        }
    });

    // Restore users
    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        for (id, user) in state.users {
            storage.insert(id, user);
        }
    });

    // Restore counters
    BLOG_ID_COUNTER.with(|counter| *counter.borrow_mut() = state.blog_id_counter);
    USER_ID_COUNTER.with(|counter| *counter.borrow_mut() = state.user_id_counter);

    ic_cdk::println!("Post-upgrade completed");
}

#[update]
async fn signup(
    username: String,
    password: String,
) -> ResponseDto<GenericResponseDto<String>, ErrorResponseDto> {
    if username.is_empty() || password.is_empty() {
        return ResponseDto::Err(ErrorResponseDto {
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
        for (_, user) in storage.iter() {
            if user.username == username {
                return ResponseDto::Err(ErrorResponseDto {
                    message: "User Already Exists".to_string(),
                    status: 400,
                });
            }
        }

        storage.insert(user_id, user);
        ResponseDto::Ok(GenericResponseDto {
            data: "User created".to_string(),
            message: "User created".to_string(),
            status: 200,
        })
    })
}

#[query]
fn signin(
    username: String,
    password: String,
) -> ResponseDto<GenericResponseDto<AuthResponseDto>, ErrorResponseDto> {
    let salted_password = format!("salt123{}", password);
    let mut hasher = Sha256::new();
    hasher.update(salted_password);
    let hashed = hex::encode(hasher.finalize());

    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();

        let user = storage
            .values()
            .find(|user| user.username == username && user.password_hash == hashed);

        match user {
            Some(user) => {
                let claims = Claims {
                    sub: user.id.to_string(),
                    exp: (ic_cdk::api::time() / 1_000_000_000) as usize + 3600,
                };

                let header = Header {
                    algorithm: jwt::AlgorithmType::Hs256,
                    ..Default::default()
                };

                let token = Token::new(header, claims);

                match Hmac::<Sha256>::new_from_slice(JWT_SECRET.as_bytes()) {
                    Ok(key) => match token.sign_with_key(&key) {
                        Ok(signed_token) => ResponseDto::Ok(GenericResponseDto {
                            data: AuthResponseDto {
                                token: signed_token.as_str().to_string(),
                            },
                            message: "Success".to_string(),
                            status: 200,
                        }),
                        Err(_) => ResponseDto::Err(ErrorResponseDto {
                            message: "Failed to sign token".to_string(),
                            status: 500,
                        }),
                    },
                    Err(_) => ResponseDto::Err(ErrorResponseDto {
                        message: "Failed to create signing key".to_string(),
                        status: 500,
                    }),
                }
            }
            None => ResponseDto::Err(ErrorResponseDto {
                message: "Invalid username or password".to_string(),
                status: 401,
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
fn protected_endpoint(token: String) -> ResponseDto<GenericResponseDto<String>, ErrorResponseDto> {
    if validate_token(&token) {
        ResponseDto::Ok(GenericResponseDto {
            data: "Access granted".to_string(),
            message: "Authenticated successfully".to_string(),
            status: 200,
        })
    } else {
        ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        })
    }
}

#[query]
fn list_user(
    token: String,
) -> ResponseDto<GenericResponseDto<Vec<UserResponseDto>>, ErrorResponseDto> {
    if validate_token(&token) {
        USER_STORAGE.with(|storage| {
            let storage = storage.borrow();
            let users: Vec<UserResponseDto> = storage
                .iter()
                .map(|(_, user)| UserResponseDto {
                    id: user.id,
                    username: user.username.clone(),
                })
                .collect();
            ResponseDto::Ok(GenericResponseDto {
                data: users,
                message: "Users retrieved successfully".to_string(),
                status: 200,
            })
        })
    } else {
        ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        })
    }
}

#[query]
fn debug_user_storage() -> ResponseDto<GenericResponseDto<Vec<u64>>, ErrorResponseDto> {
    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let keys: Vec<u64> = storage.iter().filter_map(|(key, _)| Some(key)).collect();
        ResponseDto::Ok(GenericResponseDto {
            data: keys,
            message: "Storage keys retrieved".to_string(),
            status: 200,
        })
    })
}

#[update]
fn clear_user_storage() -> ResponseDto<GenericResponseDto<String>, ErrorResponseDto> {
    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        *storage = StableBTreeMap::init(MEMORY_MANAGER.with(|m| m.get(MemoryId::new(1))));
        ResponseDto::Ok(GenericResponseDto {
            data: "Storage cleared".to_string(),
            message: "User storage cleared successfully".to_string(),
            status: 200,
        })
    })
}

#[query]
fn debug_storage_keys() -> ResponseDto<GenericResponseDto<Vec<u64>>, ErrorResponseDto> {
    USER_STORAGE.with(|storage| {
        let storage = storage.borrow();
        let keys: Vec<u64> = storage.range(..).map(|(key, _)| key).collect();
        ResponseDto::Ok(GenericResponseDto {
            data: keys,
            message: "Storage keys retrieved".to_string(),
            status: 200,
        })
    })
}

#[update]
fn create_blog(
    token: String,
    title: String,
    content: String,
    published: bool,
    categories: Option<String>,
) -> ResponseDto<GenericResponseDto<BlogResponseDto>, ErrorResponseDto> {
    if title.is_empty() || content.is_empty() {
        return ResponseDto::Err(ErrorResponseDto {
            message: "Title or content is empty".to_string(),
            status: 400,
        });
    }

    if !validate_token(&token) {
        return ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        });
    }

    let key = match Hmac::<Sha256>::new_from_slice(JWT_SECRET.as_bytes()) {
        Ok(key) => key,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Failed to process token".to_string(),
                status: 500,
            });
        }
    };

    let token: Token<Header, Claims, _> = match Token::parse_unverified(&token) {
        Ok(token) => token,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Invalid token format".to_string(),
                status: 401,
            });
        }
    };

    let claims = match token.verify_with_key(&key) {
        Ok(claims) => claims,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Token verification failed".to_string(),
                status: 401,
            });
        }
    };

    let user_id: u64 = match claims.claims().sub.parse() {
        Ok(id) => id,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Invalid user ID in token".to_string(),
                status: 401,
            });
        }
    };

    let blog_id = BLOG_ID_COUNTER.with(|counter| {
        let mut counter = counter.borrow_mut();
        let id = *counter;
        *counter += 1;
        id
    });

    let blog = models::Blog {
        id: blog_id,
        title: title.clone(),
        content: content.clone(),
        published,
        created_by: user_id,
        created_at: ic_cdk::api::time(),
        deleted_at: None,
        categories: categories.clone(),
        updated_at: None,
        updated_by: None,
    };

    BLOG_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        storage.insert(blog_id, blog);
        ResponseDto::Ok(GenericResponseDto {
            data: BlogResponseDto {
                id: blog_id,
                title,
                content,
                published,
                created_by: user_id,
                created_at: ic_cdk::api::time(),
                categories,
            },
            message: "Blog created successfully".to_string(),
            status: 200,
        })
    })
}

#[update]
fn delete_blog(
    token: String,
    id: u64,
) -> ResponseDto<GenericResponseDto<String>, ErrorResponseDto> {
    if !validate_token(&token) {
        return ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        });
    }
    BLOG_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if !storage.contains_key(&id) {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Blog not found".to_string(),
                status: 404,
            });
        }
        match storage.get(&id) {
            Some(mut blog) => {
                if blog.deleted_at.is_some() {
                    return ResponseDto::Err(ErrorResponseDto {
                        message: "Blog already deleted".to_string(),
                        status: 400,
                    });
                }
                blog.deleted_at = Some(ic_cdk::api::time());
                storage.insert(id, blog);
                ResponseDto::Ok(GenericResponseDto {
                    data: "Blog deleted successfully".to_string(),
                    message: "Blog deleted successfully".to_string(),
                    status: 200,
                })
            }
            None => ResponseDto::Err(ErrorResponseDto {
                message: "Blog not found".to_string(),
                status: 404,
            }),
        }
    })
}

#[query]
fn list_blogs(
    token: String,
) -> ResponseDto<GenericResponseDto<Vec<BlogResponseDto>>, ErrorResponseDto> {
    if !validate_token(&token) {
        return ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        });
    }

    BLOG_STORAGE.with(|storage| {
        let storage = storage.borrow();
        if storage.len() == 0 {
            return ResponseDto::Err(ErrorResponseDto {
                message: "No blogs found".to_string(),
                status: 404,
            });
        }

        let blogs: Vec<BlogResponseDto> = match storage.iter().collect::<Vec<_>>() {
            entries if !entries.is_empty() => entries
                .into_iter()
                .filter_map(|(_, blog)| {
                    if blog.deleted_at.is_none() {
                        Some(BlogResponseDto {
                            id: blog.id,
                            title: blog.title.clone(),
                            content: blog.content.clone(),
                            published: blog.published,
                            created_by: blog.created_by,
                            created_at: blog.created_at,
                            categories: blog.categories.clone(),
                        })
                    } else {
                        None
                    }
                })
                .collect(),
            _ => vec![],
        };
        ResponseDto::Ok(GenericResponseDto {
            data: blogs,
            message: "Blogs retrieved successfully".to_string(),
            status: 200,
        })
    })
}

#[update]
fn update_blog(
    token: String,
    id: u64,
    title: Option<String>,
    content: Option<String>,
    published: Option<bool>,
    categories: Option<String>,
) -> ResponseDto<GenericResponseDto<BlogResponseDto>, ErrorResponseDto> {
    if !validate_token(&token) {
        return ResponseDto::Err(ErrorResponseDto {
            message: "Token not valid".to_string(),
            status: 401,
        });
    }

    let key = match Hmac::<Sha256>::new_from_slice(JWT_SECRET.as_bytes()) {
        Ok(key) => key,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Failed to process token".to_string(),
                status: 500,
            });
        }
    };

    let claims: Token<Header, Claims, Verified> = match token.verify_with_key(&key) {
        Ok(claims) => claims,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Token verification failed".to_string(),
                status: 401,
            });
        }
    };

    let user_id: u64 = match claims.claims().sub.parse() {
        Ok(id) => id,
        Err(_) => {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Invalid user ID in token".to_string(),
                status: 401,
            });
        }
    };

    BLOG_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if !storage.contains_key(&id) {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Blog not found".to_string(),
                status: 404,
            });
        }
        let mut blog = storage.get(&id).unwrap().clone();
        if blog.deleted_at.is_some() {
            return ResponseDto::Err(ErrorResponseDto {
                message: "Blog already deleted".to_string(),
                status: 400,
            });
        }
        blog.updated_by = Some(user_id);
        blog.updated_at = Some(ic_cdk::api::time());
        if let Some(title) = title {
            blog.title = title;
        }
        if let Some(content) = content {
            blog.content = content;
        }
        if let Some(published) = published {
            blog.published = published;
        }
        if let Some(categories) = categories {
            blog.categories = Some(categories);
        }
        storage.insert(id, blog.clone());
        ResponseDto::Ok(GenericResponseDto {
            data: BlogResponseDto {
                id: blog.id,
                title: blog.title,
                content: blog.content,
                published: blog.published,
                created_by: blog.created_by,
                created_at: blog.created_at,
                categories: blog.categories,
            },
            message: "Blog updated successfully".to_string(),
            status: 200,
        })
    })
}
