use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ic_agent::{Agent, Identity};
use candid::Principal;
use dotenv::dotenv;
use std::env;
use async_std::sync::Arc;
use env_logger;
use log;
mod dtos;
mod canister;

use dtos::{LoginRequest, CreateBlogRequest, ResponseDtoAuth as DtosResponseDtoAuth, ResponseDtoBlog as DtosResponseDtoBlog, GenericResponseDtoAuth, GenericResponseDtoBlog, ErrorResponseDto, AuthResponseDto, BlogResponseDto};
use canister::{Service, ResponseDtoAuth as CanisterResponseDtoAuth, ResponseDtoBlog as CanisterResponseDtoBlog};

async fn login(
    service: web::Data<Arc<Service>>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    log::debug!("Received login request for username: {}", req.username);

    let result = service.signin(req.username.clone(), req.password.clone()).await;

    match result {
        Ok(response) => {
            let dtos_response = match response {
                CanisterResponseDtoAuth::Ok(data) => DtosResponseDtoAuth::Ok(GenericResponseDtoAuth {
                    data: AuthResponseDto { token: data.data.token },
                    message: data.message,
                    status: data.status,
                }),
                CanisterResponseDtoAuth::Err(error) => DtosResponseDtoAuth::Err(ErrorResponseDto {
                    message: error.message,
                    status: error.status,
                }),
            };
            match dtos_response {
                DtosResponseDtoAuth::Ok(data) => {
                    log::info!("Login successful for username: {}", req.username);
                    HttpResponse::Ok().json(data)
                }
                DtosResponseDtoAuth::Err(error) => {
                    log::warn!("Login failed: {:?}", error);
                    HttpResponse::BadRequest().json(error)
                }
            }
        }
        Err(e) => {
            log::error!("Canister call failed: {:?}", e);
            HttpResponse::InternalServerError().json(ErrorResponseDto {
                message: format!("Failed to contact canister: {:?}", e),
                status: 500,
            })
        }
    }
}
async fn create_blog_endpoint(
    service: web::Data<Arc<Service>>,
    req: web::Json<CreateBlogRequest>,
) -> impl Responder {
    log::debug!("Received create blog request with title: {}", req.title);

    let result = service.create_blog(
        req.token.clone(),
        req.title.clone(),
        req.content.clone(),
        req.published,
    ).await;

    match result {
        Ok(response) => {
            let dtos_response = match response {
                CanisterResponseDtoBlog::Ok(data) => DtosResponseDtoBlog::Ok(GenericResponseDtoBlog {
                    data: BlogResponseDto {
                        id: data.data.id,
                        title: data.data.title,
                        content: data.data.content,
                        published: data.data.published,
                        created_by: data.data.created_by,
                        created_at: data.data.created_at,
                    },
                    message: data.message,
                    status: data.status,
                }),
                CanisterResponseDtoBlog::Err(error) => DtosResponseDtoBlog::Err(ErrorResponseDto {
                    message: error.message,
                    status: error.status,
                }),
            };
            match dtos_response {
                DtosResponseDtoBlog::Ok(data) => {
                    log::info!("Blog created successfully: {}", data.data.title);
                    HttpResponse::Ok().json(data)
                }
                DtosResponseDtoBlog::Err(error) => {
                    log::warn!("Blog creation failed: {:?}", error);
                    HttpResponse::BadRequest().json(error)
                }
            }
        }
        Err(e) => {
            log::error!("Canister call failed: {:?}", e);
            HttpResponse::InternalServerError().json(ErrorResponseDto {
                message: format!("Failed to contact canister: {:?}", e),
                status: 500,
            })
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    dotenv().ok();

    // Load environment variables
    let ic_url = env::var("IC_URL").unwrap_or_else(|_| "http://localhost:4943".to_string());
    let canister_id_str = env::var("CANISTER_ID").unwrap_or_else(|_| "be2us-64aaa-aaaaa-qaabq-cai".to_string());

    log::info!("Starting server with IC_URL: {} and CANISTER_ID: {}", ic_url, canister_id_str);

    // Initialize IC Agent
    let agent = Agent::builder()
        .with_url(&ic_url)
        .with_identity(ic_agent::identity::AnonymousIdentity)
        .build();

    let agent = match agent {
        Ok(agent) => agent,
        Err(e) => {
            log::error!("Failed to build IC Agent: {:?}", e);
            panic!("Failed to build IC Agent: {:?}", e);
        }
    };

    // For local replica, set the root key
    if ic_url.contains("localhost") {
        if let Err(e) = agent.fetch_root_key().await {
            log::error!("Failed to fetch root key: {:?}", e);
            panic!("Failed to fetch root key: {:?}", e);
        }
    }

    let canister_id = match Principal::from_text(&canister_id_str) {
        Ok(id) => id,
        Err(e) => {
            log::error!("Invalid canister ID: {:?}", e);
            panic!("Invalid canister ID: {:?}", e);
        }
    };

    
    let service = Arc::new(Service {
        agent,
        canister_id,
    });
    log::info!("Service initialized for canister ID: {}", canister_id_str);

    // Start Actix Web server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(service.clone()))
            .route("/login", web::post().to(login))
            .route("/create-blog", web::post().to(create_blog_endpoint))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}