
use getrandom::getrandom; // Add this at the top
use axum::{
    extract::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, SECRET_KEY_LENGTH};
use std::net::SocketAddr;
use bs58;
use thiserror::Error;
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message));

    // Get PORT from env (Render sets it automatically)
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())  // fallback for local
        .parse::<u16>()
        .expect("Invalid PORT");

    let addr = SocketAddr::from(([0, 0, 0, 0], port)); // bind to 0.0.0.0 for Render
    println!("Server running at http://{}", addr);

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

// Response Wrapper
#[derive(Serialize)]
#[serde(untagged)]
enum ApiResponse<T> {
    Success { success: bool, data: T },
    Error { success: bool, error: String },
}

impl<T> ApiResponse<T> {
    fn ok(data: T) -> Self {
        ApiResponse::Success {
            success: true,
            data,
        }
    }

    fn err(msg: &str) -> Self {
        ApiResponse::Error {
            success: false,
            error: msg.to_string(),
        }
    }
}

#[derive(Error, Debug)]
enum ApiError {
    #[error("Missing required fields")]
    MissingFields,
    #[error("Invalid base58 or base64 data")]
    InvalidEncoding,
    #[error("Signature verification failed")]
    VerificationFailed,
}

// 1. Generate Keypair
#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}


async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let mut bytes = [0u8; 32];
    if let Err(_) = getrandom(&mut bytes) {
        return Json(ApiResponse::err("Failed to generate random bytes"));
    }

    let secret = ed25519_dalek::SecretKey::from_bytes(&bytes).unwrap();
    let public = PublicKey::from(&secret);
    let keypair = Keypair { secret, public };

    let pubkey_b58 = bs58::encode(keypair.public.as_bytes()).into_string();
    let secret_b58 = bs58::encode(keypair.secret.to_bytes()).into_string();

    Json(ApiResponse::ok(KeypairResponse {
        pubkey: pubkey_b58,
        secret: secret_b58,
    }))
}

// 2. Sign Message
#[derive(Deserialize)]
struct SignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
    public_key: String,
    message: String,
}

async fn sign_message(Json(payload): Json<SignRequest>) -> Json<ApiResponse<SignResponse>> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Json(ApiResponse::err(&ApiError::MissingFields.to_string()));
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(ApiResponse::err(&ApiError::InvalidEncoding.to_string())),
    };

    if secret_bytes.len() != SECRET_KEY_LENGTH {
        return Json(ApiResponse::err("Invalid secret key length"));
    }

    let secret = ed25519_dalek::SecretKey::from_bytes(&secret_bytes).unwrap();
    let public = PublicKey::from(&secret);
    let keypair = Keypair { secret, public };

    let signature = keypair.sign(payload.message.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
    let pubkey_b58 = bs58::encode(public.as_bytes()).into_string();

    Json(ApiResponse::ok(SignResponse {
        signature: signature_b64,
        public_key: pubkey_b58,
        message: payload.message,
    }))
}

// 3. Verify Message
#[derive(Deserialize)]
struct VerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn verify_message(Json(payload): Json<VerifyRequest>) -> Json<ApiResponse<VerifyResponse>> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Json(ApiResponse::err(&ApiError::MissingFields.to_string()));
    }

    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(ApiResponse::err(&ApiError::InvalidEncoding.to_string())),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Json(ApiResponse::err(&ApiError::InvalidEncoding.to_string())),
    };

    let pubkey = match PublicKey::from_bytes(&pubkey_bytes) {
        Ok(p) => p,
        Err(_) => return Json(ApiResponse::err("Invalid public key")),
    };

    let signature = match Signature::from_bytes(&signature_bytes) {
        Ok(s) => s,
        Err(_) => return Json(ApiResponse::err("Invalid signature format")),
    };

    let valid = pubkey.verify(payload.message.as_bytes(), &signature).is_ok();

    if !valid {
        return Json(ApiResponse::err(&ApiError::VerificationFailed.to_string()));
    }

    Json(ApiResponse::ok(VerifyResponse {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    }))
}
