use axum::{
    extract::Json,
    routing::post,
    Router,
};
use bs58;
use base64;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, SECRET_KEY_LENGTH};
use thiserror::Error;
use solana_program::{instruction::{Instruction, AccountMeta}, pubkey::Pubkey, system_program};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running at http://{}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}

#[derive(Serialize)]
#[serde(untagged)]
enum ApiResponse<T> {
    Success { success: bool, data: T },
    Error { success: bool, error: String },
}

impl<T> ApiResponse<T> {
    fn ok(data: T) -> Self {
        ApiResponse::Success { success: true, data }
    }

    fn err(msg: &str) -> Self {
        ApiResponse::Error { success: false, error: msg.to_string() }
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

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::generate(&mut rand::rngs::OsRng);
    let pubkey = bs58::encode(keypair.public.as_bytes()).into_string();
    let secret = bs58::encode(keypair.secret.to_bytes()).into_string();
    Json(ApiResponse::ok(KeypairResponse { pubkey, secret }))
}

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
    let signature_b64 = base64::encode(signature.to_bytes());
    let pubkey_b58 = bs58::encode(public.as_bytes()).into_string();
    Json(ApiResponse::ok(SignResponse { signature: signature_b64, public_key: pubkey_b58, message: payload.message }))
}

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
    let pubkey_bytes = bs58::decode(&payload.pubkey).into_vec().ok().ok_or_else(|| ApiResponse::err("Invalid pubkey"))?;
    let signature_bytes = base64::decode(&payload.signature).ok().ok_or_else(|| ApiResponse::err("Invalid signature"))?;
    let pubkey = PublicKey::from_bytes(&pubkey_bytes).map_err(|_| ApiResponse::err("Invalid public key"))?;
    let signature = Signature::from_bytes(&signature_bytes).map_err(|_| ApiResponse::err("Invalid signature format"))?;
    let valid = pubkey.verify(payload.message.as_bytes(), &signature).is_ok();
    if !valid {
        return Json(ApiResponse::err(&ApiError::VerificationFailed.to_string()));
    }
    Json(ApiResponse::ok(VerifyResponse { valid, message: payload.message, pubkey: payload.pubkey }))
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mint: String,
    mintAuthority: String,
    decimals: u8,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

async fn create_token(Json(input): Json<CreateTokenRequest>) -> Json<ApiResponse<InstructionResponse>> {
    let mint = Pubkey::from_str(&input.mint).unwrap();
    let authority = Pubkey::from_str(&input.mintAuthority).unwrap();
    let program_id = spl_token::id();
    let ix = spl_token::instruction::initialize_mint(&program_id, &mint, &authority, None, input.decimals).unwrap();
    respond_with_instruction(ix)
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

async fn mint_token(Json(input): Json<MintTokenRequest>) -> Json<ApiResponse<InstructionResponse>> {
    let ix = spl_token::instruction::mint_to(
        &spl_token::id(),
        &Pubkey::from_str(&input.mint).unwrap(),
        &Pubkey::from_str(&input.destination).unwrap(),
        &Pubkey::from_str(&input.authority).unwrap(),
        &[],
        input.amount,
    ).unwrap();
    respond_with_instruction(ix)
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

async fn send_sol(Json(input): Json<SendSolRequest>) -> Json<ApiResponse<InstructionResponse>> {
    let ix = solana_program::system_instruction::transfer(
        &Pubkey::from_str(&input.from).unwrap(),
        &Pubkey::from_str(&input.to).unwrap(),
        input.lamports,
    );
    respond_with_instruction(ix)
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

async fn send_token(Json(input): Json<SendTokenRequest>) -> Json<ApiResponse<InstructionResponse>> {
    let ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &Pubkey::from_str(&input.mint).unwrap(), // Assumes source is mint
        &Pubkey::from_str(&input.destination).unwrap(),
        &Pubkey::from_str(&input.owner).unwrap(),
        &[],
        input.amount,
    ).unwrap();
    respond_with_instruction(ix)
}

fn respond_with_instruction(ix: Instruction) -> Json<ApiResponse<InstructionResponse>> {
    let accounts: Vec<AccountInfo> = ix.accounts.iter().map(|a| AccountInfo {
        pubkey: a.pubkey.to_string(),
        is_signer: a.is_signer,
        is_writable: a.is_writable,
    }).collect();

    Json(ApiResponse::ok(InstructionResponse {
        program_id: ix.program_id.to_string(),
        accounts,
        instruction_data: base64::encode(ix.data),
    }))
}
