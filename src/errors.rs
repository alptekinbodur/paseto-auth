use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasetoError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Footer does not match")]
    InvalidFooter,
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Token has expired")]
    Expired,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Crypto  error: {0}")]
    Crypto(#[from] ed25519_dalek::SignatureError),

    #[error("Hex error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
}