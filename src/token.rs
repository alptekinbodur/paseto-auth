use crate::{Claims, PasetoError};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::convert::TryInto;

const FOOTER: &str = "travel"; // Global footer – must be the same in all services

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// create user token
pub fn create_token(
    claims: Claims,
    private_key: &str,
    ttl_seconds: u64,
) -> Result<String, PasetoError> {
    let sk_bytes: [u8; 32] = hex::decode(private_key)?
        .try_into()
        .map_err(|_| PasetoError::InvalidPrivateKey)?;

    let new_claims = Claims::new(
        claims.user,
        claims.company,
        claims.device,
        ttl_seconds,
    );

    create_paseto_v4_public(&new_claims, &sk_bytes)
}

/// Paseto v4.public generates tokens
fn create_paseto_v4_public(
    claims: &Claims,
    secret_key_bytes: &[u8; 32],
) -> Result<String, PasetoError> {
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = b64url_encode(&payload_json);

    let mut message = payload_json;
    let footer_b64 = b64url_encode(FOOTER.as_bytes());
    message.extend_from_slice(FOOTER.as_bytes());

    let signing_key = SigningKey::from_bytes(secret_key_bytes);
    let signature: Signature = signing_key.sign(&message);
    let sig_b64 = b64url_encode(&signature.to_bytes());

    Ok(format!("ab.travel.{}.{}.{}", payload_b64, sig_b64, footer_b64))
}

/// Validates Paseto v4.public token
pub fn verify_token(token: &str, public_key: &str) -> Result<Claims, PasetoError> {
    let pk_bytes: [u8; 32] = hex::decode(public_key)
        .map_err(PasetoError::HexError)?
        .try_into()
        .map_err(|_| PasetoError::InvalidPublicKey)?;

    verify_paseto_v4_public(&token, &pk_bytes)
}

pub fn verify_paseto_v4_public(
    token: &str,
    public_key_bytes: &[u8; 32],
) -> Result<Claims, PasetoError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 || parts[0] != "ab" || parts[1] != "travel" {
        return Err(PasetoError::InvalidFormat);
    }

    let payload_b64 = parts[2];
    let sig_b64 = parts[3];
    let footer_b64 = parts[4];

    // Footer 
    let expected_footer_b64 = b64url_encode(FOOTER.as_bytes());
    if footer_b64 != expected_footer_b64 {
        return Err(PasetoError::InvalidFooter);
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
    if sig_bytes.len() != 64 {
        return Err(PasetoError::InvalidSignature);
    }

    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)?;

    let mut message = payload_bytes.clone();
    message.extend_from_slice(FOOTER.as_bytes());

    verifying_key.verify(&message, &signature)?;
    let claims: Claims = serde_json::from_slice(&payload_bytes)?;

    if !claims.is_valid() {
        return Err(PasetoError::Expired);
    }

    Ok(claims)
}