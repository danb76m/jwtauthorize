use actix_web::Error;
use actix_web::error::ErrorUnauthorized;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use log::{debug, error};
use openssl::bn::BigNum;
use openssl::rsa::Rsa;
use serde_json::Value;

pub(crate) fn key_to_pem(key: &Value) -> Result<String, Error> {
    let n_str = key["n"].as_str().ok_or_else(|| {
        error!("'n' field not found in JWK.");
        ErrorUnauthorized("'n' field not found in JWK")
    })?;
    let e_str = key["e"].as_str().ok_or_else(|| {
        error!("'e' field not found in JWK.");
        ErrorUnauthorized("'e' field not found in JWK")
    })?;

    let mut n_str_padded = n_str.to_string();
    let mut e_str_padded = e_str.to_string();

    while n_str_padded.len() % 4 != 0 {
        n_str_padded.push('=');
    }
    while e_str_padded.len() % 4 != 0 {
        e_str_padded.push('=');
    }

    let n = BASE64_URL_SAFE.decode(n_str_padded.as_bytes()).map_err(|e| {
        ErrorUnauthorized("Failed to decode 'n' from base64url")
    })?;
    let e = BASE64_URL_SAFE.decode(e_str_padded.as_bytes()).map_err(|e| {
        ErrorUnauthorized("Failed to decode 'e' from base64url")
    })?;

    let rsa_public_key = Rsa::from_public_components(
        BigNum::from_slice(&n).map_err(|e| {
            error!("Failed to create BigNum from 'n': {:?}", e);
            ErrorUnauthorized("Failed to create BigNum from 'n'")
        })?,
        BigNum::from_slice(&e).map_err(|e| {
            error!("Failed to create BigNum from 'e': {:?}", e);
            ErrorUnauthorized("Failed to create BigNum from 'e'")
        })?,
    ).map_err(|e| {
        error!("Failed to create RSA public key: {:?}", e);
        ErrorUnauthorized("Failed to create RSA public key")
    })?;

    debug!("Converting RSA public key to PEM format.");
    let pem_bytes = rsa_public_key.public_key_to_pem_pkcs1().map_err(|e| {
        error!("Failed to convert RSA public key to PEM: {:?}", e);
        ErrorUnauthorized("Failed to convert RSA public key to PEM")
    })?;

    debug!("Converting PEM bytes to string.");
    let pem_string = String::from_utf8(pem_bytes).map_err(|e| {
        error!("Failed to convert PEM bytes to UTF-8 string: {:?}", e);
        ErrorUnauthorized("Failed to convert PEM bytes to UTF-8 string")
    })?;

    debug!("JWK converted to PEM successfully.");
    Ok(pem_string)
}
