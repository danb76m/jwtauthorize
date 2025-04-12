use lazy_static::lazy_static;
use log::{debug, error};
use moka::future::Cache;
use reqwest::Client;
use serde_json::{Value};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use std::fmt;
use std::fmt::{Display, Formatter};
use serde::Deserialize;

lazy_static! {
    static ref DURATION: Mutex<SystemTime> = Mutex::new(SystemTime::UNIX_EPOCH);
    static ref JWKS_CACHE: Cache<String, Value> = Cache::builder()
        .time_to_live(Duration::from_secs(24 * 60))
        .time_to_idle(Duration::from_secs(24 * 60))
        .build();
    static ref HTTP_CLIENT: Client = Client::new();
}

#[derive(Debug, Error)]
pub enum ErrorUnauthorisedKey {
    #[error("Failed to get JWKS: {0}")]
    GetJwksFailure(reqwest::Error),
    #[error("Failed to parse JWKS: {0}")]
    ParseJwksFailure(reqwest::Error),
    #[error("JWKS could not be converted to hashmap: {0}")]
    JwksConversionFailure(serde_json::Error),
    #[error("Failed to decode header: {0}")]
    DecodeHeaderFailure(String),
    #[error("Missing kid in header")]
    MissingKid,
    #[error("Key not found in JWKS")]
    KeyNotFound,
    #[error("Failed to create decoding key: {0}")]
    DecodingKeyFailure(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailure(String),
    #[error("Deserialize Jwks Failure")]
    DeserializeJwksFailure,
}

pub async fn key_refresh(jwks_url: String) -> Result<(), ErrorUnauthorisedKey> {
    let now = SystemTime::now();
    let mut duration = DURATION.lock().unwrap();

    if now.duration_since(*duration).unwrap_or_default() < Duration::from_secs(5 * 60) {
        return Ok(());
    }

    JWKS_CACHE.invalidate_all();

    match HTTP_CLIENT.get(&jwks_url).send().await {
        Ok(res) => {
            match res.text().await {
                Ok(body) => {
                    match serde_json::from_str::<Value>(&body) {
                        Ok(json) => {
                            if let Some(Keys) = json["keys"].as_array() {
                                for key in Keys {
                                    if let Some(kid_str) = key["kid"].as_str() {
                                        let kid = kid_str.to_string();
                                        JWKS_CACHE.insert(kid.clone(), key.clone()).await;
                                        debug!("Inserted new key {}, here is e {}", kid.clone(), key["e"].as_str().unwrap().to_string())
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            error!("Error: {}", err)
                        }
                    }
                }
                Err(err) => {
                    error!("Error: {}", err)
                }

            }
        }
        Err(err) => {
            error!("Error fetching JWKS: {}", err);
        }
    }

    *duration = now;
    Ok(())
}


async fn get_key_from_cache(kid: &str) -> Option<Value> {
    JWKS_CACHE.get(kid).await
}

pub async fn get_key(
    jwks_url: String,
    kid: String,
) -> Result<Value, ErrorUnauthorisedKey> {
    debug!("Looking for kid {} in jwks_url {}", kid, jwks_url);

    if let Some(key) = get_key_from_cache(&kid).await {
        debug!("Found key {} in JWKS", key);
        return Ok(key);
    }

    debug!("Did not find. Refreshing keys.");
    key_refresh(jwks_url.clone()).await?;

    if let Some(key) = get_key_from_cache(&kid).await {
        debug!("Found key {} in JWKS v2", key);
        return Ok(key);
    }

    debug!("Could not find key in JWKS cache.");
    Err(ErrorUnauthorisedKey::KeyNotFound)
}