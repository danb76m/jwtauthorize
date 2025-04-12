use jsonwebtoken::Algorithm;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct AuthConfig {
    pub jwks_url: String,
    pub leeway: u64, // seconds
    pub audience: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub header: String,
}