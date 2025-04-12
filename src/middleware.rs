use crate::keys::{ErrorUnauthorisedKey};
use crate::{keys, keys_utils};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized as ActixWebErrorUnauthorized, // Rename to avoid conflict
    Error, HttpMessage,
};
use futures_util::future::{ok, Ready};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{debug, error};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    rc::Rc,
};
use actix_web::error::ErrorUnauthorized;
use crate::auth::AuthConfig;
use crate::keys::ErrorUnauthorisedKey::KeyNotFound;

pub struct JwtAuthMiddlewareFactory {
    config: AuthConfig,
}

impl JwtAuthMiddlewareFactory {
    pub fn new(config: AuthConfig) -> Self {
        JwtAuthMiddlewareFactory { config }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuthMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok::<JwtAuthMiddleware<S>, ()>(JwtAuthMiddleware {
            service: Rc::new(service),
            config: self.config.clone(),
        })
    }
}

pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
    config: AuthConfig,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let config = self.config.clone();
        Box::pin(async move {
            // Skip authentication for OPTIONS requests
            if req.method() == actix_web::http::Method::OPTIONS {
                debug!("OPTIONS request, skipping authentication.");
                return srv.call(req).await;
            }

            let auth_header = req.headers().get(&config.header);
            let token = match auth_header {
                Some(header_value) => {
                    let auth_str = header_value
                        .to_str()
                        .map_err(|_| ErrorUnauthorized("Invalid Authorization header"))?;
                    if auth_str.starts_with("Bearer ") {
                        let tokes = auth_str[7..].to_string();
                        Ok(tokes)
                    } else {
                        Err(ErrorUnauthorized("Invalid Authorization header format"))
                    }
                }
                None => Err(ErrorUnauthorized("Missing Authorization header")),
            }?;

            debug!("Verifying JWT signature.");
            match verify_jwt_signature(
                token.as_str(), config,
            ).await {
                Ok(claims) => {
                    req.extensions_mut().insert(claims.clone());
                    debug!("JWT signature verified successfully.");

                    srv.call(req).await
                }
                Err(err) => {
                    debug!("Error {}", err);
                    Err(ErrorUnauthorized(err))
                }
            }
        })
    }
}

async fn verify_jwt_signature(
    token: &str,
    auth_config: AuthConfig,
) -> Result<HashMap<String, Value>, ErrorUnauthorisedKey> {
    let header = decode_header(token).map_err(|e| {
        error!("Failed to decode header: {:?}", e);
        ErrorUnauthorisedKey::DecodeHeaderFailure(e.to_string())
    })?;

    let kid = header.kid.ok_or(ErrorUnauthorisedKey::MissingKid)?;

    let key: Value = keys::get_key(
        auth_config.jwks_url.clone().parse().unwrap(),
        kid.clone().parse().unwrap(),
    )
        .await
        .map_err(|e| {
            error!("Failed to get key: {:?}", e);
            KeyNotFound
        })?;

    let key_pem = keys_utils::key_to_pem(&key).map_err(|e| {
        error!("Failed to convert key to PEM: {:?}", e);
        ErrorUnauthorisedKey::DecodingKeyFailure(e.to_string())
    })?;

    let decoding_key = DecodingKey::from_rsa_pem(key_pem.as_bytes()).map_err(|e| {
        error!("Failed to create decoding key: {:?}", e);
        ErrorUnauthorisedKey::DecodingKeyFailure(e.to_string())
    })?;

    decode::<HashMap<String, Value>>(token, &decoding_key, &create_validation(auth_config))
        .map(|decoded| {
            debug!("JWT decoded successfully.");
            decoded.claims
        })
        .map_err(|e| {
            error!("Signature verification failed: {:?}", e);
            ErrorUnauthorisedKey::SignatureVerificationFailure(e.to_string())
        })
}

pub fn create_validation(auth_config: AuthConfig) -> Validation {
    let mut validation = Validation::new(auth_config.algorithm);
    validation.leeway = auth_config.leeway;
    validation.set_audience(&[auth_config.audience.as_str()]);
    validation.set_issuer(&[auth_config.issuer.to_string()]);

    validation
}