use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::now_ms;

#[derive(Deserialize)]
struct Keys {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct Key {
    kid: String,
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
    x: String,
    turnkey_signature_algorithm: String,
    turnkey_signature_version: String,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)
}

pub async fn verify(
    client: &reqwest::Client,
    api_url: &str,
    organization: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), StatusCode> {
    let unauthorized = StatusCode::UNAUTHORIZED;
    if header(headers, "x-turnkey-organization-id")? != organization
        || header(headers, "x-turnkey-webhook-version")? != "1"
        || header(headers, "x-turnkey-signature-version")? != "v1"
        || header(headers, "x-turnkey-signature-algorithm")? != "ed25519"
        || header(headers, "x-turnkey-event-type")? != "ACTIVITY_UPDATES"
    {
        return Err(unauthorized);
    }
    let timestamp = header(headers, "x-turnkey-timestamp")?;
    let timestamp_ms: u128 = timestamp.parse().map_err(|_| unauthorized)?;
    if now_ms()?.abs_diff(timestamp_ms) > 300_000 {
        return Err(unauthorized);
    }
    let event = header(headers, "x-turnkey-event-id")?;
    let kid = header(headers, "x-turnkey-signature-key-id")?;
    let signature = Signature::from_slice(
        &hex::decode(header(headers, "x-turnkey-signature")?).map_err(|_| unauthorized)?,
    )
    .map_err(|_| unauthorized)?;
    let unavailable = StatusCode::SERVICE_UNAVAILABLE;
    let response = client
        .get(format!("{api_url}/public/v1/discovery/webhooks/jwks"))
        .send()
        .await
        .map_err(|_| unavailable)?
        .error_for_status()
        .map_err(|_| unavailable)?;
    let keys: Keys = response.json().await.map_err(|_| unavailable)?;
    let key = keys
        .keys
        .into_iter()
        .find(|key| key.kid == kid)
        .ok_or(unauthorized)?;
    if key.kty != "OKP"
        || key.crv != "Ed25519"
        || key.alg != "EdDSA"
        || key.usage != "sig"
        || key.turnkey_signature_algorithm != "ed25519"
        || key.turnkey_signature_version != "v1"
    {
        return Err(unavailable);
    }
    let public: [u8; 32] = BASE64_URL_SAFE_NO_PAD
        .decode(key.x)
        .map_err(|_| unavailable)?
        .try_into()
        .map_err(|_| unavailable)?;
    let public = VerifyingKey::from_bytes(&public).map_err(|_| unavailable)?;
    let mut message = format!("v1.ed25519.{kid}.{timestamp}.{event}.").into_bytes();
    message.extend_from_slice(body);
    public
        .verify_strict(&message, &signature)
        .map_err(|_| unauthorized)
}
