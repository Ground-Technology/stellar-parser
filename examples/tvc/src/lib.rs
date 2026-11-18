pub mod activity;
pub mod policy;
mod verification;

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::json;
use stellar_parser::xdr;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use turnkey_client::{
    TurnkeyClient,
    generated::{
        immutable::activity::v1::{ApproveActivityIntent, RejectActivityIntent},
        services::coordinator::public::v1::GetActivityRequest,
    },
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Config {
    pub organization_id: String,
    pub network_passphrase: String,
    pub allowed_contract: xdr::ContractId,
    pub turnkey_api_url: String,
}

struct App {
    config: Config,
    client: TurnkeyClient<TurnkeyP256ApiKey>,
    http: reqwest::Client,
    public_key: String,
}

pub fn router(mut config: Config, key: TurnkeyP256ApiKey) -> Result<Router, Error> {
    config.turnkey_api_url = config.turnkey_api_url.trim_end_matches('/').to_owned();
    if config.organization_id.is_empty() || config.network_passphrase.is_empty() {
        return Err("organization and network must be configured".into());
    }
    let url = reqwest::Url::parse(&config.turnkey_api_url)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid Turnkey API URL".into());
    }
    let vote_public_key = hex::encode(key.compressed_public_key());
    let client = TurnkeyClient::builder()
        .api_key(key)
        .base_url(&config.turnkey_api_url)
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(4))
        .build()?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(4))
        .build()?;
    let app = Arc::new(App {
        config,
        client,
        http,
        public_key: vote_public_key,
    });
    Ok(Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status": "healthy"})) }),
        )
        .route("/turnkey/api_public_key", get(public_key))
        .route("/webhooks/turnkey/activity", post(webhook))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(app))
}

async fn public_key(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(json!({"publicKey": app.public_key, "curveType": "API_KEY_CURVE_P256"}))
}

async fn webhook(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    verification::verify(
        &app.http,
        &app.config.turnkey_api_url,
        &app.config.organization_id,
        &headers,
        &body,
    )
    .await?;
    let delivered: activity::Activity =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if delivered.organization_id != app.config.organization_id {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !delivered.eligible() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let fetched = app
        .client
        .get_activity(GetActivityRequest {
            organization_id: app.config.organization_id.clone(),
            activity_id: delivered.id.clone(),
        })
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let fetched = fetched.activity.ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let fetched: activity::Activity = serde_json::from_value(
        serde_json::to_value(fetched).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
    )
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !delivered.same_request(&fetched) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !fetched.eligible() {
        return Ok(StatusCode::NO_CONTENT);
    }
    let approve = fetched.approve(&app.config.network_passphrase, &app.config.allowed_contract);
    let organization = app.config.organization_id.clone();
    let timestamp = now_ms()?;
    let result = if approve {
        app.client
            .approve_activity(
                organization,
                timestamp,
                ApproveActivityIntent {
                    fingerprint: fetched.fingerprint,
                },
            )
            .await
    } else {
        app.client
            .reject_activity(
                organization,
                timestamp,
                RejectActivityIntent {
                    fingerprint: fetched.fingerprint,
                },
            )
            .await
    };
    result.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    eprintln!(
        "activity={} vote={}",
        fetched.id,
        if approve { "approve" } else { "reject" }
    );
    Ok(StatusCode::NO_CONTENT)
}

pub fn now_ms() -> Result<u128, StatusCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}
