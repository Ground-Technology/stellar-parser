//! Local Turnkey protocol fixture. Never included in the TVC router.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stellar_parser::xdr::{self, ReadXdr, WriteXdr};
use stellar_tvc_example::{
    Error,
    activity::{CONSENSUS, RAW_SIGN},
    now_ms,
};
use tokio::sync::Mutex;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

pub const ORGANIZATION: &str = "local-organization";
pub const NETWORK: &str = "Test SDF Network ; September 2015";
pub const CONTRACT: &str = "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U";
const FIXTURE: &str = include_str!("../fixtures/contract_call.xdr");
const DIGEST: &str = include_str!("../fixtures/contract_call.sha256");
const KID: &str = "local-webhook-key";

pub struct Mock {
    signing: SigningKey,
    activities: Mutex<HashMap<String, Value>>,
    votes: Mutex<Vec<Value>>,
    voter_key: Mutex<String>,
    fail_jwks: AtomicBool,
    fail_fetch: AtomicBool,
    fail_vote: AtomicBool,
    suite: Mutex<()>,
}

impl Mock {
    pub fn new() -> Arc<Self> {
        let bytes: [u8; 32] = TurnkeyP256ApiKey::generate()
            .private_key()
            .try_into()
            .expect("P256 private key is 32 bytes");
        Arc::new(Self {
            signing: SigningKey::from_bytes(&bytes),
            activities: Mutex::new(HashMap::new()),
            votes: Mutex::new(Vec::new()),
            voter_key: Mutex::new(String::new()),
            fail_jwks: AtomicBool::new(false),
            fail_fetch: AtomicBool::new(false),
            fail_vote: AtomicBool::new(false),
            suite: Mutex::new(()),
        })
    }

    async fn authenticate(&self, headers: &HeaderMap, body: &[u8]) -> Result<Value, StatusCode> {
        let verify = || -> Result<(Value, String), Error> {
            let encoded = headers.get("x-stamp").ok_or("missing X-Stamp")?.to_str()?;
            let stamp: Value = serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(encoded)?)?;
            if stamp["scheme"] != "SIGNATURE_SCHEME_TK_API_P256" {
                return Err("wrong scheme".into());
            }
            let public = stamp["publicKey"].as_str().ok_or("public key missing")?;
            let key = VerifyingKey::from_sec1_bytes(&hex::decode(public)?)?;
            let signature = Signature::from_der(&hex::decode(
                stamp["signature"].as_str().ok_or("signature missing")?,
            )?)?;
            key.verify(body, &signature)?;
            Ok((serde_json::from_slice(body)?, public.to_owned()))
        };
        let (request, public) = verify().map_err(|_| StatusCode::UNAUTHORIZED)?;
        if public != *self.voter_key.lock().await || request["organizationId"] != ORGANIZATION {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(request)
    }
}

pub fn router(state: Arc<Mock>) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/public/v1/discovery/webhooks/jwks", get(jwks))
        .route("/public/v1/query/get_activity", post(fetch))
        .route("/public/v1/submit/approve_activity", post(vote))
        .route("/public/v1/submit/reject_activity", post(vote))
        .route("/test/run", post(smoke))
        .with_state(state)
}

async fn jwks(State(state): State<Arc<Mock>>) -> Result<Json<Value>, StatusCode> {
    if state.fail_jwks.load(Ordering::SeqCst) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(json!({"keys": [{
        "kid": KID, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
        "x": BASE64_URL_SAFE_NO_PAD.encode(state.signing.verifying_key().as_bytes()),
        "turnkey_signature_algorithm": "ed25519", "turnkey_signature_version": "v1"
    }]})))
}

async fn fetch(
    State(state): State<Arc<Mock>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, StatusCode> {
    let request = state.authenticate(&headers, &body).await?;
    if state.fail_fetch.load(Ordering::SeqCst) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let id = request["activityId"]
        .as_str()
        .ok_or(StatusCode::BAD_REQUEST)?;
    let activity = state
        .activities
        .lock()
        .await
        .get(id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({"activity": activity})))
}

async fn vote(
    State(state): State<Arc<Mock>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, StatusCode> {
    let request = state.authenticate(&headers, &body).await?;
    if state.fail_vote.load(Ordering::SeqCst) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let approve = uri.path().ends_with("/approve_activity");
    let kind = if approve {
        "ACTIVITY_TYPE_APPROVE_ACTIVITY"
    } else {
        "ACTIVITY_TYPE_REJECT_ACTIVITY"
    };
    let timestamp: u128 = request["timestampMs"]
        .as_str()
        .ok_or(StatusCode::BAD_REQUEST)?
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if request["type"] != kind || now_ms()?.abs_diff(timestamp) > 300_000 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut activities = state.activities.lock().await;
    let original = activities
        .values_mut()
        .find(|activity| {
            activity["fingerprint"] == request["parameters"]["fingerprint"]
                && activity["status"] == CONSENSUS
        })
        .ok_or(StatusCode::BAD_REQUEST)?;
    let fingerprint = original["fingerprint"].clone();
    original["status"] = json!(if approve {
        "ACTIVITY_STATUS_COMPLETED"
    } else {
        "ACTIVITY_STATUS_REJECTED"
    });
    state
        .votes
        .lock()
        .await
        .push(json!({"type": kind, "fingerprint": fingerprint}));
    Ok(Json(json!({"activity": {
        "id": "local-vote", "organizationId": ORGANIZATION,
        "type": kind, "status": "ACTIVITY_STATUS_COMPLETED", "fingerprint": "local-vote-fingerprint"
    }})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmokeRequest {
    tvc_url: String,
}

async fn smoke(
    State(state): State<Arc<Mock>>,
    Json(request): Json<SmokeRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    run_suite(state, &request.tvc_url)
        .await
        .map(Json)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
}

fn activity(id: &str, xdr: &str, digest: &str) -> Value {
    let parameters = json!({
        "signWith": "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H",
        "payload": digest, "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
        "hashFunction": "HASH_FUNCTION_NOT_APPLICABLE"
    });
    let message = json!({
        "type": RAW_SIGN, "organizationId": ORGANIZATION, "timestampMs": "1",
        "parameters": parameters, "stellarContext": {"envelopeXdr": xdr}
    })
    .to_string();
    json!({
        "id": id, "organizationId": ORGANIZATION, "type": RAW_SIGN, "status": CONSENSUS,
        "fingerprint": fingerprint(&message), "intent": {"signRawPayloadIntentV2": parameters},
        "votes": [{
            "id": "initiator", "userId": "local-user", "activityId": id,
            "selection": "VOTE_SELECTION_APPROVED", "message": message,
            "publicKey": "", "signature": "", "scheme": ""
        }]
    })
}

fn fingerprint(message: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(message.as_bytes())))
}

fn edit_request(activity: &mut Value, edit: impl FnOnce(&mut Value)) -> Result<(), Error> {
    let mut request: Value = serde_json::from_str(
        activity["votes"][0]["message"]
            .as_str()
            .ok_or("message missing")?,
    )?;
    edit(&mut request);
    let message = request.to_string();
    activity["fingerprint"] = json!(fingerprint(&message));
    activity["votes"][0]["message"] = json!(message);
    Ok(())
}

fn changed_transaction(
    edit: impl FnOnce(&mut xdr::TransactionV1Envelope),
) -> Result<(String, String), Error> {
    let xdr::TransactionEnvelope::Tx(mut envelope) =
        xdr::TransactionEnvelope::from_xdr_base64(FIXTURE, xdr::Limits::none())?
    else {
        return Err("fixture must be v1".into());
    };
    edit(&mut envelope);
    let payload = xdr::TransactionSignaturePayload {
        network_id: xdr::Hash(Sha256::digest(NETWORK).into()),
        tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
            envelope.tx.clone(),
        ),
    };
    let digest = hex::encode(Sha256::digest(payload.to_xdr(xdr::Limits::none())?));
    Ok((
        xdr::TransactionEnvelope::Tx(envelope).to_xdr_base64(xdr::Limits::none())?,
        digest,
    ))
}

async fn deliver(
    state: &Mock,
    client: &reqwest::Client,
    url: &str,
    activity: &Value,
    change: Option<&str>,
) -> Result<StatusCode, Error> {
    let body = activity.to_string();
    let timestamp = if change == Some("stale") {
        now_ms()
            .map_err(|_| "invalid clock")?
            .saturating_sub(300_001)
    } else {
        now_ms().map_err(|_| "invalid clock")?
    };
    let event = format!("event-{}", activity["id"].as_str().ok_or("id missing")?);
    let message = format!("v1.ed25519.{KID}.{timestamp}.{event}.{body}");
    let signature = hex::encode(state.signing.sign(message.as_bytes()).to_bytes());
    let request = client
        .post(format!("{url}/webhooks/turnkey/activity"))
        .header(
            "x-turnkey-organization-id",
            if change == Some("org-header") {
                "other-org"
            } else {
                ORGANIZATION
            },
        )
        .header(
            "x-turnkey-event-type",
            if change == Some("event-header") {
                "OTHER"
            } else {
                "ACTIVITY_UPDATES"
            },
        )
        .header("x-turnkey-webhook-version", "1")
        .header("x-turnkey-signature-version", "v1")
        .header("x-turnkey-signature-algorithm", "ed25519")
        .header("x-turnkey-signature-key-id", KID)
        .header("x-turnkey-timestamp", timestamp.to_string())
        .header("x-turnkey-event-id", event)
        .header(
            "x-turnkey-signature",
            if change == Some("signature") {
                "00".repeat(64)
            } else {
                signature
            },
        );
    let body = if change == Some("body") {
        format!("{body} ")
    } else {
        body
    };
    Ok(request.body(body).send().await?.status())
}

pub async fn run_suite(state: Arc<Mock>, url: &str) -> Result<Value, Error> {
    let _suite = state.suite.lock().await;
    let url = url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let key: Value = client
        .get(format!("{url}/turnkey/api_public_key"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    *state.voter_key.lock().await = key["publicKey"]
        .as_str()
        .ok_or("public key missing")?
        .to_owned();
    state.activities.lock().await.clear();
    state.votes.lock().await.clear();
    let mut passed = Vec::new();
    let mut cases = vec![(
        "allowed-contract",
        activity("allowed-contract", FIXTURE, DIGEST.trim()),
        true,
    )];
    for (name, mode) in [
        ("other-contract", 0),
        ("mixed-contracts", 1),
        ("classic-operation", 2),
        ("nested-other-contract", 3),
        ("empty-transaction", 4),
    ] {
        let (encoded, digest) = changed_transaction(|envelope| {
            let mut op = envelope.tx.operations[0].clone();
            if mode == 2 {
                op.body = xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp::default());
            } else if let xdr::OperationBody::InvokeHostFunction(host) = &mut op.body {
                let other = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32])));
                if mode == 3 {
                    let mut auth = host.auth[0].clone();
                    let mut child = auth.root_invocation.sub_invocations[0].clone();
                    if let xdr::SorobanAuthorizedFunction::ContractFn(call) = &mut child.function {
                        call.contract_address = other;
                    }
                    auth.root_invocation.sub_invocations =
                        vec![child].try_into().expect("one child fits");
                    host.auth = vec![auth].try_into().expect("one auth fits");
                } else if let xdr::HostFunction::InvokeContract(call) = &mut host.host_function {
                    call.contract_address = other;
                }
            }
            let operations = if mode == 4 {
                vec![]
            } else if mode == 1 {
                vec![envelope.tx.operations[0].clone(), op]
            } else {
                vec![op]
            };
            envelope.tx.operations = operations.try_into().expect("two operations fit");
        })?;
        cases.push((name, activity(name, &encoded, &digest), false));
    }
    cases.push((
        "digest-mismatch",
        activity("digest-mismatch", FIXTURE, &"00".repeat(32)),
        false,
    ));
    cases.push((
        "malformed-xdr",
        activity("malformed-xdr", "AAAA", DIGEST.trim()),
        false,
    ));
    let mut changed = activity("substituted-request", FIXTURE, DIGEST.trim());
    changed["votes"][0]["message"] = json!(format!(
        "{} ",
        changed["votes"][0]["message"]
            .as_str()
            .ok_or("message missing")?
    ));
    cases.push(("substituted-request", changed, false));
    let mut changed = activity("intent-mismatch", FIXTURE, DIGEST.trim());
    changed["intent"]["signRawPayloadIntentV2"]["signWith"] = json!("other-signer");
    cases.push(("intent-mismatch", changed, false));
    let mut changed = activity("wrong-request-org", FIXTURE, DIGEST.trim());
    edit_request(&mut changed, |request| {
        request["organizationId"] = json!("other-org")
    })?;
    cases.push(("wrong-request-org", changed, false));
    let mut changed = activity("ambiguous-original", FIXTURE, DIGEST.trim());
    let original = changed["votes"][0].clone();
    changed["votes"]
        .as_array_mut()
        .ok_or("votes missing")?
        .push(original);
    cases.push(("ambiguous-original", changed, false));
    let mut changed = activity("wrong-encoding", FIXTURE, DIGEST.trim());
    edit_request(&mut changed, |request| {
        request["parameters"]["encoding"] = json!("PAYLOAD_ENCODING_TEXT_UTF8")
    })?;
    changed["intent"]["signRawPayloadIntentV2"]["encoding"] = json!("PAYLOAD_ENCODING_TEXT_UTF8");
    cases.push(("wrong-encoding", changed, false));
    for (name, activity, approve) in cases {
        state
            .activities
            .lock()
            .await
            .insert(name.into(), activity.clone());
        let before = state.votes.lock().await.len();
        let status = deliver(&state, &client, url, &activity, None).await?;
        let votes = state.votes.lock().await;
        let expected = if approve {
            "ACTIVITY_TYPE_APPROVE_ACTIVITY"
        } else {
            "ACTIVITY_TYPE_REJECT_ACTIVITY"
        };
        if status != StatusCode::NO_CONTENT
            || votes.len() != before + 1
            || votes[before]["type"] != expected
            || votes[before]["fingerprint"] != activity["fingerprint"]
        {
            return Err(format!(
                "{name}: expected {expected} and HTTP 204, got {status}, votes={}",
                votes.len() - before
            )
            .into());
        }
        drop(votes);
        let before = state.votes.lock().await.len();
        if deliver(&state, &client, url, &activity, None).await? != StatusCode::NO_CONTENT
            || state.votes.lock().await.len() != before
        {
            return Err(format!("{name}: redelivery must ignore finalized activity").into());
        }
        passed.push(name.to_owned());
    }
    let activity = activity("delivery-checks", FIXTURE, DIGEST.trim());
    state
        .activities
        .lock()
        .await
        .insert("delivery-checks".into(), activity.clone());
    for change in ["signature", "body", "stale", "org-header", "event-header"] {
        let before = state.votes.lock().await.len();
        if deliver(&state, &client, url, &activity, Some(change)).await? != StatusCode::UNAUTHORIZED
            || state.votes.lock().await.len() != before
        {
            return Err(format!("invalid {change}: expected HTTP 401 without vote").into());
        }
        passed.push(format!("invalid-{change}"));
    }
    let mut wrong_org = activity.clone();
    wrong_org["organizationId"] = json!("other-org");
    if deliver(&state, &client, url, &wrong_org, None).await? != StatusCode::UNAUTHORIZED {
        return Err("wrong body organization accepted".into());
    }
    passed.push("wrong-body-organization".into());
    let mut fetched = activity.clone();
    fetched["fingerprint"] = json!("sha256:substituted");
    state
        .activities
        .lock()
        .await
        .insert("delivery-checks".into(), fetched);
    if deliver(&state, &client, url, &activity, None).await? != StatusCode::UNAUTHORIZED {
        return Err("mismatched fetched activity accepted".into());
    }
    passed.push("fetched-identity-mismatch".into());
    state
        .activities
        .lock()
        .await
        .insert("delivery-checks".into(), activity.clone());
    for (name, switch) in [
        ("jwks-unavailable", &state.fail_jwks),
        ("activity-unavailable", &state.fail_fetch),
        ("vote-unavailable", &state.fail_vote),
    ] {
        let before = state.votes.lock().await.len();
        switch.store(true, Ordering::SeqCst);
        let status = deliver(&state, &client, url, &activity, None).await;
        switch.store(false, Ordering::SeqCst);
        if status? != StatusCode::SERVICE_UNAVAILABLE || state.votes.lock().await.len() != before {
            return Err(format!("{name}: expected HTTP 503 without recorded vote").into());
        }
        passed.push(name.into());
    }
    if deliver(&state, &client, url, &activity, None).await? != StatusCode::NO_CONTENT {
        return Err("redelivery after dependency recovery failed".into());
    }
    passed.push("retry-after-recovery".into());
    for (name, kind, status) in [
        (
            "unrelated-activity",
            "ACTIVITY_TYPE_SIGN_TRANSACTION_V2",
            CONSENSUS,
        ),
        ("completed-activity", RAW_SIGN, "ACTIVITY_STATUS_COMPLETED"),
    ] {
        let mut ignored = activity.clone();
        ignored["type"] = json!(kind);
        ignored["status"] = json!(status);
        let before = state.votes.lock().await.len();
        if deliver(&state, &client, url, &ignored, None).await? != StatusCode::NO_CONTENT
            || state.votes.lock().await.len() != before
        {
            return Err(format!("{name}: expected HTTP 204 without vote").into());
        }
        passed.push(name.into());
    }
    if client
        .post(format!("{url}/evaluate"))
        .send()
        .await?
        .status()
        != StatusCode::NOT_FOUND
    {
        return Err("unexpected unauthenticated evaluation endpoint".into());
    }
    passed.push("no-evaluate-endpoint".into());
    Ok(
        json!({"passed": passed.len(), "allowedContract": CONTRACT, "cases": passed, "votes": state.votes.lock().await.clone()}),
    )
}
