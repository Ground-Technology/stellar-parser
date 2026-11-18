use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_parser::xdr;

use crate::policy;

pub const RAW_SIGN: &str = "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2";
pub const CONSENSUS: &str = "ACTIVITY_STATUS_CONSENSUS_NEEDED";

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: String,
    pub organization_id: String,
    pub status: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub fingerprint: String,
    #[serde(default)]
    pub intent: serde_json::Value,
    #[serde(default)]
    pub votes: Vec<Vote>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vote {
    activity_id: String,
    selection: String,
    message: String,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Parameters {
    sign_with: String,
    payload: String,
    encoding: String,
    hash_function: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(rename = "type")]
    kind: String,
    organization_id: String,
    parameters: Parameters,
    stellar_context: StellarContext,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StellarContext {
    envelope_xdr: String,
}

impl Activity {
    pub fn eligible(&self) -> bool {
        self.kind == RAW_SIGN && self.status == CONSENSUS
    }

    pub fn same_request(&self, other: &Self) -> bool {
        self.id == other.id
            && self.organization_id == other.organization_id
            && self.kind == other.kind
            && !self.fingerprint.is_empty()
            && self.fingerprint == other.fingerprint
    }

    pub fn approve(&self, network: &str, contract: &xdr::ContractId) -> bool {
        self.check(network, contract).is_ok()
    }

    fn check(&self, network: &str, contract: &xdr::ContractId) -> Result<(), &'static str> {
        let mut originals = self.votes.iter().filter(|vote| {
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(vote.message.as_bytes()))
            ) == self.fingerprint
        });
        let original = originals.next().ok_or("original request missing")?;
        if originals.next().is_some()
            || original.activity_id != self.id
            || original.selection != "VOTE_SELECTION_APPROVED"
        {
            return Err("invalid initiating vote");
        }
        let request: Request =
            serde_json::from_str(&original.message).map_err(|_| "invalid request")?;
        let intent: Parameters =
            serde_json::from_value(self.intent["signRawPayloadIntentV2"].clone())
                .map_err(|_| "invalid signing intent")?;
        if request.kind != self.kind
            || request.organization_id != self.organization_id
            || request.parameters != intent
            || intent.sign_with.is_empty()
            || intent.encoding != "PAYLOAD_ENCODING_HEXADECIMAL"
            || intent.hash_function != "HASH_FUNCTION_NOT_APPLICABLE"
        {
            return Err("request differs from activity");
        }
        let digest: [u8; 32] = hex::decode(&intent.payload)
            .map_err(|_| "invalid digest")?
            .try_into()
            .map_err(|_| "invalid digest length")?;
        match policy::evaluate(
            &request.stellar_context.envelope_xdr,
            network,
            &digest,
            contract,
        ) {
            Ok(true) => Ok(()),
            _ => Err("transaction rejected"),
        }
    }
}
