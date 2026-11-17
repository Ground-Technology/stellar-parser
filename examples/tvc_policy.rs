//! Example policy to call after a TVC application authenticates a signing request.

use std::{error::Error, fmt, fs};

use stellar_parser::{parse_base64, xdr};

#[derive(Debug)]
struct Rejected(&'static str);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Error for Rejected {}

fn require(condition: bool, reason: &'static str) -> Result<(), Box<dyn Error>> {
    if condition {
        Ok(())
    } else {
        Err(Box::new(Rejected(reason)))
    }
}

fn evaluate(
    envelope_xdr: &str,
    network: &str,
    requested_digest: &[u8; 32],
    source: &xdr::MuxedAccount,
    issuer: &xdr::AccountId,
    now: u64,
) -> Result<(), Box<dyn Error>> {
    let parsed = parse_base64(envelope_xdr, network)?;
    parsed.verify_signing_hash(requested_digest)?;
    let tx = parsed.transaction();
    require(
        parsed.signatures().is_empty(),
        "expected an unsigned transaction",
    )?;
    require(
        tx.source_account == *source,
        "unexpected transaction source",
    )?;
    require(
        tx.seq_num.0 > 0 && tx.fee > 0 && tx.fee <= 1000,
        "sequence or fee outside policy",
    )?;
    let xdr::Preconditions::Time(bounds) = &tx.cond else {
        return Err(Box::new(Rejected("expected time bounds only")));
    };
    require(
        bounds.min_time.0 <= now && bounds.max_time.0 > now && bounds.max_time.0 - now <= 600,
        "transaction is not currently valid or expires too late",
    )?;
    require(
        tx.memo == xdr::Memo::None && tx.ext == xdr::TransactionExt::V0,
        "unexpected memo or extension",
    )?;
    require(tx.operations.len() == 1, "expected exactly one operation")?;
    let operation = &tx.operations[0];
    require(
        operation
            .source_account
            .as_ref()
            .is_none_or(|value| value == source),
        "unexpected operation source",
    )?;
    let xdr::OperationBody::ChangeTrust(trustline) = &operation.body else {
        return Err(Box::new(Rejected("expected a trustline operation")));
    };
    let asset = xdr::ChangeTrustAsset::CreditAlphanum4(xdr::AlphaNum4 {
        asset_code: xdr::AssetCode4(*b"DEMO"),
        issuer: issuer.clone(),
    });
    require(
        trustline.line == asset && trustline.limit == 10_000_000_000,
        "unexpected asset or trustline limit",
    )
}

fn digest_from_hex(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    require(
        value.len() == 64 && value.is_ascii(),
        "digest must be 64 hex characters",
    )?;
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    require(
        args.len() == 6,
        "usage: tvc_policy <base64-xdr-file> <network-passphrase> <digest-hex> <source> <issuer> <now-unix-seconds>",
    )?;
    let metadata = fs::metadata(&args[0])?;
    require(
        metadata.len() <= stellar_parser::MAX_BASE64_BYTES as u64,
        "input file too large",
    )?;
    evaluate(
        &fs::read_to_string(&args[0])?,
        &args[1],
        &digest_from_hex(&args[2])?,
        &args[3].parse()?,
        &args[4].parse()?,
        args[5].parse()?,
    )?;
    println!("example policy accepted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_parser::xdr::{ReadXdr, WriteXdr};

    const NETWORK: &str = "Test SDF Network ; September 2015";

    fn check(envelope: &str, now: u64, digest: &[u8; 32]) -> Result<(), Box<dyn Error>> {
        evaluate(
            envelope,
            NETWORK,
            digest,
            &xdr::MuxedAccount::Ed25519(xdr::Uint256([1; 32])),
            &xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([2; 32]))),
            now,
        )
    }

    #[test]
    fn evaluates_the_synthetic_fixture_and_rejects_digest_and_expiry_changes()
    -> Result<(), Box<dyn Error>> {
        let fixture = include_str!("../tests/fixtures/trustline.xdr");
        let parsed = parse_base64(fixture, NETWORK)?;
        check(fixture, 1_999_999_500, parsed.signing_hash())?;
        assert!(check(fixture, 1_999_999_500, &[0; 32]).is_err());
        assert!(check(fixture, 2_000_000_000, parsed.signing_hash()).is_err());
        assert!(check(fixture, 1_999_999_000, parsed.signing_hash()).is_err());
        Ok(())
    }

    #[test]
    fn rejects_additional_operations_even_with_a_matching_digest() -> Result<(), Box<dyn Error>> {
        let mut envelope = xdr::TransactionEnvelope::from_xdr_base64(
            include_str!("../tests/fixtures/trustline.xdr"),
            xdr::Limits::none(),
        )?;
        if let xdr::TransactionEnvelope::Tx(value) = &mut envelope {
            value.tx.operations = vec![value.tx.operations[0].clone(); 2].try_into()?;
        }
        let encoded = envelope.to_xdr_base64(xdr::Limits::none())?;
        let parsed = parse_base64(&encoded, NETWORK)?;
        assert!(check(&encoded, 1_999_999_500, parsed.signing_hash()).is_err());
        Ok(())
    }
}
