//! Parser contract tests using synthetic transactions and an independent SDK fixture.

use std::error::Error as StdError;

use stellar_parser::{Error, MAX_BASE64_BYTES, MAX_XDR_BYTES, parse_base64, parse_xdr, xdr::*};

const NETWORK: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";
const FIXTURE: &str = include_str!("fixtures/trustline.xdr");

fn fixture() -> Result<TransactionEnvelope, Box<dyn StdError>> {
    Ok(TransactionEnvelope::from_xdr_base64(
        FIXTURE,
        Limits::none(),
    )?)
}

fn encode(envelope: &TransactionEnvelope) -> Result<Vec<u8>, Box<dyn StdError>> {
    Ok(envelope.to_xdr(Limits::none())?)
}

fn transaction(
    envelope: &mut TransactionEnvelope,
) -> Result<&mut TransactionV1Envelope, Box<dyn StdError>> {
    match envelope {
        TransactionEnvelope::Tx(value) => Ok(value),
        _ => Err("expected a version 1 envelope".into()),
    }
}

fn contract_call(
    tag: u8,
    name: &str,
    args: Vec<ScVal>,
) -> Result<InvokeContractArgs, Box<dyn StdError>> {
    Ok(InvokeContractArgs {
        contract_address: ScAddress::Contract(ContractId(Hash([tag; 32]))),
        function_name: ScSymbol(name.as_bytes().to_vec().try_into()?),
        args: args.try_into()?,
    })
}

fn invocation(call: InvokeContractArgs) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(call),
        sub_invocations: VecM::default(),
    }
}

#[test]
fn parses_classic_fields_and_matches_an_independent_sdk_digest() -> Result<(), Box<dyn StdError>> {
    let parsed = parse_base64(FIXTURE, NETWORK)?;
    let tx = parsed.transaction();
    assert_eq!(tx.source_account, MuxedAccount::Ed25519(Uint256([1; 32])));
    assert_eq!(tx.fee, 100);
    assert_eq!(tx.seq_num.0, 42);
    assert_eq!(tx.memo, Memo::None);
    assert!(parsed.signatures().is_empty());
    assert_eq!(tx.operations.len(), 1);
    assert!(parsed.contract_calls().next().is_none());
    let OperationBody::ChangeTrust(trustline) = &tx.operations[0].body else {
        return Err("expected a trustline".into());
    };
    assert_eq!(trustline.limit, 10_000_000_000);
    let expected = include_str!("fixtures/trustline.sha256").trim();
    let actual: String = parsed
        .signing_hash()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(actual, expected);
    parsed.verify_signing_hash(parsed.signing_hash())?;
    Ok(())
}

#[test]
fn binary_and_base64_parsing_preserve_the_same_transaction() -> Result<(), Box<dyn StdError>> {
    let envelope = fixture()?;
    let parsed = parse_xdr(&encode(&envelope)?, NETWORK)?;
    let base64 = parse_base64(FIXTURE, NETWORK)?;
    assert_eq!(parsed.transaction(), base64.transaction());
    assert_eq!(parsed.signing_hash(), base64.signing_hash());
    Ok(())
}

#[test]
fn binds_the_digest_to_the_exact_network_and_transaction() -> Result<(), Box<dyn StdError>> {
    let parsed = parse_base64(FIXTURE, NETWORK)?;
    let mainnet = parse_base64(FIXTURE, MAINNET)?;
    assert!(matches!(
        mainnet.verify_signing_hash(parsed.signing_hash()),
        Err(Error::SigningHashMismatch)
    ));
    let mut changed = fixture()?;
    transaction(&mut changed)?.tx.fee += 1;
    let changed = parse_xdr(&encode(&changed)?, NETWORK)?;
    assert!(matches!(
        changed.verify_signing_hash(parsed.signing_hash()),
        Err(Error::SigningHashMismatch)
    ));
    assert!(matches!(
        parsed.verify_signing_hash(&[0; 32]),
        Err(Error::SigningHashMismatch)
    ));
    Ok(())
}

#[test]
fn rejects_empty_malformed_truncated_and_trailing_input() -> Result<(), Box<dyn StdError>> {
    assert!(matches!(
        parse_base64("", NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    assert!(matches!(
        parse_base64("not xdr!", NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    let mut bytes = encode(&fixture()?)?;
    assert!(matches!(
        parse_xdr(&bytes[..bytes.len() - 1], NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    bytes.push(0);
    assert!(matches!(
        parse_xdr(&bytes, NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    let mut base64 = FIXTURE.trim().to_owned();
    base64.push_str("AAAA");
    assert!(matches!(
        parse_base64(&base64, NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    assert!(matches!(
        parse_base64(FIXTURE, ""),
        Err(Error::EmptyNetworkPassphrase)
    ));
    assert!(matches!(
        parse_xdr(&[], ""),
        Err(Error::EmptyNetworkPassphrase)
    ));
    Ok(())
}

#[test]
fn rejects_inputs_above_the_binary_and_encoded_limits() {
    assert!(matches!(
        parse_xdr(&vec![0; MAX_XDR_BYTES + 1], NETWORK),
        Err(Error::InputTooLarge)
    ));
    assert!(matches!(
        parse_base64(&" ".repeat(MAX_BASE64_BYTES + 1), NETWORK),
        Err(Error::InputTooLarge)
    ));
}

#[test]
fn rejects_legacy_and_fee_bump_envelopes() -> Result<(), Box<dyn StdError>> {
    let legacy = TransactionEnvelope::TxV0(TransactionV0Envelope::default());
    let fee_bump = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope::default());
    for envelope in [legacy, fee_bump] {
        let bytes = encode(&envelope)?;
        assert!(matches!(
            parse_xdr(&bytes, NETWORK),
            Err(Error::UnsupportedEnvelope)
        ));
        let base64 = envelope.to_xdr_base64(Limits::none())?;
        assert!(matches!(
            parse_base64(&base64, NETWORK),
            Err(Error::UnsupportedEnvelope)
        ));
    }
    Ok(())
}

#[test]
fn preserves_signatures_but_excludes_them_from_the_signing_digest() -> Result<(), Box<dyn StdError>>
{
    let original = parse_base64(FIXTURE, NETWORK)?;
    let mut envelope = fixture()?;
    let signature = DecoratedSignature {
        hint: SignatureHint([3; 4]),
        signature: Signature(vec![4; 64].try_into()?),
    };
    transaction(&mut envelope)?.signatures = vec![signature.clone()].try_into()?;
    let parsed = parse_xdr(&encode(&envelope)?, NETWORK)?;
    assert_eq!(parsed.signatures(), &[signature]);
    assert_eq!(parsed.signing_hash(), original.signing_hash());
    Ok(())
}

#[test]
fn preserves_soroban_arguments_credentials_nested_calls_and_other_operations()
-> Result<(), Box<dyn StdError>> {
    let args = vec![
        ScVal::I128(Int128Parts {
            hi: -1,
            lo: u64::MAX,
        }),
        ScVal::U64(u64::MAX),
        ScVal::Bytes(vec![9; 32].try_into()?),
    ];
    let call = contract_call(5, "example", args.clone())?;
    let child = invocation(contract_call(6, "child", vec![ScVal::U32(17)])?);
    let mut root = invocation(call.clone());
    root.sub_invocations = vec![child.clone()].try_into()?;
    let auth = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: root,
    };
    let mut envelope = fixture()?;
    let inner = transaction(&mut envelope)?;
    let classic = inner.tx.operations[0].clone();
    inner.tx.operations = vec![
        classic,
        Operation {
            source_account: Some(MuxedAccount::Ed25519(Uint256([7; 32]))),
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call.clone()),
                auth: vec![auth.clone()].try_into()?,
            }),
        },
    ]
    .try_into()?;
    inner.tx.ext = TransactionExt::V1(SorobanTransactionData::default());
    let parsed = parse_xdr(&encode(&envelope)?, NETWORK)?;
    let calls: Vec<_> = parsed.contract_calls().collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].operation_index, 1);
    assert_eq!(calls[0].invocation, &call);
    assert_eq!(calls[0].invocation.args.as_slice(), args);
    assert_eq!(calls[0].authorizations, &[auth]);
    assert_eq!(
        calls[0].authorizations[0]
            .root_invocation
            .sub_invocations
            .as_slice(),
        &[child]
    );
    assert_eq!(parsed.transaction().operations.len(), 2);
    assert!(parsed.transaction().operations[1].source_account.is_some());
    assert!(matches!(parsed.transaction().ext, TransactionExt::V1(_)));
    Ok(())
}

#[test]
fn rejects_excessive_authorization_nesting() -> Result<(), Box<dyn StdError>> {
    let call = contract_call(5, "example", vec![])?;
    let mut root = invocation(call.clone());
    for _ in 0..40 {
        root = SorobanAuthorizedInvocation {
            function: root.function.clone(),
            sub_invocations: vec![root].try_into()?,
        };
    }
    let mut envelope = fixture()?;
    transaction(&mut envelope)?.tx.operations = vec![Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(call),
            auth: vec![SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: root,
            }]
            .try_into()?,
        }),
    }]
    .try_into()?;
    assert!(matches!(
        parse_xdr(&encode(&envelope)?, NETWORK),
        Err(Error::InvalidXdr(_))
    ));
    Ok(())
}

#[test]
fn preserves_muxed_sources_memos_and_extended_preconditions() -> Result<(), Box<dyn StdError>> {
    let mut envelope = fixture()?;
    let inner = transaction(&mut envelope)?;
    inner.tx.source_account = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
        id: 99,
        ed25519: Uint256([8; 32]),
    });
    inner.tx.memo = Memo::Id(123);
    inner.tx.cond = Preconditions::V2(PreconditionsV2::default());
    let expected = inner.tx.clone();
    let parsed = parse_xdr(&encode(&envelope)?, NETWORK)?;
    assert_eq!(parsed.transaction(), &expected);
    Ok(())
}
