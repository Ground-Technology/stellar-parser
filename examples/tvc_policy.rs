//! Example policy to call after a TVC application authenticates a signing request.
//!
//! It approves one action: the owner depositing into a pinned vault contract,
//! where the deposit may authorize only the matching transfer on a pinned token.

use std::{error::Error, fmt, fs};

use stellar_parser::{parse_base64, xdr};

/// Largest deposit, in token units (1,000 tokens at seven decimal places).
const MAX_DEPOSIT_UNITS: i128 = 10_000_000_000;
/// Largest total fee, in stroops (1 XLM).
const MAX_FEE_STROOPS: u32 = 10_000_000;
/// Longest time a transaction may remain valid after evaluation.
const MAX_VALIDITY_SECONDS: u64 = 600;

/// The accounts and contracts one deployment of this policy is pinned to.
struct Policy {
    owner: xdr::AccountId,
    vault: xdr::ContractId,
    token: xdr::ContractId,
}

/// The policy rule a transaction failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    Source,
    Fee,
    Expiry,
    SingleOperation,
    VaultDeposit,
    DepositArguments,
    Amount,
    Authorization,
    TokenTransfer,
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "transaction and operation source must be the owner",
            Self::Fee => "fee or Soroban resource fee outside policy",
            Self::Expiry => "transaction is not currently valid or expires too late",
            Self::SingleOperation => "expected exactly one operation",
            Self::VaultDeposit => "expected a deposit call to the vault",
            Self::DepositArguments => "expected deposit(owner, i128 amount)",
            Self::Amount => "deposit amount outside policy",
            Self::Authorization => "expected one source-account authorization for the deposit",
            Self::TokenTransfer => "deposit may authorize only the matching token transfer",
        })
    }
}

#[derive(Debug)]
enum Rejection {
    Invalid(stellar_parser::Error),
    Policy(Rule),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "{error}"),
            Self::Policy(rule) => write!(f, "rejected: {rule}"),
        }
    }
}

impl Error for Rejection {}

impl From<stellar_parser::Error> for Rejection {
    fn from(error: stellar_parser::Error) -> Self {
        Self::Invalid(error)
    }
}

fn require(condition: bool, rule: Rule) -> Result<(), Rejection> {
    if condition {
        Ok(())
    } else {
        Err(Rejection::Policy(rule))
    }
}

fn evaluate(
    policy: &Policy,
    envelope_xdr: &str,
    network: &str,
    requested_digest: &[u8; 32],
    now: u64,
) -> Result<(), Rejection> {
    let parsed = parse_base64(envelope_xdr, network)?;
    parsed.verify_signing_hash(requested_digest)?;
    let tx = parsed.transaction();

    let xdr::PublicKey::PublicKeyTypeEd25519(owner_key) = &policy.owner.0;
    let source = xdr::MuxedAccount::Ed25519(owner_key.clone());
    require(tx.source_account == source, Rule::Source)?;

    let xdr::TransactionExt::V1(soroban) = &tx.ext else {
        return Err(Rejection::Policy(Rule::Fee));
    };
    require(
        tx.fee <= MAX_FEE_STROOPS
            && soroban.resource_fee >= 0
            && soroban.resource_fee <= i64::from(tx.fee),
        Rule::Fee,
    )?;

    let xdr::Preconditions::Time(bounds) = &tx.cond else {
        return Err(Rejection::Policy(Rule::Expiry));
    };
    require(
        bounds.min_time.0 <= now
            && now < bounds.max_time.0
            && bounds.max_time.0 - now <= MAX_VALIDITY_SECONDS,
        Rule::Expiry,
    )?;

    let [operation] = tx.operations.as_slice() else {
        return Err(Rejection::Policy(Rule::SingleOperation));
    };
    require(
        operation
            .source_account
            .as_ref()
            .is_none_or(|account| *account == source),
        Rule::Source,
    )?;

    let xdr::OperationBody::InvokeHostFunction(host) = &operation.body else {
        return Err(Rejection::Policy(Rule::VaultDeposit));
    };
    let xdr::HostFunction::InvokeContract(call) = &host.host_function else {
        return Err(Rejection::Policy(Rule::VaultDeposit));
    };
    let vault = xdr::ScAddress::Contract(policy.vault.clone());
    require(
        call.contract_address == vault && call.function_name.0.as_slice() == b"deposit",
        Rule::VaultDeposit,
    )?;

    let owner = xdr::ScVal::Address(xdr::ScAddress::Account(policy.owner.clone()));
    let [from, amount] = call.args.as_slice() else {
        return Err(Rejection::Policy(Rule::DepositArguments));
    };
    let xdr::ScVal::I128(parts) = amount else {
        return Err(Rejection::Policy(Rule::DepositArguments));
    };
    require(*from == owner, Rule::DepositArguments)?;
    let units = (i128::from(parts.hi) << 64) | i128::from(parts.lo);
    require(units > 0 && units <= MAX_DEPOSIT_UNITS, Rule::Amount)?;

    let [authorization] = host.auth.as_slice() else {
        return Err(Rejection::Policy(Rule::Authorization));
    };
    require(
        authorization.credentials == xdr::SorobanCredentials::SourceAccount
            && authorization.root_invocation.function
                == xdr::SorobanAuthorizedFunction::ContractFn(call.clone()),
        Rule::Authorization,
    )?;

    let [transfer] = authorization.root_invocation.sub_invocations.as_slice() else {
        return Err(Rejection::Policy(Rule::TokenTransfer));
    };
    let xdr::SorobanAuthorizedFunction::ContractFn(transfer_call) = &transfer.function else {
        return Err(Rejection::Policy(Rule::TokenTransfer));
    };
    require(
        transfer_call.contract_address == xdr::ScAddress::Contract(policy.token.clone())
            && transfer_call.function_name.0.as_slice() == b"transfer"
            && transfer_call.args.as_slice() == [owner, xdr::ScVal::Address(vault), amount.clone()]
            && transfer.sub_invocations.is_empty(),
        Rule::TokenTransfer,
    )
}

fn digest_from_hex(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("digest must be 64 hex characters".into());
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(digest)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [file, network, digest, owner, vault, token, now] = args.as_slice() else {
        return Err(
            "usage: tvc_policy <base64-xdr-file> <network-passphrase> <digest-hex> \
                    <owner-account> <vault-contract> <token-contract> <now-unix-seconds>"
                .into(),
        );
    };
    if fs::metadata(file)?.len() > stellar_parser::MAX_BASE64_BYTES as u64 {
        return Err("input file too large".into());
    }
    let policy = Policy {
        owner: owner.parse()?,
        vault: vault.parse()?,
        token: token.parse()?,
    };
    match evaluate(
        &policy,
        &fs::read_to_string(file)?,
        network,
        &digest_from_hex(digest)?,
        now.parse()?,
    ) {
        Ok(()) => println!("approved"),
        Err(rejection) => {
            eprintln!("{rejection}");
            std::process::exit(1);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_parser::xdr::{ReadXdr, WriteXdr};

    type Envelope = xdr::TransactionV1Envelope;
    type Mutation = fn(&mut Envelope) -> Result<(), Box<dyn Error>>;

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const FIXTURE: &str = include_str!("../tests/fixtures/contract_call.xdr");
    const NOW: u64 = 1_999_999_500;

    fn policy() -> Policy {
        Policy {
            owner: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([1; 32]))),
            vault: xdr::ContractId(xdr::Hash([5; 32])),
            token: xdr::ContractId(xdr::Hash([6; 32])),
        }
    }

    fn fixture() -> Result<Envelope, Box<dyn Error>> {
        let xdr::TransactionEnvelope::Tx(envelope) =
            xdr::TransactionEnvelope::from_xdr_base64(FIXTURE, xdr::Limits::none())?
        else {
            return Err("expected a v1 envelope".into());
        };
        Ok(envelope)
    }

    fn other_account() -> xdr::ScAddress {
        xdr::ScAddress::Account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(
            xdr::Uint256([9; 32]),
        )))
    }

    fn other_contract() -> xdr::ScAddress {
        xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32])))
    }

    fn i128_value(units: i128) -> xdr::ScVal {
        xdr::ScVal::I128(xdr::Int128Parts {
            hi: (units >> 64) as i64,
            lo: units as u64,
        })
    }

    fn symbol(name: &str) -> Result<xdr::ScSymbol, Box<dyn Error>> {
        Ok(xdr::ScSymbol(name.as_bytes().to_vec().try_into()?))
    }

    fn first<T, const MAX: u32>(items: &mut xdr::VecM<T, MAX>) -> Result<&mut T, Box<dyn Error>> {
        items
            .iter_mut()
            .next()
            .ok_or_else(|| "missing fixture entry".into())
    }

    fn host(envelope: &mut Envelope) -> Result<&mut xdr::InvokeHostFunctionOp, Box<dyn Error>> {
        let xdr::OperationBody::InvokeHostFunction(host) =
            &mut first(&mut envelope.tx.operations)?.body
        else {
            return Err("expected a host function".into());
        };
        Ok(host)
    }

    fn deposit(envelope: &mut Envelope) -> Result<&mut xdr::InvokeContractArgs, Box<dyn Error>> {
        let xdr::HostFunction::InvokeContract(call) = &mut host(envelope)?.host_function else {
            return Err("expected a contract call".into());
        };
        Ok(call)
    }

    fn root(
        envelope: &mut Envelope,
    ) -> Result<&mut xdr::SorobanAuthorizedInvocation, Box<dyn Error>> {
        Ok(&mut first(&mut host(envelope)?.auth)?.root_invocation)
    }

    fn contract_fn(
        invocation: &mut xdr::SorobanAuthorizedInvocation,
    ) -> Result<&mut xdr::InvokeContractArgs, Box<dyn Error>> {
        let xdr::SorobanAuthorizedFunction::ContractFn(call) = &mut invocation.function else {
            return Err("expected an authorized contract call".into());
        };
        Ok(call)
    }

    fn transfer(
        envelope: &mut Envelope,
    ) -> Result<&mut xdr::SorobanAuthorizedInvocation, Box<dyn Error>> {
        first(&mut root(envelope)?.sub_invocations)
    }

    fn set_arg(
        call: &mut xdr::InvokeContractArgs,
        index: usize,
        value: xdr::ScVal,
    ) -> Result<(), Box<dyn Error>> {
        *call.args.iter_mut().nth(index).ok_or("missing argument")? = value;
        Ok(())
    }

    fn set_amount(envelope: &mut Envelope, units: i128) -> Result<(), Box<dyn Error>> {
        set_arg(deposit(envelope)?, 1, i128_value(units))?;
        set_arg(contract_fn(root(envelope)?)?, 1, i128_value(units))?;
        set_arg(contract_fn(transfer(envelope)?)?, 2, i128_value(units))
    }

    fn time_bounds(envelope: &mut Envelope) -> Result<&mut xdr::TimeBounds, Box<dyn Error>> {
        let xdr::Preconditions::Time(bounds) = &mut envelope.tx.cond else {
            return Err("expected time bounds".into());
        };
        Ok(bounds)
    }

    fn soroban_data(
        envelope: &mut Envelope,
    ) -> Result<&mut xdr::SorobanTransactionData, Box<dyn Error>> {
        let xdr::TransactionExt::V1(data) = &mut envelope.tx.ext else {
            return Err("expected Soroban data".into());
        };
        Ok(data)
    }

    fn outcome(envelope: Envelope) -> Result<Option<Rule>, Box<dyn Error>> {
        let encoded = xdr::TransactionEnvelope::Tx(envelope).to_xdr_base64(xdr::Limits::none())?;
        let digest = *parse_base64(&encoded, NETWORK)?.signing_hash();
        match evaluate(&policy(), &encoded, NETWORK, &digest, NOW) {
            Ok(()) => Ok(None),
            Err(Rejection::Policy(rule)) => Ok(Some(rule)),
            Err(Rejection::Invalid(error)) => Err(error.into()),
        }
    }

    #[test]
    fn approves_the_fixture_with_its_independently_encoded_digest() -> Result<(), Box<dyn Error>> {
        let configured = Policy {
            owner: "GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H".parse()?,
            vault: "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U".parse()?,
            token: "CADAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMSST".parse()?,
        };
        let expected = policy();
        assert_eq!(configured.owner, expected.owner);
        assert_eq!(configured.vault, expected.vault);
        assert_eq!(configured.token, expected.token);
        let digest =
            digest_from_hex(include_str!("../tests/fixtures/contract_call.sha256").trim())?;
        evaluate(&configured, FIXTURE, NETWORK, &digest, NOW)?;
        Ok(())
    }

    #[test]
    fn fixture_matches_its_documented_fields() -> Result<(), Box<dyn Error>> {
        let owner = xdr::ScVal::Address(xdr::ScAddress::Account(policy().owner));
        let vault = xdr::ScAddress::Contract(policy().vault);
        let call = xdr::InvokeContractArgs {
            contract_address: vault.clone(),
            function_name: symbol("deposit")?,
            args: vec![owner.clone(), i128_value(1_000_000_000)].try_into()?,
        };
        let transfer = xdr::InvokeContractArgs {
            contract_address: xdr::ScAddress::Contract(policy().token),
            function_name: symbol("transfer")?,
            args: vec![owner, xdr::ScVal::Address(vault), i128_value(1_000_000_000)].try_into()?,
        };
        let expected = xdr::Transaction {
            source_account: xdr::MuxedAccount::Ed25519(xdr::Uint256([1; 32])),
            fee: 10_100,
            seq_num: xdr::SequenceNumber(42),
            cond: xdr::Preconditions::Time(xdr::TimeBounds {
                min_time: xdr::TimePoint(0),
                max_time: xdr::TimePoint(2_000_000_000),
            }),
            memo: xdr::Memo::None,
            operations: vec![xdr::Operation {
                source_account: None,
                body: xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
                    host_function: xdr::HostFunction::InvokeContract(call.clone()),
                    auth: vec![xdr::SorobanAuthorizationEntry {
                        credentials: xdr::SorobanCredentials::SourceAccount,
                        root_invocation: xdr::SorobanAuthorizedInvocation {
                            function: xdr::SorobanAuthorizedFunction::ContractFn(call),
                            sub_invocations: vec![xdr::SorobanAuthorizedInvocation {
                                function: xdr::SorobanAuthorizedFunction::ContractFn(transfer),
                                sub_invocations: xdr::VecM::default(),
                            }]
                            .try_into()?,
                        },
                    }]
                    .try_into()?,
                }),
            }]
            .try_into()?,
            ext: xdr::TransactionExt::V1(xdr::SorobanTransactionData {
                ext: xdr::SorobanTransactionDataExt::V0,
                resources: xdr::SorobanResources {
                    footprint: xdr::LedgerFootprint::default(),
                    instructions: 100_000,
                    disk_read_bytes: 0,
                    write_bytes: 0,
                },
                resource_fee: 10_000,
            }),
        };
        assert_eq!(fixture()?.tx, expected);
        assert!(fixture()?.signatures.is_empty());
        Ok(())
    }

    #[test]
    fn each_rule_rejects_the_fixture_with_one_field_changed() -> Result<(), Box<dyn Error>> {
        let cases: Vec<(&str, Mutation, Option<Rule>)> = vec![
            ("unchanged fixture", |_| Ok(()), None),
            (
                "deposit at the cap",
                |e| set_amount(e, MAX_DEPOSIT_UNITS),
                None,
            ),
            (
                "operation source set to the owner",
                |e| {
                    first(&mut e.tx.operations)?.source_account = Some(e.tx.source_account.clone());
                    Ok(())
                },
                None,
            ),
            (
                "other transaction source",
                |e| {
                    e.tx.source_account = xdr::MuxedAccount::Ed25519(xdr::Uint256([9; 32]));
                    Ok(())
                },
                Some(Rule::Source),
            ),
            (
                "other operation source",
                |e| {
                    first(&mut e.tx.operations)?.source_account =
                        Some(xdr::MuxedAccount::Ed25519(xdr::Uint256([9; 32])));
                    Ok(())
                },
                Some(Rule::Source),
            ),
            (
                "fee above the cap",
                |e| {
                    e.tx.fee = MAX_FEE_STROOPS + 1;
                    Ok(())
                },
                Some(Rule::Fee),
            ),
            (
                "resource fee above the fee",
                |e| {
                    soroban_data(e)?.resource_fee = i64::from(e.tx.fee) + 1;
                    Ok(())
                },
                Some(Rule::Fee),
            ),
            (
                "no Soroban data",
                |e| {
                    e.tx.ext = xdr::TransactionExt::V0;
                    Ok(())
                },
                Some(Rule::Fee),
            ),
            (
                "no time bounds",
                |e| {
                    e.tx.cond = xdr::Preconditions::None;
                    Ok(())
                },
                Some(Rule::Expiry),
            ),
            (
                "no upper time bound",
                |e| {
                    time_bounds(e)?.max_time = xdr::TimePoint(0);
                    Ok(())
                },
                Some(Rule::Expiry),
            ),
            (
                "expired",
                |e| {
                    time_bounds(e)?.max_time = xdr::TimePoint(NOW);
                    Ok(())
                },
                Some(Rule::Expiry),
            ),
            (
                "valid for too long",
                |e| {
                    time_bounds(e)?.max_time = xdr::TimePoint(NOW + MAX_VALIDITY_SECONDS + 1);
                    Ok(())
                },
                Some(Rule::Expiry),
            ),
            (
                "not yet valid",
                |e| {
                    time_bounds(e)?.min_time = xdr::TimePoint(NOW + 1);
                    Ok(())
                },
                Some(Rule::Expiry),
            ),
            (
                "no operations",
                |e| {
                    e.tx.operations = xdr::VecM::default();
                    Ok(())
                },
                Some(Rule::SingleOperation),
            ),
            (
                "second deposit",
                |e| {
                    let operation = first(&mut e.tx.operations)?.clone();
                    e.tx.operations = vec![operation.clone(), operation].try_into()?;
                    Ok(())
                },
                Some(Rule::SingleOperation),
            ),
            (
                "classic operation",
                |e| {
                    first(&mut e.tx.operations)?.body =
                        xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp::default());
                    Ok(())
                },
                Some(Rule::VaultDeposit),
            ),
            (
                "contract creation",
                |e| {
                    host(e)?.host_function =
                        xdr::HostFunction::CreateContract(xdr::CreateContractArgs::default());
                    Ok(())
                },
                Some(Rule::VaultDeposit),
            ),
            (
                "other contract",
                |e| {
                    deposit(e)?.contract_address = other_contract();
                    Ok(())
                },
                Some(Rule::VaultDeposit),
            ),
            (
                "other function",
                |e| {
                    deposit(e)?.function_name = symbol("withdraw")?;
                    Ok(())
                },
                Some(Rule::VaultDeposit),
            ),
            (
                "deposit from another account",
                |e| set_arg(deposit(e)?, 0, xdr::ScVal::Address(other_account())),
                Some(Rule::DepositArguments),
            ),
            (
                "amount is not an i128",
                |e| set_arg(deposit(e)?, 1, xdr::ScVal::U64(1)),
                Some(Rule::DepositArguments),
            ),
            (
                "extra argument",
                |e| {
                    let call = deposit(e)?;
                    let mut args = call.args.to_vec();
                    args.push(xdr::ScVal::Void);
                    call.args = args.try_into()?;
                    Ok(())
                },
                Some(Rule::DepositArguments),
            ),
            ("zero amount", |e| set_amount(e, 0), Some(Rule::Amount)),
            ("negative amount", |e| set_amount(e, -1), Some(Rule::Amount)),
            (
                "amount above the cap",
                |e| set_amount(e, MAX_DEPOSIT_UNITS + 1),
                Some(Rule::Amount),
            ),
            (
                "no authorization",
                |e| {
                    host(e)?.auth = xdr::VecM::default();
                    Ok(())
                },
                Some(Rule::Authorization),
            ),
            (
                "second authorization",
                |e| {
                    let entry = first(&mut host(e)?.auth)?.clone();
                    host(e)?.auth = vec![entry.clone(), entry].try_into()?;
                    Ok(())
                },
                Some(Rule::Authorization),
            ),
            (
                "address credentials",
                |e| {
                    first(&mut host(e)?.auth)?.credentials =
                        xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                            address: xdr::ScAddress::Account(policy().owner),
                            nonce: 1,
                            signature_expiration_ledger: 1,
                            signature: xdr::ScVal::Void,
                        });
                    Ok(())
                },
                Some(Rule::Authorization),
            ),
            (
                "authorization root differs from the call",
                |e| set_arg(contract_fn(root(e)?)?, 1, i128_value(1)),
                Some(Rule::Authorization),
            ),
            (
                "no token transfer",
                |e| {
                    root(e)?.sub_invocations = xdr::VecM::default();
                    Ok(())
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "second authorized call",
                |e| {
                    let call = transfer(e)?.clone();
                    root(e)?.sub_invocations = vec![call.clone(), call].try_into()?;
                    Ok(())
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "transfer on another token",
                |e| {
                    contract_fn(transfer(e)?)?.contract_address = other_contract();
                    Ok(())
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "other token function",
                |e| {
                    contract_fn(transfer(e)?)?.function_name = symbol("approve")?;
                    Ok(())
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "transfer from another account",
                |e| {
                    set_arg(
                        contract_fn(transfer(e)?)?,
                        0,
                        xdr::ScVal::Address(other_account()),
                    )
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "transfer to another recipient",
                |e| {
                    set_arg(
                        contract_fn(transfer(e)?)?,
                        1,
                        xdr::ScVal::Address(other_contract()),
                    )
                },
                Some(Rule::TokenTransfer),
            ),
            (
                "transfer amount differs",
                |e| set_arg(contract_fn(transfer(e)?)?, 2, i128_value(2)),
                Some(Rule::TokenTransfer),
            ),
            (
                "call nested under the transfer",
                |e| {
                    let nested = transfer(e)?.clone();
                    transfer(e)?.sub_invocations = vec![nested].try_into()?;
                    Ok(())
                },
                Some(Rule::TokenTransfer),
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut envelope = fixture()?;
            mutate(&mut envelope)?;
            assert_eq!(outcome(envelope)?, expected, "{name}");
        }
        Ok(())
    }

    #[test]
    fn returns_errors_for_malformed_input_wrong_network_and_digest_mismatches()
    -> Result<(), Box<dyn Error>> {
        let digest =
            digest_from_hex(include_str!("../tests/fixtures/contract_call.sha256").trim())?;
        assert!(matches!(
            evaluate(&policy(), FIXTURE, NETWORK, &[0; 32], NOW),
            Err(Rejection::Invalid(
                stellar_parser::Error::SigningHashMismatch
            ))
        ));
        assert!(matches!(
            evaluate(
                &policy(),
                FIXTURE,
                "Public Global Stellar Network ; September 2015",
                &digest,
                NOW
            ),
            Err(Rejection::Invalid(
                stellar_parser::Error::SigningHashMismatch
            ))
        ));
        assert!(matches!(
            evaluate(&policy(), "not XDR", NETWORK, &digest, NOW),
            Err(Rejection::Invalid(stellar_parser::Error::InvalidXdr(_)))
        ));
        assert!(digest_from_hex(&"+a".repeat(32)).is_err());
        Ok(())
    }
}
