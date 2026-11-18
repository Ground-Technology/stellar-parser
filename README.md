# stellar-parser

Decode a Stellar transaction and confirm it matches the digest you are about to sign.

`stellar-parser` is a small Rust library for signing policies. Given a
transaction envelope (base64 or raw XDR) and a network passphrase, it:

- decodes the envelope, rejecting anything that is not a single v1 transaction:
  fee-bump and v0 envelopes, trailing bytes, inputs over 128 KiB, and nesting
  deeper than 100 XDR types;
- computes the transaction's signing hash for that network, which is also its
  Stellar transaction hash, and checks it against the digest you were asked to
  sign;
- returns the full decoded transaction, plus each Soroban contract call with its
  arguments and authorization trees.

The parser does not decide whether a transaction is safe to sign. Your policy
makes that decision from what the parser returns. The library makes no network
calls and holds no keys.

Built on [`stellar-xdr`](https://github.com/stellar/rs-stellar-xdr) 30.0.0
(Stellar protocol 30).

## Install

Not published to crates.io. Depend on a tagged release:

```toml
[dependencies]
stellar-parser = { git = "https://github.com/Ground-Technology/stellar-parser", tag = "v0.1.0" }
```

## Usage

```rust
use stellar_parser::{parse_base64, xdr};

fn review(
    envelope_xdr: &str,
    network_passphrase: &str,
    requested_digest: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_base64(envelope_xdr, network_passphrase)?;

    // Bind the decoded transaction to the exact digest the signer was asked to sign.
    parsed.verify_signing_hash(requested_digest)?;

    // Review every operation and reject anything the policy does not understand.
    for operation in parsed.transaction().operations.iter() {
        match &operation.body {
            xdr::OperationBody::Payment(_) => {}
            xdr::OperationBody::InvokeHostFunction(op)
                if matches!(op.host_function, xdr::HostFunction::InvokeContract(_)) => {}
            _ => return Err("operation not allowed by this policy".into()),
        }
    }

    // Contract calls carry typed arguments and complete authorization trees.
    for call in parsed.contract_calls() {
        let function = std::str::from_utf8(call.invocation.function_name.0.as_slice())?;
        println!(
            "{} {function}: {} authorization entries",
            call.invocation.contract_address,
            call.authorizations.len(),
        );
    }
    Ok(())
}
```

`parse_xdr` takes raw bytes instead of base64. All XDR types are re-exported as
`stellar_parser::xdr`.

## Example: Turnkey Verifiable Cloud policy

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) is a signing policy for a
Turnkey Verifiable Cloud (TVC) application. It approves one kind of transaction:
an owner account depositing tokens into a specific vault contract. It approves
the signature only if:

- the requested digest matches the transaction;
- the owner is the transaction's source;
- the fee is at most 1 XLM, and the transaction expires within 10 minutes;
- the only operation is a call to `deposit(owner, amount)` on the vault, for at
  most 1,000 tokens;
- the owner authorizes only that call and, inside it, the token's
  `transfer(owner, vault, amount)`.

The tests change one field of a sample transaction at a time and check that the
policy rejects it. A real TVC application would also authenticate the request
and fetch it from Turnkey before calling `evaluate`; the example covers only the
policy.

Run it against the sample transaction:

```sh
cargo run --locked --example tvc_policy -- \
  tests/fixtures/contract_call.xdr \
  'Test SDF Network ; September 2015' \
  3acfe72f7023fc2c3625b7001383e0d5189bd4bdae5174bf6c0198fd771fee16 \
  GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H \
  CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U \
  CADAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMSST \
  1999999500
```

The arguments are the transaction file, network passphrase, digest to sign,
owner account, vault contract, token contract, and current Unix time. It prints
`approved`. The sample transaction is described in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

## Development

```sh
cargo test --locked --all-targets
```

CI also runs fmt, clippy, doc tests, and rustdoc, and checks the sample
transaction against an independent Python encoder
(`tests/fixtures/contract_call.py`).

## Security

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/Ground-Technology/stellar-parser/security/advisories/new),
not public issues.

## License

Copyright 2026 Ground Inc. Licensed under the
[Apache License, Version 2.0](https://github.com/Ground-Technology/stellar-parser/blob/main/LICENSE).
