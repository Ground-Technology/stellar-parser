# stellar-parser

Decode a Stellar transaction and confirm it matches the digest you are about to sign.

`stellar-parser` is a small Rust library for signing policies. It decodes a
transaction envelope within fixed size and depth limits, computes its
network-specific signing hash, and exposes every field (operations, Soroban
contract calls, and complete authorization trees) so a policy can decide whether
to approve the signature. It performs no I/O and holds no keys.

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

## What the parser guarantees

- **Complete decoding.** The whole input must decode as one v1 transaction
  envelope. Trailing bytes are rejected.
- **Digest binding.** `signing_hash()` is computed from the network passphrase
  and the decoded transaction, and equals the Stellar transaction hash. Existing
  signatures are kept but excluded from the digest.
- **Nothing hidden.** Source account, sequence, fee, preconditions, memo, every
  operation and its source, Soroban resource data, and authorization trees are
  returned as decoded. Amounts stay as raw integers; token decimals are not
  inferred.
- **Bounded work.** Inputs beyond the limits below are rejected.
- **No I/O.** No network calls, keys, or credentials.

## What the caller must do

- Authenticate the signing request before trusting its envelope or digest.
- Pass the exact network passphrase. A wrong passphrase yields a different hash,
  so `verify_signing_hash` fails.
- Inspect `transaction().operations`, not only `contract_calls()`.
  `contract_calls()` returns only `InvokeContract` host functions; other
  operations, contract creation, and Wasm uploads appear only in the operation
  list.
- Enforce its own rules: allowlists, amounts, fees, sequence, and time bounds.
- Treat a successful parse as a description of the transaction, not of its
  effects. The parser does not verify signatures or simulate execution.

## Limits and errors

| Check | Limit | Error |
| --- | --- | --- |
| Envelope type | v1 only; v0 and fee-bump are rejected | `UnsupportedEnvelope` |
| Decoded size | 128 KiB (`MAX_XDR_BYTES`) | `InputTooLarge` |
| Base64 size | 174,764 bytes including whitespace (`MAX_BASE64_BYTES`) | `InputTooLarge` |
| Decoder depth | 100 (`MAX_XDR_DEPTH`) | `InvalidXdr(DepthLimitExceeded)` |
| Network passphrase | Must not be empty | `EmptyNetworkPassphrase` |
| Requested digest | Must equal `signing_hash()` | `SigningHashMismatch` |

Decoder depth counts nested XDR types, not visible nesting. A typical Soroban
call uses about 20; a contract argument can nest about 21 vectors deep before
reaching the limit.

## Turnkey Verifiable Cloud example

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) is a complete policy for a
Turnkey Verifiable Cloud (TVC) application. It approves exactly one unsigned
`ChangeTrust` operation for a configured account and issuer, and checks the
signing digest, source, fee, trustline limit, and a 10-minute expiry window.

In a TVC application the flow is:

1. Authenticate the incoming webhook.
2. Retrieve the original signing request: envelope, digest, and network.
3. Evaluate the policy with that request and the policy configuration.
4. Vote to approve only if the policy returns `Ok`.

The example implements step 3. It includes no webhook server, keys, or deployment
configuration. Run it against the synthetic fixture:

```sh
cargo run --locked --example tvc_policy -- \
  tests/fixtures/trustline.xdr \
  'Test SDF Network ; September 2015' \
  8246452a91b1d2133d1cbf1511bf21e70ccbdcb385586890de055134a7cab068 \
  GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H \
  GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA \
  1999999500
```

It prints `example policy accepted`. The fixture's synthetic accounts and fixed
timestamp are described in [`tests/fixtures/README.md`](tests/fixtures/README.md).

## Development

Rust 1.94.0 is pinned in `rust-toolchain.toml`. CI runs:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
```

## Versioning

`stellar-xdr` types are part of this crate's public API, so upgrading
`stellar-xdr` is a breaking change and ships as a new minor version before 1.0.

## Security

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/Ground-Technology/stellar-parser/security/advisories/new),
not public issues.

## License

Copyright 2026 Ground Inc. Licensed under the
[Apache License, Version 2.0](https://github.com/Ground-Technology/stellar-parser/blob/main/LICENSE).
