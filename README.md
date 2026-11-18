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
- Check every node of each authorization tree. Signing a transaction as its
  source authorizes every invocation in its source-account authorization trees.
- Enforce its own rules: allowlists, amounts, fees, sequence, and time bounds.
- Treat a successful parse as a description of the transaction, not of its
  effects. The parser does not verify signatures or simulate execution.

`signing_hash()` is the transaction hash, which the transaction's source signs.
An account that authorizes a contract call with address credentials instead,
for example when a relayer submits the transaction, signs a different
authorization-entry digest that this crate does not compute.

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

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) is a policy for a Turnkey
Verifiable Cloud (TVC) application. It approves one action: the owner
depositing into a pinned vault contract, where the deposit may authorize only
the matching transfer on a pinned token contract. Every rule below must pass.

| Rule | Prevents |
| --- | --- |
| The requested digest equals the transaction's signing hash | Approving one transaction while signing another |
| The transaction source, and any operation source, is the owner | Signing for another account the key controls |
| Fee is at most 1 XLM, and the Soroban resource fee is within it | Draining the account through fees |
| The transaction is valid now and expires within 10 minutes | Holding a signed transaction to submit later |
| There is exactly one operation: `deposit` on the vault contract | Extra operations, other contracts, contract deployment |
| Arguments are `deposit(owner, amount)` with `0 < amount ≤ 1,000` tokens | Depositing for someone else, or more than allowed |
| One source-account authorization whose root is that exact call | Authorizing a call other than the one reviewed |
| The deposit authorizes only `token.transfer(owner, vault, amount)`, with nothing nested below it | Hidden calls the signature would also authorize |

The vault may call other contracts while it runs, but any call that requires
the owner's authorization must match the authorization tree, which the policy
checks completely. Allowances the owner granted earlier are not visible in the
transaction.

The example's tests change one field of the fixture per case and assert which
rule rejects it, covering each row above. They also accept boundary cases: a
deposit at the cap and an operation source equal to the owner.

The TVC application authenticates the webhook, retrieves the original signing
request, and passes its envelope and signing digest, with the trusted network
and policy configuration, to `evaluate`. It votes to approve only when
`evaluate` returns `Ok`. The example includes no webhook server, keys, or
deployment configuration. Run it against the synthetic fixture:

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

The arguments are the envelope file, network passphrase, requested digest,
owner account, vault contract, token contract, and current Unix time. It prints
`approved`; a rejected transaction exits with the rule it broke. The fixture's
synthetic accounts, contracts, and fixed timestamp are described in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

## Development

Rust 1.94.0 is pinned in `rust-toolchain.toml`. CI runs:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps
python3 tests/fixtures/contract_call.py | diff - <(cat tests/fixtures/contract_call.xdr tests/fixtures/contract_call.sha256)
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
