# Stellar parser

A Rust library for bounded Stellar XDR parsing and signing-digest verification.
Built on [`stellar-xdr`](https://github.com/stellar/rs-stellar-xdr), with typed
access to transaction fields, Soroban calls, and complete authorization trees.

```rust
use stellar_parser::parse_base64;

fn inspect(
    envelope_xdr: &str,
    network: &str,
    requested_digest: &[u8; 32],
) -> Result<(), stellar_parser::Error> {
    let parsed = parse_base64(envelope_xdr, network)?;
    parsed.verify_signing_hash(requested_digest)?;

    let tx = parsed.transaction();
    println!("fee: {} stroops; operations: {}", tx.fee, tx.operations.len());
    for call in parsed.contract_calls() {
        println!("{:?}: {:?}", call.invocation.contract_address, call.invocation.function_name);
    }
    Ok(())
}
```

The transaction retains its source account, sequence number, fee, preconditions,
memo, all operations, operation sources, and Soroban resource data. Contract calls
retain typed arguments and each authorization entry's credentials, root, and
nested invocations. Amounts remain integers in their original units; the parser
does not infer token decimals.

## Scope

- Version 1 transaction envelopes using `stellar-xdr` 27.0.0. Version 0 and
  fee-bump envelopes are rejected.
- Binary and base64 input; complete consumption is required.
- Limits: 128 KiB decoded XDR, depth 32, and 174,764 bytes of base64 input
  including whitespace. Inputs beyond these limits are rejected.
- Signing digests use the caller's exact network passphrase. Existing envelope
  signatures are preserved but are not checked or included in the digest.
- `contract_calls()` selects contract invocations. Inspect `transaction().operations`
  as well: other operations and host functions are retained, not approved or hidden.

Parsing does not approve a transaction, enforce expiry or allowlists, verify
signatures, simulate execution, or prove its effects. A consuming policy owns
those decisions. This library makes no network calls and needs no credentials.

## TVC example

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) shows a small policy suitable
for calling from a Turnkey Verifiable Cloud application. It accepts one unsigned
trustline operation for a caller-supplied account and issuer and checks the
requested digest, source, fee, limit, and expiry. It is a library integration
example, not a deployed TVC service.

The TVC application must authenticate the webhook, obtain the original signing
request, and supply its envelope, digest, network, and policy configuration to
the evaluator. It then owns the approval vote. The example includes no webhook
server, signing keys, deployment configuration, or Turnkey sidecar source.

```sh
cargo run --locked --example tvc_policy -- \
  tests/fixtures/trustline.xdr \
  'Test SDF Network ; September 2015' \
  8246452a91b1d2133d1cbf1511bf21e70ccbdcb385586890de055134a7cab068 \
  GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H \
  GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA \
  1999999500
```

Synthetic fixture inputs and their expected signing digest are documented in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

## Checks

Rust 1.94.0 is pinned in `rust-toolchain.toml`.

```sh
cargo fmt --all --check
cargo test --locked --all-targets
cargo test --locked --doc
cargo clippy --locked --all-targets -- -D warnings
```

## Distribution

Private review version. No open-source license has been granted yet. Choose a
license before public release. No Turnkey example implementation is included.
