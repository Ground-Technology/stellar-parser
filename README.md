# Stellar parser

A Rust library that decodes Stellar transactions and checks their network-specific
signing hash. Applications can inspect transaction fields, Soroban contract calls,
and complete authorization trees before deciding whether to approve signing.
Built on [`stellar-xdr`](https://github.com/stellar/rs-stellar-xdr).

## Parser behavior

`parse_xdr()` and `parse_base64()` decode a Stellar v1 transaction envelope and
compute its signing hash using the supplied network passphrase.
`verify_signing_hash()` returns an error if that hash differs from the requested
signing digest.

Parsing rejects:

- Version 0 and fee-bump envelopes.
- Malformed XDR or trailing bytes.
- Decoded XDR larger than 128 KiB or nesting deeper than 100 levels.
- Base64 input longer than 174,764 bytes, including whitespace.

The parser does not verify signatures or evaluate approval rules. The
[`tvc_policy` example](examples/tvc_policy.rs) restricts calls to one
configured Soroban contract.

## TVC example

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) evaluates whether a transaction
calls only the configured Soroban contract. After verifying the requested signing
hash, it returns `true` when the transaction has at least one operation and:

- Every operation is an `InvokeContract` call to the allowed contract.
- Every authorization root and nested invocation calls that same contract.

Function names and arguments are unrestricted. Other operations, host functions,
contract targets, and contract-creation authorizations return `false`. Parse errors
and signing-hash mismatches return an error.

The TVC application authenticates the signing request and supplies its envelope,
signing digest, and trusted network and allowed-contract configuration. It uses
the evaluation result to submit its vote, treating errors as rejections.
This example implements only policy evaluation. It checks declared calls;
parsing cannot establish which other contracts may be called during execution.

```sh
cargo run --locked --example tvc_policy -- \
  tests/fixtures/contract_call.xdr \
  'Test SDF Network ; September 2015' \
  d7e0577a8947703429c86f6b650d52faa4f14ac2d7d0ce4155fd4250ed7a7b03 \
  CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U
```

This command uses a synthetic transaction and contract address. It prints `true`.

Synthetic fixture inputs and their expected signing digest are documented in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

Licensed under the [Apache License, Version 2.0](LICENSE).
