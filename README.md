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
[`tvc_policy` example](examples/tvc_policy.rs) applies account, issuer,
trustline-limit, fee, and expiry checks to a parsed transaction.

## TVC example

[`examples/tvc_policy.rs`](examples/tvc_policy.rs) shows a policy for use in a
Turnkey Verifiable Cloud application. It accepts one unsigned trustline operation
for a caller-supplied account and issuer. It checks the requested signing hash,
source, fee, trustline limit, and expiry.

The TVC application authenticates the webhook, retrieves the original signing
request, and passes its envelope, signing digest, network, and policy configuration
to the evaluator. The application then submits its vote.
This example implements only policy evaluation.

```sh
cargo run --locked --example tvc_policy -- \
  tests/fixtures/trustline.xdr \
  'Test SDF Network ; September 2015' \
  8246452a91b1d2133d1cbf1511bf21e70ccbdcb385586890de055134a7cab068 \
  GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H \
  GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA \
  1999999500
```

This command uses synthetic accounts and a fixed test time. It prints
`example policy accepted`.

Synthetic fixture inputs and their expected signing digest are documented in
[`tests/fixtures/README.md`](tests/fixtures/README.md).

Licensed under the [Apache License, Version 2.0](LICENSE).
