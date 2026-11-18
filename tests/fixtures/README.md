# Synthetic fixtures

## Trustline

Generated independently using `@stellar/stellar-sdk` 17.1.0. No chain reads,
real accounts, signing keys, or production configuration were used.

- Source: `GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H` (public-key bytes `01` repeated 32 times).
- Issuer: `GABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEJXA` (public-key bytes `02` repeated 32 times).
- Network: `Test SDF Network ; September 2015`.
- Sequence: 42; fee: 100 stroops; no memo or signatures.
- Time bounds: 0 through 2000000000.
- One `ChangeTrust` operation for `DEMO`, limit 1000 tokens
  (10000000000 units at seven decimal places).
- Signing digest: `8246452a91b1d2133d1cbf1511bf21e70ccbdcb385586890de055134a7cab068`.

The Rust tests check this SDK-generated digest independently of their own
transaction construction. This fixture is for parsing and is never broadcast.

## Soroban deposit

`contract_call.xdr` and `contract_call.sha256` are encoded by
[`contract_call.py`](contract_call.py) using only Python's standard library,
without `stellar-xdr` or a Stellar SDK. Running `python3 tests/fixtures/contract_call.py`
prints both files' contents exactly; CI checks that they match. The digest is
SHA-256 of the network ID, envelope-type discriminant, and transaction XDR;
envelope signatures are excluded. The example's tests also rebuild the
transaction with `stellar-xdr` types and compare it to the decoded fixture.

- Owner and source: `GAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQDZ7H` (public-key bytes `01` repeated 32 times).
- Vault: `CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U` (contract-ID bytes `05` repeated 32 times).
- Token: `CADAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMBQGAYDAMSST` (contract-ID bytes `06` repeated 32 times).
- Network: `Test SDF Network ; September 2015`.
- Sequence: 42; fee: 10,100 stroops; no memo or signatures.
- Time bounds: 0 through 2000000000. The README command evaluates at
  1999999500, 500 seconds before expiry.
- One `InvokeContract` operation: `deposit(owner, I128(1000000000))` on the
  vault, which is 100 tokens at seven decimal places.
- One source-account authorization whose root is that call, with one child:
  `transfer(owner, vault, I128(1000000000))` on the token.
- Soroban resource data: empty footprint, 100,000 instructions, zero disk-read
  and write bytes, and a resource fee of 10,000 stroops.
- Signing digest: `3acfe72f7023fc2c3625b7001383e0d5189bd4bdae5174bf6c0198fd771fee16`.

This fixture tests parsing and policy evaluation. The contracts are synthetic
and the resource data is illustrative; this transaction is never broadcast.
