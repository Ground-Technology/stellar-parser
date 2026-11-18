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

## Soroban contract call

`contract_call.xdr` and `contract_call.sha256` are independently encoded using
Python's standard `struct`, `base64`, and `hashlib` modules, without `stellar-xdr`.
The digest is SHA-256 of the network ID, envelope-type discriminant, and transaction
XDR; envelope signatures are excluded.

- Source: the same synthetic account as the trustline fixture.
- Contract: `CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U` (contract-ID bytes `05` repeated 32 times).
- Network: `Test SDF Network ; September 2015`.
- Sequence: 42; fee: 10,100 stroops; no memo or signatures.
- Time bounds: 0 through 2000000000.
- One `InvokeContract` operation: `example(U32(17))`.
- One source-account authorization with an `example(U32(17))` root and a
  `nested()` child, both targeting the same contract.
- Soroban resource data: empty footprint, 100,000 instructions, zero disk-read
  and write bytes, and a resource fee of 10,000 stroops.
- Signing digest: `d7e0577a8947703429c86f6b650d52faa4f14ac2d7d0ce4155fd4250ed7a7b03`.

This fixture tests parsing and policy evaluation. The contract is synthetic and
the resource data is illustrative; this transaction is never broadcast.
