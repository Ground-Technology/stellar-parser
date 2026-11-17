# Synthetic trustline fixture

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
