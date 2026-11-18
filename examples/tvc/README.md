# Local Stellar TVC

A runnable Turnkey Verifiable Cloud application that approves transactions calling
one configured Soroban contract. It uses `stellar-parser` to decode the transaction
and verify its signing digest.

## Run locally

Requires Docker with Compose v2 and Make. From the repository root:

```sh
cd examples/tvc
make up
make smoke
```

`make up` builds and starts the TVC and a mock Turnkey service, then waits for
their health checks. The TVC listens on `http://127.0.0.1:44020`. The mock is
accessible only inside the Compose network. No Turnkey account, credentials,
funded wallet, or blockchain connection is required.

`make smoke` sends signed webhook deliveries through the TVC and checks its votes.
The mock verifies the P-256 signatures on activity queries and votes against the
key exposed by the TVC. It tests allowed calls, forbidden contracts and operations,
nested authorizations, digest mismatches, request substitution, invalid webhook
signatures, retries, and finalized-activity redelivery. A successful run prints a
JSON report containing the passed cases and recorded votes. These are synthetic
transactions; the example never broadcasts them.

```sh
make down
```

The voting key persists in the `voter-keys` Docker volume. To reset it, run
`docker compose down --volumes`; the next startup generates a new key.

## Policy

The TVC approves signing when the digest matches the supplied transaction and:

- The transaction contains at least one operation.
- Every operation calls the configured contract.
- Every authorization root and nested invocation calls that same contract.

Function names and arguments are unrestricted. Other operations, contract targets,
and contract-creation authorizations are rejected. Parsing errors and signing-hash
mismatches also produce a rejection vote.

This checks the calls declared in the transaction. It does not simulate execution
or establish which contracts the allowed contract may call at runtime. The policy
does not restrict the signer, source account, fee, amount, or expiry.

## Request flow

1. Verify the webhook's Ed25519 signature over the exact delivery bytes using
   Turnkey's webhook JWKS. Require a timestamp within five minutes and the
   configured organization.
2. For a `SIGN_RAW_PAYLOAD_V2` activity needing consensus, fetch the activity from
   Turnkey. Its ID, organization, type, and fingerprint must match the delivery.
3. Recover the original request from its initiating vote. Its exact message bytes
   must hash to the activity fingerprint, and its signing parameters must match
   the fetched activity intent.
4. Parse the request's transaction XDR, verify its network-specific signing hash
   against the requested digest, and apply the contract rule.
5. Submit a signed approval or rejection vote before acknowledging the webhook.

Unrelated activities and activities that no longer need consensus return HTTP 204
without a vote. Invalid webhook authentication returns 401; malformed bodies return
400; bodies over 1 MiB return 413. Activity identity mismatches return 401 without
a vote. Key-discovery, activity-fetch, and vote-submission failures return 503 so
the delivery can be retried. Policy failures submit a rejection and return 204.

## HTTP endpoints

| Endpoint | Response |
| --- | --- |
| `GET /health` | `{"status":"healthy"}` |
| `GET /turnkey/api_public_key` | Voting public key and `API_KEY_CURVE_P256` |
| `POST /webhooks/turnkey/activity` | Signed activity webhook receiver |

There is no direct evaluation endpoint. Test-control endpoints belong to the
separate mock binary and are absent from the TVC router.

## Configuration

| Environment variable | Meaning |
| --- | --- |
| `TURNKEY_ORGANIZATION_ID` | Organization whose activities the TVC handles; required |
| `STELLAR_NETWORK_PASSPHRASE` | Network used to compute signing hashes; required |
| `ALLOWED_CONTRACT` | Allowed Stellar contract address (`C…`); required |
| `TURNKEY_API_URL` | API and webhook JWKS base URL; defaults to `https://api.turnkey.com` |
| `TURNKEY_KEY_FILE` | Hex-encoded P-256 private key file; defaults to `/keys/voter.hex` |
| `LISTEN_ADDRESS` | HTTP listen address; defaults to `0.0.0.0:44020` |

On first startup, the app generates a key if the configured file does not exist.
Its parent directory must exist and be writable. Existing keys are loaded without
replacement. The key file is created with owner-only permissions on Unix.
Private keys are never returned by the HTTP API.

For a real Turnkey test organization, run the same image with your organization,
network, contract, and persistent key file. Use the real Turnkey API URL, register
the exposed public key with the permissions to read activities and submit votes,
and register a reachable HTTPS webhook URL ending in `/webhooks/turnkey/activity`.
The organization's signing policy must require the TVC user's approval. The mock
does not configure these Turnkey resources.

Raw signing requests contain a digest, so the caller also includes the transaction
as `stellarContext.envelopeXdr` in the original stamped request:

```json
{
  "type": "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
  "organizationId": "your-organization",
  "timestampMs": "current-timestamp-in-milliseconds",
  "parameters": {
    "signWith": "your-signing-account",
    "payload": "64-hex-character-transaction-signing-digest",
    "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
    "hashFunction": "HASH_FUNCTION_NOT_APPLICABLE"
  },
  "stellarContext": {
    "envelopeXdr": "base64-encoded-transaction-envelope"
  }
}
```

`stellarContext` is application context, not a Turnkey signing parameter. Include
it before stamping the request so it is covered by the fingerprint. The TVC uses
its own network and allowed-contract configuration.

Local Docker runs the application and protocol flow. It does not provide enclave
attestation or quorum key management. Hosted TVC deployment is outside this example.

## Development

From the repository root:

```sh
cargo test --locked --workspace --all-targets
```

The HTTP integration test runs the same mock and smoke cases natively on random
loopback ports. CI also builds and runs the Compose containers. The fixture in
`fixtures/` is a synthetic testnet call to contract `05…05`, with both an
authorization root and a nested call to that contract. Its expected digest was
computed independently of the parser with Python's standard library.
