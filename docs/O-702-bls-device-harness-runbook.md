# O-702 — `bls-device-harness` operator runbook

`bls-device-harness` is the subprocess form of the BLS sync committee
device. It is spawned by paxiom's `services/sync-committee/dispatch.mjs`
when the service is run with `BLS_DEVICE_VIA_SUBPROCESS=1`. It exists to
let A-202 run end-to-end without HyperBEAM up — useful for testnet, CI,
and one-shot operator verifies.

## Slice 1A scope (paxiom punch list)

Three subsystem decisions are deliberate and recorded here. Consumers
who need stronger guarantees must wait for the named follow-up slice.

| Subsystem | Slice 1A behavior                                                                                       | Out-of-scope follow-up           |
|-----------|---------------------------------------------------------------------------------------------------------|----------------------------------|
| x402      | `BLS_DEVICE_X402_MODE=disabled` (default) or `=stub` (shape-only). NEVER claims settlement.             | Slice 3 (real Coinbase facilitator) |
| signing   | Ephemeral `ed25519_dalek::SigningKey` per invocation by default. Operator opt-in via PEM env vars.       | Slice 2 / O-720 (durable + TEE)  |
| AO        | `MockAo`; `ao_message_id` is `mock-ao-...`; `ao_mode:mock` in envelope.                                  | Slice 5 (durable AO/Arweave)     |

The harness envelope makes each of these explicit in every response —
see "Output schema" below.

## Build

```
cargo build --release -p bls-device --bin bls-device-harness
```

Produces `target/release/bls-device-harness`. Install to
`/usr/local/bin/bls-device-harness` (paxiom's default lookup path) or
point paxiom at any path via `BLS_DEVICE_HARNESS=…`.

## Wire contract

```
bls-device-harness --json
  stdin  : single JSON VerifyRequest (per bls_device::VerifyRequest)
  stdout : single JSON object (one line, no trailing data)
  exit 0 : verified true OR verified false with structured reason
  exit 1 : pipeline failure (request parse, beacon, primitive, x402, ao)
  exit 2 : configuration failure (env vars, key parse, etc.)
  stderr : tracing logs + structured startup banner + error detail
```

## Env

| Var                                          | Required           | Default                                          |
|----------------------------------------------|--------------------|--------------------------------------------------|
| `BLS_DEVICE_X402_MODE`                       | no                 | `disabled` (also accepts `stub`)                 |
| `BLS_DEVICE_X402_PAYLOAD`                    | only for `stub`    | `""`                                             |
| `BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM`| no (paired)        | none — generates ephemeral key                  |
| `BLS_DEVICE_RESPONSE_SIGNING_KEY_ID`         | no (paired)        | none — derived from ephemeral pubkey fingerprint |
| `BLS_DEVICE_BEACON_LODESTAR`                 | no                 | `https://lodestar-mainnet.chainsafe.io`          |
| `BLS_DEVICE_BEACON_NIMBUS`                   | no                 | `""` (omitted)                                   |
| `BLS_DEVICE_BEACON_PRYSM`                    | no                 | `""` (omitted)                                   |
| `BLS_DEVICE_CACHE_PATH`                      | no                 | in-memory (ephemeral per invocation)             |
| `BLS_DEVICE_LOG`                             | no                 | `info`                                           |

Setting one of `BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM` or
`BLS_DEVICE_RESPONSE_SIGNING_KEY_ID` without the other is a hard
configuration error (exit 2). The harness never persists a generated
private key to disk and never logs the PEM.

## Output schema

The harness emits a single JSON object combining the underlying
`VerifyResponse` (defined in `bls_device::VerifyResponse`) with
harness-envelope truth fields layered on top:

```jsonc
{
  // ---- from bls_device::VerifyResponse ----
  "verified": false,
  "service": "A-202",
  "slot": "...",
  "fork_version": "0x...",
  "domain": "0x...",
  "signing_root": "0x...",
  "participating": 123,
  "committee_size": 512,
  "primitive_return_code": 1,
  "platform_signature": "0x...",   // ed25519(signing_root || verified)
  "ao_message_id": "mock-ao-...",
  // ---- harness envelope (added by this binary) ----
  "x402_mode": "disabled",
  "settlement_verified": false,
  "key_scope": "ephemeral-subprocess",   // or "operator-supplied"
  "notary_status": "not-persistent",     // or "operator-supplied"
  "platform_key_id": "ephemeral:abcdef0123456789",
  "ao_mode": "mock",
  "harness_version": "0.1.0"
}
```

Slice 1A invariants (consumers MUST treat as inviolate):

- `settlement_verified` is **always** `false`.
- `verified` is a BLS-verification claim only. It does **not** imply a
  payment was settled, even when `verified:true`.
- `key_scope:"ephemeral-subprocess"` and `notary_status:"not-persistent"`
  mean the harness `platform_signature` rotates every invocation.
- `notary_status` is **never** `"durable"`, `"production"`, or
  `"tee-backed"` in Slice 1A. paxiom's outer envelope (signed by
  `PAXIOM_RESPONSE_SIGNING_PRIVATE_KEY_PEM`) is the stable testnet
  receipt.

## Smoke test

```
echo '<VerifyRequest JSON>' \
  | BLS_DEVICE_X402_MODE=disabled \
    BLS_DEVICE_LOG=debug \
    target/release/bls-device-harness --json
```

Capture a real `VerifyRequest` from a closed historical period using
`bls-device/src/bin/record_fixture.rs` (see crate docs). The full
end-to-end paxiom proof lives in
`paxiom@claude/a202-subprocess-harness-DYqhU` under
`scripts/verify-a202-subprocess.sh`.

## Known not-covered (named follow-ups)

- **No `mock-x402` feature**. The cargo feature is *not* enabled by this
  binary. Operators experimenting with `MockX402` in tests must opt in
  explicitly at the crate level; the harness will not compile it in.
- **AO is mocked**. Slice 5 lands the durable AO/Arweave write.
- **No persistent default key**. By design — see Slice 1A scope. Set
  both `BLS_DEVICE_RESPONSE_*` env vars for a stable inner-ring key.
