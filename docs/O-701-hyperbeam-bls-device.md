# O-701 — HyperBEAM BLS Device (sketch)

> **Status:** scaffolded / 2026-05-02 / Rev. 1 (was sketch / 2026-04-30 / Rev. 0)
> **Predecessor:** [O-700 — BLS Sync Committee Primitive](O-700-bls-sync-committee-primitive.md)
> **Successor:** [O-702 — BLS Device Runbook](O-702-bls-device-runbook.md) — operator runbook for the implemented harness
> **Service:** Paxiom A-202 — Sync Committee Verification
> **Implementation:** [`bls-device/`](../bls-device) — Phase 0 scaffolding lands all eight pipeline stages with mock x402/AO defaults; live facilitator and AO writers are filed as follow-ups (see implementation status below).

The production verifier. Wraps the [`bls-verifier` cdylib](../bls-verifier)
primitive with the network plumbing, fork awareness, and AO/x402
plumbing it explicitly *does not* do. Compiled as a HyperBEAM device
module (`~bls-sync-committee@1.0`) and exposed as an x402-gated HTTP
endpoint at `https://paxiom.org/v1/sync-committee/verify`.

This sheet is a working sketch. Concrete decisions are tagged DECIDED;
open questions are tagged OPEN. Section numbers follow O-700's
conventions.

---

## O-701 / S.01 — Position in the stack

```
Agent  ─→  paxiom.org/v1/sync-committee/verify  (x402-gated HTTPS)
              │
              ▼
       HyperBEAM dispatch  (~http@1.0  →  ~bls-sync-committee@1.0)
              │
              ├──→  beacon I/O   (Lodestar / Nimbus / Prysm — failover)
              ├──→  state cache  (slot → committee + fork + GVR)
              ├──→  bls-verifier cdylib  (verify_sync_committee FFI)
              └──→  AO log       (compliance hook, every call)
              │
              ▼
       facilitator /settle  (Coinbase x402, deferred)
              │
              ▼
       Signed response  (proof artifact + platform-key signature)
```

Above the device: agent, x402 facilitator. Below: beacon endpoints,
the cdylib primitive, AO. The device is the only piece that carries
service-specific Paxiom logic.

## O-701 / S.02 — Public contract

### Request

`POST /v1/sync-committee/verify` (after x402 402→signed-payload retry)

```json
{
  "slot": "8421337",
  "block_root": "0x…",
  "parent_root": "0x…",
  "sync_aggregate": {
    "sync_committee_bits": "0x…",
    "sync_committee_signature": "0x…"
  }
}
```

The agent supplies these fields directly from a beacon block it
already has. The device does not require the agent to also supply the
512 pubkeys, the fork version, or `genesis_validators_root` — those
are device-side state.

> **OPEN:** allow agent to optionally pass a `slot` only and have the
> device fetch the entire `sync_aggregate` itself? Pro: simpler agent
> code. Con: hides the input the verification is over (audit-trail
> concern). **Default: require agent to supply.**

### Response

```json
{
  "verified": true,
  "service": "A-202",
  "slot": "8421337",
  "fork_version": "0x06000000",
  "domain": "0x07000000…",
  "signing_root": "0x…",
  "participating": 437,
  "committee_size": 512,
  "primitive_return_code": 1,
  "platform_signature": "0x…",
  "ao_message_id": "…"
}
```

`platform_signature` is computed over a canonical concatenation of the
verified fields with the platform's signing key (key rotation per
runbook O-720, future). `ao_message_id` is the Arweave-anchored log
entry — the audit trail.

### Error response

```json
{ "verified": false, "primitive_return_code": -3,
  "error": "AggregationFailed", "slot": "8421337" }
```

The HTTP status remains 200 even on `verified: false` — the *service*
succeeded in answering the question; the *signature* was invalid. 402
and 5xx are reserved for billing and operational failures respectively.

## O-701 / S.03 — Internal pipeline

Eight stages. Each emits a structured log line tagged with the request
UUID and slot.

| # | Stage | Inputs | Output | Failure handling |
|---|-------|--------|--------|------------------|
| 1 | Parse request | HTTP body | typed struct | 400 on malformed JSON |
| 2 | x402 verify | header, body hash | facilitator OK | 402 retry per spec |
| 3 | Fork lookup | slot | fork_version | beacon failover loop |
| 4 | Committee lookup | slot | 512 pubkeys | beacon failover + cache |
| 5 | Filter | pubkeys, bits | participating[] | none (deterministic) |
| 6 | Compute signing root | parent_root, fork_version, GVR | 32 bytes | none (deterministic) |
| 7 | **Call primitive** | participating[], sig, signing_root | i32 | map -1..-4 to error JSON |
| 8 | Sign + log | response struct | signed JSON, AO msg id | 5xx if AO unavailable |

Steps 3 and 4 are the only steps that touch the network during a
verification request. Both are cached.

## O-701 / S.04 — State the device owns

| Item | Lifetime | Storage | Refresh |
|------|----------|---------|---------|
| `genesis_validators_root` | forever | constant in code | never (chain-id change = different deployment) |
| Fork schedule | per-fork | config file | manual on fork preview |
| Sync committee per period | 256 epochs (~27h) | LMDB or sqlite | beacon API at first miss |
| Beacon endpoint health | seconds | in-memory | EWMA over recent calls |
| Platform signing key | rotation cycle | TEE (~greenzone@1.0) | per O-720 |

Sync committee caching is the single biggest performance lever. A
naive implementation re-fetches 512 validator pubkeys per request (~50
beacon calls). A period-keyed cache reduces this to one fetch every
~27 hours.

## O-701 / S.05 — Beacon endpoint failover

> **DECIDED:** at least three independent providers; weighted
> round-robin starting at the highest-EWMA-success endpoint.

Initial provider list (subject to vetting):

| Provider | Endpoint | Notes |
|----------|----------|-------|
| Chainsafe Lodestar | `https://lodestar-mainnet.chainsafe.io` | scaffold uses this |
| Nimbus public | `https://nimbus.example.endpoint` | OPEN: confirm a stable public endpoint |
| Prysm Allnodes | `https://eth-beacon.allnodes.com` | OPEN: confirm rate limits |
| (operator-run) | `https://beacon.paxiom.org` | future — own infrastructure |

Failover rules:
- Connection error or 5xx → mark endpoint degraded for 60s, try next
- 429 → mark endpoint rate-limited for `Retry-After`, try next
- 200 with malformed JSON → mark endpoint degraded, try next
- All endpoints exhausted → return 503 with `error: "no_beacon_available"`

> **OPEN:** do we need any non-beacon-API source as a tiebreaker? E.g.
> hitting an Erigon archive node directly with `eth_call`? Probably
> overkill for the launch tier; revisit if we see beacon-side incidents.

## O-701 / S.06 — Fork-version dynamism

Per O-700's failure-mode taxonomy, hardcoded fork versions are a
fork-boundary regression risk. The device fetches `fork_version` from
the beacon API:

```
GET /eth/v1/beacon/states/{slot}/fork
→ { "data": { "current_version": "0x06000000", … } }
```

This call is cached per fork epoch (rare changes, ~6 months to >1 year
between forks). The cache key is the fork epoch boundary, not the
slot, so all slots within a fork share one cached value.

> **DECIDED:** never hardcode `fork_version`. Dynamic fetch is the
> contract. A unit test asserts that no `0x06`-leading byte literal
> appears in any non-test source file.

## O-701 / S.07 — AO compliance hook

Every verification request — successful or not — produces one AO
message logging:

```
{
  "request_uuid": "…",
  "service": "A-202",
  "slot": "8421337",
  "agent_id": "…(from x402 payment auth)",
  "verified": true,
  "primitive_return_code": 1,
  "request_hash": "0x…",
  "response_hash": "0x…",
  "platform_key_id": "…",
  "timestamp": "2026-04-30T12:34:56Z"
}
```

The AO message id is included in the response, so the agent can
independently retrieve the audit trail at any later point. This is
the "audit trails as a structural property of the substrate" claim
made in [Phase 1 sheet A-100 / S.01](../../../paxiom/blueprint/A-100.md).

> **OPEN:** does the AO log entry include the full `participating[]`
> pubkey set, or just its hash? Including hashes is enough for an
> audit trail; including the full set adds storage cost. **Default:
> include only the hash and a count.**

## O-701 / S.08 — Build & deploy

The device is a HyperBEAM module. Build pipeline:

1. `cargo build --release --target wasm32-unknown-unknown -p bls-verifier`
   produces `bls_verifier.wasm` (already verified — see Drive folder
   `bls-verifier-ff3d6b8028253c00/`, ~178 KB).
2. Wrap that wasm with the device-side Erlang/Lua harness that handles
   beacon I/O, caching, AO logging.
3. Sign the device manifest with the deploy key.
4. Push to a HyperBEAM node and register with the local registry.

> **OPEN:** does the wasm32 module need to also do the SHA-256
> signing-root computation in-wasm, or do we keep that on the
> host (Erlang) side? Doing it in-wasm keeps verification entirely
> deterministic-from-inputs; doing it on the host means the wasm
> stays the minimal "verify a BLS signature" primitive. **Lean
> toward host-side** until there's a cryptographic argument otherwise.

## O-701 / S.09 — Cost model

Per-call compute estimate (single mainnet sync committee verification):
- Beacon round-trips (cache miss): ~50 calls × 100ms = 5s — but only
  on a period boundary (every ~27 hours)
- Cache hit: ~2 calls (current head + sync_aggregate from agent), 200ms
- Pairing check: ~2ms (blst is fast)
- AO write: 100-500ms

Target p95 latency under cache hit: < 500ms. Target p95 under cache
miss: < 7s (degrades gracefully).

> **OPEN:** target price per verification. Phase 1 sheet A-202
> proposes $0.50 per verification. Cost is dominated by AO write +
> beacon I/O, both nearly free. Margin is high.

## O-701 / S.10 — Risks specific to the device

| Risk | Surface | Mitigation |
|------|---------|------------|
| Beacon SSL cert change | mid-call TLS error | refresh cert store at deploy time |
| Beacon API schema change | malformed JSON | schema fixture tests against last-known-good responses |
| Cache poisoning | period rollover w/ stale committee | period-keyed cache, validate against beacon at boundary |
| Platform key compromise | all responses fraudulent | TEE attestation per O-720 |
| Wasm runtime drift | verification false-positive | reproducible build pinned in Cargo.toml + CI |
| AO outage | compliance hole | fail-closed: 503 if AO write fails |

## O-701 / S.11 — Open follow-ups (immediate)

1. **OPEN:** finalize the public-API request schema (S.02) — circulate
   to early agent operators for input.
2. **OPEN:** vet the third beacon endpoint (S.05).
3. **OPEN:** decide host-vs-wasm signing-root computation (S.08).
4. **OPEN:** define platform signing-key rotation (referenced as
   future runbook O-720).

## O-701 / S.12 — Implementation status (2026-05-02)

Phase 0 scaffolding lives in [`bls-device/`](../bls-device). Source-file map
of the eight pipeline stages:

| Stage | Source file (`bls-device/src/`)                | Status                                   |
|-------|------------------------------------------------|------------------------------------------|
| S.01  | `lib.rs::Device::verify` parse path            | Done                                     |
| S.02  | `x402.rs::MockX402`                            | Stub default; real Coinbase impl TODO    |
| S.03  | `beacon.rs::FailoverPool::fork_version_for_slot` | Done; cache key is fork epoch boundary |
| S.04  | `beacon.rs::committee_pubkeys` + `cache.rs`    | Done; sqlite default backend             |
| S.05  | `lib.rs::filter_participating`                 | Done                                     |
| S.06  | `signing_root.rs::compute_signing_root`        | Done; parameterised on fork & GVR        |
| S.07  | `primitive.rs::NativePrimitive`                | Done; wasm adapter filed as follow-up    |
| S.08  | `lib.rs::sign_response` + `ao.rs::MockAo`      | Stub signature + mock AO; real TEE/AO TODO |

Decisions made in implementation:
- **DECIDED — host-side signing-root computation** (S.08). Lives in `signing_root.rs`. Wasm primitive stays minimal.
- **DECIDED — sqlite for the period cache** (S.04). Trait-based; LMDB swap if bench shows contention.
- **DECIDED — `default_mainnet_pool` is operator-supplied** (S.05). Endpoints aren't baked in; ops vetting happens at config time.

Operator runbook: see [O-702](O-702-bls-device-runbook.md).

## Subsequent runbook entries

- **O-720** — Platform signing key rotation
- **O-730** — Audit relay signature verification
- **O-740** — Identity signing keys
