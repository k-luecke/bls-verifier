# O-702 — BLS HyperBEAM Device Runbook

> **Status:** scaffolded / 2026-05-02 / Rev. 0
> **Predecessor:** [O-701 — HyperBEAM BLS Device (sketch)](O-701-hyperbeam-bls-device.md)
> **Implementation:** `bls-device/` workspace member
> **Service:** Paxiom A-202 — Sync Committee Verification

The harness lives. This sheet documents how to build, register, and operate
the production device that wraps the [`bls-verifier`](../bls-verifier) wasm
primitive per the O-701 contract.

## O-702 / S.01 — What's in `bls-device/`

| Module                         | O-701 stage | Purpose                                                         |
|--------------------------------|-------------|-----------------------------------------------------------------|
| `src/lib.rs::Device::verify`   | S.03 (all)  | Orchestrates the eight-stage pipeline.                          |
| `src/x402.rs`                  | Stage 2     | `X402Verifier` trait + `MockX402` default. Real impl is a TODO. |
| `src/beacon.rs`                | Stages 3, 4 | `FailoverPool` over `BeaconClient` with EWMA + 60s degrade.     |
| `src/cache.rs`                 | Stage 4     | `SqliteCommitteeCache` keyed on `slot / 8192`.                  |
| `src/signing_root.rs`          | Stage 6     | `compute_domain` + `compute_signing_root`, parameterised.       |
| `src/primitive.rs`             | Stage 7     | `NativePrimitive` adapter (links blst directly).                |
| `src/ao.rs`                    | Stage 8     | `AoLogger` trait + `MockAo` default. Real impl is a TODO.       |
| `src/manifest.rs`              | S.08        | Emits the HyperBEAM device manifest JSON.                       |
| `src/bin/record_fixture.rs`    | S.10        | Operator-only beacon snapshot capture.                          |

Open follow-ups, mapped to O-701 / S.11:
1. **OPEN** — finalise the public-API request schema with early agent operators (driven from `VerifyRequest`/`VerifyResponse` in `lib.rs`).
2. **OPEN** — vet the third beacon endpoint (Nimbus public, Prysm Allnodes; `default_mainnet_pool` accepts arbitrary endpoints).
3. **DECIDED — host-side** — signing-root computation lives in `bls-device::signing_root`. Wasm primitive stays minimal.
4. **DEFERRED** — platform signing-key rotation (see future O-720). `Device::sign_response` is a SHA-256 placeholder.

## O-702 / S.02 — Build the wasm primitive

```bash
cargo build --release --target wasm32-unknown-unknown -p bls-verifier
ls -lh target/wasm32-unknown-unknown/release/bls_verifier.wasm
```

Expected: a file in the ~178 KB range. Hash it and copy to the paxiom repo:

```bash
sha256sum target/wasm32-unknown-unknown/release/bls_verifier.wasm \
    > /tmp/bls_verifier.wasm.sha256
cp target/wasm32-unknown-unknown/release/bls_verifier.wasm \
   ../paxiom/hyperbeam/devices/bls-sync-committee/bls_verifier.wasm
cp /tmp/bls_verifier.wasm.sha256 \
   ../paxiom/hyperbeam/devices/bls-sync-committee/bls_verifier.wasm.sha256
```

Update procedure on subsequent rebuilds: rerun the two `cp` commands above and
commit both the wasm and its sha256. The paxiom repo's CI hash check fails if
you forget.

## O-702 / S.03 — Build & run the harness

```bash
cargo build --release -p bls-device
```

The harness is a library (`bls_device`) plus the `record-fixture` binary. The
service-layer HTTP server lives in paxiom's `services/sync-committee/server.js`
and either calls the harness in-process (Node FFI / subprocess) or dispatches
via HyperBEAM's `hb_ao` to the registered device.

## O-702 / S.04 — Capture a fixture

Pick a slot from a **closed** sync committee period (i.e. `slot/8192` is not
the current period). The committee snapshot will then stay internally
consistent indefinitely — important for the test fixture's stability.

```bash
cargo run -p bls-device --bin record-fixture -- \
    --beacon https://lodestar-mainnet.chainsafe.io \
    --slot 8421376 \
    --out fixtures/beacon
```

Outputs:
- `header_head.json`
- `block_<slot>.json`
- `sync_committees_<slot>.json`
- `validators_chunk_<n>.json` × ~52 (one per chunks-of-10 batch)
- `fork_<slot>.json`
- `MANIFEST.json` recording slot, period_index, captured_at, fork_version

`integration_fixture.rs` skips when `MANIFEST.json` is missing, so the test
runs the day you commit a fixture. Refresh on demand; do **not** capture from
the current head.

## O-702 / S.05 — Register the device with HyperBEAM

(Operator step — assumes HyperBEAM is running locally per
`paxiom/docs/hyperbeam-bringup.md`.)

```bash
# from bls-verifier/
WASM_PATH=$(realpath target/wasm32-unknown-unknown/release/bls_verifier.wasm) \
HARNESS_BIN=$(realpath target/release/bls-device-harness) \
DEPLOY_KEY_ID="ops-key-1" \
envsubst < bls-device/manifest.json.tmpl > /tmp/bls-sync-committee.manifest.json

# Register (paxiom repo provides register.sh)
../paxiom/hyperbeam/devices/bls-sync-committee/register.sh \
    /tmp/bls-sync-committee.manifest.json
```

Smoke-test from another shell:

```bash
curl -sX POST http://localhost:8080/v1/sync-committee/verify \
    -H 'Content-Type: application/json' \
    -d @fixtures/beacon/MANIFEST.json
```

Expected: `verified: true` for a real recent slot. This is the operator proof
of the A-120 / S.02 gate.

## O-702 / S.05a — Institutional pattern: regression tests that close bug *classes*

> **CA.02 hook.** This is an instance of a broader claim Paxiom makes about
> itself — that we close bug classes, not just bugs. When the CA-Series
> compliance architecture sheet on regression discipline gets written
> (currently filed as CA.02), it should reference this section as the
> canonical worked example.

The hardcoded Fulu fork version (`[0x06, 0x00, 0x00, 0x00]`) was a textbook
small bug. Every BLS-on-Ethereum implementation has shipped one at some
point. The fix — fetch the fork version dynamically per O-701 / S.06 — is
unremarkable.

The institutional move was `bls-device/tests/no_hardcoded_fork.rs`: a
workspace test that walks every `src/` directory and fails the build if any
file outside `tests/` and `fixtures/` contains the four-byte literal in any
of its common spelling variants. Future hardcodes do not pass review; they
fail CI. The class is closed.

The same pattern should be applied wherever Paxiom catches a "this team has
shipped this bug before" failure mode:
- Hardcoded chain ids
- Hardcoded contract addresses across networks
- Hardcoded RPC endpoints in source (the no-RPC moat must hold at compile-time)
- Hardcoded process ids that shift on AO process redeployment

Each of these warrants a sibling to `no_hardcoded_fork.rs`. The tests are
cheap to write, never break under refactor (they grep, they don't compile),
and they show up to anyone reading the repo as evidence that the team
designs out problems instead of fixing them on incident review.

## O-702 / S.06 — Tests

| Layer                      | Command                                          | Where it runs |
|----------------------------|--------------------------------------------------|---------------|
| Primitive (cdylib)         | `cargo test -p bls-verifier`                     | CI            |
| No hardcoded fork version  | `cargo test --test no_hardcoded_fork`            | CI            |
| Device pipeline (fixture)  | `cargo test -p bls-device --test integration_fixture` | CI       |
| Device pipeline (live)     | `BLS_DEVICE_LIVE=1 cargo test -p bls-device --test integration_live` | Operator |

## O-702 / S.07 — Cost & failure modes

Inherits the cost model from O-701 / S.09. The sqlite cache reduces a naive
50-RTT validator fetch (~5 s) to a single read (~ms) on every request inside
a period; the period-rollover request pays the fetch cost once.

Failure modes worth pre-naming:
- **Cache poisoning at period rollover.** Mitigation: cache key is the period
  index, not slot; on rollover the period changes and the next miss re-fetches.
- **Beacon API schema drift across providers.** Mitigation: `BeaconClient` is a
  trait; per-provider normalisers can be added as separate `BeaconClient` impls
  before they hit the failover pool.
- **Wasm primitive instance reload.** Mitigation: the eventual wasm adapter
  (filed for follow-up) MUST instantiate once at startup; per-request load is
  a regression that grows p50 by ~5×.

## Next layer up

The HTTP service that owns `POST /v1/sync-committee/verify` lives in the
paxiom main repo at `services/sync-committee/`. Its server.js calls into this
harness (either directly through a Node FFI bridge or via HyperBEAM's hb_ao
dispatch). The wasm artifact, manifest template, and runbook in this repo are
the inputs; the service is the output.
