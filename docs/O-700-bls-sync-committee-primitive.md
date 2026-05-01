# O-700 — BLS Sync Committee Primitive

The cryptographic primitive at the bottom of Service 02 — Ethereum sync
committee signature verification. One C-FFI function exported from a
small Rust crate, compiled to either a native cdylib or a wasm32 module
for the HyperBEAM device. Verifies one thing well; the layers above it
do the rest.

## Artifact location

Canonical source lives in the private repository
[`k-luecke/bls-verifier`](https://github.com/k-luecke/bls-verifier) on
GitHub. Sources only — the `libbls_verifier.so` cdylib and the `bls-test`
integration binary are reproducible from those sources via
`cargo build --release` and are deliberately not committed.
[.gitignore](../.gitignore) excludes `target/`, `Cargo.lock`, `*.so`,
`*.dylib`, `*.dll`.

The repository is structured as a Cargo workspace with three members:

| Crate | Type | Purpose |
|-------|------|---------|
| [`bls-verifier`](../bls-verifier) | cdylib | The primitive — this sheet's subject. |
| [`bls-test`](../bls-test) | bin (tokio) | Fetches a current sync committee from Lodestar mainnet and verifies it end-to-end. |
| [`bls-verify-cli`](../bls-verify-cli) | bin | stdin-JSON wrapper for ad-hoc verification; its JSON schema is throwaway and will be replaced by the HyperBEAM device interface. |

## What the primitive does

A single C-ABI function, `verify_sync_committee`, takes a flat buffer of
48-byte participating BLS pubkeys, a 96-byte aggregate signature, and a
32-byte signing root. It parses each pubkey, aggregates them with subgroup
checking, and verifies the signature against the aggregate using the
BLS POP DST. Return codes are documented inline in
[`bls-verifier/src/lib.rs`](../bls-verifier/src/lib.rs) and reproduced
below as the human-readable reference.

## Reference — `verify_sync_committee` return codes

> **O-700 / R.01**

**Inputs.**

- `pubkeys_ptr` / `pubkeys_len` — concatenated 48-byte participating pubkeys
- `sig_ptr` — 96-byte aggregate signature
- `signing_root_ptr` — 32-byte signing root (caller computes domain + root)

**Caller is responsible for.**

- Filtering pubkeys by sync committee participation bits
- Computing the fork domain (`fork_version` is fork-dependent — fetch dynamically)
- Computing the signing root: `sha256(parent_root || domain)`

**Return codes.**

|  Code | Meaning                                                                |
|------:|------------------------------------------------------------------------|
|   `1` | signature verified                                                     |
|   `0` | signature invalid                                                      |
|  `-1` | signature parse failed (not a valid 96-byte G2 point)                  |
|  `-2` | no pubkeys provided (`pubkeys_len == 0`)                               |
|  `-3` | aggregation failed (subgroup check or internal blst error)             |
|  `-4` | malformed pubkey chunk (any 48-byte slice that is not a valid G1 point)|

Single source of truth is the doc-comment block in
[`bls-verifier/src/lib.rs`](../bls-verifier/src/lib.rs). If the codes ever
change, both the source and this sheet must be updated together.

## What this primitive does NOT do

> **O-700 / W.01 — CRITICAL**

`verify_sync_committee` verifies one thing — that an aggregated BLS
signature over a given signing root is valid against an aggregated
pubkey. **It does not, by itself, constitute a sync committee verifier.**
A future engineer or future-Claude looking at `lib.rs` in isolation may
mistake it for the whole story and wire it into production with
assumptions the primitive does not satisfy. The primitive specifically
does **not**:

- Filter participating pubkeys from the 512-validator sync committee using the participation bitfield
- Compute the fork domain from `fork_version` and `genesis_validators_root`
- Compute the signing root from `parent_root` and the domain
- Validate that the supplied pubkey set has length 512 (or any other count)
- Track fork epoch transitions or fetch fork versions from the beacon API
- Handle network I/O of any kind — it is a pure function over byte buffers

The HyperBEAM device that wraps this primitive (runbook
[O-701](O-701-hyperbeam-bls-device.md)) does all of the above. Calling
the primitive directly without a wrapper that supplies these
preconditions will produce signatures that verify successfully against
the wrong inputs — exactly the failure mode this runbook entry exists
to prevent.

## Failure modes

Three categories of failure surface in different ways and require
different remediations. Distinguishing them at first observation saves
time during incident response.

### Sandbox-class failures

Network outbound to `lodestar-mainnet.chainsafe.io` denied at the host
policy layer. Surfaces as a JSON decode error at the very first beacon
API call — typically
`reqwest::Error { kind: Decode, "expected value", line 1 column 1 }`
because the response body is plain-text "Host not in allowlist" rather
than JSON. Direct `curl -i` against the endpoint confirms the deny by
returning HTTP/2 403 with header `x-deny-reason: host_not_allowed`.

Remediation is environmental, not code. Run the verifier in an
environment with mainnet beacon access (operator laptop, RunPod, or
HyperBEAM node). Not a code defect; do not file an incident.

### Beacon endpoint outage

Lodestar (or whichever beacon endpoint is in use) goes down, returns
5xx, gets rate-limited, returns malformed JSON, or times out under
load. Symptomatically similar to sandbox-class failures from the
caller's perspective — JSON decode failures, connection resets — but
the remediation is different: failover to an alternate beacon endpoint
rather than relocating the runtime.

The integration test `bls-test` currently hardcodes a single Chainsafe
endpoint, which is acceptable for a scaffold. Production HyperBEAM-device
implementations must support beacon endpoint failover with at least two
and ideally three independent providers. A sync committee verifier that
depends on a single beacon endpoint inherits that endpoint's
availability as a hard dependency.

### Fork-boundary regression

At the next mainnet fork (Glamsterdam, currently targeted Q2/Q3 2026),
the `current_version` value returned by the beacon API
`/eth/v1/beacon/states/{slot}/fork` endpoint will change from the
present `0x06000000` (Fulu, active since 2025-12-03) to the next
allocated value. As long as the verifier fetches fork version
dynamically — which the production HyperBEAM device must — this is not
a regression. The signing root will recompute correctly with the new
domain and verification will continue to succeed.

A future operator observing the fork version value change in
production logs may mistake this for a bug. It is not. The primitive
itself is fork-version-agnostic; the wrapper supplies the value.
Verify that the wrapper is fetching the value dynamically (rather than
hardcoding) before treating any fork-boundary value change as an
incident.

> **Scaffold drift note (2026-04-30):** the current `bls-test` and
> `bls-verify-cli` binaries hardcode `fork_version = [0x06, 0x00, 0x00, 0x00]`
> in `compute_domain()`. This is acceptable for the scaffold but **must**
> be replaced by a dynamic fetch before production use. Tracked as a
> known-issue against this repo, not against O-700 itself.

## Next layer up

The HyperBEAM device that wraps this primitive is the production
verifier and is the proper subject of Service 02 in the A-series
blueprint. The device handles the participation-bit filtering, domain
computation, signing-root computation, fork-version fetching, beacon
endpoint failover, AO compliance hook, and x402 facilitator
integration. It is the layer that becomes a public service; the
primitive in `k-luecke/bls-verifier` is one component of it.

The device runbook is
[O-701 — HyperBEAM BLS Device](O-701-hyperbeam-bls-device.md).

Subsequent verification primitives (audit relay signatures, identity
signing keys) extend the same series: O-720, O-730, and so on.
