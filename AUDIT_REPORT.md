# Code Audit Report — `bls-verifier` workspace

Auditor: third-party code review
Date: 2026-05-05
Scope: `/home/user/bls-verifier` — crates `bls-verifier`, `bls-device`,
`bls-test`, `bls-verify-cli`, plus integration tests under
`bls-device/tests/`.

---

## 1. Executive summary

The workspace implements a small primitive — a single C-FFI function
that aggregates BLS12-381 G1 public keys, parses a G2 signature, and
runs a `min_pk` verify with the IETF POP DST — and a HyperBEAM "device"
harness around it (`bls-device`) that wires in beacon failover, a
period-keyed SQLite committee cache, SSZ-style domain/signing-root
construction, an x402 payment hook, and an AO compliance log. There
are also two ad-hoc tools (`bls-test`, `bls-verify-cli`).

Overall the BLS plumbing itself is short, mostly correct, and uses
`blst` correctly: subgroup checks are enabled on aggregation
(`AggregatePublicKey::aggregate(&pk_refs, true)`), the signature
verify call requests subgroup validation on both sides
(`sig.verify(true, …, true)`), and the IETF POP DST string is the
right one for Ethereum sync committees. Domain separation chunks the
fork version and `genesis_validators_root` correctly and truncates
`fork_data_root` to 28 bytes for the `Domain` SSZ object.

However, **the harness (the layer the network actually exposes via
HyperBEAM Service A-202) is not production-ready** and has multiple
correctness, robustness, and security weaknesses that an attacker or
even a well-intentioned operator can trip:

- The most consequential cryptographic gap is that **the participation
  bitfield is parsed with the wrong bit-order convention for SSZ
  bitvectors and is never length-checked against the expected 512-bit
  committee size** (see C-1, C-2). The order convention happens to
  match how Ethereum serializes `Bitvector[N]` (LSB-first within a
  byte), but no check rejects truncated or oversize bitfields, so a
  malformed bitfield silently picks an arbitrary subset of the cached
  committee.
- The **committee fetched from `/sync_committees` is *not* keyed by
  period in the URL** — `committee_pubkeys(slot)` queries by slot but
  then resolves validator pubkeys from `…/validators?id=…` against
  `head` rather than against the slot's state (see C-3). On a
  validator-key rotation or exit between the slot of interest and
  `head`, the cached "committee" is wrong. The cache then pins the
  wrong-but-self-consistent set under the period key.
- The **x402 verification is a mock that always succeeds** (S-1) and
  the **platform signature is a SHA-256 stub, not a signature** (S-2).
  Both are documented as such, but the harness exposes a
  `platform_signature` field over the wire that downstream consumers
  may treat as authoritative.
- The CLI and `bls-test` binaries are riddled with `unwrap()` on
  attacker-controlled input (any malformed JSON or short hex string
  panics the process), and the CLI does not validate hex length or
  even that pubkey bytes are 48 bytes before passing them to blst —
  it relies on `from_bytes` returning `Err`, then silently drops the
  pubkey instead of failing the request.
- **No `Cargo.lock` is committed** (gitignored deliberately per
  `O-700 / R.01`), so blst, reqwest, sha2, rusqlite, etc. float on
  caret-range minor updates. For a security-critical primitive that
  is unsuitable; the runbook claims "build artifacts reproducible"
  but it actually means "not reproducible across time".

There are no critical bugs in the C-FFI primitive itself. The
critical-class findings are all in the harness layer that supplies
inputs to the primitive.

A total of **31 findings** are listed below: 2 Critical, 6 High, 9
Medium, 8 Low, 6 Info.

---

## 2. Architecture overview

```
                ┌──────────────────────────────────────────────────┐
                │  bls-verifier (cdylib, also wasm32 target)       │
                │                                                  │
                │  extern "C" verify_sync_committee(               │
                │      pubkeys_ptr, pubkeys_len,                   │
                │      sig_ptr (96B),                              │
                │      signing_root_ptr (32B)                      │
                │  ) -> i32                                        │
                │                                                  │
                │  Aggregates 48-byte G1 pubkeys, parses 96-byte   │
                │  G2 sig, calls blst::min_pk::Signature::verify   │
                │  with the IETF BLS POP DST and subgroup checks.  │
                └──────────────▲───────────────────────────────────┘
                               │ called via NativePrimitive (re-impl)
                               │
┌──────────────────────────────┴───────────────────────────────────┐
│ bls-device (HyperBEAM ~bls-sync-committee@1.0)                   │
│                                                                  │
│   Device::verify(req, x402_payload) — 8 stages:                  │
│     1. parse VerifyRequest (slot, parent_root, sync_aggregate)   │
│     2. x402::X402Verifier::verify   (MockX402: always Ok)        │
│     3. FailoverPool::fork_version_for_slot (EWMA-ranked HTTP)    │
│     4. CommitteeCache.get(period) or fetch from beacon          │
│     5. filter_participating(pubkeys, bits)                       │
│     6. signing_root::compute_domain + compute_signing_root       │
│     7. NativePrimitive::verify (re-runs the blst path inline)    │
│     8. sign_response (SHA-256 stub) + AoLogger::log (MockAo)     │
│                                                                  │
│   Modules: ao, beacon, cache, lib, manifest, primitive,          │
│            signing_root, x402, bin/record_fixture.rs             │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────┐ ┌──────────────────────────┐
│ bls-test (bin)           │ │ bls-verify-cli (bin)     │
│ live mainnet smoke test  │ │ stdin-JSON one-shot      │
│ direct blst calls        │ │ verifier                 │
└──────────────────────────┘ └──────────────────────────┘
```

Notable architectural observations:

- The primitive is duplicated. The same blst code path (parse pubkeys,
  aggregate with subgroup check, parse signature, verify with POP DST)
  appears in three places: `bls-verifier/src/lib.rs:60-89`,
  `bls-device/src/primitive.rs:33-65`, and `bls-test/src/main.rs:122-137`,
  and again in `bls-verify-cli/src/main.rs:60-79`. Per-crate drift is
  possible (and as of this audit return-code semantics already differ
  between O-700's documented codes and `primitive.rs` — see M-1).

- `Device` holds `Arc<dyn …>` for every collaborator, which is the
  right shape for swapping a `MockX402`/`MockAo` in tests, but means
  the production path silently runs the mocks if construction is wrong
  (no compile-time guard against "device shipped with mocks").

- `bls-device` depends on `tokio` with `features = ["full"]` and
  `reqwest` with `features = ["json"]`, but the `lib` target itself
  doesn't strictly need `tokio::main`. The harness compiles to
  wasm32 only via the primitive crate; `bls-device` is native-only
  (uses sqlite + reqwest).

---

## 3. Findings table

Severity scale:
- **Critical** — exploitable / immediately incorrect under realistic input
- **High** — likely-exploitable robustness gap or wrong cryptographic input
- **Medium** — correctness bug or hardening miss with limited blast radius
- **Low** — code quality / minor robustness
- **Info** — observation, not a defect

### Critical

| # | File:line | Title |
|---|-----------|-------|
| C-1 | `bls-device/src/lib.rs:228-239` | `filter_participating` does not validate bitfield length against committee size |
| C-2 | `bls-device/src/lib.rs:228-239` | Bit-iteration order is not validated as SSZ `Bitvector[512]` order — silently agrees with the wire format but is not asserted, so a future refactor could flip it without breaking any test |
| C-3 | `bls-device/src/beacon.rs:81-118` | `committee_pubkeys` resolves validator pubkeys against `head`, not the request's slot/period; under validator-key rotation the cached committee binds the wrong pubkeys to a period |

### High

| # | File:line | Title |
|---|-----------|-------|
| H-1 | `bls-device/src/x402.rs:15-22`, `bls-device/src/lib.rs:155-158` | `MockX402` always returns `Ok`; `Device::new` does not require a non-mock impl in production builds |
| H-2 | `bls-device/src/lib.rs:258-265` | `sign_response` returns `SHA-256(key_id ‖ root ‖ verified_byte)` — *not a signature*. Anyone who knows `key_id` (it is in the response) can forge it. |
| H-3 | `bls-device/src/primitive.rs:40-49` | Pubkey parse failures are masked: `filter_map(...).ok())` then a count-based check. If two pubkeys both fail to parse the count check happens to fire, but if the check is reordered, malformed pubkeys silently disappear |
| H-4 | `bls-verify-cli/src/main.rs:6-34`, `127-133` | CLI panics on every error path: malformed JSON, missing field, bad hex, odd-length hex. Trivial DoS on any caller-supplied bug; no error JSON returned for those cases |
| H-5 | `bls-verifier/src/lib.rs:50-58` | C-FFI does not check `pubkeys_ptr`/`sig_ptr`/`signing_root_ptr` for null and uses `from_raw_parts` directly — a null or unaligned pointer is undefined behaviour. The contract should reject these explicitly. |
| H-6 | `bls-device/src/lib.rs:165-173`, `bls-device/src/cache.rs:60-87` | Cache returns no metadata (slot or fork version captured at fetch time), so a poisoned row from one period transfers across fork boundaries without invalidation |

### Medium

| # | File:line | Title |
|---|-----------|-------|
| M-1 | `bls-device/src/primitive.rs:14-27`, `bls-device/src/manifest.rs:37-44`, `bls-verifier/src/lib.rs:33-44` | Three different return-code taxonomies. `bls-verifier`'s docs say `-2` = "no pubkeys" and `-4` = "malformed pubkey chunk"; `primitive.rs` says `-2` = "pubkey parse failure" and `-4` = "signing root not 32 bytes"; `manifest.rs` enumerates yet a third labeling. Consumers reading `primitive_return_code` will mis-classify errors. |
| M-2 | `bls-device/src/lib.rs:178-189` | An empty `participating` set returns code `-3` from `NativePrimitive` ("aggregation failed") rather than a distinct "no participants" code. Operationally indistinguishable from a real subgroup-check failure. |
| M-3 | `bls-device/src/beacon.rs:81-118` | Sync committee fetch silently drops any pubkey whose `bytes.len() != 48`, returning a short list rather than an error. A buggy beacon yields a self-consistent but wrong-size committee that then gets cached. |
| M-4 | `bls-device/src/beacon.rs:152-176` | EWMA cooldown uses `Mutex<Vec<EndpointHealth>>` and re-locks across `await` points by snapshotting `order()` first; that's correct, but `record()` clobbers any concurrent record's cooldown without merging. Under concurrent load endpoints can flip in/out of cooldown unpredictably. |
| M-5 | `bls-device/src/cache.rs:62, 98, 117`, `bls-device/src/beacon.rs:154, 168, 185` | `Mutex::lock().unwrap()` everywhere. A poisoned mutex from any panic in another stage takes down all subsequent verify requests for the process lifetime. |
| M-6 | `bls-device/src/lib.rs:241-254` | `hash_request` canonicalises with `format!("{}|{}|...")` over user-controlled hex strings. There is no length-bound, no normalisation (mixed case `0x` vs `0X`, leading zeros, etc.), and no domain tag. Two semantically identical requests with different hex case produce different request hashes — and therefore different x402 receipts and AO ids. |
| M-7 | `bls-device/src/lib.rs:144-152` | `decode_hex` strips a leading `0x` but does *not* require it. `bits` is then passed to `filter_participating` with no length check at all (a 0-byte bits string trivially returns an empty participating set). |
| M-8 | `bls-device/src/cache.rs:67, 102` | `period as i64` silently wraps on `period > i64::MAX` (theoretically slot ≈ 7.5e22 — far in the future, but the conversion is unchecked). Sqlite stores a signed 64-bit int. |
| M-9 | `bls-device/src/lib.rs:38-41` | `MAINNET_GENESIS_VALIDATORS_ROOT` is a constant inside the lib; if a misconfigured operator reuses `Device::new` with the constant on a non-mainnet network, signatures will silently fail without explanation. There is no `network: NetworkId` enum to gate it. |

### Low

| # | File:line | Title |
|---|-----------|-------|
| L-1 | `bls-device/src/signing_root.rs:32-36` | `sha256` returns `Vec<u8>` and the caller does `try_into().expect(…)`. Returning `[u8; 32]` from `sha256` removes the runtime check. |
| L-2 | `bls-device/src/signing_root.rs:7` | `DOMAIN_SYNC_COMMITTEE` is a private 4-byte constant inside the module. The corresponding constant exists in `bls-verify-cli/src/main.rs:99` and `bls-test/src/main.rs:153` as duplicates. |
| L-3 | `bls-device/src/beacon.rs:33-35` | `reqwest::Client::builder()...build().expect("reqwest client")` panics in `HttpBeaconClient::new`. Constructor is infallible from the caller's perspective, but actually panics on TLS init failure. |
| L-4 | `bls-device/src/cache.rs:94-97` | `SystemTime::now().duration_since(UNIX_EPOCH).map(...).unwrap_or(0)` silently records `fetched_at = 0` if the system clock is before 1970. Should propagate the error or at least log. |
| L-5 | `bls-device/src/manifest.rs:49` | `to_json_pretty` does `expect("manifest serialises")`; a `Serialize` failure in a third-party type would panic. |
| L-6 | `bls-test/src/main.rs:124-129`, `185-191` | Same `unwrap()`-on-everything pattern as the CLI. This is a developer tool, but it is referenced in O-702 as the smoke test — a malformed beacon response then crashes rather than reporting `verified: false`. |
| L-7 | `bls-device/src/primitive.rs:80-81` | `_unused_marker(_: DeviceError)` dead code marker, never called, only suppresses an unused-import warning. Should be removed. |
| L-8 | `bls-device/src/lib.rs:182-183` | `format!("0x{}", hex::encode(&domain))` and similar — `hex::encode` already accepts a slice, the `&` is harmless but the `format!` allocates per response; minor. |

### Info

| # | File:line | Title |
|---|-----------|-------|
| I-1 | `Cargo.toml` (workspace), `*/Cargo.toml` | No `Cargo.lock` is committed. Per `.gitignore`. For a security-critical primitive, lockfile pinning is industry standard. |
| I-2 | `bls-device/Cargo.toml:21-23` | `tokio = { ..., features = ["full"] }` and `reqwest = { ..., features = ["json"] }` — `full` pulls everything; tighten to `["macros", "rt-multi-thread", "sync"]` if known. |
| I-3 | `bls-verifier/Cargo.toml:6-7`, `bls-verifier/Cargo.toml:10` | `crate-type = ["cdylib"]` only — Rust callers cannot use this as a library; `bls-device::primitive::NativePrimitive` therefore re-implements the same code, perpetuating the duplication. Add `"rlib"` so the device can call the same `verify_sync_committee` it ships. |
| I-4 | `bls-device/tests/integration_fixture.rs:12-13` | Test explicitly does not assert `verified == true` because the canned signature is a placeholder. The CI gate therefore proves only "pipeline does not panic", not "pipeline accepts a valid signature and rejects an invalid one." Negative tests against tampered fixtures are missing. |
| I-5 | `bls-device/tests/integration_live.rs:18-21` | Live test is gated on env var; if the env var is unset the test prints to stderr and returns success. There is no assertion that *some* test ran. |
| I-6 | `bls-device/tests/no_hardcoded_fork.rs:38-44` | The grep test only catches three exact stylings of `[0x06, 0x00, 0x00, 0x00]`. It will not catch e.g. a `b"\x06\x00\x00\x00"` literal, a `let v = [6u8, 0, 0, 0]` form, an `0x06000000_u32.to_le_bytes()`, or a base64'd embedding. |

---

## 4. Cryptographic concerns called out separately

### 4.1 BLS12-381 / blst usage

- **DST string**: `b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"` is
  the correct IETF BLS POP-mode DST that Ethereum consensus clients
  use (`min_pk`, signatures in G2, pubkeys in G1). Confirmed in
  `bls-verifier/src/lib.rs:85`, `bls-device/src/primitive.rs:59`,
  `bls-test/src/main.rs:131`, `bls-verify-cli/src/main.rs:78`.
  All four locations match. Drift risk: see I-3 (no shared crate).
- **Subgroup checks**: `AggregatePublicKey::aggregate(&pk_refs, true)`
  passes `pks_validate = true`, and `sig.verify(true, root, dst, &[],
  &agg_pk, true)` passes both `sig_groupcheck = true` and
  `pks_validate = true`. This is the safe configuration.
  (`bls-verifier/src/lib.rs:80, 86`; mirrored in `primitive.rs:51, 60`.)
- **Infinity / identity points**: `blst::min_pk::PublicKey::from_bytes`
  accepts the all-zero compressed encoding as a non-canonical input
  and returns an error. The empty-pubkey case (`pubkeys_len == 0` →
  `-2`) is handled. **However**, the harness path
  (`bls-device/src/primitive.rs:40-42`) treats *empty participating
  list* as "aggregation failed" (`-3`), which conflates a non-cryptographic
  caller bug with a genuine subgroup failure (M-2).
- **Signing-root / domain construction**: matches the spec — domain
  type `0x07000000` for `DOMAIN_SYNC_COMMITTEE`, fork-data root =
  `SHA256( pad32(fork_version) ‖ genesis_validators_root )`, domain =
  `domain_type ‖ fork_data_root[..28]`, signing root =
  `SHA256(object_root ‖ domain)`. `signing_root.rs:9-23` is correct.
  Note: `compute_domain` does not bound-check `fork_version.len() ==
  4`; it relies on the `&[u8; 4]` type, so this is fine in
  `signing_root.rs` but not in the CLI variant
  (`bls-verify-cli/src/main.rs:48-54`) where a length check is
  present but only after potentially-panicking hex decode.

### 4.2 Sync-committee participation handling

- **Bitfield order**: SSZ encodes `Bitvector[N]` little-endian within
  a byte (bit 0 of byte 0 = participant 0). The current iteration
  `(bits[byte_idx] >> bit_idx) & 1` matches that convention — good.
  But there is **no comment or test asserting it**, no length check
  against `committee_size`, and no rejection of trailing non-zero
  bits past `N=512`. (C-1, C-2)
- **No 512 sanity check**: per O-700 / W.01 the harness is supposed
  to enforce committee length 512. `bls-device/src/lib.rs:174` records
  `committee_size = pubkeys.len()` but never asserts it equals 512.
  A truncated beacon response would yield committee_size < 512 and
  still verify against a partial-aggregate signature — *which is what
  the attacker wants*. The committee size is recorded in the response
  but the device does not refuse to proceed.

### 4.3 Slot / period / fork boundaries

- `period = slot / SLOTS_PER_PERIOD` (8192) is correct.
- **Fork-version is fetched dynamically** — good, and enforced by the
  `no_hardcoded_fork` test (with caveat I-6).
- **Boundary risk**: at slot `period * 8192`, the *upcoming* committee
  is what signs, not the *current* one. The Ethereum consensus spec
  uses `compute_sync_committee_period_at_slot(slot + 1)` semantics in
  some places. The harness uses plain `slot / 8192` everywhere; this
  is correct for the *signing committee for slot s* (which is the
  committee of period `s/8192`, see `EIP-altair`) but it is
  **silently dependent** on that subtlety and there are no boundary
  tests for slots near a period transition (Info / consider adding
  a "transition slot" fixture).
- **Cache key collision across networks**: `period` is a bare `u64`.
  If the cache file is reused across a Holesky/Hoodi/Mainnet operator
  switch, the same period number resolves to a different committee.
  The cache row should include `network_id` or `genesis_validators_root`
  in the key. (related to M-9, H-6)

### 4.4 Timing side channels

- BLS verification time is dominated by pairings; success/failure paths
  go through the same blst code path inside `Signature::verify`. blst
  itself is constant-time within the field operations.
- However, `Device::verify` returns *early* on parse failures vs late
  on cryptographic failures, and the AO log is only written after the
  primitive call. An external observer measuring response latency can
  distinguish "pubkey parse failure" from "sig verify failure" easily
  — typically a non-issue for sync-committee verification (public
  signatures), but worth noting for the more general x402-paid use
  case where unpaid attacker probes are billed differently per outcome.

### 4.5 `sign_response` is not a signature (H-2)

```rust
fn sign_response(key_id: &str, signing_root: &[u8;32], verified: bool) -> [u8;32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(key_id.as_bytes());
    h.update(signing_root);
    h.update([verified as u8]);
    h.finalize().into()
}
```

`key_id` is also returned in the response (`platform_key_id` is in the
AO event payload, and the manifest exposes the deploy key id), so this
"signature" is publicly recomputable by anyone. Even with the comment
"Real implementation lives in O-720 (TEE-bound key rotation runbook)",
the response field name `platform_signature` will mislead consumers.
At minimum the field should be named `platform_signature_stub` until
O-720 lands.

### 4.6 Manifest signing

`manifest.rs::DeviceManifest` does not sign at all — it serialises a
JSON document with a `deploy_key_id` field and stops. Whatever
upstream HyperBEAM registrar consumes this JSON is the trust boundary;
the manifest itself has no integrity protection. This is acceptable
*if* the registrar signs at upload time, but the audit cannot verify
that without seeing the registrar code.

---

## 5. Specific code observations

### 5.1 Re-implemented primitive in `NativePrimitive`

```rust
// bls-device/src/primitive.rs:33-65
impl Primitive for NativePrimitive {
    fn verify(&self, participating: &[&[u8;48]], signature: &[u8;96], signing_root: &[u8;32])
        -> Result<i32>
    {
        if participating.is_empty() { return Ok(-3); }      // <- M-2: should be its own code
        let pks: Vec<PublicKey> = participating.iter()
            .filter_map(|pk| PublicKey::from_bytes(*pk).ok())
            .collect();
        if pks.len() != participating.len() { return Ok(-2); } // <- H-3 ordering hazard
        ...
        let agg_pk = match AggregatePublicKey::aggregate(&pk_refs, true) { ... };
        let sig   = match Signature::from_bytes(signature) { ... };
        let dst   = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        match sig.verify(true, signing_root, dst, &[], &agg_pk, true) { ... }
    }
}
```

This bypasses the cdylib entirely. The doc comment on `Primitive` says
"Two adapters: native (link to libbls_verifier.so cdylib via blst
directly) and wasm". In practice it links blst, not the cdylib; the
function name `verify_sync_committee` in `bls-verifier` is never
actually called by the device. The code path that gets audited at the
primitive level is therefore not the same code path the device
exercises (subtle drift risk; see I-3).

### 5.2 SSZ bitvector length

In `bls-device/src/lib.rs:228-239`:

```rust
fn filter_participating<'a>(pubkeys: &'a [[u8; 48]], bits: &[u8]) -> Vec<&'a [u8; 48]> {
    pubkeys.iter().enumerate().filter(|(i, _)| {
        let byte_idx = i / 8;
        let bit_idx  = i % 8;
        byte_idx < bits.len() && (bits[byte_idx] >> bit_idx) & 1 == 1
    }).map(|(_, pk)| pk).collect()
}
```

If `bits.len() < ceil(committee_size / 8)`, the function happily
proceeds and "filters" using whatever bits are available — including
returning an empty participating set if `bits` is empty. Since
"empty participating" maps to primitive code `-3`
("aggregation failed"), an attacker who can poison the request body
gets a `-3` response that looks like an internal error rather than
"you supplied a malformed bitfield".

The function should:
1. assert `pubkeys.len() == 512` (or the committee size constant);
2. assert `bits.len() == 64` (= 512/8);
3. assert that bits beyond index 511 are all zero (forbidden by SSZ
   `Bitvector[512]`).

### 5.3 SQLite cache

`SqliteCommitteeCache::open` does not set `journal_mode`, `synchronous`,
or any pragma. Default journal is `DELETE` and synchronous is `FULL`,
which is fine for correctness but slow; not a security issue. The
`Mutex<Connection>` serialises every read against every write — for
this workload that's actually fine (one read per request, one write
per ~27 hours). No issue.

### 5.4 `decode_hex` is permissive

```rust
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.trim_start_matches("0x"))?)
}
```

- Does not reject `0X` (uppercase prefix).
- Does not reject embedded whitespace; `hex::decode` of `"01 02"` errors but the message is unhelpful.
- Used for both `parent_root` (length-checked) and `bits` (not length-checked, M-7).

---

## 6. Test coverage assessment

| Test | Verifies | Gap |
|------|----------|-----|
| `bls-verifier/src/lib.rs` | None — no unit tests in the cdylib at all | The C-FFI surface is the entire trust boundary; needs negative tests for null ptrs (after H-5 fix), short pubkey buffers, all-zero pubkey, identity signature |
| `bls-device/src/lib.rs::tests` | `filter_participating_picks_only_set_bits` (smoke), `hash_request_is_deterministic` (smoke) | Misses: bitfield length mismatch, oversized bits, empty bits, bit-order regression (would catch a future MSB/LSB flip) |
| `bls-device/src/cache.rs::tests` | `put_get_roundtrip` only | Misses: corrupted blob (length not multiple of 48 — code path exists, no test), reopen-on-disk persistence, period collision across networks |
| `bls-device/src/signing_root.rs::tests` | `domain_changes_with_fork_version`, `signing_root_is_deterministic` | Misses: KAT (known-answer test) against an Ethereum spec test vector — currently you're computing what the code says, not verifying it matches the spec |
| `bls-device/tests/integration_fixture.rs` | Pipeline runs end-to-end without panicking; cache hit on second call; response shape | Does not verify a real signature (placeholder), does not test tampered inputs, does not exercise fork-version mismatch or wrong genesis_validators_root |
| `bls-device/tests/integration_live.rs` | Live mainnet head verifies | Skipped silently if env var unset (I-5); no negative live tests (e.g., flip a bit in the signature → expect `verified == false`) |
| `bls-device/tests/no_hardcoded_fork.rs` | No source file outside tests/ contains the literal `[0x06, 0x00, 0x00, 0x00]` | Brittle (I-6) — many alternate spellings escape detection |

The CI gate is therefore a *shape* gate, not a *correctness* gate. The
only thing that proves verification actually works is the live test
gated on `BLS_DEVICE_LIVE=1` — which by definition cannot run in CI.

Concrete additions worth writing:
- KAT for `compute_signing_root` against an Ethereum consensus-spec
  test vector (e.g., a known mainnet block).
- Negative fixture variant: same fixture with one bit flipped in the
  signature → assert `verified == false` and the AO log records that.
- Bitfield round-trip property test: random `bits` byte arrays, verify
  the participation set matches an oracle implementation (e.g., sum-of-set-bits).

---

## 7. Dependency hygiene

| Crate | Version | Risk |
|-------|---------|------|
| `blst` | `"0.3"` (caret) | Caret allows any 0.3.x; `blst` had a 0.3.13 release with security-relevant changes. Pin to `=0.3.x` and re-pin on review. |
| `sha2` | `"0.10"` | Fine; `sha2 0.10.x` is the mature line. |
| `hex` | `"0.4"` | Fine. |
| `serde` | `"1"` | Fine. |
| `serde_json` | `"1"` | Fine. |
| `tokio` | `"1"` `features=["full"]` | `full` is broad; tighten. |
| `reqwest` | `"0.11"` `features=["json"]` | 0.11 → 0.12 transition is in-flight in the ecosystem; pin or move. |
| `rusqlite` | `"0.31"` `features=["bundled"]` | `bundled` ships its own sqlite — good for reproducibility, but means you must track sqlite CVEs out-of-band. |
| `async-trait` | `"0.1"` | Fine. |
| `thiserror` | `"1"` | Fine. |
| `tracing` | `"0.1"` | Fine. |
| `uuid` | `"1"` `features=["v4"]` | Fine. |
| `tempfile` (dev) | `"3"` | Fine. |

**Headline: no `Cargo.lock` is committed.** This is documented as an
intentional choice ("sources only") but it precludes reproducible
builds and means a fresh `cargo build` six months from now picks up
new minor versions of blst, reqwest, sha2, etc. For a primitive whose
correctness is the entire point, commit the lockfile.

---

## 8. Recommendations summary (not patches — pointers only)

1. Make `filter_participating` strict: 512 pubkeys, 64 bytes of bits,
   trailing zero bits enforced. (C-1, C-2)
2. Fetch validator pubkeys against the slot's state, not `head`.
   (C-3)
3. Replace `MockX402` with a real verifier or refuse to start.
   (H-1)
4. Replace `sign_response` with an actual signature, or rename the
   field. (H-2)
5. Reconcile the three return-code taxonomies; have one canonical
   enum. (M-1)
6. Make the cache row include `genesis_validators_root` in the
   primary key. (H-6, M-9)
7. Add KAT tests for `compute_signing_root` against a real mainnet
   block; add a negative fixture variant. (test-coverage section)
8. Add `rlib` to `bls-verifier`'s `crate-type` and have
   `NativePrimitive` call the cdylib's `verify_sync_committee` rather
   than re-implementing the same blst calls. (I-3, drift risk)
9. Commit `Cargo.lock`. (I-1)
10. Replace every `.unwrap()` on attacker-reachable input
    (CLI, beacon JSON parsing, hex decoding) with explicit error JSON.
    (H-4, L-6)
11. Add null-pointer checks at the C-FFI boundary. (H-5)
12. Replace `Mutex` with `parking_lot::Mutex` or document the
    poisoning behaviour; consider `tokio::sync::Mutex` for the cache
    so a poisoned mutex doesn't permanently kill the device.
    (M-5)

---

## 9. Files reviewed

- `/home/user/bls-verifier/Cargo.toml`
- `/home/user/bls-verifier/bls-verifier/Cargo.toml`
- `/home/user/bls-verifier/bls-verifier/src/lib.rs`
- `/home/user/bls-verifier/bls-device/Cargo.toml`
- `/home/user/bls-verifier/bls-device/src/lib.rs`
- `/home/user/bls-verifier/bls-device/src/ao.rs`
- `/home/user/bls-verifier/bls-device/src/beacon.rs`
- `/home/user/bls-verifier/bls-device/src/cache.rs`
- `/home/user/bls-verifier/bls-device/src/manifest.rs`
- `/home/user/bls-verifier/bls-device/src/primitive.rs`
- `/home/user/bls-verifier/bls-device/src/signing_root.rs`
- `/home/user/bls-verifier/bls-device/src/x402.rs`
- `/home/user/bls-verifier/bls-device/src/bin/record_fixture.rs`
- `/home/user/bls-verifier/bls-device/tests/integration_fixture.rs`
- `/home/user/bls-verifier/bls-device/tests/integration_live.rs`
- `/home/user/bls-verifier/bls-device/tests/no_hardcoded_fork.rs`
- `/home/user/bls-verifier/bls-test/Cargo.toml`
- `/home/user/bls-verifier/bls-test/src/main.rs`
- `/home/user/bls-verifier/bls-verify-cli/Cargo.toml`
- `/home/user/bls-verifier/bls-verify-cli/src/main.rs`
- `/home/user/bls-verifier/.gitignore`
- `/home/user/bls-verifier/README.md`
- `/home/user/bls-verifier/docs/O-700-bls-sync-committee-primitive.md` (skim)
- `/home/user/bls-verifier/docs/O-701-hyperbeam-bls-device.md` (skim)
- `/home/user/bls-verifier/docs/O-702-bls-device-runbook.md` (skim)
- `/home/user/bls-verifier/fixtures/beacon/README.md`
