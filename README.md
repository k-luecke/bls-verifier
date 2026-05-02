# bls-verifier

The cryptographic primitive at the bottom of Paxiom **Service A-202** —
Ethereum sync committee signature verification. One C-FFI function in a
small Rust crate, compiled to either a native cdylib or a wasm32 module
for the HyperBEAM device.

> **Verifies one thing well; the layers above it do the rest.**

## Workspace

| Crate | Type | Purpose |
|-------|------|---------|
| [`bls-verifier`](bls-verifier) | cdylib | The primitive — single C-FFI `verify_sync_committee`. |
| [`bls-test`](bls-test) | bin (tokio) | End-to-end test against Lodestar mainnet. |
| [`bls-verify-cli`](bls-verify-cli) | bin | stdin-JSON wrapper for ad-hoc verification. |
| [`bls-device`](bls-device) | lib + bin | Production O-701 harness: beacon failover, period-keyed sync committee cache, signing-root computation, AO/x402 hooks. Wraps the cdylib/wasm primitive into the HyperBEAM `~bls-sync-committee@1.0` device. |

## Build

```bash
cargo build --release
```

Produces:
- `target/release/libbls_verifier.so` — the primitive cdylib (~730 KB)
- `target/release/bls-test` — Lodestar integration runner
- `target/release/bls-verify-cli` — stdin-JSON CLI

For the HyperBEAM device's wasm32 build:

```bash
cargo build --release --target wasm32-unknown-unknown -p bls-verifier
```

`Cargo.lock`, `target/`, and `*.so`/`*.dylib`/`*.dll` are gitignored —
this repo is sources only.

## Documentation

- **[O-700 — BLS Sync Committee Primitive](docs/O-700-bls-sync-committee-primitive.md)** — runbook for this crate. Return codes, what the primitive does and explicitly does not do, failure-mode taxonomy.
- **[O-701 — HyperBEAM BLS Device](docs/O-701-hyperbeam-bls-device.md)** — sketch of the production wrapper that turns this primitive into Service A-202.
- **[O-702 — BLS Device Runbook](docs/O-702-bls-device-runbook.md)** — operator runbook for the implemented harness in `bls-device/`: build, register, capture fixtures, smoke-test.

If you only read one thing, read **O-700 / W.01** in the O-700 runbook —
the primitive is *not* a complete sync-committee verifier and must not
be wired directly into production.
