//! Audit M-9 (#24) regression lock.
//!
//! The audit raised concern that a misconfigured operator could re-use a
//! `MAINNET_GENESIS_VALIDATORS_ROOT` constant against a non-mainnet beacon
//! and silently produce wrong-domain signing roots. Five implementer
//! drafts proposed a `NetworkId` enum threaded into `Device::new` and
//! into the cache key. Moderator review rejected that approach:
//!
//!   1. paxiom Phase 0 only targets mainnet beacon. A repo-wide grep of
//!      `/home/user/paxiom` for `MAINNET_GENESIS_VALIDATORS_ROOT` /
//!      `genesis_validators_root` returns zero Rust call sites; the only
//!      hits are docs and Lua dispatch shims. There is no out-of-tree
//!      caller for the enum to serve.
//!   2. `signing_root::compute_domain` already mixes GVR into the
//!      SHA256 fork-data root (see `bls-device/src/signing_root.rs:9`),
//!      so a wrong GVR cannot collide with a correct one across networks
//!      at the crypto layer; the only failure mode is a verify error,
//!      not signature reuse.
//!   3. Hardcoding testnet GVRs (Holesky / Hoodi / Sepolia) inside the
//!      crate moves the operator footgun from "wrong constant" to "wrong
//!      enum variant" without removing it. The well-known testnet GVR
//!      values cited by implementer drafts were placeholders, not
//!      real values, which itself is evidence that the curated list is
//!      a maintenance burden the project does not need.
//!   4. Threading `NetworkId` into the cache key is asymmetric with the
//!      H-6 fix: that fix already keys on `(period, fork_version)`, and
//!      `fork_version` is per-network in practice. A `Custom([u8;32])`
//!      variant under a 1-byte discriminator (the majority implementer
//!      proposal) would collide for any two custom networks.
//!
//! Resolution: keep `Device::new(genesis_validators_root: [u8; 32], ...)`
//! taking 32 bytes the operator must justify, demote the constant to
//! `pub(crate)`, and expose only `mainnet_genesis_validators_root()` as
//! an explicit network choice. This test locks that contract in place.

use std::fs;
use std::path::Path;

#[test]
fn mainnet_gvr_constant_is_not_publicly_re_exported() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let lib = workspace_root.join("bls-device/src/lib.rs");
    let src = fs::read_to_string(&lib).expect("read lib.rs");

    // The constant must be crate-private. A `pub const` re-introduces the
    // exact footgun audit M-9 flagged.
    assert!(
        !src.contains("pub const MAINNET_GENESIS_VALIDATORS_ROOT"),
        "M-9 regression: MAINNET_GENESIS_VALIDATORS_ROOT must remain pub(crate). \
         Out-of-tree callers should supply 32 bytes they verified against \
         their beacon (or use mainnet_genesis_validators_root() as an \
         explicit network choice)."
    );
    assert!(
        src.contains("pub(crate) const MAINNET_GENESIS_VALIDATORS_ROOT"),
        "M-9 regression: expected the constant to exist as pub(crate); \
         got neither pub(crate) nor pub. If it was deleted, update the \
         accessor and this test together."
    );
    // Make sure the explicit accessor still exists. Tests in this crate
    // and the public docs depend on it.
    assert!(
        src.contains("pub fn mainnet_genesis_validators_root()"),
        "M-9 regression: the explicit `mainnet_genesis_validators_root()` \
         accessor must remain so call sites read as a deliberate network \
         choice, not a copy-paste of an opaque constant."
    );
}

#[test]
fn no_network_id_enum_is_introduced_into_device() {
    // The five implementer drafts converged on a `NetworkId` enum threaded
    // into Device::new and the cache key. Moderator rejected that path
    // (see module-level doc above). Lock it: no `enum NetworkId` may
    // appear in the device crate sources.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let crate_src = workspace_root.join("bls-device/src");
    let mut hits = Vec::new();
    walk(&crate_src, &mut hits);
    let mut offenders = Vec::new();
    for f in &hits {
        let s = fs::read_to_string(f).unwrap_or_default();
        // Match `enum NetworkId` with any whitespace, but allow it to
        // appear inside a string/comment if it ever needs to be referenced
        // by name in a doc. The cheap check below is "non-comment lines".
        for (i, line) in s.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
                continue;
            }
            if trimmed.contains("enum NetworkId")
                || trimmed.contains("pub enum NetworkId")
            {
                offenders.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "M-9 regression: NetworkId enum re-introduced at:\n{}\n\n\
         If the project has acquired a real testnet caller and the \
         tradeoffs in the M-9 module doc no longer hold, update the \
         module doc together with this test.",
        offenders.join("\n")
    );
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
}
