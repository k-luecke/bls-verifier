//! BLS Sync Committee Primitive (O-700)
//!
//! Single C-ABI function `verify_sync_committee`. Verifies that an
//! aggregated BLS signature over a given signing root is valid against
//! an aggregated pubkey using the BLS POP DST.
//!
//! # What this primitive deliberately does NOT do (sheet O-700 / W.01)
//!
//! - Filter participating pubkeys from the 512-validator sync committee
//!   using the participation bitfield.
//! - Compute the fork domain from `fork_version` and
//!   `genesis_validators_root`.
//! - Compute the signing root from `parent_root` and the domain.
//! - Validate that the supplied pubkey set has length 512.
//! - Track fork epoch transitions or fetch fork versions.
//! - Handle network I/O — pure function over byte buffers.
//!
//! The HyperBEAM device that wraps this primitive (future runbook entry
//! O-701) supplies all of the above. Calling this primitive directly
//! without that wrapper will produce signatures that verify successfully
//! against the wrong inputs.
//!
//! # Inputs
//!
//! - `pubkeys_ptr` / `pubkeys_len` — concatenated 48-byte participating
//!   BLS pubkeys (caller must filter by sync-committee participation bits).
//! - `sig_ptr` — 96-byte aggregate signature.
//! - `signing_root_ptr` — 32-byte signing root
//!   (`sha256(parent_root || domain)`, computed by caller).
//!
//! # Return codes
//!
//! |  Code | Meaning                                                       |
//! |------:|---------------------------------------------------------------|
//! |   `1` | signature verified                                            |
//! |   `0` | signature invalid                                             |
//! |  `-1` | signature parse failed (not a valid 96-byte G2 point)         |
//! |  `-2` | no pubkeys provided (`pubkeys_len == 0`)                      |
//! |  `-3` | aggregation failed (subgroup check or internal blst error)    |
//! |  `-4` | malformed pubkey chunk (any 48-byte slice that is not a valid |
//! |       | G1 point)                                                     |
//!
//! These codes are the single source of truth — both this doc-comment
//! and runbook O-700 must update together if codes change.

use blst::min_pk::{PublicKey, Signature, AggregatePublicKey};
use blst::BLST_ERROR;

/// # Safety
///
/// The caller is responsible for the standard FFI pointer-validity contract:
/// - `pubkeys_ptr` must point to at least `pubkeys_len` valid bytes
/// - `sig_ptr` must point to at least 96 valid bytes
/// - `signing_root_ptr` must point to exactly 32 valid bytes
/// - all three pointers must be non-null and properly aligned for `u8`
/// - the memory must remain valid for the duration of this call
///
/// Null pointers and zero-length pubkeys input are detected and return -2
/// (matching the "no pubkeys provided" error code) rather than segfaulting,
/// but this defense is best-effort — any other invalid pointer is undefined
/// behavior.
#[no_mangle]
pub unsafe extern "C" fn verify_sync_committee(
    pubkeys_ptr: *const u8,
    pubkeys_len: usize,
    sig_ptr: *const u8,
    signing_root_ptr: *const u8,
) -> i32 {
    if sig_ptr.is_null() || signing_root_ptr.is_null() {
        return -1;
    }
    if pubkeys_ptr.is_null() || pubkeys_len == 0 {
        return -2;
    }
    let pubkeys_bytes = unsafe { std::slice::from_raw_parts(pubkeys_ptr, pubkeys_len) };
    let sig_bytes = unsafe { std::slice::from_raw_parts(sig_ptr, 96) };
    let signing_root = unsafe { std::slice::from_raw_parts(signing_root_ptr, 32) };

    // Parse signature
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    // Parse and aggregate pubkeys (each 48 bytes)
    let mut pubkeys: Vec<PublicKey> = vec![];
    for chunk in pubkeys_bytes.chunks(48) {
        match PublicKey::from_bytes(chunk) {
            Ok(pk) => pubkeys.push(pk),
            Err(_) => return -4,
        }
    }

    if pubkeys.is_empty() {
        return -2;
    }

    let pk_refs: Vec<&PublicKey> = pubkeys.iter().collect();
    let agg_pk = match AggregatePublicKey::aggregate(&pk_refs, true) {
        Ok(a) => a.to_public_key(),
        Err(_) => return -3,
    };

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    match sig.verify(true, signing_root, dst, &[], &agg_pk, true) {
        BLST_ERROR::BLST_SUCCESS => 1,
        _ => 0,
    }
}

