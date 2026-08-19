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
//! |  `-6` | one or more input pointers were null                          |
//!
//! These codes are the single source of truth — both this doc-comment
//! and runbook O-700 must update together if codes change.
//!
//! # Safety
//!
//! This function is `unsafe` because it dereferences raw pointers supplied
//! by the C caller. The caller must ensure that `pubkeys_ptr` points to at
//! least `pubkeys_len` bytes, `sig_ptr` to at least 96 bytes, and
//! `signing_root_ptr` to at least 32 bytes of initialized memory for the
//! duration of the call. Null pointers are checked and return `-6`; other
//! invalid pointers (dangling, misaligned, insufficient length) are UB.

use blst::min_pk::{PublicKey, Signature, AggregatePublicKey};
use blst::BLST_ERROR;

#[no_mangle]
pub unsafe extern "C" fn verify_sync_committee(
    pubkeys_ptr: *const u8,
    pubkeys_len: usize,
    sig_ptr: *const u8,
    signing_root_ptr: *const u8,
) -> i32 {
    if pubkeys_ptr.is_null() || sig_ptr.is_null() || signing_root_ptr.is_null() {
        return -6;
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


#[cfg(test)]
mod tests {
    use super::*;

    /// Audit H-5 (#14): null pointer in any input must return -6, not UB.
    #[test]
    fn null_pointers_return_minus_six() {
        let pks: [u8; 48] = [0; 48];
        let sig: [u8; 96] = [0; 96];
        let root: [u8; 32] = [0; 32];

        unsafe {
            assert_eq!(
                verify_sync_committee(std::ptr::null(), 48, sig.as_ptr(), root.as_ptr()),
                -6
            );
            assert_eq!(
                verify_sync_committee(pks.as_ptr(), 48, std::ptr::null(), root.as_ptr()),
                -6
            );
            assert_eq!(
                verify_sync_committee(pks.as_ptr(), 48, sig.as_ptr(), std::ptr::null()),
                -6
            );
        }
    }
}
