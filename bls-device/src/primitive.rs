//! O-701 / S.07 — primitive call.
//!
//! Two adapters: native (link to `libbls_verifier.so` cdylib via blst directly)
//! and wasm (load `bls_verifier.wasm` and invoke through wasmtime). For Phase 0
//! we ship only the native adapter — the harness can run alongside HyperBEAM
//! in-process, and the wasm adapter is filed as a follow-up once HyperBEAM's
//! device hosting interface is locked.
//!
//! # Two distinct ABIs (audit M-1, #16)
//!
//! There are two return-code taxonomies in this workspace, and they
//! intentionally do **not** match:
//!
//! - **Trait `Primitive::verify` (this file)** — consumed in-process by
//!   `Device::verify`. Its codes flow into `VerifyResponse.primitive_return_code`
//!   on the JSON wire. Type-safe inputs (`&[u8; 32]`, `&[u8; 96]`) make some
//!   cdylib failure modes unrepresentable here, so the trait taxonomy is a
//!   subset, not a copy, of the cdylib's.
//! - **C-FFI `verify_sync_committee` in the `bls-verifier` cdylib** — the
//!   wasm artifact HyperBEAM loads. Its codes are the source of truth for
//!   `manifest.rs` and `bls-verifier/src/lib.rs`. Raw pointers force extra
//!   failure modes (`-6` null) and assign different numbers to the same
//!   conditions (`-2 = no pubkeys`, `-4 = malformed pubkey`).
//!
//! Do not "unify" by renumbering. The cdylib ABI is a published wasm device
//! contract; the trait's H-3 regression test (PR #48) asserts `-2` verbatim;
//! `-5 NoParticipants` was deliberately introduced by M-2 (PR #43) so
//! operators could distinguish "caller passed empty bitfield" from
//! "aggregation failed." Each taxonomy is the source of truth for its own
//! ABI; this module documents the divergence.

use crate::Result;
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;

pub trait Primitive: Send + Sync {
    /// Trait return code (in-process ABI; distinct from the cdylib C-FFI
    /// taxonomy — see module-level doc).
    ///   1 = valid signature
    ///   0 = invalid signature
    ///  -1 = signature parse failure
    ///  -2 = pubkey parse failure (any participating entry not a valid G1 point)
    ///  -3 = aggregation failure
    ///  -5 = empty participating set (caller bug, not a crypto failure)
    ///
    /// Note: there is no `-4` in this ABI. The cdylib uses `-4` for
    /// malformed pubkey, but the type system here (`&[u8; 32]` signing root,
    /// `&[u8; 48]` pubkey slots) makes the wrong-length paths the cdylib
    /// historically labelled `-4` unrepresentable.
    fn verify(
        &self,
        participating: &[&[u8; 48]],
        signature: &[u8; 96],
        signing_root: &[u8; 32],
    ) -> Result<i32>;
}

/// Native adapter — links blst directly. Same crypto path as the cdylib's
/// `verify_sync_committee` C-FFI function, but uses the trait taxonomy
/// (NOT the cdylib taxonomy). See the module-level doc on the deliberate
/// ABI divergence.
pub struct NativePrimitive;

impl Primitive for NativePrimitive {
    fn verify(
        &self,
        participating: &[&[u8; 48]],
        signature: &[u8; 96],
        signing_root: &[u8; 32],
    ) -> Result<i32> {
        if participating.is_empty() {
            // Empty participating set is a caller-side bug (e.g. all-zero
            // bitfield), not a real cryptographic aggregation failure.
            // Return -5 so operators can distinguish the two paths.
            return Ok(-5);
        }
        let mut pks: Vec<PublicKey> = Vec::with_capacity(participating.len());
        for pk in participating {
            match PublicKey::from_bytes(*pk) {
                Ok(parsed) => pks.push(parsed),
                Err(_) => return Ok(-2),
            }
        }
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();
        let agg_pk = match AggregatePublicKey::aggregate(&pk_refs, true) {
            Ok(a) => a.to_public_key(),
            Err(_) => return Ok(-3),
        };
        let sig = match Signature::from_bytes(signature) {
            Ok(s) => s,
            Err(_) => return Ok(-1),
        };
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        match sig.verify(true, signing_root, dst, &[], &agg_pk, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(1),
            _ => Ok(0),
        }
    }
}

/// Maps a trait-ABI return code to a stable error label string. The cdylib
/// ABI has its own labels — see `manifest.rs`. Do not cross the streams.
///
/// `-4` is intentionally absent here: the trait's type-checked inputs
/// rule out the malformed-input path the cdylib uses `-4` for (audit M-1).
pub fn return_code_to_error_label(code: i32) -> Option<&'static str> {
    match code {
        1 | 0 => None,
        -1 => Some("SignatureParseFailure"),
        -2 => Some("PubkeyParseFailure"),
        -3 => Some("AggregationFailed"),
        -5 => Some("NoParticipants"),
        _ => Some("UnknownPrimitiveError"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit H-3 (#12): a malformed pubkey anywhere in `participating` MUST
    /// short-circuit to `Ok(-2)` rather than silently dropping the entry.
    /// Locks the explicit-loop semantics against future refactors.
    #[test]
    fn malformed_pubkey_returns_minus_two() {
        let bad: [u8; 48] = [0xff; 48];
        let participating: Vec<&[u8; 48]> = vec![&bad];
        let signature: [u8; 96] = [0u8; 96];
        let signing_root: [u8; 32] = [0u8; 32];

        let result = NativePrimitive
            .verify(&participating, &signature, &signing_root)
            .expect("verify should not return Err");
        assert_eq!(result, -2, "malformed pubkey must yield -2");
    }

    /// Audit M-1 (#16): trait ABI returns `-5` for empty participating
    /// (distinct from cdylib's `-2`). Lock against accidental "unification"
    /// renumbers — see module-level doc on the two-ABI design.
    #[test]
    fn empty_participating_returns_minus_five() {
        let participating: Vec<&[u8; 48]> = vec![];
        let signature: [u8; 96] = [0u8; 96];
        let signing_root: [u8; 32] = [0u8; 32];

        let result = NativePrimitive
            .verify(&participating, &signature, &signing_root)
            .expect("verify should not return Err");
        assert_eq!(result, -5, "empty participating set must yield -5 (M-2 / PR #43)");
    }

    /// Audit M-1 (#16): `-4` is reserved in the trait ABI — the type system
    /// rules out the cdylib's `-4 = MalformedPubkey` path. Reading `-4` from
    /// a trait `primitive_return_code` is a bug somewhere upstream.
    #[test]
    fn minus_four_is_not_a_trait_label() {
        assert_eq!(
            return_code_to_error_label(-4),
            Some("UnknownPrimitiveError")
        );
    }
}
