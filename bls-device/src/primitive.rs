//! O-701 / S.07 — primitive call.
//!
//! Two adapters: native (link to `libbls_verifier.so` cdylib via blst directly)
//! and wasm (load `bls_verifier.wasm` and invoke through wasmtime). For Phase 0
//! we ship only the native adapter — the harness can run alongside HyperBEAM
//! in-process, and the wasm adapter is filed as a follow-up once HyperBEAM's
//! device hosting interface is locked.

use crate::Result;
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;

pub trait Primitive: Send + Sync {
    /// Return code matches O-700 contract:
    ///   1 = valid signature
    ///   0 = invalid signature
    ///  -1 = signature parse failure
    ///  -2 = pubkey parse failure
    ///  -3 = aggregation failure
    ///  -4 = signing root is not 32 bytes
    fn verify(
        &self,
        participating: &[&[u8; 48]],
        signature: &[u8; 96],
        signing_root: &[u8; 32],
    ) -> Result<i32>;
}

/// Native adapter — links blst directly. Same code path as the cdylib's
/// `verify_sync_committee` C-FFI function.
pub struct NativePrimitive;

impl Primitive for NativePrimitive {
    fn verify(
        &self,
        participating: &[&[u8; 48]],
        signature: &[u8; 96],
        signing_root: &[u8; 32],
    ) -> Result<i32> {
        if participating.is_empty() {
            return Ok(-3);
        }
        let pks: Vec<PublicKey> = participating
            .iter()
            .filter_map(|pk| PublicKey::from_bytes(*pk).ok())
            .collect();
        if pks.len() != participating.len() {
            return Ok(-2);
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

/// Catches the trivial failure modes the trait contract calls out so callers
/// can map them to error JSON without re-implementing the taxonomy.
pub fn return_code_to_error_label(code: i32) -> Option<&'static str> {
    match code {
        1 | 0 => None,
        -1 => Some("SignatureParseFailure"),
        -2 => Some("PubkeyParseFailure"),
        -3 => Some("AggregationFailed"),
        -4 => Some("InvalidSigningRoot"),
        _ => Some("UnknownPrimitiveError"),
    }
}
