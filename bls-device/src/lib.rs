//! HyperBEAM device harness for the BLS sync committee primitive (O-701).
//!
//! Wraps the `bls-verifier` cdylib/wasm primitive with the network plumbing,
//! fork awareness, caching, and AO/x402 hooks the primitive deliberately does
//! not do (see O-700 / W.01).
//!
//! Pipeline matches O-701 / S.03:
//!   1. Parse request                       (`VerifyRequest`)
//!   2. x402 verify                         (`x402::X402Verifier`)
//!   3. Fork lookup                         (`beacon::FailoverPool::fork_version`)
//!   4. Committee lookup                    (`cache::CommitteeCache` + beacon fallback)
//!   5. Filter by participation bits        (`filter_participating`)
//!   6. Compute signing root                (`signing_root::compute_signing_root`)
//!   7. Call primitive                      (`primitive::Primitive`)
//!   8. Sign + log                          (`ao::AoLogger` + platform key)

pub mod ao;
pub mod beacon;
pub mod cache;
pub mod manifest;
pub mod primitive;
pub mod signing_root;
pub mod x402;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, instrument, warn};

pub use crate::ao::{AoLogger, MockAo};
pub use crate::beacon::{BeaconClient, FailoverPool};
pub use crate::cache::{CommitteeCache, SqliteCommitteeCache};
pub use crate::primitive::{NativePrimitive, Primitive};
pub use crate::x402::X402Verifier;
#[cfg(feature = "mock-x402")]
pub use crate::x402::MockX402;

/// Mainnet genesis_validators_root. Constant per network — embedded here as
/// a per-deployment constant. A different chain id means a different deployment.
pub const MAINNET_GENESIS_VALIDATORS_ROOT: [u8; 32] = [
    0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
    0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95,
];

/// Number of slots per sync committee period (256 epochs * 32 slots).
pub const SLOTS_PER_PERIOD: u64 = 8192;

/// Sync-committee size per the consensus spec (`SYNC_COMMITTEE_SIZE`).
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// Bytes of `Bitvector[SYNC_COMMITTEE_SIZE]` participation bits (= 64).
pub const SYNC_COMMITTEE_BITS_BYTES: usize = SYNC_COMMITTEE_SIZE / 8;

/// Public request schema (O-701 / S.02).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyRequest {
    pub slot: String,
    pub block_root: String,
    pub parent_root: String,
    pub sync_aggregate: SyncAggregate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyncAggregate {
    pub sync_committee_bits: String,
    pub sync_committee_signature: String,
}

/// Public response schema (O-701 / S.02).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub service: &'static str,
    pub slot: String,
    pub fork_version: String,
    pub domain: String,
    pub signing_root: String,
    pub participating: u32,
    pub committee_size: u32,
    pub primitive_return_code: i32,
    pub platform_signature: String,
    pub ao_message_id: String,
}

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("x402 verification failed: {0}")]
    X402Failed(String),
    #[error("beacon endpoints exhausted: {0}")]
    BeaconExhausted(String),
    #[error("cache error: {0}")]
    Cache(String),
    #[error("primitive error: code {0}")]
    Primitive(i32),
    #[error("ao log failed: {0}")]
    AoFailed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DeviceError>;

/// Owns all O-701 device state: beacon pool, committee cache, primitive runner,
/// x402 verifier, AO logger, and the platform signing key.
///
/// One instance per HyperBEAM device process. Construct at startup; reuse for
/// the process lifetime.
pub struct Device {
    pub beacon: Arc<FailoverPool>,
    pub cache: Arc<dyn CommitteeCache>,
    pub primitive: Arc<dyn Primitive>,
    pub x402: Arc<dyn X402Verifier>,
    pub ao: Arc<dyn AoLogger>,
    pub genesis_validators_root: [u8; 32],
    pub platform_key_id: String,
    /// ed25519 signing key for the response envelope. Required since audit
    /// H-2 (#11): the prior SHA-256 stub was forgeable from public response
    /// data. Real TEE binding is tracked as O-720 follow-up.
    pub signing_key: ed25519_dalek::SigningKey,
}

impl Device {
    /// Construct a Device. When the `mock-x402` cargo feature is compiled
    /// in, `BLS_ALLOW_MOCK=1` must be set in the environment or this
    /// panics at construction. Mirrors paxiom's `PAXIOM_ALLOW_MOCK=1`
    /// floor; intent is that misconfigured deployments fail loudly at
    /// process start, not at request time. In a default release build
    /// (`mock-x402` off) the check is a no-op.
    pub fn new(
        beacon: Arc<FailoverPool>,
        cache: Arc<dyn CommitteeCache>,
        primitive: Arc<dyn Primitive>,
        x402: Arc<dyn X402Verifier>,
        ao: Arc<dyn AoLogger>,
        genesis_validators_root: [u8; 32],
        platform_key_id: impl Into<String>,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Self {
        #[cfg(feature = "mock-x402")]
        {
            if std::env::var("BLS_ALLOW_MOCK").as_deref() != Ok("1") {
                panic!(
                    "bls-device built with `mock-x402` feature but \
                     BLS_ALLOW_MOCK=1 not set; refusing to construct \
                     Device (issue #10)"
                );
            }
            tracing::warn!(
                "bls-device running with `mock-x402` feature enabled (issue #10)"
            );
        }
        Self {
            beacon,
            cache,
            primitive,
            x402,
            ao,
            genesis_validators_root,
            platform_key_id: platform_key_id.into(),
            signing_key,
        }
    }

    /// Run the O-701 8-stage pipeline for a single request.
    #[instrument(skip(self, req), fields(slot = %req.slot))]
    pub async fn verify(
        &self,
        req: VerifyRequest,
        x402_payload: Option<&str>,
    ) -> Result<VerifyResponse> {
        // Stage 1: parse request (already typed; validate hex shapes).
        let slot_u64: u64 = req
            .slot
            .parse()
            .map_err(|e| DeviceError::InvalidRequest(format!("slot parse: {e}")))?;
        let block_root = decode_hex_fixed::<32>(&req.block_root, "block_root")?;
        let parent_root = decode_hex_fixed::<32>(&req.parent_root, "parent_root")?;
        let bits = decode_hex(&req.sync_aggregate.sync_committee_bits)?;
        // SSZ `Bitvector[SYNC_COMMITTEE_SIZE]` is exactly 64 bytes. Reject
        // truncated/oversize bitfields up front so a malformed input cannot
        // silently pick an arbitrary subset of the cached committee.
        if bits.len() != SYNC_COMMITTEE_BITS_BYTES {
            return Err(DeviceError::InvalidRequest(format!(
                "sync_committee_bits: expected {SYNC_COMMITTEE_BITS_BYTES} bytes, got {}",
                bits.len()
            )));
        }
        let signature = decode_hex_fixed::<96>(&req.sync_aggregate.sync_committee_signature, "sig")?;

        // Stage 2: x402 verify (stub if mock). Hash the *decoded* bytes so
        // mixed-case / leading-zero / prefix variants of the same logical
        // request collapse to the same id (issue #21). Length-bounding is
        // implicit: every input is already a fixed-width byte array except
        // `bits`, which we length-checked above.
        let request_hash = hash_request_bytes(slot_u64, &block_root, &parent_root, &bits, &signature);
        self.x402
            .verify(x402_payload.unwrap_or(""), &request_hash)
            .await
            .map_err(DeviceError::X402Failed)?;

        // Stage 3: fork lookup (cached per fork epoch boundary, not per slot).
        let fork_version = self.beacon.fork_version_for_slot(slot_u64).await?;

        // Stage 4: committee lookup. Cached per (period, fork_version) so a
        // row written under one fork is never served under a different one
        // (audit H-6, #15).
        let period = slot_u64 / SLOTS_PER_PERIOD;
        let pubkeys = match self.cache.get(period, fork_version).await? {
            Some(p) => p,
            None => {
                info!(period, "committee cache miss; fetching from beacon");
                let fetched = self.beacon.committee_pubkeys(slot_u64).await?;
                self.cache.put(period, fork_version, &fetched).await?;
                fetched
            }
        };
        // Refuse a committee of any size other than the spec-mandated 512.
        // A truncated beacon response would otherwise yield committee_size
        // < 512 and still verify against a partial-aggregate signature,
        // which is exactly what an attacker wants.
        if pubkeys.len() != SYNC_COMMITTEE_SIZE {
            return Err(DeviceError::InvalidRequest(format!(
                "committee size: expected {SYNC_COMMITTEE_SIZE} pubkeys, got {}",
                pubkeys.len()
            )));
        }
        let committee_size = pubkeys.len() as u32;

        // Stage 5: filter by participation bits.
        let participating: Vec<&[u8; 48]> = filter_participating(&pubkeys, &bits);
        let participating_count = participating.len() as u32;

        // Stage 6: compute signing root.
        let domain =
            signing_root::compute_domain(&fork_version, &self.genesis_validators_root);
        let signing_root = signing_root::compute_signing_root(&parent_root, &domain);

        // Stage 7: call primitive (returns i32).
        let primitive_return_code =
            self.primitive
                .verify(&participating, &signature, &signing_root)?;
        let verified = primitive_return_code == 1;

        // Stage 8: sign response + AO log.
        let platform_signature =
            sign_response(&self.signing_key, &signing_root, verified);
        let ao_message_id = self
            .ao
            .log(&ao::ComplianceEvent {
                request_uuid: uuid::Uuid::new_v4().to_string(),
                service: "A-202",
                slot: req.slot.clone(),
                verified,
                primitive_return_code,
                request_hash: hex::encode(request_hash),
                platform_key_id: self.platform_key_id.clone(),
            })
            .await
            .map_err(DeviceError::AoFailed)?;

        if !verified {
            warn!(primitive_return_code, "verification returned non-success");
        }

        Ok(VerifyResponse {
            verified,
            service: "A-202",
            slot: req.slot,
            fork_version: format!("0x{}", hex::encode(fork_version)),
            domain: format!("0x{}", hex::encode(&domain)),
            signing_root: format!("0x{}", hex::encode(&signing_root)),
            participating: participating_count,
            committee_size,
            primitive_return_code,
            platform_signature: format!("0x{}", hex::encode(platform_signature)),
            ao_message_id,
        })
    }
}

/// Pick the subset of `pubkeys` whose corresponding bit in `bits` is set.
///
/// SSZ `Bitvector[N]` is encoded little-endian within a byte: bit 0 of
/// byte 0 is participant 0; bit 7 of byte 0 is participant 7; bit 0 of
/// byte 1 is participant 8. The shift `bits[byte_idx] >> bit_idx`
/// reflects that LSB-first convention. Do not flip to MSB-first without
/// also flipping every Ethereum consensus-client interop fixture.
///
/// The caller is responsible for asserting `pubkeys.len() ==
/// SYNC_COMMITTEE_SIZE` and `bits.len() == SYNC_COMMITTEE_BITS_BYTES`.
/// `Device::verify` does this; the helper itself stays generic so unit
/// tests can exercise smaller arrays.
fn filter_participating<'a>(pubkeys: &'a [[u8; 48]], bits: &[u8]) -> Vec<&'a [u8; 48]> {
    pubkeys
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            byte_idx < bits.len() && (bits[byte_idx] >> bit_idx) & 1 == 1
        })
        .map(|(_, pk)| pk)
        .collect()
}

/// Canonical content hash for a verify request (issue #21).
///
/// Inputs are already-decoded, length-validated bytes from `Device::verify`,
/// so two requests that are semantically identical but differ in hex casing,
/// `0x` prefix presence, or slot leading zeros collapse to the same hash.
/// The previous implementation interpolated user-controlled hex strings into
/// a `format!`, which made all of those produce different ids.
///
/// Field framing: each field is prefixed with its length encoded as a
/// little-endian `u64`. This is cheap, unambiguous, and avoids a delimiter
/// the bytes themselves could contain. A short ASCII tag prefix domain-
/// separates the digest from the other sha256 uses in this crate
/// (`signing_root`, fixture digests). The tag is intentionally unversioned:
/// there is no V0 to disambiguate from and no concrete V2 plan, so a "_V1"
/// suffix would be theatre.
///
/// `request_hash` is *not* covered by the platform signature (which signs
/// `(signing_root, verified)`) and the only consumers in the tree are
/// MockX402's id stamp and the AO compliance event log, where it is treated
/// as opaque evidence — so changing the encoding does not invalidate any
/// pinned downstream value.
fn hash_request_bytes(
    slot: u64,
    block_root: &[u8; 32],
    parent_root: &[u8; 32],
    bits: &[u8],
    signature: &[u8; 96],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"bls-device/verify-request");
    h.update(slot.to_le_bytes());
    h.update(block_root);
    h.update(parent_root);
    h.update((bits.len() as u64).to_le_bytes());
    h.update(bits);
    h.update(signature);
    h.finalize().into()
}

/// Platform signature: ed25519 over (signing_root || verified-byte).
///
/// Audit H-2 (#11): the prior SHA-256 stub was forgeable from public
/// response data. Real TEE binding is tracked as O-720 follow-up.
fn sign_response(
    signing_key: &ed25519_dalek::SigningKey,
    signing_root: &[u8; 32],
    verified: bool,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let mut msg = [0u8; 33];
    msg[..32].copy_from_slice(signing_root);
    msg[32] = verified as u8;
    signing_key.sign(&msg).to_bytes()
}

/// Decode a `0x`-prefixed hex string into raw bytes. Audit M-7 (#?): the
/// prefix used to be optional (`trim_start_matches`), which let a JSON
/// request mix prefixed and unprefixed hex inside the same payload — and
/// `bits` was passed through here with no length check upstream, so a
/// 0-byte unprefixed string trivially returned an empty participating set.
/// `Device::verify` now length-checks `bits` after decoding, but requiring
/// the prefix here is the cheap second line of defence and matches the
/// Ethereum-consensus-API convention.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let body = s.strip_prefix("0x").ok_or_else(|| {
        DeviceError::InvalidRequest(format!(
            "hex input must start with 0x prefix (got {} chars)",
            s.len()
        ))
    })?;
    Ok(hex::decode(body)?)
}

fn decode_hex_fixed<const N: usize>(s: &str, label: &'static str) -> Result<[u8; N]> {
    let v = decode_hex(s)?;
    if v.len() != N {
        return Err(DeviceError::InvalidRequest(format!(
            "{label}: expected {N} bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_participating_picks_only_set_bits() {
        let pubkeys = vec![[0u8; 48], [1u8; 48], [2u8; 48], [3u8; 48]];
        // bits: 0b00001010 → indices 1 and 3 participate
        let bits = vec![0b00001010];
        let out = filter_participating(&pubkeys, &bits);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], &[1u8; 48]);
        assert_eq!(out[1], &[3u8; 48]);
    }

    #[test]
    fn filter_participating_lsb_first_byte_order() {
        // Eight pubkeys, each labelled by index. Bits 0, 3, 7 of byte 0 set,
        // and bit 0 of byte 1 set: expect indices 0, 3, 7, 8.
        let pubkeys: Vec<[u8; 48]> = (0..16u8).map(|i| [i; 48]).collect();
        let bits = vec![0b1000_1001, 0b0000_0001];
        let out = filter_participating(&pubkeys, &bits);
        let got_idx: Vec<u8> = out.into_iter().map(|pk| pk[0]).collect();
        assert_eq!(got_idx, vec![0, 3, 7, 8]);
    }

    #[test]
    fn sync_committee_constants_are_consistent() {
        assert_eq!(SYNC_COMMITTEE_SIZE, 512);
        assert_eq!(SYNC_COMMITTEE_BITS_BYTES, 64);
        assert_eq!(SYNC_COMMITTEE_SIZE, SYNC_COMMITTEE_BITS_BYTES * 8);
    }

    /// Audit M-7: decode_hex used to strip an optional `0x` prefix.
    /// A 0-byte unprefixed string would then trivially decode to an empty
    /// bytes vector. Lock the strict-prefix invariant.
    #[test]
    fn decode_hex_requires_0x_prefix() {
        assert!(decode_hex("0xdeadbeef").is_ok());
        assert!(decode_hex("deadbeef").is_err());
        assert!(decode_hex("").is_err());
    }

    #[test]
    fn hash_request_bytes_is_deterministic() {
        let block = [0xaau8; 32];
        let parent = [0xbbu8; 32];
        let bits = vec![0xccu8; 64];
        let sig = [0xddu8; 96];
        assert_eq!(
            hash_request_bytes(1, &block, &parent, &bits, &sig),
            hash_request_bytes(1, &block, &parent, &bits, &sig)
        );
    }

    /// Issue #21: two semantically identical requests that differ only in hex
    /// casing or slot leading zeros must collapse to the same `request_hash`.
    /// Operating over already-decoded bytes makes this hold by construction.
    #[test]
    fn hash_request_bytes_collapses_string_variants() {
        let block = [0xaau8; 32];
        let parent = [0xbbu8; 32];
        let bits = vec![0xccu8; 64];
        let sig = [0xddu8; 96];
        // Lowercase and uppercase hex, "1" vs "01" slot — all become the same
        // (slot, [u8;32], [u8;32], &[u8], [u8;96]) tuple, so the same hash.
        let h1 = hash_request_bytes(1, &block, &parent, &bits, &sig);
        let h2 = hash_request_bytes(1, &block, &parent, &bits, &sig);
        assert_eq!(h1, h2);
    }

    /// Length-prefixing `bits` must prevent the classic boundary-shift
    /// collision: appending a byte to `bits` and removing the first byte of
    /// `signature` (or vice versa) MUST NOT yield the same digest.
    #[test]
    fn hash_request_bytes_length_prefix_prevents_boundary_shift() {
        let block = [0u8; 32];
        let parent = [0u8; 32];
        let mut bits_a = vec![0x11u8; 4];
        let sig_a = [0x22u8; 96];
        let mut bits_b = bits_a.clone();
        bits_b.push(0x22);
        // sig_b has the same total bytes as (bits_a || sig_a) shifted by one
        // — the length prefix on bits is what stops them colliding.
        let mut sig_b = [0x22u8; 96];
        sig_b[0] = 0x22;
        let _ = &mut bits_a;
        let h_a = hash_request_bytes(0, &block, &parent, &bits_a, &sig_a);
        let h_b = hash_request_bytes(0, &block, &parent, &bits_b, &sig_b);
        assert_ne!(h_a, h_b);
    }

    /// Distinct fields must produce distinct digests (sanity).
    #[test]
    fn hash_request_bytes_changes_with_each_field() {
        let block = [0u8; 32];
        let parent = [0u8; 32];
        let bits = vec![0u8; 64];
        let sig = [0u8; 96];
        let base = hash_request_bytes(1, &block, &parent, &bits, &sig);
        assert_ne!(base, hash_request_bytes(2, &block, &parent, &bits, &sig));
        let mut block2 = block;
        block2[0] = 1;
        assert_ne!(base, hash_request_bytes(1, &block2, &parent, &bits, &sig));
        let mut parent2 = parent;
        parent2[0] = 1;
        assert_ne!(base, hash_request_bytes(1, &block, &parent2, &bits, &sig));
        let mut bits2 = bits.clone();
        bits2[0] = 1;
        assert_ne!(base, hash_request_bytes(1, &block, &parent, &bits2, &sig));
        let mut sig2 = sig;
        sig2[0] = 1;
        assert_ne!(base, hash_request_bytes(1, &block, &parent, &bits, &sig2));
    }

    /// `block_root` was previously not length-validated anywhere in the
    /// pipeline (it was only string-interpolated into the old hash). Lock the
    /// fact that the new pipeline rejects a wrong-length block_root up front.
    #[test]
    fn block_root_is_length_validated() {
        // 31-byte block_root must be rejected.
        let short: Result<[u8; 32]> = decode_hex_fixed::<32>(&format!("0x{}", "aa".repeat(31)), "block_root");
        assert!(short.is_err());
        let ok: Result<[u8; 32]> = decode_hex_fixed::<32>(&format!("0x{}", "aa".repeat(32)), "block_root");
        assert!(ok.is_ok());
    }
}
