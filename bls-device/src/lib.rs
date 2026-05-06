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

        // Stage 2: x402 verify (stub if mock).
        let request_hash = hash_request(&req);
        self.x402
            .verify(x402_payload.unwrap_or(""), &request_hash)
            .await
            .map_err(DeviceError::X402Failed)?;

        // Stage 3: fork lookup (cached per fork epoch boundary, not per slot).
        let fork_version = self.beacon.fork_version_for_slot(slot_u64).await?;

        // Stage 4: committee lookup (cached per period; ~27h refresh).
        let period = slot_u64 / SLOTS_PER_PERIOD;
        let pubkeys = match self.cache.get(period).await? {
            Some(p) => p,
            None => {
                info!(period, "committee cache miss; fetching from beacon");
                let fetched = self.beacon.committee_pubkeys(slot_u64).await?;
                self.cache.put(period, &fetched).await?;
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

fn hash_request(req: &VerifyRequest) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let canonical = format!(
        "{}|{}|{}|{}|{}",
        req.slot,
        req.block_root,
        req.parent_root,
        req.sync_aggregate.sync_committee_bits,
        req.sync_aggregate.sync_committee_signature,
    );
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
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

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.trim_start_matches("0x"))?)
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

    #[test]
    fn hash_request_is_deterministic() {
        let req = VerifyRequest {
            slot: "1".into(),
            block_root: "0xaa".into(),
            parent_root: "0xbb".into(),
            sync_aggregate: SyncAggregate {
                sync_committee_bits: "0xcc".into(),
                sync_committee_signature: "0xdd".into(),
            },
        };
        assert_eq!(hash_request(&req), hash_request(&req));
    }
}
