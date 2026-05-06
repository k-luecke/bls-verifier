//! Fixture-driven integration test for the O-701 device pipeline.
//!
//! Uses a `FixtureBeacon` that reads canned beacon responses from
//! `fixtures/beacon/` instead of the network. This is the CI gate.
//!
//! Acceptance: the pipeline runs all eight stages end-to-end without panicking,
//! returns a `VerifyResponse` whose shape matches O-701 / S.02, and exercises
//! the cache miss path on first call and the cache hit path on second call.
//!
//! Note: this test does not assert `verified == true` because the canned
//! signature in the fixture is a placeholder. A live test against Lodestar
//! is gated behind `BLS_DEVICE_LIVE=1` (see `integration_live.rs`).

use async_trait::async_trait;
use bls_device::{
    ao::MockAo,
    beacon::{BeaconClient, FailoverPool},
    cache::SqliteCommitteeCache,
    primitive::NativePrimitive,
    x402::MockX402,
    Device, DeviceError, MAINNET_GENESIS_VALIDATORS_ROOT, SyncAggregate, VerifyRequest,
};
use std::path::PathBuf;
use std::sync::Arc;

struct FixtureBeacon {
    fixture_dir: PathBuf,
    fixture_slot: u64,
}

impl FixtureBeacon {
    fn new(fixture_dir: PathBuf, fixture_slot: u64) -> Self {
        Self { fixture_dir, fixture_slot }
    }
}

#[async_trait]
impl BeaconClient for FixtureBeacon {
    async fn fork_version_for_slot(&self, _slot: u64) -> Result<[u8; 4], DeviceError> {
        let path = self.fixture_dir.join(format!("fork_{}.json", self.fixture_slot));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let s = v["data"]["current_version"].as_str().unwrap();
        let bytes = hex::decode(s.trim_start_matches("0x"))?;
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    async fn committee_pubkeys(&self, _slot: u64) -> Result<Vec<[u8; 48]>, DeviceError> {
        let mut out = Vec::new();
        let mut n = 0;
        loop {
            let path = self
                .fixture_dir
                .join(format!("validators_chunk_{}.json", n));
            if !path.exists() {
                break;
            }
            let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            if let Some(validators) = v["data"].as_array() {
                for v in validators {
                    if let Some(s) = v["validator"]["pubkey"].as_str() {
                        let bytes = hex::decode(s.trim_start_matches("0x"))?;
                        if bytes.len() == 48 {
                            let mut pk = [0u8; 48];
                            pk.copy_from_slice(&bytes);
                            out.push(pk);
                        }
                    }
                }
            }
            n += 1;
        }
        Ok(out)
    }
}

fn fixture_request(fixture_dir: &PathBuf, slot: u64) -> VerifyRequest {
    let block: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_dir.join(format!("block_{slot}.json"))).unwrap()).unwrap();
    let header: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_dir.join("header_head.json")).unwrap()).unwrap();
    VerifyRequest {
        slot: slot.to_string(),
        block_root: header["data"]["root"].as_str().unwrap().into(),
        parent_root: block["data"]["message"]["parent_root"]
            .as_str()
            .unwrap()
            .into(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: block["data"]["message"]["body"]["sync_aggregate"]
                ["sync_committee_bits"]
                .as_str()
                .unwrap()
                .into(),
            sync_committee_signature: block["data"]["message"]["body"]["sync_aggregate"]
                ["sync_committee_signature"]
                .as_str()
                .unwrap()
                .into(),
        },
    }
}

fn fixture_slot(fixture_dir: &PathBuf) -> u64 {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_dir.join("MANIFEST.json")).unwrap())
            .unwrap();
    manifest["slot"].as_u64().unwrap()
}

#[tokio::test]
async fn pipeline_runs_end_to_end_against_fixture() {
    std::env::set_var("BLS_ALLOW_MOCK", "1");
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("fixtures/beacon");
    if !fixture_dir.join("MANIFEST.json").exists() {
        eprintln!(
            "fixture not present at {}; skipping. Run record-fixture to capture one.",
            fixture_dir.display()
        );
        return;
    }
    let slot = fixture_slot(&fixture_dir);

    let beacon: Box<dyn BeaconClient> =
        Box::new(FixtureBeacon::new(fixture_dir.clone(), slot));
    let pool = Arc::new(FailoverPool::new(vec![beacon], vec!["fixture".into()]));
    let cache = Arc::new(SqliteCommitteeCache::open_in_memory().unwrap());
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let device = Device::new(
        pool,
        cache.clone(),
        Arc::new(NativePrimitive),
        Arc::new(MockX402),
        Arc::new(MockAo),
        MAINNET_GENESIS_VALIDATORS_ROOT,
        "test-key-1",
        signing_key,
    );

    let req = fixture_request(&fixture_dir, slot);

    // First call exercises the cache miss path.
    let resp1 = device.verify(req.clone(), None).await.unwrap();
    assert_eq!(resp1.service, "A-202");
    assert_eq!(resp1.slot, slot.to_string());
    assert!(resp1.committee_size > 0);
    // ed25519 signature is 64 bytes = 128 hex chars after the "0x" prefix.
    assert!(resp1.platform_signature.starts_with("0x"));
    assert_eq!(resp1.platform_signature.len(), 2 + 128);
    assert!(resp1.ao_message_id.starts_with("mock-ao-"));

    // Second call exercises the cache hit path.
    let resp2 = device.verify(req, None).await.unwrap();
    assert_eq!(resp2.committee_size, resp1.committee_size);
}
