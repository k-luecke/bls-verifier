//! Live integration test against real Lodestar mainnet.
//!
//! Gated on `BLS_DEVICE_LIVE=1` so CI never hits the network. Operators run
//! this as the proof of the S.02 gate (see paxiom-static phase-0-status).

use bls_device::{
    ao::MockAo,
    beacon::default_mainnet_pool,
    cache::SqliteCommitteeCache,
    primitive::NativePrimitive,
    x402::MockX402,
    Device, MAINNET_GENESIS_VALIDATORS_ROOT, SyncAggregate, VerifyRequest,
};
use std::sync::Arc;

#[tokio::test]
async fn live_lodestar_verifies_current_head() {
    if std::env::var("BLS_DEVICE_LIVE").ok().as_deref() != Some("1") {
        eprintln!("BLS_DEVICE_LIVE not set; skipping live test");
        return;
    }
    std::env::set_var("BLS_ALLOW_MOCK", "1");

    let endpoints = vec![(
        "lodestar".to_string(),
        "https://lodestar-mainnet.chainsafe.io".to_string(),
    )];
    let pool = Arc::new(default_mainnet_pool(&endpoints).expect("default_mainnet_pool"));
    let cache = Arc::new(SqliteCommitteeCache::open_in_memory().unwrap());

    // Fetch current head to build a request.
    let http = reqwest::Client::new();
    let head: serde_json::Value = http
        .get("https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/headers/head")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slot = head["data"]["header"]["message"]["slot"].as_str().unwrap().to_string();
    let block: serde_json::Value = http
        .get(format!(
            "https://lodestar-mainnet.chainsafe.io/eth/v2/beacon/blocks/{slot}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let req = VerifyRequest {
        slot: slot.clone(),
        block_root: head["data"]["root"].as_str().unwrap().into(),
        parent_root: block["data"]["message"]["parent_root"].as_str().unwrap().into(),
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
    };

    let device = Device::new(
        pool,
        cache,
        Arc::new(NativePrimitive),
        Arc::new(MockX402),
        Arc::new(MockAo),
        MAINNET_GENESIS_VALIDATORS_ROOT,
        "live-test-key",
    );

    let resp = device.verify(req, None).await.expect("device.verify");
    assert!(resp.verified, "live mainnet head should verify; got {resp:?}");
}
