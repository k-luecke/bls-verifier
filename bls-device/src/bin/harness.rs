//! `bls-device-harness` — operator CLI wrapping `bls_device::Device::verify`.
//!
//! Reads a `VerifyRequest` JSON object from stdin, runs the eight-stage
//! O-701 pipeline against a real beacon endpoint, prints the
//! `VerifyResponse` JSON to stdout.
//!
//! Used by paxiom's `services/sync-committee/dispatch.mjs` when run with
//! `BLS_DEVICE_VIA_SUBPROCESS=1` — i.e. the operator-side S.02 dispatch
//! path that doesn't require HyperBEAM to be up. Also useful for ad-hoc
//! verification: pipe a JSON request in, get a verified response out.
//!
//! Configuration via env (all optional, sensible defaults for mainnet):
//!   BLS_DEVICE_BEACON_URL    — single beacon endpoint (default: Lodestar mainnet)
//!   BLS_DEVICE_CACHE_PATH    — sqlite cache file (default: in-memory; ephemeral
//!                              per invocation, fine for one-off verifies)
//!   BLS_DEVICE_KEY_ID        — platform key id stamped into the response
//!                              (default: "harness-key-1")
//!
//! Mainnet `genesis_validators_root` is compiled in (per O-701: a different
//! chain id means a different deployment).
//!
//! Exit codes:
//!   0  — JSON response printed to stdout (verified=true OR verified=false
//!        with structured fields explaining why; this is the normal path)
//!   1  — request parse failure (malformed stdin); error JSON to stderr
//!   2  — pipeline error (beacon exhausted, primitive failure, etc.); error
//!        JSON to stderr

use std::sync::Arc;

use bls_device::{
    ao::MockAo,
    beacon::default_mainnet_pool,
    cache::SqliteCommitteeCache,
    primitive::NativePrimitive,
    x402::MockX402,
    Device, VerifyRequest, MAINNET_GENESIS_VALIDATORS_ROOT,
};

#[tokio::main]
async fn main() {
    if let Err((code, body)) = run().await {
        eprintln!("{}", body);
        std::process::exit(code);
    }
}

async fn run() -> Result<(), (i32, String)> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| (1, error_json("stdin read failed", &e.to_string())))?;

    let req: VerifyRequest = serde_json::from_str(&input)
        .map_err(|e| (1, error_json("request parse failed", &e.to_string())))?;

    let beacon_url = std::env::var("BLS_DEVICE_BEACON_URL")
        .unwrap_or_else(|_| "https://lodestar-mainnet.chainsafe.io".into());
    let key_id = std::env::var("BLS_DEVICE_KEY_ID").unwrap_or_else(|_| "harness-key-1".into());
    let cache = match std::env::var("BLS_DEVICE_CACHE_PATH").ok() {
        Some(path) => SqliteCommitteeCache::open(path),
        None => SqliteCommitteeCache::open_in_memory(),
    }
    .map_err(|e| (2, error_json("cache init failed", &e.to_string())))?;

    let pool = Arc::new(default_mainnet_pool(&[("operator-supplied".into(), beacon_url)]));
    let device = Device::new(
        pool,
        Arc::new(cache),
        Arc::new(NativePrimitive),
        Arc::new(MockX402),
        Arc::new(MockAo),
        MAINNET_GENESIS_VALIDATORS_ROOT,
        key_id,
    );

    let resp = device
        .verify(req, None)
        .await
        .map_err(|e| (2, error_json("device.verify failed", &e.to_string())))?;

    let json = serde_json::to_string_pretty(&resp)
        .map_err(|e| (2, error_json("response serialize failed", &e.to_string())))?;
    println!("{}", json);
    Ok(())
}

fn error_json(msg: &str, detail: &str) -> String {
    serde_json::json!({
        "error": msg,
        "detail": detail,
        "verified": false,
    })
    .to_string()
}
