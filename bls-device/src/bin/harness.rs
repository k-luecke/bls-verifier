//! Operator binary: stdin-JSON wrapper around `bls_device::Device::verify`.
//!
//! Spawned by paxiom's `services/sync-committee/dispatch.mjs` when the
//! service is run with `BLS_DEVICE_VIA_SUBPROCESS=1`. Invocation contract
//! (matches `dispatch.mjs::harnessDispatch`):
//!
//!   bls-device-harness --json
//!     stdin:  JSON `VerifyRequest`
//!     stdout: JSON `VerifyResponse` (single line, no trailing data)
//!     exit:   0 on Ok, 1 on Err (error message on stderr)
//!
//! Tracing logs from the device go to stderr so stdout stays a clean JSON
//! channel for the parent process.
//!
//! Environment overrides:
//!   BLS_DEVICE_BEACON_LODESTAR  default https://lodestar-mainnet.chainsafe.io
//!   BLS_DEVICE_BEACON_NIMBUS    default empty (disabled) — set to a known-good
//!                               public Nimbus endpoint to add to the trio
//!   BLS_DEVICE_BEACON_PRYSM     default empty (disabled) — set to a known-good
//!                               public Prysm endpoint to add to the trio
//!   BLS_DEVICE_CACHE_PATH       default $XDG_CACHE_HOME/bls-device-harness/committees.sqlite
//!                               (or $HOME/.cache/... if XDG_CACHE_HOME unset)
//!   BLS_DEVICE_PLATFORM_KEY_ID  default "bls-device-harness-v0.1"
//!
//! Defaults are conservative because (a) public Nimbus/Prysm endpoints vary
//! in archive depth and the historical-slot story isn't uniform across
//! providers, and (b) the harness should "just work" out of the box. Operators
//! who want the planned trio can set the env vars from the runbook.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use bls_device::{
    beacon::default_mainnet_pool, AoLogger, CommitteeCache, Device, DeviceError, MockAo, MockX402,
    NativePrimitive, Primitive, SqliteCommitteeCache, VerifyRequest, VerifyResponse, X402Verifier,
    MAINNET_GENESIS_VALIDATORS_ROOT,
};

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    if let Err(e) = parse_args() {
        eprintln!("usage: bls-device-harness --json   (reads VerifyRequest JSON from stdin)\n{e}");
        return ExitCode::from(2);
    }

    let req = match read_request() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bls-device-harness: read request failed: {e}");
            return ExitCode::from(1);
        }
    };

    let device = match build_device() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("bls-device-harness: build device failed: {e}");
            return ExitCode::from(1);
        }
    };

    match device.verify(req, None).await {
        Ok(resp) => {
            if let Err(e) = write_response(&resp) {
                eprintln!("bls-device-harness: write response failed: {e}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bls-device-harness: device.verify failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn parse_args() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--json") => Ok(()),
        Some("-h") | Some("--help") => Err("--help".into()),
        Some(other) => Err(format!("unknown arg: {other}")),
        None => Err("missing --json".into()),
    }
}

fn read_request() -> Result<VerifyRequest, DeviceError> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let req: VerifyRequest = serde_json::from_str(&buf)?;
    Ok(req)
}

fn write_response(resp: &VerifyResponse) -> Result<(), DeviceError> {
    let line = serde_json::to_string(resp)?;
    println!("{line}");
    Ok(())
}

fn build_device() -> Result<Device, DeviceError> {
    let endpoints = beacon_endpoints();
    let pool = Arc::new(default_mainnet_pool(&endpoints));

    let cache_path = cache_path();
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cache: Arc<dyn CommitteeCache> = Arc::new(SqliteCommitteeCache::open(&cache_path)?);

    let primitive: Arc<dyn Primitive> = Arc::new(NativePrimitive);
    let x402: Arc<dyn X402Verifier> = Arc::new(MockX402);
    let ao: Arc<dyn AoLogger> = Arc::new(MockAo);

    let key_id = std::env::var("BLS_DEVICE_PLATFORM_KEY_ID")
        .unwrap_or_else(|_| "bls-device-harness-v0.1".to_string());

    Ok(Device::new(
        pool,
        cache,
        primitive,
        x402,
        ao,
        MAINNET_GENESIS_VALIDATORS_ROOT,
        key_id,
    ))
}

fn beacon_endpoints() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (label, var, default) in [
        (
            "lodestar",
            "BLS_DEVICE_BEACON_LODESTAR",
            "https://lodestar-mainnet.chainsafe.io",
        ),
        ("nimbus", "BLS_DEVICE_BEACON_NIMBUS", ""),
        ("prysm", "BLS_DEVICE_BEACON_PRYSM", ""),
    ] {
        let url = std::env::var(var).unwrap_or_else(|_| default.to_string());
        if !url.is_empty() {
            out.push((label.to_string(), url));
        }
    }
    out
}

fn cache_path() -> PathBuf {
    if let Ok(p) = std::env::var("BLS_DEVICE_CACHE_PATH") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    base.join("bls-device-harness").join("committees.sqlite")
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("BLS_DEVICE_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}
