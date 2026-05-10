//! `bls-device-harness` — operator CLI for paxiom A-202 subprocess dispatch.
//!
//! Reads a `VerifyRequest` JSON object from stdin, runs `Device::verify`
//! against a real beacon, prints exactly one JSON object to stdout
//! containing the underlying `VerifyResponse` fields plus harness-envelope
//! truth fields (`x402_mode`, `settlement_verified`, `key_scope`,
//! `notary_status`, `platform_key_id`, `ao_mode`, `harness_version`).
//!
//! Spawned by paxiom's `services/sync-committee/dispatch.mjs` when the
//! service is run with `BLS_DEVICE_VIA_SUBPROCESS=1`.
//!
//! ## Slice 1A scope (recorded here so consumers can check)
//!
//! - **x402**: shape-only stub or disabled. NO settlement verification of
//!   any kind. `BLS_DEVICE_X402_MODE=disabled` (default) skips the payload
//!   check entirely; `=stub` shape-validates the payload only. Both
//!   harness modes emit `settlement_verified:false`. NO code path here may
//!   claim a payment was settled. Slice 3 follow-up replaces this with a
//!   real Coinbase facilitator client; until then, downstream consumers
//!   MUST treat `verified:true` as a BLS-verification claim only — NOT as
//!   a settled-payment claim.
//! - **signing key**: ephemeral `ed25519_dalek::SigningKey` per invocation
//!   by default; `key_scope:ephemeral-subprocess`,
//!   `notary_status:not-persistent`, `platform_key_id:ephemeral:<hex16>`.
//!   An operator may opt into a persistent key by setting both
//!   `BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM` and
//!   `BLS_DEVICE_RESPONSE_SIGNING_KEY_ID`; setting one without the other
//!   is a hard failure. The harness `platform_signature` is *inner*
//!   evidence — the user-facing trust anchor is paxiom's outer envelope
//!   (`PAXIOM_RESPONSE_SIGNING_PRIVATE_KEY_PEM`). Do NOT call this key
//!   TEE-backed, durable, or production-grade.
//! - **AO**: `MockAo`; `ao_mode:mock`. Punch-list Slice 5 lands the
//!   durable AO/Arweave write.
//!
//! ## Wire contract
//!
//!   bls-device-harness --json
//!     stdin  : single JSON `VerifyRequest`
//!     stdout : single JSON object (one line, no trailing data)
//!     exit 0 : verified=true OR verified=false with structured reason
//!     exit 1 : pipeline failure (request parse, beacon, primitive, x402, ao)
//!     exit 2 : configuration failure (env vars, key parse, etc.)
//!     stderr : tracing logs + structured startup banner + error detail

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use async_trait::async_trait;
use bls_device::{
    beacon::default_mainnet_pool,
    mainnet_genesis_validators_root,
    AoLogger, CommitteeCache, Device, MockAo, NativePrimitive, Primitive,
    SqliteCommitteeCache, VerifyRequest, X402Verifier,
};
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};
use rand::rngs::OsRng;
use serde_json::Value;

const HARNESS_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    if let Err(e) = parse_args() {
        eprintln!(
            "usage: bls-device-harness --json   (reads VerifyRequest JSON from stdin)\n{e}"
        );
        return ExitCode::from(2);
    }

    let req = match read_request() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bls-device-harness: read request failed: {e}");
            return ExitCode::from(1);
        }
    };

    let built = match build_device() {
        Ok(b) => b,
        Err(BuildError::Config(e)) => {
            eprintln!("bls-device-harness: config error: {e}");
            return ExitCode::from(2);
        }
        Err(BuildError::Pipeline(e)) => {
            eprintln!("bls-device-harness: pipeline init error: {e}");
            return ExitCode::from(1);
        }
    };

    tracing::info!(
        platform_key_id = %built.platform_key_id,
        key_scope = %built.key_scope,
        x402_mode = %built.x402_mode_label,
        ao_mode = "mock",
        harness_version = HARNESS_VERSION,
        "bls-device-harness starting verify"
    );

    let x402_payload = built.x402_payload.clone();
    match built.device.verify(req, Some(&x402_payload)).await {
        Ok(resp) => {
            let line = match envelope_response(&resp, &built) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("bls-device-harness: envelope encode failed: {e}");
                    return ExitCode::from(1);
                }
            };
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bls-device-harness: device.verify failed: {e}");
            ExitCode::from(1)
        }
    }
}

enum BuildError {
    Config(String),
    Pipeline(String),
}

struct Built {
    device: Device,
    platform_key_id: String,
    key_scope: &'static str,
    notary_status: &'static str,
    x402_mode_label: &'static str,
    x402_payload: String,
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

fn read_request() -> Result<VerifyRequest, String> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("stdin read: {e}"))?;
    serde_json::from_str(&buf).map_err(|e| format!("VerifyRequest parse: {e}"))
}

fn build_device() -> Result<Built, BuildError> {
    let (x402_impl, x402_mode_label, x402_payload) = build_x402()?;

    let endpoints = beacon_endpoints();
    if endpoints.is_empty() {
        return Err(BuildError::Config(
            "no beacon endpoints configured (set BLS_DEVICE_BEACON_LODESTAR / _NIMBUS / _PRYSM)"
                .to_string(),
        ));
    }
    let pool = default_mainnet_pool(&endpoints).map_err(|e| BuildError::Pipeline(e.to_string()))?;
    let pool = Arc::new(pool);

    let cache = open_cache().map_err(|e| BuildError::Pipeline(e.to_string()))?;
    let cache: Arc<dyn CommitteeCache> = Arc::new(cache);

    let primitive: Arc<dyn Primitive> = Arc::new(NativePrimitive);
    let ao: Arc<dyn AoLogger> = Arc::new(MockAo);

    let key = build_key()?;

    let device = Device::new(
        pool,
        cache,
        primitive,
        x402_impl,
        ao,
        mainnet_genesis_validators_root(),
        key.platform_key_id.clone(),
        key.signing_key,
    );

    Ok(Built {
        device,
        platform_key_id: key.platform_key_id,
        key_scope: key.key_scope,
        notary_status: key.notary_status,
        x402_mode_label,
        x402_payload,
    })
}

fn build_x402() -> Result<(Arc<dyn X402Verifier>, &'static str, String), BuildError> {
    let mode = std::env::var("BLS_DEVICE_X402_MODE").unwrap_or_else(|_| "disabled".to_string());
    let payload = std::env::var("BLS_DEVICE_X402_PAYLOAD").unwrap_or_default();
    match mode.as_str() {
        "disabled" => Ok((Arc::new(DisabledX402) as Arc<dyn X402Verifier>, "disabled", payload)),
        "stub" => Ok((Arc::new(StubX402) as Arc<dyn X402Verifier>, "stub", payload)),
        other => Err(BuildError::Config(format!(
            "BLS_DEVICE_X402_MODE: expected 'disabled' or 'stub' (Slice 1A); got '{other}'. \
             Real facilitator wiring is punch-list Slice 3."
        ))),
    }
}

/// Disabled mode: no payload check is performed. The harness envelope
/// emits `x402_mode:disabled` and `settlement_verified:false`. Returning
/// `Ok` here is *not* a settlement claim — it lets `Device::verify`
/// proceed past the x402 stage so the BLS pipeline can be exercised on
/// testnet without a payment infrastructure. Consumers that need a
/// settlement guarantee MUST gate on `settlement_verified`, NOT on
/// `verified` (which is the BLS-only verdict).
struct DisabledX402;

#[async_trait]
impl X402Verifier for DisabledX402 {
    async fn verify(&self, _payload: &str, request_hash: &[u8; 32]) -> Result<String, String> {
        tracing::warn!(
            target: "bls_device_harness::x402",
            "x402 mode 'disabled' — no payment verification performed; \
             harness envelope emits settlement_verified:false"
        );
        Ok(format!("x402-disabled-{}", hex::encode(&request_hash[..8])))
    }
}

/// Stub mode: shape-validate the payload only. NO settlement
/// verification. The harness envelope emits `x402_mode:stub` and
/// `settlement_verified:false`. Same caveat as `DisabledX402` — the
/// returned id is opaque and MUST NOT be treated as a settlement
/// receipt. Slice 3 lands the real Coinbase facilitator client.
struct StubX402;

#[async_trait]
impl X402Verifier for StubX402 {
    async fn verify(&self, payload: &str, request_hash: &[u8; 32]) -> Result<String, String> {
        if payload.is_empty() {
            return Err("stub x402: empty payload (set BLS_DEVICE_X402_PAYLOAD)".to_string());
        }
        if payload.len() > 8192 {
            return Err(format!(
                "stub x402: payload too large ({} bytes > 8192 cap)",
                payload.len()
            ));
        }
        if !payload.bytes().all(|b| matches!(b, 0x20..=0x7e)) {
            return Err("stub x402: payload not ASCII-printable".to_string());
        }
        tracing::warn!(
            target: "bls_device_harness::x402",
            payload_len = payload.len(),
            "x402 mode 'stub' — payload shape OK, NO settlement verification; \
             harness envelope emits settlement_verified:false"
        );
        Ok(format!("x402-stub-{}", hex::encode(&request_hash[..8])))
    }
}

struct KeyConfig {
    signing_key: SigningKey,
    platform_key_id: String,
    key_scope: &'static str,
    notary_status: &'static str,
}

fn build_key() -> Result<KeyConfig, BuildError> {
    let pem = std::env::var("BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM").ok();
    let key_id = std::env::var("BLS_DEVICE_RESPONSE_SIGNING_KEY_ID").ok();
    match (pem, key_id) {
        (Some(pem), Some(key_id)) => {
            let signing_key = SigningKey::from_pkcs8_pem(&pem).map_err(|e| {
                BuildError::Config(format!(
                    "BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM parse failed: {e}"
                ))
            })?;
            Ok(KeyConfig {
                signing_key,
                platform_key_id: key_id,
                key_scope: "operator-supplied",
                notary_status: "operator-supplied",
            })
        }
        (Some(_), None) | (None, Some(_)) => Err(BuildError::Config(
            "BLS_DEVICE_RESPONSE_SIGNING_PRIVATE_KEY_PEM and \
             BLS_DEVICE_RESPONSE_SIGNING_KEY_ID must be set together"
                .to_string(),
        )),
        (None, None) => {
            // Ephemeral default — see module doc. Private key never leaves
            // process memory; only the verifying-key fingerprint appears
            // in the envelope.
            let mut rng = OsRng;
            let signing_key = SigningKey::generate(&mut rng);
            let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
            let platform_key_id = format!("ephemeral:{}", &pubkey_hex[..16]);
            Ok(KeyConfig {
                signing_key,
                platform_key_id,
                key_scope: "ephemeral-subprocess",
                notary_status: "not-persistent",
            })
        }
    }
}

fn envelope_response(
    resp: &bls_device::VerifyResponse,
    built: &Built,
) -> Result<String, String> {
    let mut value = serde_json::to_value(resp)
        .map_err(|e| format!("VerifyResponse to_value: {e}"))?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| "VerifyResponse did not serialize as object".to_string())?;
    // Layer harness-side envelope facts on top. None of these may exist in
    // `VerifyResponse` itself — the audit-hardened lib.rs is intentionally
    // not modified by Slice 1A.
    obj.insert("x402_mode".into(), Value::String(built.x402_mode_label.into()));
    obj.insert("settlement_verified".into(), Value::Bool(false));
    obj.insert("key_scope".into(), Value::String(built.key_scope.into()));
    obj.insert("notary_status".into(), Value::String(built.notary_status.into()));
    obj.insert("platform_key_id".into(), Value::String(built.platform_key_id.clone()));
    obj.insert("ao_mode".into(), Value::String("mock".into()));
    obj.insert("harness_version".into(), Value::String(HARNESS_VERSION.into()));
    serde_json::to_string(&value).map_err(|e| format!("envelope encode: {e}"))
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

fn open_cache() -> bls_device::Result<SqliteCommitteeCache> {
    if let Ok(path) = std::env::var("BLS_DEVICE_CACHE_PATH") {
        let p = PathBuf::from(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        SqliteCommitteeCache::open(&p)
    } else {
        SqliteCommitteeCache::open_in_memory()
    }
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
