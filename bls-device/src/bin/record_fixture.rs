//! Operator-only binary: capture a beacon snapshot for fixture-driven tests.
//!
//! Pick a slot from a CLOSED historical period (period boundary = slot/8192;
//! a closed period is one whose end-slot is < current_head). The captured
//! committee snapshot then stays internally consistent indefinitely.
//!
//! Usage:
//!   cargo run -p bls-device --bin record-fixture -- \
//!       --beacon https://lodestar-mainnet.chainsafe.io \
//!       --slot 8421376 \
//!       --out fixtures/beacon

use serde_json::Value;
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut beacon = "https://lodestar-mainnet.chainsafe.io".to_string();
    let mut slot: Option<u64> = None;
    let mut out = PathBuf::from("fixtures/beacon");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--beacon" => {
                beacon = args[i + 1].clone();
                i += 2;
            }
            "--slot" => {
                slot = Some(args[i + 1].parse()?);
                i += 2;
            }
            "--out" => {
                out = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => return Err(format!("unknown arg: {other}").into()),
        }
    }

    let slot = slot.ok_or("--slot is required")?;
    std::fs::create_dir_all(&out)?;
    let client = reqwest::Client::new();

    let header = get_json(&client, &format!("{beacon}/eth/v1/beacon/headers/head")).await?;
    write_json(&out.join("header_head.json"), &header)?;

    let block = get_json(
        &client,
        &format!("{beacon}/eth/v2/beacon/blocks/{slot}"),
    )
    .await?;
    write_json(&out.join(format!("block_{slot}.json")), &block)?;

    let sc = get_json(
        &client,
        &format!("{beacon}/eth/v1/beacon/states/{slot}/sync_committees"),
    )
    .await?;
    write_json(&out.join(format!("sync_committees_{slot}.json")), &sc)?;

    let fork = get_json(
        &client,
        &format!("{beacon}/eth/v1/beacon/states/{slot}/fork"),
    )
    .await?;
    write_json(&out.join(format!("fork_{slot}.json")), &fork)?;

    let indices: Vec<String> = sc["data"]["validators"]
        .as_array()
        .ok_or("missing validators")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    for (n, chunk) in indices.chunks(10).enumerate() {
        let query: String = chunk
            .iter()
            .map(|id| format!("id={id}"))
            .collect::<Vec<_>>()
            .join("&");
        let resp = get_json(
            &client,
            &format!("{beacon}/eth/v1/beacon/states/head/validators?{query}"),
        )
        .await?;
        write_json(&out.join(format!("validators_chunk_{n}.json")), &resp)?;
    }

    let manifest = serde_json::json!({
        "slot": slot,
        "period_index": slot / 8192,
        "captured_at": chrono_now_iso(),
        "fork_version": fork["data"]["current_version"],
        "beacon_endpoint": beacon,
    });
    write_json(&out.join("MANIFEST.json"), &manifest)?;
    println!("wrote fixture to {}", out.display());
    Ok(())
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} from {url}", resp.status()).into());
    }
    Ok(resp.json::<Value>().await?)
}

fn write_json(path: &std::path::Path, v: &Value) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, serde_json::to_string_pretty(v)?)?;
    Ok(())
}

fn chrono_now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("unix:{secs}")
}
