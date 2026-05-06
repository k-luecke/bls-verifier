//! O-701 / S.05 — beacon endpoint failover.
//!
//! `BeaconClient` is a single endpoint. `FailoverPool` ranks endpoints by
//! exponentially-weighted success rate and walks down the list on failure.

use crate::{DeviceError, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Trait so tests can replace the network with a fixture-backed beacon.
#[async_trait]
pub trait BeaconClient: Send + Sync {
    async fn fork_version_for_slot(&self, slot: u64) -> Result<[u8; 4]>;
    async fn committee_pubkeys(&self, slot: u64) -> Result<Vec<[u8; 48]>>;
}

pub struct HttpBeaconClient {
    pub base_url: String,
    pub label: String,
    pub http: reqwest::Client,
}

impl HttpBeaconClient {
    pub fn new(base_url: impl Into<String>, label: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| DeviceError::BeaconExhausted(format!("reqwest client init: {e}")))?;
        Ok(Self {
            base_url: base_url.into(),
            label: label.into(),
            http,
        })
    }

    async fn get_json(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| DeviceError::BeaconExhausted(format!("{}: {e}", self.label)))?;
        if !resp.status().is_success() {
            return Err(DeviceError::BeaconExhausted(format!(
                "{}: HTTP {}",
                self.label,
                resp.status()
            )));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| DeviceError::BeaconExhausted(format!("{}: malformed JSON: {e}", self.label)))
    }
}

#[async_trait]
impl BeaconClient for HttpBeaconClient {
    async fn fork_version_for_slot(&self, slot: u64) -> Result<[u8; 4]> {
        let v = self
            .get_json(&format!("/eth/v1/beacon/states/{slot}/fork"))
            .await?;
        let s = v["data"]["current_version"]
            .as_str()
            .ok_or_else(|| DeviceError::BeaconExhausted("missing current_version".into()))?;
        let bytes = hex::decode(s.trim_start_matches("0x"))
            .map_err(|e| DeviceError::BeaconExhausted(format!("bad fork hex: {e}")))?;
        if bytes.len() != 4 {
            return Err(DeviceError::BeaconExhausted(format!(
                "fork version: expected 4 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 4];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    async fn committee_pubkeys(&self, slot: u64) -> Result<Vec<[u8; 48]>> {
        let sc = self
            .get_json(&format!("/eth/v1/beacon/states/{slot}/sync_committees"))
            .await?;
        let indices: Vec<String> = sc["data"]["validators"]
            .as_array()
            .ok_or_else(|| DeviceError::BeaconExhausted("missing validators".into()))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();

        let mut pubkeys: Vec<[u8; 48]> = Vec::with_capacity(indices.len());
        // Mirrors the chunks-of-10 pattern from bls-test/src/main.rs:64
        for chunk in indices.chunks(10) {
            let query: String = chunk
                .iter()
                .map(|id| format!("id={id}"))
                .collect::<Vec<_>>()
                .join("&");
            // Resolve validator pubkeys against the request's slot, not
            // `head`. On a validator-key rotation or exit between the slot
            // of interest and `head`, querying `head` returns the wrong
            // pubkey set and the cache pins the wrong-but-self-consistent
            // committee under the period key.
            let resp = self
                .get_json(&format!("/eth/v1/beacon/states/{slot}/validators?{query}"))
                .await?;
            if let Some(validators) = resp["data"].as_array() {
                for v in validators {
                    if let Some(s) = v["validator"]["pubkey"].as_str() {
                        let bytes = hex::decode(s.trim_start_matches("0x"))
                            .map_err(|e| DeviceError::BeaconExhausted(format!("bad pubkey: {e}")))?;
                        // Audit M-3 (#?): a buggy beacon returning a wrong-size
                        // pubkey used to be silently dropped, leaving us with a
                        // self-consistent but truncated committee that then got
                        // cached. Error out so the failover pool moves on to a
                        // healthy endpoint instead of pinning bad data.
                        if bytes.len() != 48 {
                            return Err(DeviceError::BeaconExhausted(format!(
                                "{}: pubkey expected 48 bytes, got {}",
                                self.label,
                                bytes.len()
                            )));
                        }
                        let mut pk = [0u8; 48];
                        pk.copy_from_slice(&bytes);
                        pubkeys.push(pk);
                    }
                }
            }
        }
        Ok(pubkeys)
    }
}

#[derive(Debug)]
struct EndpointHealth {
    label: String,
    success_ewma: f64,
    cooldown_until: Option<Instant>,
}

/// Ranks endpoints by EWMA success rate; degrades for 60s on error.
pub struct FailoverPool {
    clients: Vec<Box<dyn BeaconClient>>,
    health: Mutex<Vec<EndpointHealth>>,
    cooldown: Duration,
}

impl FailoverPool {
    pub fn new(clients: Vec<Box<dyn BeaconClient>>, labels: Vec<String>) -> Self {
        let health = labels
            .into_iter()
            .map(|label| EndpointHealth {
                label,
                success_ewma: 1.0,
                cooldown_until: None,
            })
            .collect();
        Self {
            clients,
            health: Mutex::new(health),
            cooldown: Duration::from_secs(60),
        }
    }

    fn order(&self) -> Vec<usize> {
        let now = Instant::now();
        // Audit M-5: poison-tolerant. EWMA stats are not safety-critical;
        // recovering from a panic in another stage lets the failover pool
        // keep serving rather than wedge for the process lifetime.
        let h = self.health.lock().unwrap_or_else(|p| p.into_inner());
        let mut indices: Vec<usize> = (0..h.len())
            .filter(|i| h[*i].cooldown_until.map_or(true, |t| t <= now))
            .collect();
        indices.sort_by(|a, b| {
            h[*b]
                .success_ewma
                .partial_cmp(&h[*a].success_ewma)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        indices
    }

    fn record(&self, idx: usize, success: bool) {
        // M-5: poison-tolerant; see comment in `order`.
        let mut h = self.health.lock().unwrap_or_else(|p| p.into_inner());
        let alpha = 0.3;
        h[idx].success_ewma = alpha * (success as u8 as f64) + (1.0 - alpha) * h[idx].success_ewma;
        if !success {
            h[idx].cooldown_until = Some(Instant::now() + self.cooldown);
        } else {
            h[idx].cooldown_until = None;
        }
    }

    pub async fn fork_version_for_slot(&self, slot: u64) -> Result<[u8; 4]> {
        let order = self.order();
        if order.is_empty() {
            return Err(DeviceError::BeaconExhausted("no endpoints available".into()));
        }
        let mut last_err = None;
        for idx in order {
            debug!(endpoint = %self.health.lock().unwrap_or_else(|p| p.into_inner())[idx].label, "fork lookup");
            match self.clients[idx].fork_version_for_slot(slot).await {
                Ok(v) => {
                    self.record(idx, true);
                    return Ok(v);
                }
                Err(e) => {
                    warn!(?e, "endpoint failed; cooling down");
                    self.record(idx, false);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| DeviceError::BeaconExhausted("all exhausted".into())))
    }

    pub async fn committee_pubkeys(&self, slot: u64) -> Result<Vec<[u8; 48]>> {
        let order = self.order();
        if order.is_empty() {
            return Err(DeviceError::BeaconExhausted("no endpoints available".into()));
        }
        let mut last_err = None;
        for idx in order {
            match self.clients[idx].committee_pubkeys(slot).await {
                Ok(v) => {
                    self.record(idx, true);
                    return Ok(v);
                }
                Err(e) => {
                    warn!(?e, "committee fetch failed; cooling down");
                    self.record(idx, false);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| DeviceError::BeaconExhausted("all exhausted".into())))
    }
}

/// Convenience constructor for the production trio (Lodestar / Nimbus / Prysm).
/// Endpoints are operator-supplied so the pool can be reconfigured without rebuild.
pub fn default_mainnet_pool(endpoints: &[(String, String)]) -> Result<FailoverPool> {
    let labels: Vec<String> = endpoints.iter().map(|(label, _)| label.clone()).collect();
    let mut clients: Vec<Box<dyn BeaconClient>> = Vec::with_capacity(endpoints.len());
    for (label, url) in endpoints {
        let c = HttpBeaconClient::new(url.clone(), label.clone())?;
        clients.push(Box::new(c) as Box<dyn BeaconClient>);
    }
    Ok(FailoverPool::new(clients, labels))
}
