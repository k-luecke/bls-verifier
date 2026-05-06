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
        let now = Instant::now();
        // Audit M-4 (#19): record() used to clobber cooldown_until on every
        // call. Two interleaved verify()s on the same endpoint — A fails and
        // sets cooldown_until = now+60s, B's earlier in-flight request then
        // returns Ok and clears cooldown_until = None — re-elect the bad
        // endpoint immediately. Merge instead of clobber:
        //   - failure: extend the cooldown window (max with existing),
        //   - success: only clear if the existing cooldown has naturally
        //     expired. Lets EWMA recover before the endpoint is reranked
        //     into rotation, and prevents a stale-success ack from
        //     short-circuiting a fresh failure's cooldown.
        if !success {
            let new_until = now + self.cooldown;
            h[idx].cooldown_until = Some(match h[idx].cooldown_until {
                Some(existing) if existing > new_until => existing,
                _ => new_until,
            });
        } else if let Some(until) = h[idx].cooldown_until {
            if until <= now {
                h[idx].cooldown_until = None;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// Beacon stub whose call ordering and per-call result are scripted by
    /// the test. `gate` lets the test hold a call mid-flight so the pool
    /// can interleave two calls and force the buggy success-path clobber.
    struct ScriptedBeacon {
        first_call_done: Arc<Notify>,
        release_first: Arc<Notify>,
        // call n returns results[n]; runs out -> panic so the test fails loudly
        results: Mutex<std::collections::VecDeque<bool>>,
        gate_first: Mutex<bool>,
    }

    #[async_trait]
    impl BeaconClient for ScriptedBeacon {
        async fn fork_version_for_slot(&self, _slot: u64) -> Result<[u8; 4]> {
            let pop = self
                .results
                .lock()
                .unwrap()
                .pop_front()
                .expect("script exhausted");
            let is_first = {
                let mut g = self.gate_first.lock().unwrap();
                let was = *g;
                *g = false;
                was
            };
            if is_first {
                // First call: notify test, wait for release. Second call's
                // failure recording happens between these two Notify points.
                self.first_call_done.notify_one();
                self.release_first.notified().await;
            }
            if pop {
                Ok([1, 2, 3, 4])
            } else {
                Err(DeviceError::BeaconExhausted("scripted failure".into()))
            }
        }
        async fn committee_pubkeys(&self, _: u64) -> Result<Vec<[u8; 48]>> {
            unreachable!()
        }
    }

    /// Audit M-4 (#19): record() used to unconditionally set cooldown=None
    /// on success. Two interleaved verify()s — call A starts (will succeed
    /// later), call B fails and sets cooldown — A's late success then
    /// clobbered the cooldown back to None and immediately re-elected the
    /// just-cooled endpoint.
    ///
    /// Reproduction: single-endpoint pool, two concurrent fork_version
    /// calls. Both pass `order()` (still healthy at lookup). Schedule the
    /// failure to record first, then release the success. After both
    /// complete, `order()` must still see the endpoint as cooled — i.e. a
    /// third call must error with BeaconExhausted, not return Ok.
    #[tokio::test]
    async fn record_success_does_not_clobber_concurrent_failure_cooldown() {
        let first_done = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let beacon = Arc::new(ScriptedBeacon {
            first_call_done: first_done.clone(),
            release_first: release.clone(),
            // call 1 (the gated one) -> Ok; call 2 -> Err
            results: Mutex::new(vec![true, false].into()),
            gate_first: Mutex::new(true),
        });

        // Single-endpoint pool: cooldown is the only thing keeping a bad
        // endpoint out of rotation, so a clobber bug is observable as
        // "next call still routes to the just-cooled endpoint".
        let beacon_dyn: Box<dyn BeaconClient> = Box::new(ArcBeacon(beacon.clone()));
        let pool = Arc::new(FailoverPool::new(vec![beacon_dyn], vec!["ep0".into()]));

        // Spawn the call that will succeed late (it parks on `release`).
        let p1 = pool.clone();
        let h1 = tokio::spawn(async move { p1.fork_version_for_slot(1).await });

        // Wait until call A is parked inside the beacon.
        first_done.notified().await;

        // Issue call B; it grabs the same endpoint, fails, records cooldown.
        let r2 = pool.fork_version_for_slot(2).await;
        assert!(r2.is_err(), "call B was scripted to fail");

        // Release call A so it records success. Buggy code clears cooldown.
        release.notify_one();
        let r1 = h1.await.unwrap();
        assert!(r1.is_ok(), "call A was scripted to succeed");

        // Cooldown invariant: after a fresh failure, a same-tick success
        // from a concurrent in-flight request must not unstick the
        // endpoint. Issue a third call — under the bug, ep0 is healthy
        // again and this returns Ok. With the fix, ep0 is still cooled
        // and we get BeaconExhausted("no endpoints available").
        let r3 = pool.fork_version_for_slot(3).await;
        match r3 {
            Err(DeviceError::BeaconExhausted(m)) => assert!(
                m.contains("no endpoints"),
                "expected exhausted-due-to-cooldown, got: {m}"
            ),
            other => panic!(
                "M-4 regression: cooldown was clobbered by concurrent success record; \
                 expected BeaconExhausted, got {other:?}"
            ),
        }
    }

    // FailoverPool wants Box<dyn BeaconClient>, but the test holds the
    // beacon as Arc to script it from the outside. Thin newtype to bridge.
    struct ArcBeacon(Arc<ScriptedBeacon>);
    #[async_trait]
    impl BeaconClient for ArcBeacon {
        async fn fork_version_for_slot(&self, s: u64) -> Result<[u8; 4]> {
            self.0.fork_version_for_slot(s).await
        }
        async fn committee_pubkeys(&self, s: u64) -> Result<Vec<[u8; 48]>> {
            self.0.committee_pubkeys(s).await
        }
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
