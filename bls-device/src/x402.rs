//! O-701 / S.03 stage 2 — x402 verification stub.
//!
//! Real implementation (Coinbase facilitator integration) lives in a future
//! runbook. For Phase 0 the device runs with a mock that accepts any payload
//! and returns a deterministic id derived from the request hash, so the
//! pipeline shape is exercised end-to-end without a live facilitator.

use async_trait::async_trait;

#[async_trait]
pub trait X402Verifier: Send + Sync {
    async fn verify(&self, payload: &str, request_hash: &[u8; 32]) -> Result<String, String>;
}

pub struct MockX402;

#[async_trait]
impl X402Verifier for MockX402 {
    async fn verify(&self, _payload: &str, request_hash: &[u8; 32]) -> Result<String, String> {
        Ok(format!("mock-{}", hex::encode(&request_hash[..8])))
    }
}
