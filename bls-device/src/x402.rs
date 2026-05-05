//! O-701 / S.03 stage 2 — x402 verification trait.
//!
//! Real implementation (Coinbase facilitator integration) is tracked as a
//! follow-up to issue #10. The facilitator schema is defined by Coinbase
//! and MUST NOT be invented in this repo. For Phase 0 a mock is provided
//! behind the `mock-x402` cargo feature for tests only.

use async_trait::async_trait;

/// x402 payment verification.
///
/// # Security contract (issue #10)
///
/// A production `X402Verifier` MUST authenticate the payload against the
/// Coinbase x402 facilitator and return `Err` when the payment is missing,
/// unsettled, replayed, or otherwise invalid. Implementations that
/// unconditionally return `Ok` (such as `MockX402`) are a security
/// violation outside of test code and must never be wired into a release
/// `Device`. The trait itself cannot enforce this — operators and reviewers
/// must. `Device::new` enforces a runtime floor when the `mock-x402`
/// feature is compiled in.
#[async_trait]
pub trait X402Verifier: Send + Sync {
    async fn verify(&self, payload: &str, request_hash: &[u8; 32]) -> Result<String, String>;
}

/// Test-only verifier that accepts every payload. Gated behind the
/// `mock-x402` cargo feature so it cannot be named from a default
/// release build. Every accept is logged at WARN so a misconfigured
/// staging deploy is observable in logs.
#[cfg(feature = "mock-x402")]
pub struct MockX402;

#[cfg(feature = "mock-x402")]
#[async_trait]
impl X402Verifier for MockX402 {
    async fn verify(&self, _payload: &str, request_hash: &[u8; 32]) -> Result<String, String> {
        let id = format!("mock-{}", hex::encode(&request_hash[..8]));
        tracing::warn!(
            target: "bls_device::x402",
            id = %id,
            "MockX402 accepting payload without facilitator check (issue #10); \
             this MUST NOT appear in production logs"
        );
        Ok(id)
    }
}
