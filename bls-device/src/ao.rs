//! O-701 / S.07 — AO compliance hook.
//!
//! Real implementation calls `aoconnect` to publish a permanent message on
//! Arweave. Phase 0 ships the mock that emits a tracing span and returns a
//! deterministic id — this exercises the device pipeline shape and lets the
//! response include an `ao_message_id` field per S.02.

use async_trait::async_trait;
use serde::Serialize;
use tracing::info;

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceEvent {
    pub request_uuid: String,
    pub service: &'static str,
    pub slot: String,
    pub verified: bool,
    pub primitive_return_code: i32,
    pub request_hash: String,
    pub platform_key_id: String,
}

#[async_trait]
pub trait AoLogger: Send + Sync {
    async fn log(&self, event: &ComplianceEvent) -> Result<String, String>;
}

pub struct MockAo;

#[async_trait]
impl AoLogger for MockAo {
    async fn log(&self, event: &ComplianceEvent) -> Result<String, String> {
        info!(?event, "ao compliance event (mock)");
        Ok(format!("mock-ao-{}-{}", event.slot, event.request_uuid))
    }
}
