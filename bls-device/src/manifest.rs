//! Emits the HyperBEAM device manifest.
//!
//! HyperBEAM identifies devices by a `name@version` tag plus the wasm artifact
//! they wrap. This module is a thin templater so paxiom's `hyperbeam/`
//! registrar can populate the manifest without re-encoding the schema.
//!
//! # ABI scope (audit M-1, #16)
//!
//! The manifest describes the **cdylib wasm** (`bls-verifier/src/lib.rs`'s
//! `verify_sync_committee`). Codes here MUST match that file's doc-comment,
//! NOT the in-process trait ABI in `primitive.rs`. The two ABIs are
//! deliberately separate; see `primitive.rs` module-level doc.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DeviceManifest {
    pub name: String,
    pub version: String,
    pub wasm_path: String,
    pub harness_entrypoint: String,
    pub deploy_key_id: String,
    pub primitive_return_codes: Vec<ReturnCode>,
}

#[derive(Debug, Serialize)]
pub struct ReturnCode {
    pub code: i32,
    pub label: &'static str,
}

impl DeviceManifest {
    pub fn bls_sync_committee(
        wasm_path: impl Into<String>,
        harness_entrypoint: impl Into<String>,
        deploy_key_id: impl Into<String>,
    ) -> Self {
        Self {
            name: "~bls-sync-committee".into(),
            version: "1.0".into(),
            wasm_path: wasm_path.into(),
            harness_entrypoint: harness_entrypoint.into(),
            deploy_key_id: deploy_key_id.into(),
            // Codes mirror the cdylib C-FFI ABI in
            // `bls-verifier/src/lib.rs` doc-comment — single source of truth
            // for the wasm artifact this manifest describes. NOT the trait
            // ABI in `primitive.rs` (audit M-1).
            primitive_return_codes: vec![
                ReturnCode { code: 1, label: "Valid" },
                ReturnCode { code: 0, label: "Invalid" },
                ReturnCode { code: -1, label: "SignatureParseFailure" },
                ReturnCode { code: -2, label: "NoPubkeys" },
                ReturnCode { code: -3, label: "AggregationFailed" },
                ReturnCode { code: -4, label: "MalformedPubkey" },
                ReturnCode { code: -6, label: "NullPointer" },
            ],
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
