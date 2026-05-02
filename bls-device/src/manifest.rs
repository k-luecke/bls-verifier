//! Emits the HyperBEAM device manifest.
//!
//! HyperBEAM identifies devices by a `name@version` tag plus the wasm artifact
//! they wrap. This module is a thin templater so paxiom's `hyperbeam/`
//! registrar can populate the manifest without re-encoding the schema.

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
            primitive_return_codes: vec![
                ReturnCode { code: 1, label: "Valid" },
                ReturnCode { code: 0, label: "Invalid" },
                ReturnCode { code: -1, label: "SignatureParseFailure" },
                ReturnCode { code: -2, label: "PubkeyParseFailure" },
                ReturnCode { code: -3, label: "AggregationFailed" },
                ReturnCode { code: -4, label: "InvalidSigningRoot" },
            ],
        }
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialises")
    }
}
