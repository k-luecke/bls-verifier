use blst::min_pk::{PublicKey, Signature, AggregatePublicKey};
use blst::BLST_ERROR;
use sha2::{Sha256, Digest};
use std::io::{self, Read};

fn run() -> Result<serde_json::Value, String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|e| format!("stdin read: {e}"))?;

    let data: serde_json::Value = serde_json::from_str(&input)
        .map_err(|e| format!("invalid JSON: {e}"))?;

    let sig_hex = data["signature"].as_str()
        .ok_or("missing 'signature' field")?
        .trim_start_matches("0x");
    let bits_hex = data["bits"].as_str()
        .ok_or("missing 'bits' field")?
        .trim_start_matches("0x");
    let parent_root_hex = data["parent_root"].as_str()
        .ok_or("missing 'parent_root' field")?
        .trim_start_matches("0x");
    let pubkeys_array = data["pubkeys"].as_array()
        .ok_or("missing 'pubkeys' field")?;

    // Parse participation bits and filter pubkeys
    let bits_bytes = hex_to_bytes(bits_hex)?;
    let mut participating_pubkeys: Vec<PublicKey> = vec![];

    for (i, pk_hex) in pubkeys_array.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < bits_bytes.len() {
            let participated = (bits_bytes[byte_idx] >> bit_idx) & 1 == 1;
            if participated {
                let pk_str = pk_hex.as_str()
                    .ok_or("pubkey entry must be a hex string")?
                    .trim_start_matches("0x");
                let pk_bytes = hex_to_bytes(pk_str)?;
                if let Ok(pk) = PublicKey::from_bytes(&pk_bytes) {
                    participating_pubkeys.push(pk);
                }
            }
        }
    }

    // Compute domain and signing root.
    // Per O-701 / S.06 the fork version is supplied by the caller (the
    // HyperBEAM device fetches it dynamically). The CLI accepts it as an
    // input field so this stays a pure function over byte buffers.
    let genesis_validators_root = hex_to_bytes(
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    )?;
    let fork_version_hex = data["fork_version"]
        .as_str()
        .ok_or("missing 'fork_version' field (4-byte hex, e.g. \"0x06000000\")")?
        .trim_start_matches("0x");
    let fork_version = hex_to_bytes(fork_version_hex)?;
    if fork_version.len() != 4 {
        return Err(format!("fork_version must be 4 bytes, got {}", fork_version.len()));
    }
    let domain = compute_domain(&fork_version, &genesis_validators_root);
    let parent_root_bytes = hex_to_bytes(parent_root_hex)?;
    let signing_root = compute_signing_root(&parent_root_bytes, &domain);

    // Aggregate pubkeys and verify
    let pk_refs: Vec<&PublicKey> = participating_pubkeys.iter().collect();
    let agg_pk = AggregatePublicKey::aggregate(&pk_refs, true)
        .map_err(|e| format!("{:?}", e))?
        .to_public_key();

    let sig_bytes = hex_to_bytes(sig_hex)?;
    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|e| format!("{:?}", e))?;

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let result = sig.verify(true, &signing_root, dst, &[], &agg_pk, true);

    match result {
        BLST_ERROR::BLST_SUCCESS => Ok(serde_json::json!({
            "verified": true,
            "participating": pk_refs.len(),
            "signing_root": bytes_to_hex(&signing_root)
        })),
        _ => Ok(serde_json::json!({
            "verified": false,
            "error": format!("{:?}", result)
        })),
    }
}

fn main() {
    match run() {
        Ok(out) => println!("{out}"),
        Err(e) => println!("{}", serde_json::json!({"verified": false, "error": e})),
    }
}

fn compute_domain(fork_version: &[u8], genesis_validators_root: &[u8]) -> Vec<u8> {
    let domain_type = [0x07, 0x00, 0x00, 0x00];
    let mut chunk1 = [0u8; 32];
    chunk1[..4].copy_from_slice(fork_version);
    let mut chunk2 = [0u8; 32];
    chunk2.copy_from_slice(genesis_validators_root);
    let mut combined = Vec::new();
    combined.extend_from_slice(&chunk1);
    combined.extend_from_slice(&chunk2);
    let fork_data_root = sha256(&combined);
    let mut domain = Vec::new();
    domain.extend_from_slice(&domain_type);
    domain.extend_from_slice(&fork_data_root[..28]);
    domain
}

fn compute_signing_root(object_root: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(object_root);
    data.extend_from_slice(domain);
    sha256(&data)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim_start_matches("0x");
    if hex.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
