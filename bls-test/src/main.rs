use blst::min_pk::{PublicKey, Signature, AggregatePublicKey};
use blst::BLST_ERROR;
use sha2::{Sha256, Digest};
use reqwest;
use serde_json::Value;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::new();

    // Step 1: fetch current head block
    println!("Fetching current head block...");
    let head = client
        .get("https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/headers/head")
        .send().await.unwrap()
        .json::<Value>().await.unwrap();

    let slot = head["data"]["header"]["message"]["slot"].as_str().unwrap().to_string();
    let block_root = head["data"]["root"].as_str().unwrap().to_string();
    let parent_root = head["data"]["header"]["message"]["parent_root"]
        .as_str().unwrap().to_string();
    println!("Slot: {}", slot);
    println!("Block root: {}", block_root);
    println!("Parent root: {}", parent_root);

    // Step 2: fetch full block for sync aggregate
    let block_url = format!(
        "https://lodestar-mainnet.chainsafe.io/eth/v2/beacon/blocks/{}",
        slot
    );
    let block = client.get(&block_url).send().await.unwrap()
        .json::<Value>().await.unwrap();

    let sig_hex = block["data"]["message"]["body"]["sync_aggregate"]["sync_committee_signature"]
        .as_str().unwrap()
        .trim_start_matches("0x")
        .to_string();

    let bits_hex = block["data"]["message"]["body"]["sync_aggregate"]["sync_committee_bits"]
        .as_str().unwrap()
        .trim_start_matches("0x")
        .to_string();
    println!("Got sync aggregate signature and bits");

    // Step 3: fetch sync committee for this slot
    let sc_url = format!(
        "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/states/{}/sync_committees",
        slot
    );
    let sc = client.get(&sc_url).send().await.unwrap()
        .json::<Value>().await.unwrap();

    let indices: Vec<String> = sc["data"]["validators"]
        .as_array().unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    println!("Got {} sync committee indices", indices.len());

    // Step 4: fetch all pubkeys in batches of 10
    println!("Fetching pubkeys...");
    // Beacon API `/validators?id=...` re-sorts the response by validator
    // index ascending — the response order does NOT match the request
    // order. Build an index→pubkey map, then reassemble in `indices` order.
    // Without this, sync committee bitfield positions get mismapped to the
    // wrong pubkeys and BLS verification fails. (Issue #4 root cause.)
    use std::collections::HashMap;
    let mut by_index: HashMap<String, PublicKey> = HashMap::with_capacity(indices.len());

    for chunk in indices.chunks(10) {
        let query: String = chunk.iter()
            .map(|id| format!("id={}", id))
            .collect::<Vec<_>>()
            .join("&");

        let url = format!(
            "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/states/head/validators?{}",
            query
        );

        let resp = client.get(&url).send().await.unwrap()
            .json::<Value>().await.unwrap();

        if let Some(validators) = resp["data"].as_array() {
            for v in validators {
                let idx = v["index"].as_str().unwrap_or("").to_string();
                let pubkey_hex = v["validator"]["pubkey"].as_str().unwrap_or("");
                let bytes = hex_to_bytes(pubkey_hex);
                if let Ok(pk) = PublicKey::from_bytes(&bytes) {
                    by_index.insert(idx, pk);
                }
            }
        }
    }

    // Reassemble in sync-committee position order.
    let all_pubkeys: Vec<PublicKey> = indices
        .iter()
        .filter_map(|i| by_index.get(i).cloned())
        .collect();
    println!("Total pubkeys fetched: {}", all_pubkeys.len());

    // Step 5: filter pubkeys by participation bits
    let bits_bytes = hex_to_bytes(&bits_hex);
    let mut participating_pubkeys: Vec<&PublicKey> = vec![];

    for (i, pk) in all_pubkeys.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if byte_idx < bits_bytes.len() {
            let participated = (bits_bytes[byte_idx] >> bit_idx) & 1 == 1;
            if participated {
                participating_pubkeys.push(pk);
            }
        }
    }
    println!("Participating validators: {}", participating_pubkeys.len());

    // Step 6: compute signing root using parent_root
    let genesis_validators_root = hex_to_bytes(
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
    );

    // Fetch fork_version dynamically per O-701 / S.06. No hardcoded version.
    let fork_version = fetch_fork_version(&client, &slot).await;
    println!("Fork version: 0x{}", bytes_to_hex(&fork_version));

    let domain = compute_domain(&fork_version, &genesis_validators_root);
    println!("Domain: {}", bytes_to_hex(&domain));

    let parent_root_bytes = hex_to_bytes(&parent_root);
    let signing_root = compute_signing_root(&parent_root_bytes, &domain);
    println!("Signing root: {}", bytes_to_hex(&signing_root));

    // Step 7: aggregate participating pubkeys and verify
    let agg_pk = AggregatePublicKey::aggregate(&participating_pubkeys, true)
        .expect("aggregation failed");
    let agg_pk = agg_pk.to_public_key();
    println!("Pubkeys aggregated");

    let sig_bytes = hex_to_bytes(&sig_hex);
    let sig = Signature::from_bytes(&sig_bytes).expect("sig parse failed");

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let result = sig.verify(true, &signing_root, dst, &[], &agg_pk, true);

    match result {
        BLST_ERROR::BLST_SUCCESS => println!("\nSIGNATURE VALID - Paxiom verified Ethereum consensus!"),
        _ => println!("\nResult: {:?}", result),
    }
}

async fn fetch_fork_version(client: &reqwest::Client, slot: &str) -> Vec<u8> {
    let url = format!(
        "https://lodestar-mainnet.chainsafe.io/eth/v1/beacon/states/{}/fork",
        slot
    );
    let resp = client.get(&url).send().await.unwrap()
        .json::<Value>().await.unwrap();
    let s = resp["data"]["current_version"].as_str()
        .expect("beacon /fork response missing current_version");
    hex_to_bytes(s.trim_start_matches("0x"))
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

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
