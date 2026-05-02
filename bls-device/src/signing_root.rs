//! O-701 / S.06 — signing root computation.
//!
//! Parameterised on `fork_version` and `genesis_validators_root`. No constants.

use sha2::{Digest, Sha256};

const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

pub fn compute_domain(fork_version: &[u8; 4], genesis_validators_root: &[u8; 32]) -> [u8; 32] {
    let mut chunk1 = [0u8; 32];
    chunk1[..4].copy_from_slice(fork_version);

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&chunk1);
    combined.extend_from_slice(genesis_validators_root);

    let fork_data_root = sha256(&combined);

    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root(object_root: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(object_root);
    data[32..].copy_from_slice(domain);
    sha256(&data).try_into().expect("sha256 output is 32 bytes")
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_changes_with_fork_version() {
        let gvr = [0x42u8; 32];
        let d1 = compute_domain(&[0x06, 0, 0, 0], &gvr);
        let d2 = compute_domain(&[0x07, 0, 0, 0], &gvr);
        assert_ne!(d1, d2);
        assert_eq!(d1[..4], DOMAIN_SYNC_COMMITTEE);
    }

    #[test]
    fn signing_root_is_deterministic() {
        let object = [0x11u8; 32];
        let domain = [0x22u8; 32];
        assert_eq!(
            compute_signing_root(&object, &domain),
            compute_signing_root(&object, &domain),
        );
    }
}
