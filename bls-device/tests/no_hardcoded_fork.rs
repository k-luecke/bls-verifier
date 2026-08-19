//! O-701 / S.06 contract: no source file outside `tests/` and `fixtures/` may
//! contain the byte literal pattern `[0x06, 0x00, 0x00, 0x00]` (the Fulu fork
//! version, hardcoded historically). Any new fork version must be fetched
//! dynamically from a beacon API. Compile-time grep enforces this.

use std::fs;
use std::path::Path;

fn walk(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "target" | ".git" | "fixtures" | "tests") {
                    continue;
                }
                walk(&p, files);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "no_hardcoded_fork.rs" {
                    continue;
                }
                files.push(p);
            }
        }
    }
}

#[test]
fn no_hardcoded_fork_version_in_sources() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for member in &["bls-verifier", "bls-test", "bls-verify-cli", "bls-device"] {
        walk(&workspace_root.join(member).join("src"), &mut files);
    }

    // Audit I-6: catch alternate spellings of the Fulu fork version
    // beyond the canonical `[0x06, 0x00, 0x00, 0x00]` array literal.
    // Decimal forms (`[6, 0, 0, 0]`, `[6u8, 0, 0, 0]`), byte-string
    // literals (`b"\x06\x00\x00\x00"`), and the packed u32 form
    // (`0x06000000`) all encode the same value and would defeat the
    // earlier exact-match-only grep.
    let needles = [
        // four-byte array literal (hex)
        "[0x06, 0x00, 0x00, 0x00]",
        "[0x06,0x00,0x00,0x00]",
        "[ 0x06, 0x00, 0x00, 0x00 ]",
        // four-byte array literal (decimal)
        "[6, 0, 0, 0]",
        "[6,0,0,0]",
        "[ 6, 0, 0, 0 ]",
        "[6u8, 0, 0, 0]",
        "[6u8,0,0,0]",
        "[6u8, 0u8, 0u8, 0u8]",
        // byte-string literal forms
        "b\"\\x06\\x00\\x00\\x00\"",
        "b\"\\x06\\0\\0\\0\"",
        // packed u32 (little-endian byte 0x06 in MSB position)
        "0x06000000",
        "0x06_00_00_00",
        "0x06000000u32",
        "0x06000000_u32",
    ];

    let mut hits = Vec::new();
    for f in &files {
        let contents = fs::read_to_string(f).unwrap_or_default();
        for needle in needles {
            if contents.contains(needle) {
                hits.push(format!("{}: matches '{needle}'", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "hardcoded Fulu fork version found in:\n{}\n\nFetch it dynamically via BeaconClient::fork_version_for_slot.",
        hits.join("\n")
    );
}
