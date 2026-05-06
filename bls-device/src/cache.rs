//! O-701 / S.04 — period-keyed sync committee cache.
//!
//! Period = slot / 8192 (256 epochs * 32 slots, ~27h). One read per request,
//! one write every ~27h on a cache miss.

use crate::{DeviceError, Result};
use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use tokio::task;

#[async_trait]
pub trait CommitteeCache: Send + Sync {
    /// Fetch the cached committee for `(period, fork_version)`. Returns
    /// `None` if no row exists for that exact pair, ensuring a row written
    /// under one fork is never served under a different fork (audit H-6).
    async fn get(
        &self,
        period: u64,
        fork_version: [u8; 4],
    ) -> Result<Option<Vec<[u8; 48]>>>;

    async fn put(
        &self,
        period: u64,
        fork_version: [u8; 4],
        pubkeys: &[[u8; 48]],
    ) -> Result<()>;
}

/// SQLite-backed cache. Default for Phase 0 (debuggability over LMDB perf).
/// Storage is one row per period; pubkeys are concatenated into a single BLOB.
pub struct SqliteCommitteeCache {
    conn: Mutex<Connection>,
}

impl SqliteCommitteeCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| DeviceError::Cache(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_committee (
                period INTEGER NOT NULL,
                fork_version BLOB NOT NULL,
                pubkeys BLOB NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (period, fork_version)
            )",
            [],
        )
        .map_err(|e| DeviceError::Cache(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| DeviceError::Cache(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sync_committee (
                period INTEGER NOT NULL,
                fork_version BLOB NOT NULL,
                pubkeys BLOB NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (period, fork_version)
            )",
            [],
        )
        .map_err(|e| DeviceError::Cache(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl CommitteeCache for SqliteCommitteeCache {
    async fn get(
        &self,
        period: u64,
        fork_version: [u8; 4],
    ) -> Result<Option<Vec<[u8; 48]>>> {
        let period_i64 = i64::try_from(period)
            .map_err(|_| DeviceError::Cache(format!("period {period} overflows i64")))?;
        // Audit M-5: a poisoned Mutex (panic in another stage) used to take
        // down all subsequent verify requests for the process lifetime.
        // sqlite has its own ACID guarantees; recovering the inner guard
        // is safe and lets the device keep serving traffic.
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn
            .prepare(
                "SELECT pubkeys FROM sync_committee WHERE period = ?1 AND fork_version = ?2",
            )
            .map_err(|e| DeviceError::Cache(e.to_string()))?;
        let row: rusqlite::Result<Vec<u8>> =
            stmt.query_row(params![period_i64, &fork_version[..]], |r| r.get(0));
        match row {
            Ok(blob) => {
                if blob.len() % 48 != 0 {
                    return Err(DeviceError::Cache(format!(
                        "stored pubkey blob length {} not a multiple of 48",
                        blob.len()
                    )));
                }
                let mut out = Vec::with_capacity(blob.len() / 48);
                for chunk in blob.chunks_exact(48) {
                    let mut pk = [0u8; 48];
                    pk.copy_from_slice(chunk);
                    out.push(pk);
                }
                Ok(Some(out))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(DeviceError::Cache(e.to_string())),
        }
    }

    async fn put(
        &self,
        period: u64,
        fork_version: [u8; 4],
        pubkeys: &[[u8; 48]],
    ) -> Result<()> {
        let period_i64 = i64::try_from(period)
            .map_err(|_| DeviceError::Cache(format!("period {period} overflows i64")))?;
        let mut blob = Vec::with_capacity(pubkeys.len() * 48);
        for pk in pubkeys {
            blob.extend_from_slice(pk);
        }
        // SystemTime before UNIX_EPOCH would mean a clock skew so severe
        // (or a deliberate attack) that recording any timestamp at all is
        // misleading. Surface the error rather than silently writing 0.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| DeviceError::Cache(format!("system clock before UNIX_EPOCH: {e}")))?
            .as_secs() as i64;
        // M-5: poison-tolerant; see comment in `get`.
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.execute(
            "INSERT OR REPLACE INTO sync_committee
             (period, fork_version, pubkeys, fetched_at) VALUES (?1, ?2, ?3, ?4)",
            params![period_i64, &fork_version[..], blob, now],
        )
        .map_err(|e| DeviceError::Cache(e.to_string()))?;
        Ok(())
    }
}

// Spawn-blocking wrapper if you need true async; the operations above are
// fast enough not to need it for Phase 0. Keeping the helper here so callers
// have a hook if contention shows up.
pub async fn maybe_blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    task::spawn_blocking(f).await.expect("spawn_blocking")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_roundtrip() {
        let cache = SqliteCommitteeCache::open_in_memory().unwrap();
        let pubkeys: Vec<[u8; 48]> = (0..3).map(|i| [i as u8; 48]).collect();
        let fork_a: [u8; 4] = [0, 0, 0, 1];
        cache.put(42, fork_a, &pubkeys).await.unwrap();
        let got = cache.get(42, fork_a).await.unwrap().unwrap();
        assert_eq!(got, pubkeys);
        assert!(cache.get(43, fork_a).await.unwrap().is_none());
    }

    /// Audit H-6 (#15): a row written under one fork version MUST NOT be
    /// served under a different fork version even if the period matches.
    #[tokio::test]
    async fn fork_version_isolates_rows() {
        let cache = SqliteCommitteeCache::open_in_memory().unwrap();
        let pubkeys_a: Vec<[u8; 48]> = (0..3).map(|i| [i as u8; 48]).collect();
        let pubkeys_b: Vec<[u8; 48]> = (10..13).map(|i| [i as u8; 48]).collect();
        let fork_a: [u8; 4] = [0, 0, 0, 1];
        let fork_b: [u8; 4] = [0, 0, 0, 2];

        cache.put(42, fork_a, &pubkeys_a).await.unwrap();
        // Same period, different fork: must miss.
        assert!(cache.get(42, fork_b).await.unwrap().is_none());

        cache.put(42, fork_b, &pubkeys_b).await.unwrap();
        assert_eq!(cache.get(42, fork_a).await.unwrap().unwrap(), pubkeys_a);
        assert_eq!(cache.get(42, fork_b).await.unwrap().unwrap(), pubkeys_b);
    }
}
