//! Persists inode-bound retirement leases in publisher-private embedded state.
//!
//! ```toml
//! version = 1
//! domain = "public"
//! key = [1, 2]
//! device = 1
//! inode = 2
//! changed_seconds = 1800000000
//! changed_nanoseconds = 0
//! deadline_unix_ms = 1800000000000
//! ```
//!
//! Keys are bounded internal typed-key encodings, never bucket names. Unknown
//! deadlines receive a fresh conservative interval rather than immediate expiry.

use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::state::FsPublicationState;
use crate::store::LocalFs;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    domain: String,
    key: Vec<u8>,
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    deadline_unix_ms: u64,
}

/// Identifies the actual retained inode and its post-rename change timestamp.
///
/// The timestamp distinguishes a reused inode number after publisher restart.
/// This record alone grants no namespace, content or serving authority.
#[derive(Clone, Copy)]
pub struct RetirementInode {
    /// The actual filesystem device number.
    pub device: u64,
    /// The actual inode number.
    pub inode: u64,
    /// Seconds in the inode change timestamp after the pending rename.
    pub changed_seconds: i64,
    /// Nanoseconds in that same change timestamp.
    pub changed_nanoseconds: i64,
}

/// Retains an actual durably recorded pending-inode deadline.
pub struct RetirementLease {
    deadline_unix_ms: u64,
}

impl RetirementLease {
    /// Checks expiry against the system wall clock without delaying the owner.
    ///
    /// # Errors
    /// Returns an error for an unavailable or unrepresentable Unix clock.
    pub fn expired(&self) -> io::Result<bool> {
        Ok(now_ms()? >= self.deadline_unix_ms)
    }
}

fn now_ms() -> io::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    elapsed.as_millis().try_into().map_err(io::Error::other)
}

enum LeaseMode {
    Begin,
    Recover,
}

impl<F: LocalFs + Sync> FsPublicationState<F> {
    /// Retains a durable lease, reconstructing a missing deadline conservatively.
    ///
    /// The native owner supplies its actual retained inode and holds exclusive
    /// publication custody through this future's physical completion. A changed
    /// inode starts a fresh interval. An existing same-inode lease is preserved.
    ///
    /// # Errors
    /// Returns invalid context, malformed state, clock, write or durability errors.
    pub async fn retirement_lease(
        &self,
        domain: &str,
        key: &[u8],
        incarnation: RetirementInode,
        interval: Duration,
    ) -> io::Result<RetirementLease> {
        self.persist_retirement_lease(domain, key, incarnation, interval, LeaseMode::Recover)
            .await
    }

    /// Starts a fresh durable interval after an actual newly completed retirement.
    ///
    /// The caller retains native exclusion and supplies the inode actually moved
    /// into pending storage. This also renews a restored-and-retired same inode.
    ///
    /// # Errors
    /// Returns invalid context, clock, serialization, write or durability errors.
    pub async fn begin_retirement_lease(
        &self,
        domain: &str,
        key: &[u8],
        incarnation: RetirementInode,
        interval: Duration,
    ) -> io::Result<RetirementLease> {
        self.persist_retirement_lease(domain, key, incarnation, interval, LeaseMode::Begin)
            .await
    }

    async fn persist_retirement_lease(
        &self,
        domain: &str,
        key: &[u8],
        incarnation: RetirementInode,
        interval: Duration,
        mode: LeaseMode,
    ) -> io::Result<RetirementLease> {
        terrane_core::properties::Domain::parse(domain)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if key.is_empty()
            || key.len() > 128
            || interval.is_zero()
            || interval > Duration::from_secs(300)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid retirement lease context",
            ));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(key);
        let path = self
            .directory
            .join(format!("retirement-{}.toml", hasher.finalize().to_hex()));
        if matches!(mode, LeaseMode::Recover) {
            match self.fs.metadata(&path).await {
                Ok(metadata) if !metadata.is_file() || metadata.len() > 4096 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid retirement lease size or type",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            match self.fs.read_nofollow(&path).await {
                Ok(bytes) => {
                    if bytes.len() > 4096 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "oversized retirement lease",
                        ));
                    }
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    let record: Record = toml::from_str(text)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    if record.version != 1 || record.domain != domain || record.key != key {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "retirement lease context mismatch",
                        ));
                    }
                    if record.device == incarnation.device
                        && record.inode == incarnation.inode
                        && record.changed_seconds == incarnation.changed_seconds
                        && record.changed_nanoseconds == incarnation.changed_nanoseconds
                    {
                        // Re-acknowledgment requires the actual existing file and
                        // parent durability, not merely a successful parse.
                        self.fs.sync_file(&path).await?;
                        self.fs.sync_directory(&self.directory).await?;
                        return Ok(RetirementLease {
                            deadline_unix_ms: record.deadline_unix_ms,
                        });
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let interval_ms: u64 = interval
            .as_millis()
            .max(1)
            .try_into()
            .map_err(io::Error::other)?;
        let deadline_unix_ms = now_ms()?
            .checked_add(interval_ms)
            .ok_or_else(|| io::Error::other("retirement deadline overflow"))?;
        let record = Record {
            version: 1,
            domain: domain.to_owned(),
            key: key.to_owned(),
            device: incarnation.device,
            inode: incarnation.inode,
            changed_seconds: incarnation.changed_seconds,
            changed_nanoseconds: incarnation.changed_nanoseconds,
            deadline_unix_ms,
        };
        let bytes = toml::to_string(&record).map_err(io::Error::other)?;
        let random = self.fs.random_bytes(16).await?;
        let temporary = self.directory.join(format!(
            ".binding-retirement-{}",
            super::state::hexadecimal(&random)
        ));
        self.fs.write_new(&temporary, bytes.as_bytes()).await?;
        self.fs.sync_file(&temporary).await?;
        self.fs.rename(&temporary, &path).await?;
        self.fs.sync_file(&path).await?;
        self.fs.sync_directory(&self.directory).await?;
        Ok(RetirementLease { deadline_unix_ms })
    }
}
