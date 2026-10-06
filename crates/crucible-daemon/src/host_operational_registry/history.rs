//! Descriptor-bound, bounded disk idempotency for operational mutations.
//!
//! ```text
//! writer.lock
//! counters                         checksummed fixed-width reserved byte count
//! <target-digest>/<key>.prepared   checksummed principal-bound request digest
//! <target-digest>/<key>.committed  checksummed original canonical response
//! ```
//!
//! Reservations are durably charged before creating intent. An unfinished
//! intent fences that key after restart; it is never reinterpreted as a new
//! request. Direct filename lookup is the bounded disk index: history is not
//! loaded into memory or silently forgotten to admit another mutation.

use std::fs;
use std::path::{Path, PathBuf};

use crucible_api::host_operational::{HostOperationalError, HostOperationalResponse, codec};

use crate::anchored_fs::AnchoredDirectory;
use crate::owned_advisory_lock::OwnedAdvisoryLock;

pub(super) const RECORD_CHARGE: u64 = 32 * 1024;
pub(super) const FIXED_HISTORY_CHARGE: u64 = 64 * 1024;
const MAX_RECORD_BYTES: u64 = 8192;
const MAGIC: &[u8; 8] = b"HOSTCTL1";

pub(super) struct History {
    root: AnchoredDirectory,
    lock: OwnedAdvisoryLock,
    reserved_bytes: u64,
    maximum_bytes: u64,
}

impl History {
    pub(super) fn open(path: &Path, maximum_bytes: u64) -> Result<Self, HostOperationalError> {
        fs::create_dir_all(path).map_err(unavailable)?;
        let root = AnchoredDirectory::open(path.to_path_buf()).map_err(unavailable)?;
        let lock = root
            .open_or_create_regular(&path.join("writer.lock"), "open-host-control-lock")
            .and_then(OwnedAdvisoryLock::try_exclusive_bound)
            .map_err(unavailable)?;
        let mut reserved_bytes = match root
            .open_regular_optional(&path.join("counters"), "read-host-control-counters")
            .map_err(unavailable)?
        {
            Some(file) => {
                let bytes = file.read_bounded(48).map_err(unavailable)?;
                let payload = validate_record(&bytes)?;
                if payload.len() != 8 {
                    return Err(HostOperationalError::Unavailable);
                }
                u64::from_be_bytes(payload.try_into().map_err(unavailable)?)
            }
            None => FIXED_HISTORY_CHARGE,
        };
        if reserved_bytes < FIXED_HISTORY_CHARGE
            || !(reserved_bytes - FIXED_HISTORY_CHARGE).is_multiple_of(RECORD_CHARGE)
            || reserved_bytes > maximum_bytes
        {
            return Err(HostOperationalError::Unavailable);
        }
        // A synced charge may remain staged when the previous writer dies
        // before rename. Recover that exact fixed-size record conservatively;
        // unfinished request intents remain fenced independently.
        let counters = path.join("counters");
        if let Some(staged) = root
            .open_regular_optional(&path.join("counters.next"), "recover-host-control-charge")
            .map_err(unavailable)?
        {
            let bytes = staged.read_bounded(48).map_err(unavailable)?;
            let payload = validate_record(&bytes)?;
            let staged_charge = u64::from_be_bytes(payload.try_into().map_err(unavailable)?);
            if reserved_bytes.checked_add(RECORD_CHARGE) != Some(staged_charge)
                || staged_charge > maximum_bytes
            {
                return Err(HostOperationalError::Unavailable);
            }
            root.rename_file(&staged, &counters, false, "recover-host-control-counters")
                .map_err(unavailable)?;
            root.sync().map_err(unavailable)?;
            reserved_bytes = staged_charge;
        }
        Ok(Self {
            root,
            lock,
            reserved_bytes,
            maximum_bytes,
        })
    }

    pub(super) fn lookup(
        &self,
        target: [u8; 32],
        key: [u8; 32],
        digest: [u8; 32],
    ) -> Result<Option<HostOperationalResponse>, HostOperationalError> {
        self.lock.verify_path_binding().map_err(unavailable)?;
        let directory = self.directory(target);
        let committed = directory.join(format!("{}.committed", hex(key)));
        if let Some(file) = self
            .root
            .open_regular_optional(&committed, "read-host-control-commit")
            .map_err(unavailable)?
        {
            let bytes = file.read_bounded(MAX_RECORD_BYTES).map_err(unavailable)?;
            let payload = validate_record(&bytes)?;
            if payload.len() < 32 || payload[..32] != digest {
                return Err(HostOperationalError::IdempotencyConflict);
            }
            return codec::decode_response(&payload[32..]).map(Some);
        }
        let prepared = directory.join(format!("{}.prepared", hex(key)));
        if let Some(file) = self
            .root
            .open_regular_optional(&prepared, "read-host-control-intent")
            .map_err(unavailable)?
        {
            let bytes = file.read_bounded(80).map_err(unavailable)?;
            let payload = validate_record(&bytes)?;
            if payload != digest {
                return Err(HostOperationalError::IdempotencyConflict);
            }
            // A crash or transport ambiguity cannot manufacture another apply.
            return Err(HostOperationalError::Unavailable);
        }
        Ok(None)
    }

    pub(super) fn prepare(
        &mut self,
        target: [u8; 32],
        key: [u8; 32],
        digest: [u8; 32],
    ) -> Result<bool, HostOperationalError> {
        let reserved = self
            .reserved_bytes
            .checked_add(RECORD_CHARGE)
            .ok_or(HostOperationalError::Unavailable)?;
        if reserved > self.maximum_bytes {
            return Ok(false);
        }
        self.lock.verify_path_binding().map_err(unavailable)?;
        let directory = self.directory(target);
        // Charge before intent publication. Crashes may conservatively retain
        // surplus quota; they may never make written history unaccounted.
        let counters = self.root.path().join("counters");
        let staging = self.root.path().join("counters.next");
        let file = self
            .root
            .create_new_regular(&staging, "stage-host-control-counters")
            .map_err(unavailable)?;
        file.write_all_sync(&record(&reserved.to_be_bytes()))
            .map_err(unavailable)?;
        self.root
            .rename_file(&file, &counters, false, "publish-host-control-counters")
            .map_err(unavailable)?;
        self.root.sync().map_err(unavailable)?;
        self.reserved_bytes = reserved;

        self.root
            .ensure_directory(&directory, "create-host-control-target")
            .map_err(unavailable)?;

        let prepared = directory.join(format!("{}.prepared", hex(key)));
        let file = self
            .root
            .create_new_regular(&prepared, "prepare-host-control-request")
            .map_err(unavailable)?;
        file.write_all_sync(&record(&digest)).map_err(unavailable)?;
        self.root
            .sync_parent(&prepared, "sync-host-control-intent")
            .map_err(unavailable)?;
        Ok(true)
    }

    pub(super) fn commit(
        &self,
        target: [u8; 32],
        key: [u8; 32],
        digest: [u8; 32],
        response: &HostOperationalResponse,
    ) -> Result<(), HostOperationalError> {
        self.lock.verify_path_binding().map_err(unavailable)?;
        let mut payload = digest.to_vec();
        payload.extend(codec::encode_response(response)?);
        let bytes = record(&payload);
        if u64::try_from(bytes.len()).map_err(unavailable)? > MAX_RECORD_BYTES {
            return Err(HostOperationalError::Unavailable);
        }
        let path = self
            .directory(target)
            .join(format!("{}.committed", hex(key)));
        let file = self
            .root
            .create_new_regular(&path, "commit-host-control-response")
            .map_err(unavailable)?;
        file.write_all_sync(&bytes).map_err(unavailable)?;
        self.root
            .sync_parent(&path, "sync-host-control-commit")
            .map_err(unavailable)?;
        // Keep the prepared record as conservative reconciliation evidence;
        // lookup prefers the authenticated complete committed response.
        Ok(())
    }

    fn directory(&self, target: [u8; 32]) -> PathBuf {
        self.root.path().join(hex(target))
    }
}

pub(super) fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(payload);
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn validate_record(bytes: &[u8]) -> Result<&[u8], HostOperationalError> {
    if bytes.len() < 40 || &bytes[..8] != MAGIC {
        return Err(HostOperationalError::Unavailable);
    }
    let split = bytes.len() - 32;
    if blake3::hash(&bytes[..split]).as_bytes() != &bytes[split..] {
        return Err(HostOperationalError::Unavailable);
    }
    Ok(&bytes[8..split])
}

fn unavailable<T>(_source: T) -> HostOperationalError {
    HostOperationalError::Unavailable
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- durable journal fixtures panic at failed exact-filesystem assumptions.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn restart_rolls_forward_an_exact_synced_charge_and_retains_quota() {
        let directory = tempfile::tempdir().unwrap();
        let maximum = FIXED_HISTORY_CHARGE + 2 * RECORD_CHARGE;
        let history = History::open(directory.path(), maximum).unwrap();
        let staged = history
            .root
            .create_new_regular(&directory.path().join("counters.next"), "test-stage-charge")
            .unwrap();
        staged
            .write_all_sync(&record(
                &(FIXED_HISTORY_CHARGE + RECORD_CHARGE).to_be_bytes(),
            ))
            .unwrap();
        drop(staged);
        drop(history);

        let mut recovered = History::open(directory.path(), maximum).unwrap();

        assert_eq!(
            recovered.reserved_bytes,
            FIXED_HISTORY_CHARGE + RECORD_CHARGE
        );
        assert!(!directory.path().join("counters.next").exists());
        assert!(recovered.prepare([1; 32], [2; 32], [3; 32]).unwrap());
        assert!(!recovered.prepare([1; 32], [4; 32], [5; 32]).unwrap());
    }

    #[test]
    fn restart_refuses_corrupt_staged_charge_without_forgetting_it() {
        let directory = tempfile::tempdir().unwrap();
        let history = History::open(directory.path(), 1024 * 1024).unwrap();
        let staged_path = directory.path().join("counters.next");
        let staged = history
            .root
            .create_new_regular(&staged_path, "test-stage-charge")
            .unwrap();
        staged.write_all_sync(b"incomplete").unwrap();
        drop(staged);
        drop(history);

        assert!(History::open(directory.path(), 1024 * 1024).is_err());
        assert!(staged_path.exists());
    }
}
