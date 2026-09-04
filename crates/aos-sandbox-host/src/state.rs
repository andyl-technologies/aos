//! Checksummed atomic host fences and request replay state.
//!
//! The on-disk format is a bounded JSON body inside a fixed binary envelope:
//!
//! ```text
//! magic[8] | version:u32-le | body-length:u64-le | sha256[32] | body
//! ```
//!
//! JSON is an internal node-local format, not a portable or wire contract.
//! Unknown fields, checksum failures, overlong bodies, duplicate identities,
//! and invalid pending/completed records fail closed during startup.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;

use aos_sandbox_protocol::ValidatedAssignmentFence;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{HostError, Result};

const MAGIC: &[u8; 8] = b"AOSHOST\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 8 + 4 + 8 + 32;
const MAXIMUM_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_REQUESTS: usize = 16_384;
const MAXIMUM_RECEIPT_BYTES: usize = 1024 * 1024;

/// Reports whether an exact request is new, pending after a crash, or complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The fence and pending intent were newly persisted.
    New,
    /// The same request was already durably pending and must be reconciled.
    Pending,
    /// The exact completed request replayed its persisted response bytes.
    Complete(Vec<u8>),
}

/// In-memory form of a fully validated durable host snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostState {
    fences: BTreeMap<[u8; 16], DurableFence>,
    requests: BTreeMap<[u8; 16], RequestRecord>,
    observation_sequences: BTreeMap<[u8; 16], u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableFence {
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    request_id: [u8; 16],
    request_digest: [u8; 32],
    fence: DurableFence,
    action: u8,
    receipt: Option<Vec<u8>>,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateWire {
    fences: Vec<DurableFence>,
    requests: Vec<RequestRecord>,
    observation_sequences: Vec<ObservationSequence>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationSequence {
    incarnation_id: [u8; 16],
    sequence: u64,
}

impl HostState {
    pub(crate) fn admit(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        action: u8,
    ) -> Result<Admission> {
        if let Some(record) = self.requests.get(&request_id) {
            if record.request_digest != request_digest {
                return Err(HostError::Fence(
                    "request ID was reused with different bytes",
                ));
            }
            return Ok(match &record.receipt {
                Some(receipt) => Admission::Complete(receipt.clone()),
                None => Admission::Pending,
            });
        }
        if self.requests.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table reached its fixed bound".to_owned(),
            ));
        }

        let proposed = DurableFence::from_validated(fence);
        if let Some(current) = self.fences.get(fence.sandbox_id()) {
            current.validate_successor(proposed)?;
        }
        self.fences.insert(*fence.sandbox_id(), proposed);
        self.requests.insert(
            request_id,
            RequestRecord {
                request_id,
                request_digest,
                fence: proposed,
                action,
                receipt: None,
            },
        );
        Ok(Admission::New)
    }

    pub(crate) fn complete(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        receipt: Vec<u8>,
    ) -> Result<()> {
        if receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(HostError::State(
                "host replay receipt is empty or exceeds one MiB".to_owned(),
            ));
        }
        let record = self.requests.get_mut(&request_id).ok_or(HostError::State(
            "pending host request disappeared".to_owned(),
        ))?;
        if record.request_digest != request_digest {
            return Err(HostError::Fence(
                "completion digest differs from pending request",
            ));
        }
        if let Some(existing) = &record.receipt {
            return if existing == &receipt {
                Ok(())
            } else {
                Err(HostError::Fence(
                    "completed request produced conflicting response bytes",
                ))
            };
        }
        record.receipt = Some(receipt);
        Ok(())
    }

    pub(crate) fn next_observation_sequence(&mut self, incarnation: [u8; 16]) -> Result<u64> {
        let sequence = self.observation_sequences.entry(incarnation).or_default();
        *sequence = sequence
            .checked_add(1)
            .ok_or_else(|| HostError::State("observation sequence overflow".to_owned()))?;
        Ok(*sequence)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let wire = StateWire {
            fences: self.fences.values().copied().collect(),
            requests: self.requests.values().cloned().collect(),
            observation_sequences: self
                .observation_sequences
                .iter()
                .map(|(incarnation_id, sequence)| ObservationSequence {
                    incarnation_id: *incarnation_id,
                    sequence: *sequence,
                })
                .collect(),
        };
        serde_json::to_vec(&wire).map_err(|error| HostError::State(error.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: StateWire =
            serde_json::from_slice(bytes).map_err(|error| HostError::State(error.to_string()))?;
        if wire.requests.len() > MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table exceeds its fixed bound".to_owned(),
            ));
        }
        let mut state = Self::default();
        for fence in wire.fences {
            validate_fence(fence)?;
            if state.fences.insert(fence.sandbox_id, fence).is_some() {
                return Err(HostError::State(
                    "duplicate durable sandbox fence".to_owned(),
                ));
            }
        }
        for request in wire.requests {
            validate_request(&request)?;
            if state.requests.insert(request.request_id, request).is_some() {
                return Err(HostError::State("duplicate durable request ID".to_owned()));
            }
        }
        for observation in wire.observation_sequences {
            if observation.incarnation_id == [0; 16]
                || observation.sequence == 0
                || state
                    .observation_sequences
                    .insert(observation.incarnation_id, observation.sequence)
                    .is_some()
            {
                return Err(HostError::State(
                    "invalid durable observation sequence".to_owned(),
                ));
            }
        }
        Ok(state)
    }
}

impl DurableFence {
    fn from_validated(fence: &ValidatedAssignmentFence) -> Self {
        Self {
            sandbox_id: *fence.sandbox_id(),
            incarnation_id: *fence.incarnation_id(),
            assignment_epoch: fence.assignment_epoch(),
            desired_generation: fence.desired_generation(),
            assignment_digest: *fence.assignment_digest(),
        }
    }

    fn validate_successor(self, proposed: Self) -> Result<()> {
        if proposed.assignment_epoch < self.assignment_epoch
            || (proposed.assignment_epoch == self.assignment_epoch
                && proposed.desired_generation < self.desired_generation)
        {
            return Err(HostError::Fence("assignment generation is stale"));
        }
        if proposed.assignment_epoch == self.assignment_epoch {
            if proposed.incarnation_id != self.incarnation_id {
                return Err(HostError::Fence(
                    "equal assignment epoch changed incarnation",
                ));
            }
            if proposed.desired_generation == self.desired_generation
                && proposed.assignment_digest != self.assignment_digest
            {
                return Err(HostError::Fence(
                    "equal assignment generation changed semantic digest",
                ));
            }
        }
        Ok(())
    }
}

fn validate_fence(fence: DurableFence) -> Result<()> {
    if fence.sandbox_id == [0; 16]
        || fence.incarnation_id == [0; 16]
        || fence.assignment_epoch == 0
        || fence.desired_generation == 0
        || fence.assignment_digest == [0; 32]
    {
        return Err(HostError::State(
            "durable assignment fence contains a sentinel".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request(request: &RequestRecord) -> Result<()> {
    validate_fence(request.fence)?;
    if request.request_id == [0; 16]
        || request.request_digest == [0; 32]
        || request.action == 0
        || request
            .receipt
            .as_ref()
            .is_some_and(|receipt| receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES)
    {
        return Err(HostError::State(
            "durable host request record is invalid".to_owned(),
        ));
    }
    Ok(())
}

/// Persists complete host state before and after every privileged effect.
pub trait HostStateStore {
    /// Loads and validates the current durable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O, bounds, checksum, schema, or invariant
    /// failures. Missing state initializes an empty broker.
    fn load(&self) -> Result<HostState>;

    /// Atomically commits one complete replacement snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error unless file contents and the containing directory are
    /// durably synchronized.
    fn commit(&self, state: &HostState) -> Result<()>;
}

/// Stores one checksummed snapshot beneath a pre-created private directory.
#[derive(Clone, Debug)]
pub struct FileHostStateStore {
    directory: PathBuf,
    state_path: PathBuf,
    temporary_path: PathBuf,
}

impl FileHostStateStore {
    /// Opens a private state directory and fixes the state filename.
    ///
    /// # Errors
    ///
    /// Returns an error unless `directory` is a real directory with no group
    /// or other permission bits. Symlink directories are rejected.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| HostError::State(error.to_string()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(HostError::State(
                "host state directory must be a private real directory".to_owned(),
            ));
        }
        Ok(Self {
            state_path: directory.join("state.bin"),
            temporary_path: directory.join("state.next"),
            directory,
        })
    }

    fn write_atomic(&self, bytes: &[u8]) -> Result<()> {
        match fs::remove_file(&self.temporary_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(HostError::State(error.to_string())),
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.temporary_path)
            .map_err(|error| HostError::State(error.to_string()))?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| HostError::State(error.to_string()))?;
        fs::rename(&self.temporary_path, &self.state_path)
            .map_err(|error| HostError::State(error.to_string()))?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| HostError::State(error.to_string()))
    }
}

impl HostStateStore for FileHostStateStore {
    fn load(&self) -> Result<HostState> {
        let mut input = match File::open(&self.state_path) {
            Ok(input) => input,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HostState::default()),
            Err(error) => return Err(HostError::State(error.to_string())),
        };
        let file_length = usize::try_from(
            input
                .metadata()
                .map_err(|error| HostError::State(error.to_string()))?
                .size(),
        )
        .map_err(|_| HostError::State("host state size does not fit usize".to_owned()))?;
        if !(HEADER_BYTES..=HEADER_BYTES + MAXIMUM_STATE_BYTES).contains(&file_length) {
            return Err(HostError::State(
                "host state file length is outside its fixed bounds".to_owned(),
            ));
        }
        let mut bytes = vec![0; file_length];
        input
            .read_exact(&mut bytes)
            .map_err(|error| HostError::State(error.to_string()))?;
        decode_envelope(&bytes)
    }

    fn commit(&self, state: &HostState) -> Result<()> {
        let body = state.encode()?;
        if body.len() > MAXIMUM_STATE_BYTES {
            return Err(HostError::State(
                "encoded host state exceeds sixteen MiB".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(body.len())
                .map_err(|_| HostError::State("host state size overflow".to_owned()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&Sha256::digest(&body));
        bytes.extend_from_slice(&body);
        self.write_atomic(&bytes)
    }
}

fn decode_envelope(bytes: &[u8]) -> Result<HostState> {
    if &bytes[..8] != MAGIC {
        return Err(HostError::State("host state magic mismatch".to_owned()));
    }
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| HostError::State("host state version field is truncated".to_owned()))?,
    );
    if version != VERSION {
        return Err(HostError::State(
            "host state version is unsupported".to_owned(),
        ));
    }
    let body_length =
        usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().map_err(
            |_| HostError::State("host state length field is truncated".to_owned()),
        )?))
        .map_err(|_| HostError::State("host state body length does not fit usize".to_owned()))?;
    if body_length > MAXIMUM_STATE_BYTES || HEADER_BYTES + body_length != bytes.len() {
        return Err(HostError::State(
            "host state body length is inconsistent".to_owned(),
        ));
    }
    let expected: [u8; 32] = bytes[20..52]
        .try_into()
        .map_err(|_| HostError::State("host state checksum is truncated".to_owned()))?;
    let body = &bytes[HEADER_BYTES..];
    if Sha256::digest(body).as_slice() != expected {
        return Err(HostError::State("host state checksum mismatch".to_owned()));
    }
    HostState::decode(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn empty_state_round_trips_and_checksum_corruption_fails() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open(directory.path()).unwrap();
        store.commit(&HostState::default()).unwrap();
        assert!(store.load().is_ok());

        let path = directory.path().join("state.bin");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn public_state_directory_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileHostStateStore::open(directory.path()).is_err());
    }
}
