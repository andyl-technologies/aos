//! Versioned codec for the private fixed-ZFS-worker protocol.
//!
//! The closed version-two records are:
//!
//! ```text
//! REQUEST  = magic | version | verb | executable | operation | catalog
//! MUTATION = magic | version | success | timeout | stdout | stderr
//! OBSERVE  = magic | version | state | optional-guid | evidence-digest
//! ```

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use crate::observation::{ZfsObservationResult, ZfsObservationState};
use crate::{ResolvedCatalogCommitmentV1, StorageOperation, ZfsHelperContract, ZfsWorkerError};

use super::{Decoder, WorkerObservationOutcome, WorkerProcessOutput};

const REQUEST_MAGIC: &[u8; 8] = b"AOSZREQ2";
const MUTATION_RESPONSE_MAGIC: &[u8; 8] = b"AOSZRSP2";
const OBSERVATION_RESPONSE_MAGIC: &[u8; 8] = b"AOSZOBS2";

pub(super) const WIRE_VERSION: u16 = 2;
pub(super) const MAXIMUM_REQUEST_BYTES: usize = 24 * 1024;
pub(super) const MAXIMUM_RESPONSE_BYTES: usize = 132 * 1024;
pub(super) const MAXIMUM_OBSERVATION_RESPONSE_BYTES: usize = 52;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkerRequestVerb {
    Mutate,
    ObservePreconditions,
    ObservePostcondition,
}

impl WorkerRequestVerb {
    const fn code(self) -> u8 {
        match self {
            Self::Mutate => 1,
            Self::ObservePreconditions => 2,
            Self::ObservePostcondition => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, ZfsWorkerError> {
        match code {
            1 => Ok(Self::Mutate),
            2 => Ok(Self::ObservePreconditions),
            3 => Ok(Self::ObservePostcondition),
            _ => Err(ZfsWorkerError::Protocol("worker request verb is invalid")),
        }
    }
}

pub(super) struct WorkerRequest {
    pub(super) verb: WorkerRequestVerb,
    pub(super) executable: PathBuf,
    pub(super) operation: StorageOperation,
    pub(super) catalog: ResolvedCatalogCommitmentV1,
}

pub(super) fn encode_request(
    verb: WorkerRequestVerb,
    contract: &ZfsHelperContract,
    operation: StorageOperation,
    catalog: &ResolvedCatalogCommitmentV1,
) -> Result<Vec<u8>, ZfsWorkerError> {
    let path = contract.executable().as_os_str().as_encoded_bytes();
    let path_length = u16::try_from(path.len())
        .map_err(|_| ZfsWorkerError::Protocol("executable path is too long"))?;
    let catalog_length = u32::try_from(catalog.canonical_bytes().len())
        .map_err(|_| ZfsWorkerError::Protocol("catalog is too long"))?;
    let (code, storage, version, quota) = operation_fields(operation);
    let mut bytes = Vec::with_capacity(96 + path.len() + catalog.canonical_bytes().len());
    bytes.extend_from_slice(REQUEST_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.push(verb.code());
    bytes.extend_from_slice(&path_length.to_be_bytes());
    bytes.extend_from_slice(path);
    bytes.push(code);
    bytes.extend_from_slice(&storage.unwrap_or([0; 32]));
    bytes.extend_from_slice(&version.unwrap_or([0; 32]));
    bytes.extend_from_slice(&quota.to_be_bytes());
    bytes.extend_from_slice(&catalog_length.to_be_bytes());
    bytes.extend_from_slice(catalog.canonical_bytes());
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol("request exceeds byte ceiling"));
    }
    Ok(bytes)
}

pub(super) fn decode_request(bytes: &[u8]) -> Result<WorkerRequest, ZfsWorkerError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ZfsWorkerError::Protocol("request exceeds byte ceiling"));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != REQUEST_MAGIC || decoder.u16()? != WIRE_VERSION {
        return Err(ZfsWorkerError::Protocol(
            "request magic or version mismatch",
        ));
    }
    let verb = WorkerRequestVerb::from_code(decoder.byte()?)?;
    let path_length = usize::from(decoder.u16()?);
    let path = PathBuf::from(OsString::from_vec(decoder.take(path_length)?.to_vec()));
    let code = decoder.byte()?;
    let storage = optional_handle(decoder.array()?)?;
    let version = optional_handle(decoder.array()?)?;
    let quota = decoder.u64()?;
    let catalog_length = usize::try_from(decoder.u32()?)
        .map_err(|_| ZfsWorkerError::Protocol("catalog length does not fit usize"))?;
    let catalog = ResolvedCatalogCommitmentV1::from_canonical_bytes(decoder.take(catalog_length)?)
        .map_err(|_| ZfsWorkerError::Protocol("resolved catalog is invalid"))?;
    decoder.finish()?;
    let operation = operation_from_fields(code, storage, version, quota)?;
    Ok(WorkerRequest {
        verb,
        executable: path,
        operation,
        catalog,
    })
}

pub(super) fn encode_mutation_response(
    output: &WorkerProcessOutput,
) -> Result<Vec<u8>, ZfsWorkerError> {
    let stdout_length = u32::try_from(output.stdout.len())
        .map_err(|_| ZfsWorkerError::Protocol("stdout length does not fit u32"))?;
    let stderr_length = u32::try_from(output.stderr.len())
        .map_err(|_| ZfsWorkerError::Protocol("stderr length does not fit u32"))?;
    let mut bytes = Vec::with_capacity(20 + output.stdout.len() + output.stderr.len());
    bytes.extend_from_slice(MUTATION_RESPONSE_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.push(u8::from(output.success));
    bytes.push(u8::from(output.timed_out));
    bytes.extend_from_slice(&stdout_length.to_be_bytes());
    bytes.extend_from_slice(&stderr_length.to_be_bytes());
    bytes.extend_from_slice(&output.stdout);
    bytes.extend_from_slice(&output.stderr);
    if bytes.len() > MAXIMUM_RESPONSE_BYTES {
        return Err(ZfsWorkerError::Protocol("response exceeds byte ceiling"));
    }
    Ok(bytes)
}

pub(super) fn decode_mutation_response(
    bytes: &[u8],
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != MUTATION_RESPONSE_MAGIC || decoder.u16()? != WIRE_VERSION {
        return Err(ZfsWorkerError::Protocol(
            "response magic or version mismatch",
        ));
    }
    let success = bool_byte(decoder.byte()?)?;
    let timed_out = bool_byte(decoder.byte()?)?;
    if success && timed_out {
        return Err(ZfsWorkerError::Protocol(
            "timed-out response reports success",
        ));
    }
    let stdout_length = usize::try_from(decoder.u32()?)
        .map_err(|_| ZfsWorkerError::Protocol("stdout length does not fit usize"))?;
    let stderr_length = usize::try_from(decoder.u32()?)
        .map_err(|_| ZfsWorkerError::Protocol("stderr length does not fit usize"))?;
    if stdout_length > super::MAXIMUM_STDOUT_BYTES || stderr_length > super::MAXIMUM_STDERR_BYTES {
        return Err(ZfsWorkerError::Protocol("response output exceeds ceiling"));
    }
    let stdout = decoder.take(stdout_length)?.to_vec();
    let stderr = decoder.take(stderr_length)?.to_vec();
    decoder.finish()?;
    Ok(WorkerProcessOutput {
        stdout,
        stderr,
        success,
        timed_out,
    })
}

pub(super) fn encode_observation_response(
    observation: ZfsObservationResult,
) -> Result<Vec<u8>, ZfsWorkerError> {
    let (state, object_guid, digest) = match observation.state {
        ZfsObservationState::Matched => (
            1,
            observation.object_guid,
            observation.digest.ok_or(ZfsWorkerError::Protocol(
                "matched observation lacks a digest",
            ))?,
        ),
        ZfsObservationState::Incomplete => {
            if observation.object_guid.is_some() || observation.digest.is_some() {
                return Err(ZfsWorkerError::Protocol(
                    "incomplete observation carries matched evidence",
                ));
            }
            (2, None, aos_sandbox_core::ObjectDigest::from_bytes([0; 32]))
        }
        ZfsObservationState::Mismatch => {
            if observation.object_guid.is_some() || observation.digest.is_some() {
                return Err(ZfsWorkerError::Protocol(
                    "mismatched observation carries matched evidence",
                ));
            }
            (3, None, aos_sandbox_core::ObjectDigest::from_bytes([0; 32]))
        }
    };
    if state == 1 && digest.as_bytes() == &[0; 32] {
        return Err(ZfsWorkerError::Protocol(
            "matched observation digest is zero",
        ));
    }
    let mut bytes = Vec::with_capacity(MAXIMUM_OBSERVATION_RESPONSE_BYTES);
    bytes.extend_from_slice(OBSERVATION_RESPONSE_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.push(state);
    bytes.push(u8::from(object_guid.is_some()));
    bytes.extend_from_slice(&object_guid.unwrap_or(0).to_be_bytes());
    bytes.extend_from_slice(digest.as_bytes());
    debug_assert_eq!(bytes.len(), MAXIMUM_OBSERVATION_RESPONSE_BYTES);
    Ok(bytes)
}

pub(super) fn decode_observation_response(
    bytes: &[u8],
) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
    if bytes.len() != MAXIMUM_OBSERVATION_RESPONSE_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "observation response length is invalid",
        ));
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != OBSERVATION_RESPONSE_MAGIC || decoder.u16()? != WIRE_VERSION {
        return Err(ZfsWorkerError::Protocol(
            "observation response magic or version mismatch",
        ));
    }
    let state = decoder.byte()?;
    let has_guid = bool_byte(decoder.byte()?)?;
    let raw_guid = decoder.u64()?;
    let digest = aos_sandbox_core::ObjectDigest::from_bytes(decoder.array()?);
    decoder.finish()?;
    let object_guid = match (has_guid, raw_guid) {
        (false, 0) => None,
        (true, guid @ 1..) => Some(guid),
        _ => {
            return Err(ZfsWorkerError::Protocol(
                "observation object GUID shape is invalid",
            ));
        }
    };
    match state {
        1 if digest.as_bytes() != &[0; 32] => Ok(WorkerObservationOutcome::Matched {
            object_guid,
            observation_digest: digest,
        }),
        2 if object_guid.is_none() && digest.as_bytes() == &[0; 32] => {
            Ok(WorkerObservationOutcome::Incomplete)
        }
        3 if object_guid.is_none() && digest.as_bytes() == &[0; 32] => {
            Ok(WorkerObservationOutcome::Mismatch)
        }
        _ => Err(ZfsWorkerError::Protocol(
            "observation response state is inconsistent",
        )),
    }
}

fn operation_fields(operation: StorageOperation) -> (u8, Option<[u8; 32]>, Option<[u8; 32]>, u64) {
    match operation {
        StorageOperation::CreateWorkspace { quota_bytes } => (1, None, None, quota_bytes),
        StorageOperation::Snapshot { storage_handle } => (2, Some(storage_handle), None, 0),
        StorageOperation::HoldSnapshot {
            storage_handle,
            version_handle,
        } => (3, Some(storage_handle), Some(version_handle), 0),
        StorageOperation::ReleaseHold {
            storage_handle,
            version_handle,
        } => (4, Some(storage_handle), Some(version_handle), 0),
        StorageOperation::Clone {
            storage_handle,
            version_handle,
            quota_bytes,
        } => (5, Some(storage_handle), Some(version_handle), quota_bytes),
        StorageOperation::SetQuota {
            storage_handle,
            quota_bytes,
        } => (6, Some(storage_handle), None, quota_bytes),
        StorageOperation::Destroy {
            storage_handle,
            version_handle,
        } => (7, Some(storage_handle), version_handle, 0),
    }
}

fn operation_from_fields(
    code: u8,
    storage: Option<[u8; 32]>,
    version: Option<[u8; 32]>,
    quota: u64,
) -> Result<StorageOperation, ZfsWorkerError> {
    match (code, storage, version, quota) {
        (1, None, None, 1..) => Ok(StorageOperation::CreateWorkspace { quota_bytes: quota }),
        (2, Some(storage_handle), None, 0) => Ok(StorageOperation::Snapshot { storage_handle }),
        (3, Some(storage_handle), Some(version_handle), 0) => Ok(StorageOperation::HoldSnapshot {
            storage_handle,
            version_handle,
        }),
        (4, Some(storage_handle), Some(version_handle), 0) => Ok(StorageOperation::ReleaseHold {
            storage_handle,
            version_handle,
        }),
        (5, Some(storage_handle), Some(version_handle), 1..) => Ok(StorageOperation::Clone {
            storage_handle,
            version_handle,
            quota_bytes: quota,
        }),
        (6, Some(storage_handle), None, 1..) => Ok(StorageOperation::SetQuota {
            storage_handle,
            quota_bytes: quota,
        }),
        (7, Some(storage_handle), version_handle, 0) => Ok(StorageOperation::Destroy {
            storage_handle,
            version_handle,
        }),
        _ => Err(ZfsWorkerError::Protocol(
            "operation fields are inconsistent",
        )),
    }
}

fn optional_handle(bytes: [u8; 32]) -> Result<Option<[u8; 32]>, ZfsWorkerError> {
    if bytes == [0; 32] {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

fn bool_byte(value: u8) -> Result<bool, ZfsWorkerError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ZfsWorkerError::Protocol("boolean byte is invalid")),
    }
}
