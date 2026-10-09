//! Canonical, bounded block-fault continuation codec.

use super::*;
use crate::snapshot_codec::{
    SnapshotEncodeError, SnapshotResourceError, admit_input, encode_prefixed_with_admission,
    map_decode_error,
};

/// Maximum canonical byte length of one persisted block-fault continuation.
pub const MAX_BLOCK_FAULT_STATE_BYTES: u64 = 536_870_912;

const BLOCK_FAULT_STATE_MAGIC: &[u8] = b"crucible.block-fault-state.v4\0";

impl BlockFaultState {
    /// Encodes every storage-fault continuation field in its canonical envelope.
    ///
    /// # Errors
    ///
    /// Returns [`BlockFaultStateCodecError`] if serialization fails or the
    /// resulting state exceeds the compiled checkpoint ceiling.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BlockFaultStateCodecError> {
        self.to_canonical_bytes_with_limit(MAX_BLOCK_FAULT_STATE_BYTES)
    }

    /// Encodes the continuation under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BlockFaultStateCodecError`] under the same conditions as
    /// [`Self::to_canonical_bytes`], and when the representation exceeds
    /// `maximum`.
    pub fn to_canonical_bytes_with_limit(
        &self,
        maximum: u64,
    ) -> Result<Vec<u8>, BlockFaultStateCodecError> {
        self.to_canonical_bytes_with_admission(maximum, &mut |_| Ok(()))
    }

    pub(crate) fn to_canonical_bytes_with_admission(
        &self,
        maximum: u64,
        admit_output: &mut dyn FnMut(u64) -> Result<(), &'static str>,
    ) -> Result<Vec<u8>, BlockFaultStateCodecError> {
        if self.observation_mutation_active {
            return Err(BlockFaultStateCodecError::Invalid);
        }
        encode_prefixed_with_admission(
            self,
            BLOCK_FAULT_STATE_MAGIC,
            "block fault-state bytes",
            maximum,
            MAX_BLOCK_FAULT_STATE_BYTES,
            admit_output,
        )
        .map_err(map_encode_error)
    }

    /// Decodes and deeply validates a complete block-fault continuation.
    ///
    /// # Errors
    ///
    /// Returns [`BlockFaultStateCodecError`] for unsupported, malformed,
    /// over-limit, noncanonical, or restore-invalid state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        device_length: u64,
    ) -> Result<Self, BlockFaultStateCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, device_length, MAX_BLOCK_FAULT_STATE_BYTES)
    }

    /// Decodes the continuation under an enclosing checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BlockFaultStateCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `maximum`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        device_length: u64,
        maximum: u64,
    ) -> Result<Self, BlockFaultStateCodecError> {
        Self::from_canonical_bytes_with_decoder(
            bytes,
            device_length,
            maximum,
            &mut |_| Ok(()),
            |payload| ciborium::de::from_reader(payload),
        )
    }

    /// Decodes nested fault state through the enclosing owner's parser.
    ///
    /// The supplied parser retains its original account and typed refusal
    /// separately from this codec's fixed relay. The output callback admits
    /// the counted canonical validation buffer before reservation. Restore
    /// validation's other allocations retain their separate purposes.
    ///
    /// # Errors
    /// Returns a fixed malformed relay for a supplied parser failure, or the
    /// same version, resource, restore and canonical failures as
    /// [`Self::from_canonical_bytes_with_limit`].
    pub fn from_canonical_bytes_with_decoder<F>(
        bytes: &[u8],
        device_length: u64,
        maximum: u64,
        admit_output: &mut dyn FnMut(u64) -> Result<(), &'static str>,
        decode: F,
    ) -> Result<Self, BlockFaultStateCodecError>
    where
        F: FnOnce(&[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>>,
    {
        let payload = bytes
            .strip_prefix(BLOCK_FAULT_STATE_MAGIC)
            .ok_or(BlockFaultStateCodecError::Version)?;
        admit_input(
            bytes,
            "block fault-state bytes",
            maximum,
            MAX_BLOCK_FAULT_STATE_BYTES,
        )
        .map_err(map_resource_error)?;
        let state = decode(payload).map_err(|error| {
            map_decode_error(error).map_or(BlockFaultStateCodecError::Malformed, map_resource_error)
        })?;
        state
            .validate_restore(device_length)
            .map_err(|_| BlockFaultStateCodecError::Invalid)?;
        if state
            .to_canonical_bytes_with_admission(maximum, admit_output)?
            .as_slice()
            != bytes
        {
            return Err(BlockFaultStateCodecError::Noncanonical);
        }
        Ok(state)
    }
}

/// Failure to encode or authenticate persisted block-fault state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BlockFaultStateCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported block-fault state version")]
    Version,
    /// The state could not be serialized or decoded.
    #[error("malformed block-fault state")]
    Malformed,
    /// The state exceeds a configured or compiled resource ceiling.
    #[error(
        "block-fault state resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Resource field that rejected the operation.
        field: &'static str,
        /// Bytes or entries already retained by the operation.
        current: u64,
        /// Additional bytes or entries requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// The state violates live restore invariants.
    #[error("block-fault state violates restore invariants")]
    Invalid,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical block-fault state")]
    Noncanonical,
}

fn map_encode_error(error: SnapshotEncodeError) -> BlockFaultStateCodecError {
    match error {
        SnapshotEncodeError::Malformed => BlockFaultStateCodecError::Malformed,
        SnapshotEncodeError::Resource(error) => map_resource_error(error),
    }
}

fn map_resource_error(error: SnapshotResourceError) -> BlockFaultStateCodecError {
    BlockFaultStateCodecError::ResourceLimit {
        field: error.field,
        current: error.current,
        requested: error.requested,
        configured: error.configured,
        hard: error.hard,
    }
}
