//! Connection-keyed canonical encoding for dormant worker recovery state.
//!
//! A codec is derived from one opaque prepared connection. It can serialize
//! only already-authorized opaque values, and every byte string carries a keyed
//! SHA-256 commitment checked in constant time. This crate has no direct HMAC
//! dependency in the source-only partition, so the commitment is deliberately
//! not described as a standard MAC. Decoding cannot turn caller-selected
//! identity scalars into connection, backing, or lifecycle authority.

use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest};
use sha2::{Digest, Sha256};

use super::{
    BackingIdentity, DurableLifecycleEvent, DurableRegistrationRecord, WorkerLifecycle,
    WorkerLifecycleSnapshot,
};

const MAGIC: &[u8; 8] = b"AOSDST01";
const HEADER_BYTES: usize = 17;
const TAG_BYTES: usize = 32;
const BACKING_KIND: u8 = 1;
const REGISTRATIONS_KIND: u8 = 2;
const LIFECYCLE_SNAPSHOT_KIND: u8 = 3;
const LIFECYCLE_EVENT_KIND: u8 = 4;

/// Bounds canonical recovery records before any allocation or decode work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableStateLimits {
    /// Maximum complete encoded bytes, including header and verification tag.
    pub maximum_bytes: usize,
    /// Maximum registration records in one snapshot.
    pub maximum_registration_records: usize,
}

/// Reports malformed, foreign, oversized, or unverified recovery state.
#[derive(Debug, thiserror::Error)]
pub enum DurableStateError {
    /// Codec limits are zero or cannot contain the fixed envelope.
    #[error("invalid durable-state limits")]
    InvalidLimit,
    /// Exact bounded allocation was refused or over-allocated.
    #[error("durable-state allocation was refused")]
    AllocationRefused,
    /// The record exceeds its admitted byte or entry ceiling.
    #[error("durable-state record exceeds its admitted ceiling")]
    ResourceExhausted,
    /// Canonical bytes, connection tag, discriminant, or sentinel is invalid.
    #[error("durable-state record failed canonical integrity validation")]
    Integrity,
    /// Registration-state validation failed.
    #[error("durable registration state is invalid: {0}")]
    Registration(#[from] super::DataError),
    /// Lifecycle-state validation failed.
    #[error("durable lifecycle state is invalid: {0}")]
    Lifecycle(#[from] super::LifecycleError),
}

/// Encodes and verifies recovery records for one exact prepared connection.
///
/// The private key is derived from trusted connection entropy and is never
/// exposed. Encoded bytes are persistence payloads, not live authority; decode
/// must succeed through the same authority-bound codec before restoration.
pub struct DurableStateCodec {
    authority_binding: [u8; 32],
    verification_key: [u8; 32],
    limits: DurableStateLimits,
}

impl DurableStateCodec {
    pub(super) fn new(
        authority_binding: [u8; 32],
        inode_key: [u8; 32],
        limits: DurableStateLimits,
    ) -> Result<Self, DurableStateError> {
        if authority_binding == [0; 32]
            || inode_key == [0; 32]
            || limits.maximum_registration_records == 0
            || limits.maximum_bytes < HEADER_BYTES + TAG_BYTES
        {
            return Err(DurableStateError::InvalidLimit);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"aos-filesystem-durable-state-key-v1\0");
        hasher.update(inode_key);
        hasher.update(authority_binding);
        let verification_key = hasher.finalize().into();
        Ok(Self {
            authority_binding,
            verification_key,
            limits,
        })
    }

    /// Encodes one verifier-issued backing identity canonically.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for a foreign backing or exceeded bound.
    pub fn encode_backing(&self, backing: BackingIdentity) -> Result<Vec<u8>, DurableStateError> {
        if backing.authority_binding() != self.authority_binding {
            return Err(DurableStateError::Integrity);
        }
        self.encode(BACKING_KIND, |writer| backing.encode_canonical(writer))
    }

    /// Decodes one connection-keyed backing identity for this exact connection.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for foreign, modified, malformed, or
    /// oversized bytes.
    pub fn decode_backing(&self, bytes: &[u8]) -> Result<BackingIdentity, DurableStateError> {
        let payload = self.decode(BACKING_KIND, bytes)?;
        let mut cursor = Cursor::new(payload);
        let backing = BackingIdentity::decode_canonical(&mut cursor, self.authority_binding)?;
        cursor.finish()?;
        Ok(backing)
    }

    /// Encodes ordered live passthrough-registration records canonically.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for a foreign record, excessive record
    /// count, invalid phase state, or exceeded byte bound.
    pub fn encode_registrations(
        &self,
        records: &[DurableRegistrationRecord],
    ) -> Result<Vec<u8>, DurableStateError> {
        if records.len() > self.limits.maximum_registration_records {
            return Err(DurableStateError::ResourceExhausted);
        }
        self.encode(REGISTRATIONS_KIND, |writer| {
            super::registration::encode_canonical_records(writer, records, self.authority_binding)
        })
    }

    /// Decodes bounded registration records without replaying OS effects.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for modified, foreign, malformed, unordered,
    /// or excessive records.
    pub fn decode_registrations(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<DurableRegistrationRecord>, DurableStateError> {
        let payload = self.decode(REGISTRATIONS_KIND, bytes)?;
        let mut cursor = Cursor::new(payload);
        let records = super::registration::decode_canonical_records(
            &mut cursor,
            self.authority_binding,
            self.limits.maximum_registration_records,
        )?;
        cursor.finish()?;
        Ok(records)
    }

    /// Encodes one complete lifecycle snapshot canonically.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] if the snapshot is foreign, incoherent, or
    /// exceeds the byte ceiling.
    pub fn encode_lifecycle_snapshot(
        &self,
        snapshot: &WorkerLifecycleSnapshot,
    ) -> Result<Vec<u8>, DurableStateError> {
        self.encode(LIFECYCLE_SNAPSHOT_KIND, |writer| {
            super::lifecycle::encode_canonical_snapshot(writer, snapshot, self.authority_binding)
        })
    }

    /// Decodes and restores one exact connection-keyed lifecycle snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for modified, foreign, malformed, or
    /// incoherent state.
    pub fn restore_lifecycle_snapshot(
        &self,
        bytes: &[u8],
    ) -> Result<WorkerLifecycle, DurableStateError> {
        let payload = self.decode(LIFECYCLE_SNAPSHOT_KIND, bytes)?;
        let mut cursor = Cursor::new(payload);
        let snapshot =
            super::lifecycle::decode_canonical_snapshot(&mut cursor, self.authority_binding)?;
        cursor.finish()?;
        Ok(WorkerLifecycle::restore(snapshot)?)
    }

    /// Encodes one opaque canonical lifecycle journal event.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] when the event is foreign, malformed, or
    /// exceeds the byte ceiling.
    pub fn encode_lifecycle_event(
        &self,
        event: &DurableLifecycleEvent,
    ) -> Result<Vec<u8>, DurableStateError> {
        self.encode(LIFECYCLE_EVENT_KIND, |writer| {
            super::lifecycle::encode_canonical_event(writer, event, self.authority_binding)
        })
    }

    /// Decodes one connection-keyed canonical lifecycle journal event.
    ///
    /// # Errors
    ///
    /// Returns [`DurableStateError`] for modified, foreign, malformed, or
    /// oversized event bytes.
    pub fn decode_lifecycle_event(
        &self,
        bytes: &[u8],
    ) -> Result<DurableLifecycleEvent, DurableStateError> {
        let payload = self.decode(LIFECYCLE_EVENT_KIND, bytes)?;
        let mut cursor = Cursor::new(payload);
        let event = super::lifecycle::decode_canonical_event(&mut cursor, self.authority_binding)?;
        cursor.finish()?;
        Ok(event)
    }

    fn encode(
        &self,
        kind: u8,
        encode_payload: impl FnOnce(&mut Writer) -> Result<(), DurableStateError>,
    ) -> Result<Vec<u8>, DurableStateError> {
        let mut payload = Writer::new(self.limits.maximum_bytes - HEADER_BYTES - TAG_BYTES)?;
        encode_payload(&mut payload)?;
        let payload = payload.finish();
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableStateError::ResourceExhausted)?;

        let mut output = Writer::new(self.limits.maximum_bytes)?;
        output.bytes(MAGIC)?;
        output.u8(kind)?;
        output.u64(payload_len)?;
        output.bytes(&payload)?;
        let tag = self.tag(kind, &payload);
        output.bytes(&tag)?;
        Ok(output.finish())
    }

    fn decode<'a>(
        &self,
        expected_kind: u8,
        bytes: &'a [u8],
    ) -> Result<&'a [u8], DurableStateError> {
        if bytes.len() > self.limits.maximum_bytes || bytes.len() < HEADER_BYTES + TAG_BYTES {
            return Err(DurableStateError::ResourceExhausted);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) || bytes.get(8).copied() != Some(expected_kind)
        {
            return Err(DurableStateError::Integrity);
        }
        let length_bytes: [u8; 8] = bytes
            .get(9..17)
            .ok_or(DurableStateError::Integrity)?
            .try_into()
            .map_err(|_| DurableStateError::Integrity)?;
        let payload_len = usize::try_from(u64::from_be_bytes(length_bytes))
            .map_err(|_| DurableStateError::ResourceExhausted)?;
        let payload_end = HEADER_BYTES
            .checked_add(payload_len)
            .ok_or(DurableStateError::ResourceExhausted)?;
        let expected_end = payload_end
            .checked_add(TAG_BYTES)
            .ok_or(DurableStateError::ResourceExhausted)?;
        if expected_end != bytes.len() {
            return Err(DurableStateError::Integrity);
        }
        let payload = bytes
            .get(HEADER_BYTES..payload_end)
            .ok_or(DurableStateError::Integrity)?;
        let tag = bytes
            .get(payload_end..)
            .ok_or(DurableStateError::Integrity)?;
        let expected_tag = self.tag(expected_kind, payload);
        if !constant_time_eq(tag, &expected_tag) {
            return Err(DurableStateError::Integrity);
        }
        Ok(payload)
    }

    fn tag(&self, kind: u8, payload: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"aos-filesystem-durable-state-tag-v1\0");
        hasher.update(self.verification_key);
        hasher.update(self.authority_binding);
        hasher.update([kind]);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        hasher.update(self.verification_key);
        hasher.finalize().into()
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

pub(super) struct Writer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Writer {
    fn new(maximum: usize) -> Result<Self, DurableStateError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| DurableStateError::AllocationRefused)?;
        if bytes.capacity() > maximum {
            return Err(DurableStateError::ResourceExhausted);
        }
        Ok(Self { bytes, maximum })
    }

    pub(super) fn u8(&mut self, value: u8) -> Result<(), DurableStateError> {
        self.bytes(&[value])
    }

    pub(super) fn u32(&mut self, value: u32) -> Result<(), DurableStateError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), DurableStateError> {
        self.bytes(&value.to_be_bytes())
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), DurableStateError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(DurableStateError::ResourceExhausted)?;
        if next > self.maximum {
            return Err(DurableStateError::ResourceExhausted);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(super) fn descriptor(
        &mut self,
        descriptor: &ObjectDescriptor,
    ) -> Result<(), DurableStateError> {
        let media = descriptor.media_type().as_str().as_bytes();
        let length = u8::try_from(media.len()).map_err(|_| DurableStateError::Integrity)?;
        self.u8(length)?;
        self.bytes(media)?;
        self.bytes(descriptor.digest().as_bytes())?;
        self.u64(descriptor.encoded_size())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub(super) struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(super) fn u8(&mut self) -> Result<u8, DurableStateError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(DurableStateError::Integrity)?;
        self.position += 1;
        Ok(value)
    }

    pub(super) fn u32(&mut self) -> Result<u32, DurableStateError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, DurableStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], DurableStateError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(DurableStateError::Integrity)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableStateError::Integrity)?
            .try_into()
            .map_err(|_| DurableStateError::Integrity)?;
        self.position = end;
        Ok(value)
    }

    pub(super) fn descriptor(&mut self) -> Result<ObjectDescriptor, DurableStateError> {
        let media_len = usize::from(self.u8()?);
        if media_len == 0 {
            return Err(DurableStateError::Integrity);
        }
        let end = self
            .position
            .checked_add(media_len)
            .ok_or(DurableStateError::Integrity)?;
        let media_bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(DurableStateError::Integrity)?;
        let mut media = String::new();
        media
            .try_reserve_exact(media_len)
            .map_err(|_| DurableStateError::AllocationRefused)?;
        if media.capacity() > media_len {
            return Err(DurableStateError::ResourceExhausted);
        }
        media.push_str(std::str::from_utf8(media_bytes).map_err(|_| DurableStateError::Integrity)?);
        self.position = end;
        let media_type = MediaType::new(media).map_err(|_| DurableStateError::Integrity)?;
        let digest = ObjectDigest::from_bytes(self.array()?);
        let encoded_size = self.u64()?;
        if digest.as_bytes() == &[0; 32] || encoded_size == 0 {
            return Err(DurableStateError::Integrity);
        }
        Ok(ObjectDescriptor::new(media_type, digest, encoded_size))
    }

    fn finish(self) -> Result<(), DurableStateError> {
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(DurableStateError::Integrity)
    }
}
