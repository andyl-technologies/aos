//! Owns established policy-hold record DATA without native writer authority.
//!
//! These codecs preserve the original physical bytes and canonical checks.
//! Held/released values are comparison DATA: mutation, currentness, signing,
//! Root grants and protected writer disposition stay with actual native owners.

//! Canonical records retain their established layouts:
//!
//! ```text
//! AOSSDH01 | version:u16 | held/released:u8 | reserved:5 |
//! operation:16 | sandbox:16 | controller-source:32 | ancestry:32 |
//! binding:32 | epoch:u64 | domain-separated SHA256:32
//! AOSSDP08 | version:u16 | pending:u8 | reserved:5 |
//! binding:32 | epoch:u64 | held-record:32 | released-record:32 | SHA256:32
//! ```
//!
use aos_sandbox_model::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};
use super::ProtectedHistoryDataErrorV1;

const MAGIC: &[u8; 8] = b"AOSSDH01";
const V8_PENDING_MAGIC: &[u8; 8] = b"AOSSDP08";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-hold.v1\0";
const V8_PENDING_CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.source-domain-policy-v8-pending-settlement.v1\0";
const RECORD_BYTES: usize = 184;
const V8_PENDING_RECORD_BYTES: usize = 152;

/// Identifies one exact, nonauthorizing source-domain policy hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainPolicyHoldV1 {
    operation: OperationId,
    sandbox: SandboxId,
    controller_source: ObjectDigest,
    ancestry: ObjectDigest,
    binding: ObjectDigest,
    epoch: u64,
    held: bool,
}

impl SourceDomainPolicyHoldV1 {
    /// Returns the same fields with the held phase as comparison DATA.
    ///
    /// Native writer membership and mutation authority remain independent.
    #[must_use]
    pub const fn held_data(self) -> Self {
        Self { held: true, ..self }
    }

    /// Returns the same fields with the released phase as comparison DATA.
    ///
    /// This cannot release a writer, clear a gate or create a current loan.
    #[must_use]
    pub const fn released_data(self) -> Self {
        Self { held: false, ..self }
    }

    /// Constructs canonical comparison DATA for the exact proposal ancestry.
    ///
    /// # Errors
    ///
    /// Rejects a zero identity, commitment, or epoch.
    pub fn new(
        operation: OperationId,
        sandbox: SandboxId,
        controller_source: ObjectDigest,
        ancestry: ObjectDigest,
        binding: ObjectDigest,
        epoch: u64,
    ) -> Result<Self, ProtectedHistoryDataErrorV1> {
        let hold = Self {
            operation,
            sandbox,
            controller_source,
            ancestry,
            binding,
            epoch,
            held: true,
        };
        hold.validate()?;
        Ok(hold)
    }

    /// Returns the accepted Create operation fixed by this hold.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the accepted Create sandbox fixed by this hold.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }

    /// Returns the Controller source commitment observed under its writer.
    #[must_use]
    pub const fn controller_source(self) -> ObjectDigest {
        self.controller_source
    }

    /// Returns the exact hierarchy ancestry head held for this Create.
    #[must_use]
    pub const fn ancestry(self) -> ObjectDigest {
        self.ancestry
    }

    /// Returns the root binding digest fixed before Q04 submission.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the root handoff epoch fixed before Q04 submission.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Reports whether this record encodes the held phase.
    #[must_use]
    pub const fn is_held(self) -> bool {
        self.held
    }

    /// Returns the digest of the exact canonical held or released record.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Source hold.
    pub fn record_digest(self) -> Result<ObjectDigest, ProtectedHistoryDataErrorV1> {
        Ok(ObjectDigest::from_bytes(
            Sha256::digest(self.encode()?).into(),
        ))
    }

    // This reuses the sole record encoder for equality DATA. It supplies no
    // Source writer, observed release, settlement permission or authority.
    /// Returns canonical released-record comparison DATA for this same hold.
    ///
    /// This neither releases a writer nor proves a native transition.
    ///
    /// # Errors
    /// Rejects invalid canonical hold fields.
    pub fn q04_released_record_digest(self) -> Result<ObjectDigest, ProtectedHistoryDataErrorV1> {
        Self { held: false, ..self }.record_digest()
    }

    /// Checks canonical identity DATA without native custody or admission.
    ///
    /// # Errors
    /// Rejects the existing reserved identity or epoch sentinels.
    pub fn validate(self) -> Result<(), ProtectedHistoryDataErrorV1> {
        if self.operation.as_bytes() == &[0; 16]
            || self.sandbox.as_bytes() == &[0; 16]
            || self.controller_source.as_bytes() == &[0; 32]
            || self.ancestry.as_bytes() == &[0; 32]
            || self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(())
    }

    /// Encodes the exact established canonical record as nonauthorizing DATA.
    ///
    /// # Errors
    /// Rejects fields that fail the existing canonical record constraints.
    pub fn encode(self) -> Result<[u8; RECORD_BYTES], ProtectedHistoryDataErrorV1> {
        self.validate()?;
        let mut bytes = [0_u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = if self.held { 1 } else { 2 };
        bytes[16..32].copy_from_slice(self.operation.as_bytes());
        bytes[32..48].copy_from_slice(self.sandbox.as_bytes());
        bytes[48..80].copy_from_slice(self.controller_source.as_bytes());
        bytes[80..112].copy_from_slice(self.ancestry.as_bytes());
        bytes[112..144].copy_from_slice(self.binding.as_bytes());
        bytes[144..152].copy_from_slice(&self.epoch.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes[..152])
            .finalize();
        bytes[152..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes exact established bytes without proving native membership.
    ///
    /// # Errors
    /// Rejects malformed fields, reserved bytes, phase, version or checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != RECORD_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || !matches!(bytes[10], 1 | 2)
            || bytes[11..16] != [0; 5]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let hold = Self {
            operation: OperationId::from_bytes(
                bytes[16..32]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            sandbox: SandboxId::from_bytes(
                bytes[32..48]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            controller_source: ObjectDigest::from_bytes(
                bytes[48..80]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            ancestry: ObjectDigest::from_bytes(
                bytes[80..112]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            binding: ObjectDigest::from_bytes(
                bytes[112..144]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[144..152]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            held: bytes[10] == 1,
        };
        if hold.encode()?.as_slice() != bytes {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(hold)
    }
}

/// Retains exact V8 Source release evidence until Root successor settlement.
///
/// This owner-local marker is not a Controller or Root release authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDomainPolicyV8PendingSettlementV1 {
    binding: ObjectDigest,
    epoch: u64,
    held_record: ObjectDigest,
    released_record: ObjectDigest,
}

impl SourceDomainPolicyV8PendingSettlementV1 {
    /// Constructs the exact pending-settlement comparison DATA.
    ///
    /// # Errors
    /// Rejects a released input or invalid canonical hold fields.
    pub fn new(expected: SourceDomainPolicyHoldV1) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if !expected.is_held() {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let released = SourceDomainPolicyHoldV1 {
            held: false,
            ..expected
        };
        Ok(Self {
            binding: expected.binding(),
            epoch: expected.epoch(),
            held_record: expected.record_digest()?,
            released_record: released.record_digest()?,
        })
    }

    /// Returns the binding whose released Source record remains protected.
    #[must_use]
    pub const fn binding(self) -> ObjectDigest {
        self.binding
    }

    /// Returns the protected binding's handoff epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Returns the digest of the canonical prior held Source record.
    #[must_use]
    pub const fn held_record_digest(self) -> ObjectDigest {
        self.held_record
    }

    /// Returns the digest of the canonical released Source record.
    #[must_use]
    pub const fn released_record_digest(self) -> ObjectDigest {
        self.released_record
    }

    /// Compares the two exact canonical hold commitments as DATA only.
    ///
    /// # Errors
    /// Rejects invalid canonical hold fields.
    pub fn matches_released(self, released: SourceDomainPolicyHoldV1) -> Result<bool, ProtectedHistoryDataErrorV1> {
        if released.is_held()
            || self.binding != released.binding()
            || self.epoch != released.epoch()
        {
            return Ok(false);
        }
        let held = SourceDomainPolicyHoldV1 {
            held: true,
            ..released
        };
        Ok(self.held_record == held.record_digest()?
            && self.released_record == released.record_digest()?)
    }

    /// Encodes the exact established canonical record as nonauthorizing DATA.
    ///
    /// # Errors
    /// Rejects fields that fail the existing canonical record constraints.
    pub fn encode(self) -> Result<[u8; V8_PENDING_RECORD_BYTES], ProtectedHistoryDataErrorV1> {
        if self.binding.as_bytes() == &[0; 32]
            || self.epoch == 0
            || self.held_record.as_bytes() == &[0; 32]
            || self.released_record.as_bytes() == &[0; 32]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let mut bytes = [0; V8_PENDING_RECORD_BYTES];
        bytes[..8].copy_from_slice(V8_PENDING_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = 1;
        bytes[16..48].copy_from_slice(self.binding.as_bytes());
        bytes[48..56].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[56..88].copy_from_slice(self.held_record.as_bytes());
        bytes[88..120].copy_from_slice(self.released_record.as_bytes());
        let checksum = Sha256::new()
            .chain_update(V8_PENDING_CHECKSUM_DOMAIN)
            .chain_update(&bytes[..120])
            .finalize();
        bytes[120..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    /// Decodes exact established bytes without proving native membership.
    ///
    /// # Errors
    /// Rejects malformed fields, reserved bytes, phase, version or checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != V8_PENDING_RECORD_BYTES
            || bytes.get(..8) != Some(V8_PENDING_MAGIC.as_slice())
            || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
            || bytes[10] != 1
            || bytes[11..16] != [0; 5]
        {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let marker = Self {
            binding: ObjectDigest::from_bytes(
                bytes[16..48]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            epoch: u64::from_be_bytes(
                bytes[48..56]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            held_record: ObjectDigest::from_bytes(
                bytes[56..88]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
            released_record: ObjectDigest::from_bytes(
                bytes[88..120]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            ),
        };
        if marker.encode()?.as_slice() != bytes {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        Ok(marker)
    }
}
