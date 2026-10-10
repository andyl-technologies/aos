//! Encodes fixed device-digest purpose evidence inside the sealed setup plan.
//!
//! These values describe an issued purpose; decoding them does not issue credit,
//! authenticate its producer, or admit a worker. Native acceptance additionally
//! requires the genuine descriptor carrier and its matching compiled proof.
//!
//! ```text
//! 0..8      CRUCWSP1
//! 8..12     schema 1
//! 12..16    lifecycle scope (1 initial, 2 separately admitted child)
//! 16..48    matching source-proof digest
//! 48..72    unchanged TOTAL, fixed metadata purpose, fixed resident purpose
//! 72..96    process, account, workspace generations
//! 96..112   device, inode
//! 112..120  fixed native descriptor and mapping peaks
//! 120..128  fixed workspace bytes (65536)
//! ```

use thiserror::Error;

/// Canonical encoded bytes in one device-digest purpose record.
pub const DEVICE_DIGEST_PURPOSE_BYTES: usize = 128;

const MAGIC: [u8; 8] = *b"CRUCWSP1";
const VERSION: u32 = 1;
const WORKSPACE_BYTES: u64 = 65_536;

/// Identifies the lifecycle at which a separate purpose was issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceDigestPurposeScope {
    /// An initial process whose owner admits the purpose before its birth.
    Initial,
    /// A separately admitted child, including its inherited allocation overlap.
    Child,
}

/// Describes the fixed source-bound terms of an issued device-digest purpose.
///
/// This process-neutral evidence contains no pointer, capability, or account.
/// Native acceptance must compare these terms with its matching compiled proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDigestPurposeFields {
    /// Initial-process or genuinely separately admitted child lifecycle.
    pub scope: DeviceDigestPurposeScope,
    /// Digest of the immutable matched producer/native/worker proof edition.
    pub source_proof_digest: [u8; 32],
    /// Unchanged native TOTAL before any purpose or native-floor subtraction.
    pub original_total_metadata_bytes: u64,
    /// Fixed metadata subset, including the 65536-byte workspace exactly once.
    pub metadata_purpose_bytes: u64,
    /// Full resident purpose, including its metadata subset and resident-only terms.
    pub resident_purpose_bytes: u64,
    /// Actual prebirth process incarnation selected by the issuing owner.
    pub process_generation: u64,
    /// Actual admitted account generation retained by the issuing owner.
    pub account_generation: u64,
    /// Once-issued workspace generation within that same account.
    pub workspace_generation: u64,
    /// Actual workspace descriptor device identity.
    pub device: u64,
    /// Actual workspace descriptor inode identity.
    pub inode: u64,
    /// Matched native descriptor overlap, including staged and inherited aliases.
    pub native_descriptor_peak: u32,
    /// Matched native mapping overlap for this lifecycle scope.
    pub native_mapping_peak: u32,
}

/// Contains one syntactically validated fixed purpose-evidence record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDigestPurpose {
    fields: DeviceDigestPurposeFields,
}

impl DeviceDigestPurpose {
    /// Validates the fixed record's bounds and lifecycle identities.
    ///
    /// # Errors
    /// Refuses absent identities, invalid fixed terms, and inconsistent subsets.
    /// Successful validation does not authenticate an issuer or admit resources.
    pub fn new(fields: DeviceDigestPurposeFields) -> Result<Self, DeviceDigestPurposeError> {
        if fields.source_proof_digest == [0; 32]
            || fields.process_generation == 0
            || fields.account_generation == 0
            || fields.workspace_generation == 0
            || fields.inode == 0
            || fields.native_descriptor_peak == 0
            || fields.native_mapping_peak == 0
            || fields.metadata_purpose_bytes < WORKSPACE_BYTES
            || fields.metadata_purpose_bytes > fields.original_total_metadata_bytes
            || fields.metadata_purpose_bytes > fields.resident_purpose_bytes
        {
            return Err(DeviceDigestPurposeError::InvalidTerms);
        }
        Ok(Self { fields })
    }

    /// Borrows the scalar evidence for comparison with a matched source proof.
    #[must_use]
    pub const fn fields(&self) -> &DeviceDigestPurposeFields {
        &self.fields
    }

    /// Encodes the fixed record without allocating storage.
    #[must_use]
    pub fn encode(&self) -> [u8; DEVICE_DIGEST_PURPOSE_BYTES] {
        let mut bytes = [0; DEVICE_DIGEST_PURPOSE_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&VERSION.to_be_bytes());
        let scope: u32 = match self.fields.scope {
            DeviceDigestPurposeScope::Initial => 1,
            DeviceDigestPurposeScope::Child => 2,
        };
        bytes[12..16].copy_from_slice(&scope.to_be_bytes());
        bytes[16..48].copy_from_slice(&self.fields.source_proof_digest);
        for (offset, value) in [
            (48, self.fields.original_total_metadata_bytes),
            (56, self.fields.metadata_purpose_bytes),
            (64, self.fields.resident_purpose_bytes),
            (72, self.fields.process_generation),
            (80, self.fields.account_generation),
            (88, self.fields.workspace_generation),
            (96, self.fields.device),
            (104, self.fields.inode),
            (120, WORKSPACE_BYTES),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[112..116].copy_from_slice(&self.fields.native_descriptor_peak.to_be_bytes());
        bytes[116..120].copy_from_slice(&self.fields.native_mapping_peak.to_be_bytes());
        bytes
    }

    /// Decodes exactly one fixed record, without issuing resource authority.
    ///
    /// # Errors
    /// Refuses wrong framing, magic, schema, scope, workspace size, or terms.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeviceDigestPurposeError> {
        let bytes: &[u8; DEVICE_DIGEST_PURPOSE_BYTES] = bytes
            .try_into()
            .map_err(|_| DeviceDigestPurposeError::InvalidFraming)?;
        let u32_at = |offset: usize| {
            let mut value = [0; 4];
            value.copy_from_slice(&bytes[offset..offset + 4]);
            u32::from_be_bytes(value)
        };
        let u64_at = |offset: usize| {
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_be_bytes(value)
        };
        if bytes[..8] != MAGIC || u32_at(8) != VERSION || u64_at(120) != WORKSPACE_BYTES {
            return Err(DeviceDigestPurposeError::InvalidFraming);
        }
        let scope = match u32_at(12) {
            1 => DeviceDigestPurposeScope::Initial,
            2 => DeviceDigestPurposeScope::Child,
            _ => return Err(DeviceDigestPurposeError::InvalidFraming),
        };
        let mut source_proof_digest = [0; 32];
        source_proof_digest.copy_from_slice(&bytes[16..48]);
        Self::new(DeviceDigestPurposeFields {
            scope,
            source_proof_digest,
            original_total_metadata_bytes: u64_at(48),
            metadata_purpose_bytes: u64_at(56),
            resident_purpose_bytes: u64_at(64),
            process_generation: u64_at(72),
            account_generation: u64_at(80),
            workspace_generation: u64_at(88),
            device: u64_at(96),
            inode: u64_at(104),
            native_descriptor_peak: u32_at(112),
            native_mapping_peak: u32_at(116),
        })
    }
}

/// Invalid fixed device-digest purpose evidence.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeviceDigestPurposeError {
    /// Length, magic, version, lifecycle scope, or fixed workspace size differs.
    #[error("device digest purpose framing is invalid")]
    InvalidFraming,
    /// An identity or fixed source-bound resource term is inconsistent.
    #[error("device digest purpose terms are invalid")]
    InvalidTerms,
}
