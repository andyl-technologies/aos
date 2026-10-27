//! Owns the sole immutable V1/V2 failed-Create receipt codecs.

use super::*;

const MAGIC: &[u8; 8] = b"AOSCFB01";
const DOMAIN: &[u8] = b"aos.sandbox.create-failed-before-commit.v1\0";
const VERSION: u16 = 1;
const RECEIPT_BYTES: usize = 8 + 2 + 2 + 32 * 3 + HOST_EXECUTION_NO_APPLY_RECORD_BYTES_V1 + 32 * 3 + 8 + 4 + 8 + 32;
const RESOURCE_VERSION_DOMAIN: &[u8] = b"aos.sandbox.failed-create-resource-version.v1\0";
const RECEIPT_MAGIC: &[u8; 8] = b"AOSCFB02";
const RECEIPT_DOMAIN: &[u8] = b"aos.sandbox.create-failed-before-commit.closed.v2\0";
const RESOURCE_DOMAIN: &[u8] = b"aos.sandbox.failed-create-resource-version.closed.v2\0";
pub(super) const RECEIPT_BYTES_V2: usize = 12 + 64 + BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2 + 96 + 8 + 4 + 8 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Retains the immutable legacy terminal receipt.
pub struct CreateFailureReceiptV1 {
    /// Retains the canonical historical Host marker.
    pub marker: HostExecutionNoApplyRecordV1,
    /// Commits the historical Host archive.
    pub archive_head: ObjectDigest,
    /// Commits the historical signed outcome.
    pub signed_outcome: ObjectDigest,
    /// Commits the historical Host cut.
    pub current_host_cut: ObjectDigest,
    /// Commits the original projection revision.
    pub predecessor_revision: ObjectDigest,
    /// Commits the successor projection revision.
    pub successor_revision: ObjectDigest,
    /// Commits the successor operation encoding.
    pub successor_operation: ObjectDigest,
    /// Records the original observation sequence.
    pub predecessor_sequence: u64,
    /// Records the accepted Effect attempt.
    pub effect_attempt: u32,
    /// Records the terminal wall coordinate.
    pub wall_seconds: i64,
}

impl CreateFailureReceiptV1 {
    /// Encodes the exact historical grammar and checksum.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        for digest in [
            self.archive_head,
            self.signed_outcome,
            self.current_host_cut,
        ] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.marker.encode_canonical());
        bytes.extend_from_slice(self.predecessor_revision.as_bytes());
        bytes.extend_from_slice(self.successor_revision.as_bytes());
        bytes.extend_from_slice(self.successor_operation.as_bytes());
        bytes.extend_from_slice(&self.predecessor_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.effect_attempt.to_be_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        let checksum = Sha256::new()
            .chain_update(DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Decodes only the exact historical grammar.
    ///
    /// # Errors
    /// Refuses a malformed envelope, field, checksum or noncanonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, ()> {
        if !bytes.starts_with(MAGIC) {
            return Ok(None);
        }
        if bytes.len() != RECEIPT_BYTES
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..RECEIPT_BYTES - 32])
                .finalize()
                .as_slice()
                != &bytes[RECEIPT_BYTES - 32..]
        {
            return Err(());
        }

        let digest = |start: usize| -> Result<ObjectDigest, ()> {
            let raw: [u8; 32] = bytes[start..start + 32].try_into().map_err(|_| ())?;
            if raw == [0; 32] {
                return Err(());
            }
            Ok(ObjectDigest::from_bytes(raw))
        };
        let marker =
            HostExecutionNoApplyRecordV1::decode_canonical(&bytes[108..492]).map_err(|_| ())?;
        let predecessor_sequence = u64::from_be_bytes(bytes[588..596].try_into().map_err(|_| ())?);
        let effect_attempt = u32::from_be_bytes(bytes[596..600].try_into().map_err(|_| ())?);
        let wall_seconds = i64::from_be_bytes(bytes[600..608].try_into().map_err(|_| ())?);
        if predecessor_sequence == 0 || effect_attempt == 0 {
            return Err(());
        }

        Ok(Some(Self {
            marker,
            archive_head: digest(12)?,
            signed_outcome: digest(44)?,
            current_host_cut: digest(76)?,
            predecessor_revision: digest(492)?,
            successor_revision: digest(524)?,
            successor_operation: digest(556)?,
            predecessor_sequence,
            effect_attempt,
            wall_seconds,
        }))
    }

    /// Computes the historical failed-resource commitment.
    pub fn resource_version(self) -> [u8; 32] {
        Sha256::new()
            .chain_update(RESOURCE_VERSION_DOMAIN)
            .chain_update(self.marker.encode_canonical())
            .chain_update(self.archive_head.as_bytes())
            .chain_update(self.signed_outcome.as_bytes())
            .chain_update(self.current_host_cut.as_bytes())
            .chain_update(self.predecessor_revision.as_bytes())
            .finalize()
            .into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Retains the immutable closed-before-argument terminal receipt.
pub struct ClosedCreateFailureReceiptV2 {
    /// Retains the immutable terminal identity.
    pub identity: ClosedCreateFailureIdentityDataV2,
    /// Commits the original projection revision.
    pub predecessor_revision: ObjectDigest,
    /// Commits the successor projection revision.
    pub successor_revision: ObjectDigest,
    /// Commits the successor operation encoding.
    pub successor_operation: ObjectDigest,
    /// Records the original observation sequence.
    pub predecessor_sequence: u64,
    /// Records the accepted Effect attempt.
    pub effect_attempt: u32,
    /// Records the terminal wall coordinate.
    pub wall_seconds: i64,
}

impl ClosedCreateFailureReceiptV2 {
    /// Encodes the exact historical grammar and checksum.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_BYTES_V2);
        bytes.extend_from_slice(RECEIPT_MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(self.identity.terminal_archive.as_bytes());
        bytes.extend_from_slice(self.identity.signed_terminal.as_bytes());
        bytes.extend_from_slice(&self.identity.marker.encode_canonical());
        for digest in [self.predecessor_revision, self.successor_revision, self.successor_operation] {
            bytes.extend_from_slice(digest.as_bytes());
        }
        bytes.extend_from_slice(&self.predecessor_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.effect_attempt.to_be_bytes());
        bytes.extend_from_slice(&self.wall_seconds.to_be_bytes());
        append_checksum(&mut bytes, RECEIPT_DOMAIN);
        bytes
    }

    /// Decodes only the exact historical grammar.
    ///
    /// # Errors
    /// Refuses a malformed envelope, field, checksum or noncanonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ()> {
        require_envelope(bytes, RECEIPT_MAGIC, RECEIPT_BYTES_V2, RECEIPT_DOMAIN)?;
        let mut reader = BoundedReader::new(&bytes[12..RECEIPT_BYTES_V2 - 32], |_| ());
        let terminal_archive = digest(&mut reader)?;
        let signed_terminal = digest(&mut reader)?;
        let marker = ClosedBeforeArgumentNoApplyRecordV2::decode_canonical(
            &reader.array::<BEFORE_ARGUMENT_NO_APPLY_RECORD_BYTES_V2>()?,
        ).map_err(|_| ())?;
        let receipt = Self {
            identity: ClosedCreateFailureIdentityDataV2 { marker, terminal_archive, signed_terminal },
            predecessor_revision: digest(&mut reader)?,
            successor_revision: digest(&mut reader)?,
            successor_operation: digest(&mut reader)?,
            predecessor_sequence: u64::from_be_bytes(reader.array::<8>()?),
            effect_attempt: u32::from_be_bytes(reader.array::<4>()?),
            wall_seconds: i64::from_be_bytes(reader.array::<8>()?),
        };
        if reader.remaining() != 0 || receipt.predecessor_sequence == 0 || receipt.effect_attempt == 0
            || receipt.encode() != bytes { return Err(()); }
        Ok(receipt)
    }

    /// Computes the historical failed-resource commitment.
    pub fn resource_version(self) -> [u8; 32] {
        Sha256::new().chain_update(RESOURCE_DOMAIN)
            .chain_update(self.identity.marker.encode_canonical())
            .chain_update(self.identity.terminal_archive.as_bytes())
            .chain_update(self.identity.signed_terminal.as_bytes())
            .chain_update(self.predecessor_revision.as_bytes()).finalize().into()
    }
}

/// Borrows immutable after-argument receipt inputs, never its live proof.
#[derive(Clone, Copy)]
pub struct AfterArgumentCreateFailureIdentityDataV1<'identity> {
    /// Exact historical marker.
    /// Retains the canonical historical Host marker.
    pub marker: &'identity HostExecutionNoApplyRecordV1,
    /// Actual archive commitment.
    /// Commits the historical Host archive.
    pub archive_head: &'identity ObjectDigest,
    /// Actual signed outcome commitment.
    /// Commits the historical signed outcome.
    pub signed_outcome: &'identity ObjectDigest,
    /// Actual historical Host cut commitment.
    /// Commits the historical Host cut.
    pub current_host_cut: &'identity ObjectDigest,
}

/// Selects a receipt grammar as diagnostic DATA only.
pub enum CreateFailurePlanIdentityV2<'identity> {
    /// Retains only immutable legacy receipt inputs.
    AfterArgument(AfterArgumentCreateFailureIdentityDataV1<'identity>),
    /// Borrows the canonical closed terminal identity.
    ClosedBeforeArgument(&'identity ClosedCreateFailureIdentityDataV2),
}

impl CreateFailurePlanIdentityV2<'_> {
    /// Checks the same-cut accepted request commitment for the closed identity.
    ///
    /// # Errors
    /// Refuses the ordered immutable identity or accepted-digest mismatch.
    pub(super) fn require_current_journal_data_v2(&self, journal: &CreateFailureHistoricalDataV2<'_>) -> Result<(), CreateFailureDataErrorV2> {
        if let Self::ClosedBeforeArgument(identity) = self {
            super::planning::require_accepted_request_digest_data_v2(journal, identity.marker)
        } else { Ok(()) }
    }
    /// Checks nonzero immutable terminal commitments.
    ///
    /// # Errors
    /// Refuses the ordered immutable identity or accepted-digest mismatch.
    pub fn require_identity_data_v2(&self) -> Result<(), CreateFailureDataErrorV2> {
        if let Self::ClosedBeforeArgument(identity) = self {
            if identity.terminal_archive.as_bytes() == &[0; 32]
                || identity.signed_terminal.as_bytes() == &[0; 32]
            { return Err(invalid_settlement()); }
        }
        Ok(())
    }

    /// Returns the accepted Create and Execution identities.
    pub(super) fn target_data_v2(&self) -> ([u8; 16], [u8; 16]) {
        match self {
            Self::AfterArgument(proof) => {
                let fields = proof.marker.fields();
                (fields.create_operation_id, fields.execution_id)
            }
            Self::ClosedBeforeArgument(identity) => {
                let fields = identity.marker.fields().source.fields();
                (fields.create_operation, fields.execution)
            }
        }
    }

    /// Assembles immutable terminal receipt DATA.
    pub(super) fn receipt_data_v2(&self, predecessor_revision: ObjectDigest,
        successor_revision: ObjectDigest, successor_operation: ObjectDigest,
        predecessor_sequence: u64, effect_attempt: u32, wall_seconds: i64,
    ) -> CreateFailureReceiptDataV2 {
        match self {
            Self::AfterArgument(proof) => CreateFailureReceiptDataV2::AfterArgument(CreateFailureReceiptV1 {
                marker: *proof.marker, archive_head: *proof.archive_head, signed_outcome: *proof.signed_outcome,
                current_host_cut: *proof.current_host_cut, predecessor_revision, successor_revision, successor_operation,
                predecessor_sequence, effect_attempt, wall_seconds,
            }),
            Self::ClosedBeforeArgument(identity) => CreateFailureReceiptDataV2::ClosedBeforeArgument(
                ClosedCreateFailureReceiptV2 { identity: **identity, predecessor_revision,
                    successor_revision, successor_operation, predecessor_sequence, effect_attempt, wall_seconds },
            ),
        }
    }
}

/// Selects the two established immutable terminal receipt grammars.
pub enum CreateFailureReceiptDataV2 {
    /// Retains the legacy after-argument terminal DATA.
    AfterArgument(CreateFailureReceiptV1),
    /// Retains the closed-before-argument terminal DATA.
    ClosedBeforeArgument(ClosedCreateFailureReceiptV2),
}

impl CreateFailureReceiptDataV2 {
    /// Decodes only the exact historical grammar.
    ///
    /// # Errors
    /// Refuses a malformed envelope, field, checksum or noncanonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, ()> {
        if bytes.starts_with(RECEIPT_MAGIC) {
            ClosedCreateFailureReceiptV2::decode(bytes).map(Self::ClosedBeforeArgument).map(Some)
        } else if bytes.starts_with(b"AOSCFB") && !bytes.starts_with(MAGIC) {
            Err(())
        } else {
            CreateFailureReceiptV1::decode(bytes).map(|value| value.map(Self::AfterArgument))
        }
    }

    /// Encodes the exact historical grammar and checksum.
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::AfterArgument(receipt) => receipt.encode(),
            Self::ClosedBeforeArgument(receipt) => receipt.encode(),
        }
    }

    /// Computes the historical failed-resource commitment.
    pub fn resource_version(&self) -> [u8; 32] {
        match self {
            Self::AfterArgument(receipt) => receipt.resource_version(),
            Self::ClosedBeforeArgument(receipt) => receipt.resource_version(),
        }
    }

    /// Replaces the successor projection commitment as plain DATA.
    pub(super) fn with_successor_revision_v2(self, successor_revision: ObjectDigest) -> Self {
        match self {
            Self::AfterArgument(receipt) => Self::AfterArgument(CreateFailureReceiptV1 { successor_revision, ..receipt }),
            Self::ClosedBeforeArgument(receipt) => Self::ClosedBeforeArgument(ClosedCreateFailureReceiptV2 { successor_revision, ..receipt }),
        }
    }
}

fn append_checksum(bytes: &mut Vec<u8>, domain: &[u8]) {
    let checksum = Sha256::new().chain_update(domain).chain_update(&*bytes).finalize();
    bytes.extend_from_slice(&checksum);
}

fn require_envelope(bytes: &[u8], magic: &[u8; 8], width: usize, domain: &[u8]) -> Result<(), ()> {
    if bytes.len() != width || bytes.get(..8) != Some(magic.as_slice())
        || bytes[8..10] != 2_u16.to_be_bytes() || bytes[10..12] != [0; 2]
        || Sha256::new().chain_update(domain).chain_update(&bytes[..width - 32]).finalize().as_slice()
            != &bytes[width - 32..] { return Err(()); }
    Ok(())
}

fn digest(reader: &mut BoundedReader<'_, ()>) -> Result<ObjectDigest, ()> {
    let bytes = reader.array::<32>()?;
    if bytes == [0; 32] { return Err(()); }
    Ok(ObjectDigest::from_bytes(bytes))
}
