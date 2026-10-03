//! Original Source floor DATA with immutable admission and provenance retention.
//!
//! ```text
//! AOSJCR01 | [0,5,41,11,0,0] | native_bindings[204] | admission[16] |
//! origin_budgets[24] | original_provenance[617+R+C] | identity[32]
//! ```
//!
//! This codec does not admit, transfer, or spend a floor. A future named Source
//! writer must validate actual original rows, transaction membership, the whole
//! current owner graph and every branch's opened-limit geometry independently.

use aos_sandbox_source_provider_ledger::ledger::native_completion::{
    MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5, OriginalSourceProvenanceV5,
};
use sha2::{Digest as _, Sha256};

use super::super::super::{JournalError, JournalRecord, RecordNamespace};
use super::super::{reservation_key, take};
use super::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRequestV3, binding_bytes, decode_bindings,
    invalid,
};

/// Bounds the original Source floor, including its retained archive and identity.
pub const ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5: usize =
    290 + MAXIMUM_ORIGINAL_SOURCE_PROVENANCE_BYTES_V5;

const _: () = assert!(ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5 == 30_413);

const HEADER: [u8; 6] = [0, 5, 41, 11, 0, 0];
const DOMAIN: &[u8] = b"aos.sandbox.journal.source-original-native-capacity.v5\0";
const OWNER_DOMAIN: &[u8] = b"aos.sandbox.source-provider.native-dispatch-capacity-owner.v2\0";
const ORIGINAL_COUNT: u32 = 20;

/// Retains immutable original suffix budgets for inverse initial identity DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalSourceCapacityBudgetsV5 {
    /// Names the complete original normal suffix's aggregate record frames.
    pub terminal_records: u32,
    /// Names the complete original normal suffix's fully framed append bytes.
    pub terminal_bytes: u64,
    /// Names the complete original cold/Closed suffix's aggregate record frames.
    pub poison_records: u32,
    /// Names the complete original cold/Closed suffix's fully framed append bytes.
    pub poison_bytes: u64,
}

impl OriginalSourceCapacityBudgetsV5 {
    fn matches(self, request: NativeHeldCapacityRequestV3) -> bool {
        self.terminal_records == request.terminal_records
            && self.terminal_bytes == request.terminal_bytes
            && self.poison_records == request.poison_records
            && self.poison_bytes == request.poison_bytes
    }

    fn contains(self, request: NativeHeldCapacityRequestV3) -> bool {
        request.terminal_records <= self.terminal_records
            && request.terminal_bytes <= self.terminal_bytes
            && request.poison_records <= self.poison_records
            && request.poison_bytes <= self.poison_bytes
    }
}

/// Retains exact original Source capacity DATA without a writer or append grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalSourceCapacityRecordV5 {
    request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    origin: OriginalSourceCapacityBudgetsV5,
    provenance: OriginalSourceProvenanceV5,
    identity: [u8; 32],
}

impl OriginalSourceCapacityRecordV5 {
    /// Constructs a private count 1..20 Source5 DATA profile from exact archives.
    ///
    /// The semantic Provider purpose remains 9; this family alone encodes wire
    /// purpose 11. Applying owner digest and effect ID remain nonzero commitments,
    /// not an inferred join to absent Applying bytes. A real writer must rejoin
    /// those original rows, budget geometry and physical admission separately.
    ///
    /// # Errors
    ///
    /// Rejects foreign purpose, sentinel bindings/admission, count outside 1..20,
    /// enlarged remaining budgets, changed initial budgets or archived subjects.
    pub fn new(
        request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
        origin: OriginalSourceCapacityBudgetsV5,
        provenance: OriginalSourceProvenanceV5,
    ) -> Result<Self, JournalError> {
        request.validate_with_maximum(ORIGINAL_COUNT)?;
        let claims = provenance.claims();
        let (provider, acquisition) = claims.claims.provider_acquisition();
        let holder = claims.claims.holder_session().0;
        let owner: [u8; 32] = Sha256::new()
            .chain_update(OWNER_DOMAIN)
            .chain_update(provider)
            .chain_update(holder)
            .chain_update(acquisition.as_bytes())
            .finalize()
            .into();
        if request.purpose != NativeHeldCapacityPurposeV3::Provider
            || admission == [0; 16]
            || !origin.contains(request)
            || (request.future_transactions == ORIGINAL_COUNT && !origin.matches(request))
            || request.owner_id != owner
            || request.artifact_digest != *claims.claims.attempt().1.as_bytes()
            || request.checkpoint_digest
                != *claims.root_prepared.scope().original_root_request.as_bytes()
            || request.chain_head_digest != *claims.claims.holder_session().1.as_bytes()
        {
            return Err(invalid("original Source capacity bindings or budgets"));
        }
        let mut record = Self {
            request,
            admission,
            origin,
            provenance,
            identity: [0; 32],
        };
        record.identity = identity(&record.payload(request))?;
        Ok(record)
    }

    /// Returns remaining native accounting DATA, never a general V3 grant.
    #[must_use]
    pub const fn request(&self) -> NativeHeldCapacityRequestV3 {
        self.request
    }

    /// Returns the immutable original admission transaction claim.
    #[must_use]
    pub const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission
    }

    /// Returns immutable original complete suffix budget DATA.
    #[must_use]
    pub const fn origin_budgets(&self) -> OriginalSourceCapacityBudgetsV5 {
        self.origin
    }

    /// Returns the archived original provenance, not authenticated owner state.
    #[must_use]
    pub const fn original_provenance(&self) -> &OriginalSourceProvenanceV5 {
        &self.provenance
    }

    /// Returns the current domain-separated exact floor identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.identity
    }

    /// Reproduces the canonical initial count 20 identity from immutable DATA.
    ///
    /// This inverse supplies an identity for a future exact physical admission
    /// join. It does not demonstrate that the initial row was ever committed.
    ///
    /// # Errors
    ///
    /// Rejects an impossible retained payload width or length representation.
    pub fn origin_reservation_id(&self) -> Result<[u8; 32], JournalError> {
        let mut request = self.request;
        request.future_transactions = ORIGINAL_COUNT;
        request.terminal_records = self.origin.terminal_records;
        request.terminal_bytes = self.origin.terminal_bytes;
        request.poison_records = self.origin.poison_records;
        request.poison_bytes = self.origin.poison_bytes;
        identity(&self.payload(request))
    }

    /// Encodes self-bound floor DATA without admitting it to a protected journal.
    ///
    /// # Errors
    ///
    /// Rejects an impossible retained payload width or identity representation.
    pub fn to_journal_record(&self) -> Result<JournalRecord, JournalError> {
        let mut value = self.payload(self.request);
        if identity(&value)? != self.identity {
            return Err(invalid("original Source capacity identity"));
        }
        value.extend_from_slice(&self.identity);
        Ok(JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.identity),
            value,
        ))
    }

    /// Decodes canonical Source5 DATA without claiming physical original admission.
    ///
    /// # Errors
    ///
    /// Rejects foreign namespace/deletion, wrong tuple/width, malformed archives,
    /// substituted identity/key, enlarged budgets or noncanonical bytes.
    pub fn from_journal_record(record: &JournalRecord) -> Result<Self, JournalError> {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Self::decode(
            record.key(),
            record.value().ok_or(JournalError::InvalidTransaction)?,
        )
    }

    pub(in crate::journal) fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, JournalError> {
        // The lower bound protects the shared fixed 204 decoder and origin words.
        if !(907..=ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5).contains(&bytes.len())
            || &bytes[..8] != b"AOSJCR01"
            || bytes[8..14] != HEADER
        {
            return Err(invalid("original Source capacity envelope"));
        }
        let mut offset = 14;
        let request = decode_bindings(NativeHeldCapacityPurposeV3::Provider, bytes, &mut offset);
        let admission = take::<16>(bytes, &mut offset);
        let origin = OriginalSourceCapacityBudgetsV5 {
            terminal_records: u32::from_be_bytes(take::<4>(bytes, &mut offset)),
            terminal_bytes: u64::from_be_bytes(take::<8>(bytes, &mut offset)),
            poison_records: u32::from_be_bytes(take::<4>(bytes, &mut offset)),
            poison_bytes: u64::from_be_bytes(take::<8>(bytes, &mut offset)),
        };
        let identity_offset = bytes.len() - 32;
        let provenance =
            OriginalSourceProvenanceV5::from_canonical_bytes(&bytes[offset..identity_offset])
                .map_err(|_| invalid("original Source provenance encoding"))?;
        let mut candidate = [0; 32];
        candidate.copy_from_slice(&bytes[identity_offset..]);
        let decoded = Self::new(request, admission, origin, provenance)?;
        if candidate != decoded.identity
            || key != reservation_key(candidate).as_slice()
            || decoded.to_journal_record()?.value() != Some(bytes)
        {
            return Err(invalid("original Source capacity key or canonical identity"));
        }
        Ok(decoded)
    }

    fn payload(&self, request: NativeHeldCapacityRequestV3) -> Vec<u8> {
        let mut bytes = b"AOSJCR01".to_vec();
        bytes.extend_from_slice(&HEADER);
        bytes.extend_from_slice(&binding_bytes(&request));
        bytes.extend_from_slice(&self.admission);
        bytes.extend_from_slice(&self.origin.terminal_records.to_be_bytes());
        bytes.extend_from_slice(&self.origin.terminal_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.origin.poison_records.to_be_bytes());
        bytes.extend_from_slice(&self.origin.poison_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.provenance.to_canonical_bytes());
        bytes
    }
}

fn identity(payload: &[u8]) -> Result<[u8; 32], JournalError> {
    if payload.len() > ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5 - 32 {
        return Err(invalid("original Source capacity maximum width"));
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| invalid("original Source payload length"))?;
    Ok(Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(length.to_be_bytes())
        .chain_update(payload)
        .finalize()
        .into())
}

#[cfg(test)]
mod tests;
