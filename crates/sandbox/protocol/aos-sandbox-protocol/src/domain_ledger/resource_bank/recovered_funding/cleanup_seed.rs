//! Records a fresh cleanup-only seed on the existing recovered baseline.
//!
//! ```text
//! AOSRFS02 | purpose22 | reserved7 | enrollment96 | recipient16 |
//! baseline176 | chargedBefore176 | chargedAfter176 | seedComplete176 |
//! association176 | originalCNext8 | originalCEnd8 | checksum32
//! association = Recover16 | cleanup16 | oldStop16 | exactVersion32 |
//!               publicRequest32 | protectedSourceParent32 | cleanupSubject32
//! ```
//!
//! This finite purpose does not require ordinary enrollment or the D/X pair.
//! It grants none of their permissions. The same native issuer must retain the
//! actual completed Recover/C/Source association and current capability/policy;
//! passive historical balances cannot construct that issuer or a Stop effect.

use super::*;

/// Gives the fixed accepted Recover/target financial association width.
pub const HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1: usize = 176;
/// Gives the exact finite cleanup seed row width.
pub const RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1: usize = 1056;
const PURPOSE: u8 = 22;

/// Keeps ordinary enrollment funding and finite cleanup provenance distinct.
///
/// Both variants use the same Stop financial/native publication engine. This
/// passive enum cannot turn cleanup funding into ordinary enrollment or an
/// accepted public Stop graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveredStopSeedFundingDataV3 {
    /// Retains the original purpose21 completed-enrollment seed law.
    Ordinary(RecoveredLifecycleStopFundingDataV2),
    /// Retains purpose22's accepted Recover/old-target cleanup association.
    Cleanup(RecoveredHostStopCleanupFundingDataV1),
}

impl RecoveredStopSeedFundingDataV3 {
    /// Returns the unchanged original shared-bank enrollment.
    #[must_use]
    pub const fn enrollment_v3(self) -> EnrollmentIdentity {
        match self { Self::Ordinary(row) => row.enrollment, Self::Cleanup(row) => row.enrollment }
    }

    /// Returns the actual recovered Controller recipient.
    #[must_use]
    pub const fn recipient_v3(self) -> [u8; 16] {
        match self { Self::Ordinary(row) => row.recipient, Self::Cleanup(row) => row.recipient }
    }

    /// Returns the inclusive original B, without creating another account.
    #[must_use]
    pub const fn baseline_v3(self) -> ResourceVector {
        match self { Self::Ordinary(row) => row.baseline, Self::Cleanup(row) => row.baseline }
    }

    /// Returns the original exact complete seed debit.
    #[must_use]
    pub const fn complete_v3(self) -> ResourceVector {
        match self { Self::Ordinary(row) => row.complete, Self::Cleanup(row) => row.complete }
    }

    /// Gives the same funding-family key for this variant's distinct purpose.
    #[must_use]
    pub fn key_v3(self) -> [u8; 17] {
        match self { Self::Ordinary(row) => row.key_v2(), Self::Cleanup(row) => row.key_v1() }
    }

    /// Constructs the exact variant's one-row publication DATA.
    ///
    /// # Errors
    /// Returns the original format-owned canonical funding/transaction refusal.
    pub fn transaction_data_v3(self) -> Result<JournalTransaction, ResourceBankDataError> {
        match self { Self::Ordinary(row) => row.transaction_data_v2(), Self::Cleanup(row) => row.transaction_data_v1() }
    }

    /// Requires the variant's exact protected financial history.
    ///
    /// # Errors
    /// Preserves purpose21's D/X prerequisites and purpose22's distinct native
    /// recipient/baseline law; refuses absent or substituted canonical rows.
    pub fn require_replayed_v3(self, state: &State) -> Result<(), ResourceBankDataError> {
        match self { Self::Ordinary(row) => row.require_replayed_v2(state), Self::Cleanup(row) => row.require_replayed_v1(state) }
    }
}

/// Names an accepted Recover's exact cleanup child without issuing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredHostStopCleanupAssociationDataV1 {
    /// Binds the actual newly accepted public Recover operation.
    pub recovery_operation: [u8; 16],
    /// Binds its distinct fresh cleanup operation/request.
    pub cleanup_operation: [u8; 16],
    /// Binds the immutable protected original Stop operation.
    pub target_stop_operation: [u8; 16],
    /// Binds the exact expected protected Stop resource version.
    pub expected_resource_version: [u8; 32],
    /// Binds the actual canonical public Recover request digest.
    pub public_request_digest: [u8; 32],
    /// Binds the actual selected protected Source parent record.
    pub source_parent_digest: [u8; 32],
    /// Binds the canonical fresh Host cleanup subject.
    pub cleanup_subject_digest: [u8; 32],
}

impl RecoveredHostStopCleanupAssociationDataV1 {
    /// Encodes the fixed passive association without admitting its references.
    ///
    /// # Errors
    /// Refuses unspecified fields or an aliased new operation identity.
    pub fn encode_v1(self) -> Result<[u8; HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1], ResourceBankDataError> {
        if self.recovery_operation == [0; 16] || self.cleanup_operation == [0; 16]
            || self.target_stop_operation == [0; 16]
            || self.recovery_operation == self.cleanup_operation
            || self.recovery_operation == self.target_stop_operation
            || self.cleanup_operation == self.target_stop_operation
            || self.expected_resource_version == [0; 32]
            || self.public_request_digest == [0; 32] || self.source_parent_digest == [0; 32]
            || self.cleanup_subject_digest == [0; 32]
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let mut bytes = [0; HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1];
        bytes[..16].copy_from_slice(&self.recovery_operation);
        bytes[16..32].copy_from_slice(&self.cleanup_operation);
        bytes[32..48].copy_from_slice(&self.target_stop_operation);
        bytes[48..80].copy_from_slice(&self.expected_resource_version);
        bytes[80..112].copy_from_slice(&self.public_request_digest);
        bytes[112..144].copy_from_slice(&self.source_parent_digest);
        bytes[144..176].copy_from_slice(&self.cleanup_subject_digest);
        Ok(bytes)
    }

    /// Decodes the exact association as comparison DATA.
    ///
    /// # Errors
    /// Refuses another width, unspecified identities or operation aliasing.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        if bytes.len() != HOST_STOP_CLEANUP_ASSOCIATION_BYTES_V1 {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        let value = Self {
            recovery_operation: field(bytes, 0)?, cleanup_operation: field(bytes, 16)?,
            target_stop_operation: field(bytes, 32)?, expected_resource_version: field(bytes, 48)?,
            public_request_digest: field(bytes, 80)?, source_parent_digest: field(bytes, 112)?,
            cleanup_subject_digest: field(bytes, 144)?,
        };
        value.encode_v1()?;
        Ok(value)
    }
}

/// Retains exact financial comparisons for one freshly funded cleanup seed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredHostStopCleanupFundingDataV1 {
    /// Binds the original shared-bank enrollment.
    pub enrollment: EnrollmentIdentity,
    /// Binds the actual generation-one Controller invocation.
    pub recipient: [u8; 16],
    /// Gives the unchanged inclusive baseline B.
    pub baseline: ResourceVector,
    /// Gives actual charged usage immediately before this seed debit.
    pub charged_before: ResourceVector,
    /// Gives actual charged usage immediately after this seed debit.
    pub charged_after: ResourceVector,
    /// Gives the exact complete initial cleanup native/model/publication charge.
    pub complete: ResourceVector,
    /// Retains the distinct accepted Recover/cleanup/old target association.
    pub association: RecoveredHostStopCleanupAssociationDataV1,
    /// Gives actual C NEXT before the seed publication.
    pub controller_next: u64,
    /// Gives actual durable C end before the seed publication.
    pub controller_end: u64,
}

impl RecoveredHostStopCleanupFundingDataV1 {
    fn common_v2(self) -> common::FundingCommonDataV2 {
        common::FundingCommonDataV2 { purpose: PURPOSE, enrollment: self.enrollment,
            recipient: self.recipient, baseline: self.baseline, charged_before: self.charged_before,
            charged_after: self.charged_after, complete: self.complete,
            controller_next: self.controller_next, controller_end: self.controller_end }
    }

    /// Encodes this purpose through the sole common funding/vector/checksum engine.
    ///
    /// # Errors
    /// Refuses invalid fixed references, balances or native publication cut.
    pub fn encode_v1(self) -> Result<[u8; RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1], ResourceBankDataError> {
        let association = self.association.encode_v1()?;
        let mut bytes = [0; RECOVERED_HOST_STOP_CLEANUP_SEED_BYTES_V1];
        common::encode_with_association_v2(self.common_v2(), None, &association, &mut bytes)?;
        Ok(bytes)
    }

    /// Decodes the sole fixed cleanup purpose without reinterpreting Stop21.
    ///
    /// # Errors
    /// Refuses another purpose, checksum, width or malformed association.
    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        let (common, declared) = common::decode_v2(bytes)?;
        if common.purpose != PURPOSE || declared.is_some() {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(Self { enrollment: common.enrollment, recipient: common.recipient,
            baseline: common.baseline, charged_before: common.charged_before,
            charged_after: common.charged_after, complete: common.complete,
            association: RecoveredHostStopCleanupAssociationDataV1::decode_v1(&bytes[832..1008])?,
            controller_next: common.controller_next, controller_end: common.controller_end })
    }

    /// Gives the common funding-family key with distinct cleanup purpose22.
    #[must_use]
    pub fn key_v1(self) -> [u8; 17] { common::key_v2(self.enrollment, self.recipient, PURPOSE) }

    fn require_bank_binding_v1(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.association.encode_v1()?;
        common::require_canonical_v2(self.common_v2(), None)?;
        let recipient = recipient::controller_recipient_for_invocation_v2(state, self.enrollment, self.recipient)?;
        if recipient.generation() == 0 || recipient.recipient() != self.recipient
            || recipient.charged_baseline_v1()? != self.baseline
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        // Cleanup precedes ordinary enrollment. Prior normal/Recover/native
        // usage remains spent; no D/X row or amount is manufactured here.
        self.charged_before.checked_sub(recipient.outside_allowance_v2()?)?;
        Ok(())
    }

    /// Compares the exact historical row against the complete protected bank.
    ///
    /// This financial replay grants no current capability, native cleanup or
    /// ordinary enrollment. Those actual owners cannot be recreated by replay.
    ///
    /// # Errors
    /// Refuses another recipient/baseline or an absent/substituted row.
    pub fn require_replayed_v1(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.require_bank_binding_v1(state)?;
        let key = self.key_v1();
        let mut id = [0; 16];
        id.copy_from_slice(&key[1..]);
        if replay::record_bytes(state, PREFIX, id) != Some(self.encode_v1()?.as_slice()) {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }

    fn transaction_id_v1(self) -> Result<[u8; 16], ResourceBankDataError> {
        let hash = Sha256::new().chain_update(b"aos.controller.host-stop-cleanup-seed.transaction.v1\0")
            .chain_update(self.encode_v1()?).finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&hash[..16]);
        Ok(id)
    }

    /// Constructs the exact one-row publication DATA without entering IO.
    ///
    /// # Errors
    /// Refuses invalid seed or transaction identity.
    pub fn transaction_data_v1(self) -> Result<JournalTransaction, ResourceBankDataError> {
        Ok(JournalTransaction::new(self.transaction_id_v1()?, vec![JournalRecord::put(
            RecordNamespace::ControllerResourceReservation, self.key_v1().to_vec(),
            self.encode_v1()?.to_vec(),
        )])?)
    }
}

pub(super) fn enrollment_v1(key: &[u8], bytes: &[u8]) -> Result<EnrollmentIdentity, ResourceBankDataError> {
    let row = RecoveredHostStopCleanupFundingDataV1::decode_v1(bytes)?;
    if key != row.key_v1() { return Err(ResourceBankDataError::CorruptLedger); }
    Ok(row.enrollment)
}

pub(super) fn validate_transaction_v1(state: &State, transaction: &JournalTransaction,
    next: u64, end: u64,
) -> Result<(), ResourceBankDataError> {
    if transaction.records().len() != 1 { return Err(ResourceBankDataError::CorruptLedger); }
    let record = &transaction.records()[0];
    if record.namespace() != RecordNamespace::ControllerResourceReservation {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let row = RecoveredHostStopCleanupFundingDataV1::decode_v1(record.value()
        .ok_or(ResourceBankDataError::CorruptLedger)?)?;
    row.require_bank_binding_v1(state)?;
    let mut id = [0; 16];
    id.copy_from_slice(&row.key_v1()[1..]);
    if record.key() != row.key_v1() || (row.controller_next, row.controller_end) != (next, end)
        || replay::record_bytes(state, PREFIX, id).is_some()
        || transaction.id() != &row.transaction_id_v1()?
        || replay::validate(state)? != Some(row.enrollment)
    {
        return Err(ResourceBankDataError::Conflict);
    }
    Ok(())
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ResourceBankDataError> {
    bytes.get(offset..offset + N).ok_or(ResourceBankDataError::CorruptLedger)?
        .try_into().map_err(|_| ResourceBankDataError::CorruptLedger)
}
