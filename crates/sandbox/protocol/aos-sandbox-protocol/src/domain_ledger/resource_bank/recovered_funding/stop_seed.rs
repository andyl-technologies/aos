//! Records an actual recovered Stop seed on the same permanent baseline.
//!
//! ```text
//! AOSRFS02 | StopPurpose1=21 | reserved7 | enrollment96 | recipient16 |
//! baseline176 | chargedBefore176 | chargedAfter176 | seedComplete176 |
//! originalCNext8 | originalCEnd8 | checksum32
//! ```
//!
//! The seed has no image declaration or transferable capacity. Later exact
//! requirements remain permanent debits on the same native baseline owner.
//! This historical row cannot reconstruct a lost receiving original.

use super::*;

/// Gives the canonical historical Stop seed width.
pub const RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2: usize = 880;
const PURPOSE: u8 = 21;

/// Carries actual seed-debit comparisons without issuing Stop authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredLifecycleStopFundingDataV2 {
    /// Binds the existing whole-bank enrollment.
    pub enrollment: EnrollmentIdentity,
    /// Binds the actual generation-one Controller invocation.
    pub recipient: [u8; 16],
    /// Gives the original inclusive baseline B.
    pub baseline: ResourceVector,
    /// Gives actual charged usage immediately before the seed debit.
    pub charged_before: ResourceVector,
    /// Gives actual charged usage immediately after the seed debit.
    pub charged_after: ResourceVector,
    /// Gives the exact initial native/model/publication requirement paid.
    pub complete: ResourceVector,
    /// Gives actual C NEXT before funding publication.
    pub controller_next: u64,
    /// Gives actual durable C end before funding publication.
    pub controller_end: u64,
}

impl RecoveredLifecycleStopFundingDataV2 {
    fn require_canonical_v2(self) -> Result<(), ResourceBankDataError> {
        common::require_canonical_v2(self.common_v2(), None)
    }

    fn common_v2(self) -> common::FundingCommonDataV2 {
        common::FundingCommonDataV2 {
            purpose: PURPOSE, enrollment: self.enrollment, recipient: self.recipient,
            baseline: self.baseline, charged_before: self.charged_before, charged_after: self.charged_after,
            complete: self.complete, controller_next: self.controller_next, controller_end: self.controller_end,
        }
    }

    /// Encodes only the explicit Stop seed grammar.
    ///
    /// # Errors
    /// Refuses invalid identity, balance, zero seed or native coordinates.
    pub fn encode_v2(self) -> Result<[u8; RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2], ResourceBankDataError> {
        let mut bytes = [0; RECOVERED_LIFECYCLE_STOP_SEED_BYTES_V2];
        common::encode_into_v2(self.common_v2(), None, &mut bytes)?;
        Ok(bytes)
    }

    /// Decodes only the complete explicit Stop seed shape.
    ///
    /// # Errors
    /// Refuses obsolete magic, declared-purpose shape or canonical errors.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, ResourceBankDataError> {
        let (common, declared) = common::decode_v2(bytes)?;
        if common.purpose != PURPOSE || declared.is_some() {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        Ok(Self {
            enrollment: common.enrollment, recipient: common.recipient, baseline: common.baseline,
            charged_before: common.charged_before, charged_after: common.charged_after, complete: common.complete,
            controller_next: common.controller_next, controller_end: common.controller_end,
        })
    }

    /// Gives the existing funding family key with a distinct Stop purpose.
    #[must_use]
    pub fn key_v2(self) -> [u8; 17] {
        common::key_v2(self.enrollment, self.recipient, PURPOSE)
    }

    fn require_bank_binding_v2(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.require_canonical_v2()?;
        let recipient = recipient::controller_recipient_for_invocation_v2(state, self.enrollment, self.recipient)?;
        if recipient.generation() == 0 || recipient.recipient() != self.recipient
            || recipient.charged_baseline_v1()? != self.baseline
        {
            return Err(ResourceBankDataError::CorruptLedger);
        }
        self.charged_before.checked_sub(recipient.outside_allowance_v2()?)?;
        // The actual issuer requires completed ordinary enrollment, whose
        // exact D/X pair must remain in this same protected bank after restart.
        // A later seed cannot move the baseline balance back before that pair.
        let load = |purpose| -> Result<RecoveredOperationFundingDataV1, ResourceBankDataError> {
            let key = common::key_v2(self.enrollment, self.recipient, purpose);
            let mut id = [0; 16];
            id.copy_from_slice(&key[1..]);
            RecoveredOperationFundingDataV1::decode_v1(replay::record_bytes(state, PREFIX, id)
                .ok_or(ResourceBankDataError::CorruptLedger)?)
        };
        let pair = [load(17)?, load(18)?];
        require_recovered_funding_pair_data_v1(&pair)?;
        for row in pair { row.require_replayed_v1(state)?; }
        if pair[0].enrollment != self.enrollment || pair[0].recipient != self.recipient
            || pair[0].baseline != self.baseline
        { return Err(ResourceBankDataError::CorruptLedger); }
        self.charged_before.checked_sub(pair[1].charged_after)?;
        Ok(())
    }

    /// Checks the exact historical seed against the actual full protected bank.
    ///
    /// # Errors
    /// Refuses absent/substituted rows, another recipient or foreign baseline.
    pub fn require_replayed_v2(self, state: &State) -> Result<(), ResourceBankDataError> {
        self.require_bank_binding_v2(state)?;
        let key = self.key_v2();
        let mut id = [0; 16];
        id.copy_from_slice(&key[1..]);
        if replay::record_bytes(state, PREFIX, id) != Some(self.encode_v2()?.as_slice()) {
            return Err(ResourceBankDataError::Conflict);
        }
        Ok(())
    }

    fn transaction_id_data_v2(self) -> Result<[u8; 16], ResourceBankDataError> {
        let hash = Sha256::new().chain_update(b"aos.controller.stop-seed.transaction.v2\0")
            .chain_update(self.encode_v2()?).finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&hash[..16]);
        Ok(id)
    }

    /// Constructs only the canonical one-row metadata transaction.
    ///
    /// # Errors
    /// Refuses an invalid seed or transaction identity; this performs no IO.
    pub fn transaction_data_v2(self) -> Result<JournalTransaction, ResourceBankDataError> {
        let encoded = self.encode_v2()?;
        Ok(JournalTransaction::new(self.transaction_id_data_v2()?, vec![JournalRecord::put(
            RecordNamespace::ControllerResourceReservation, self.key_v2().to_vec(), encoded.to_vec(),
        )])?)
    }
}

pub(super) fn enrollment_v2(key: &[u8], bytes: &[u8]) -> Result<EnrollmentIdentity, ResourceBankDataError> {
    let row = RecoveredLifecycleStopFundingDataV2::decode_v2(bytes)?;
    if key != row.key_v2() { return Err(ResourceBankDataError::CorruptLedger); }
    Ok(row.enrollment)
}

pub(super) fn validate_transaction_v2(state: &State, transaction: &JournalTransaction,
    next: u64, end: u64,
) -> Result<(), ResourceBankDataError> {
    if transaction.records().len() != 1 { return Err(ResourceBankDataError::CorruptLedger); }
    let record = &transaction.records()[0];
    if record.namespace() != RecordNamespace::ControllerResourceReservation {
        return Err(ResourceBankDataError::CorruptLedger);
    }
    let row = RecoveredLifecycleStopFundingDataV2::decode_v2(record.value()
        .ok_or(ResourceBankDataError::CorruptLedger)?)?;
    row.require_bank_binding_v2(state)?;
    let mut id = [0; 16];
    id.copy_from_slice(&row.key_v2()[1..]);
    if record.key() != row.key_v2() || (row.controller_next, row.controller_end) != (next, end)
        || replay::record_bytes(state, PREFIX, id).is_some()
        || transaction.id() != &row.transaction_id_data_v2()?
        || replay::validate(state)? != Some(row.enrollment)
    {
        return Err(ResourceBankDataError::Conflict);
    }
    Ok(())
}
