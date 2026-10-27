//! Adds a closed final clock restriction to the actual Storage Prepare owner.
//!
//! This loan borrows authenticated admission and the exact sealed transaction.
//! It grants no journal authority: Native must still apply every ordinary guard.
//! The four members remain DesiredState, Effect, AuthorityPublication and
//! StorageCatalogPreparation, in that order. No format or issuer is added.

use aos_sandbox_model::{BrokerGrantTarget, BrokerVerb, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_protocol::nix_generation::CanonicalNixGenerationPreparationV1;

use super::{
    BrokerAdmissionError, BrokerAuthority, BrokerDomain, BrokerEffectStatusV1,
    BrokerLocalRecordDomain, RecordNamespace, VerifiedBrokerAdmission,
};

const PREPARATION_DOMAIN: [u8; 16] = *b"AOSSTGPREPV10001";

enum PreparationInputV1<'original> {
    Nix(&'original CanonicalNixGenerationPreparationV1),
    Ordinary(
        &'original aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1,
    ),
}

impl PreparationInputV1<'_> {
    fn preparation(
        &self,
    ) -> &aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1 {
        match self {
            Self::Nix(selected) => selected.prepare(),
            Self::Ordinary(preparation) => preparation,
        }
    }

    fn commitment(&self) -> aos_sandbox_model::BrokerArgumentCommitment {
        match self {
            Self::Nix(selected) => selected.argument_commitment(),
            Self::Ordinary(preparation) => preparation.argument_commitment(),
        }
    }
}

/// Borrows an exact admitted Prepare solely to restrict its append.
///
/// This is neither a transferable grant nor a generic clock callback. Native
/// observes the clock itself while these original authority objects stay held.
/// Ordinary semantic, capacity, Q04 and other owner guards remain mandatory.
pub struct StoragePrepareNativeClockLoanV1<'original> {
    authority: &'original BrokerAuthority,
    admission: &'original VerifiedBrokerAdmission,
    input: PreparationInputV1<'original>,
    transaction: &'original JournalTransaction,
}

impl BrokerAuthority {
    /// Borrows a fixed extra clock check for the same original Nix preparation.
    ///
    /// It authenticates all four exact native locations before frame building.
    /// There is no caller timestamp, deadline override or replacement issuer.
    ///
    /// # Errors
    /// Rejects another broker purpose, substituted wrapper, differing admitted
    /// effect/fence or any malformed, moved, missing or extra sealed member.
    pub fn borrow_nix_storage_prepare_native_clock<'original>(
        &'original self,
        admission: &'original VerifiedBrokerAdmission,
        selected: &'original CanonicalNixGenerationPreparationV1,
        transaction: &'original JournalTransaction,
    ) -> Result<StoragePrepareNativeClockLoanV1<'original>, BrokerAdmissionError> {
        self.borrow_storage_prepare_native_clock_for_v1(
            admission, PreparationInputV1::Nix(selected), transaction,
        )
    }

    /// Borrows a final clock restriction for the actual ordinary Prepare admission.
    ///
    /// The same verifier, effect, fence and exact four sealed members remain
    /// borrowed. This supplies no journal authority and no Nix prefix identity.
    ///
    /// # Errors
    /// Rejects a mismatched purpose, admitted request/fence or sealed transaction.
    pub fn borrow_ordinary_storage_prepare_native_clock<'original>(
        &'original self,
        admission: &'original VerifiedBrokerAdmission,
        preparation: &'original aos_sandbox_protocol::semantics::storage_prepare::CanonicalStoragePreparationSemanticsV1,
        transaction: &'original JournalTransaction,
    ) -> Result<StoragePrepareNativeClockLoanV1<'original>, BrokerAdmissionError> {
        self.borrow_storage_prepare_native_clock_for_v1(
            admission, PreparationInputV1::Ordinary(preparation), transaction,
        )
    }

    fn borrow_storage_prepare_native_clock_for_v1<'original>(
        &'original self,
        admission: &'original VerifiedBrokerAdmission,
        input: PreparationInputV1<'original>,
        transaction: &'original JournalTransaction,
    ) -> Result<StoragePrepareNativeClockLoanV1<'original>, BrokerAdmissionError> {
        let effect = &admission.effect;
        let preparation = input.preparation();
        let assignment = admission.fence.assignment();
        if self.domain != BrokerDomain::Storage
            || effect.status() != BrokerEffectStatusV1::Pending
            || effect.verb() != BrokerVerb::StoragePrepareCatalog
            || effect.target() != BrokerGrantTarget::Assignment
            || effect.request_id() != preparation.header().request_id()
            || effect.request_digest() != input.commitment().digest()
            || effect.plan_digest() != admission.fence.plan_digest()
            || effect.lease_digest() != admission.fence.local_lease_record().lease_digest()
            || assignment.sandbox().as_bytes() != preparation.fence().sandbox_id()
            || assignment.incarnation().as_bytes() != preparation.fence().incarnation_id()
            || assignment.epoch().get() != preparation.fence().assignment_epoch()
            || assignment.desired_generation().get() != preparation.fence().desired_generation()
            || assignment.digest().as_bytes() != preparation.fence().assignment_digest()
            || matches!(&input, PreparationInputV1::Nix(selected)
                if admission.fence.node().as_bytes() != &selected.origin().node
                    || effect.host_boot_id() != &selected.prefix().host_boot_id
                    || effect.request_deadline_boottime_nanoseconds()
                        != selected.prefix().deadline_boottime_nanoseconds)
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        self.check_current_fence(&admission.fence)?;
        let records = transaction.records();
        let sandbox = assignment.sandbox();
        let operation = preparation.operation_id();
        let request = effect.request_id();
        let locations = [
            (RecordNamespace::DesiredState, sandbox.as_bytes().as_slice()),
            (RecordNamespace::Effect, request.as_slice()),
            (RecordNamespace::AuthorityPublication, operation.as_slice()),
            (
                RecordNamespace::StorageCatalogPreparation,
                operation.as_slice(),
            ),
        ];
        if records.len() != locations.len()
            || records.iter().zip(locations).any(|(record, location)| {
                record.namespace() != location.0
                    || record.key() != location.1
                    || record.value().is_none()
            })
        {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let value = |index: usize| {
            records[index]
                .value()
                .ok_or(BrokerAdmissionError::RequestMismatch)
        };
        let fence_matches = crate::record::require_exact_storage_prepare_fence(
            &self.journal_mac_key,
            RecordNamespace::DesiredState,
            sandbox.as_bytes(),
            value(0)?,
            &admission.fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if !fence_matches {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let effect_matches = crate::record::require_exact_storage_prepare_effect(
            &self.journal_mac_key,
            request,
            value(1)?,
            &admission.effect,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if !effect_matches {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let operation_matches = crate::record::require_exact_storage_prepare_fence(
            &self.journal_mac_key,
            RecordNamespace::AuthorityPublication,
            &operation,
            value(2)?,
            &admission.fence,
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if !operation_matches {
            return Err(BrokerAdmissionError::RequestMismatch);
        }
        let domain = BrokerLocalRecordDomain::new(PREPARATION_DOMAIN)
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        self.open_local_record(
            RecordNamespace::StorageCatalogPreparation,
            &operation,
            domain,
            value(3)?,
        )?;
        Ok(StoragePrepareNativeClockLoanV1 {
            authority: self,
            admission,
            input,
            transaction,
        })
    }
}

impl StoragePrepareNativeClockLoanV1<'_> {
    /// Borrows the exact immutable transaction authenticated by this restriction.
    #[must_use]
    pub fn transaction(&self) -> &JournalTransaction {
        self.transaction
    }

    /// Compares a Native-observed pair with the actual original restrictions.
    ///
    /// The sample is untrusted DATA here. The specific Native entrypoint must
    /// obtain it directly from its fixed kernel adapter at the append frontier.
    /// Successful comparison grants no journal or effect authority.
    ///
    /// # Errors
    /// Rejects changed provenance/boot, either clock rolling back or diverging,
    /// the selected Nix prefix expiry when applicable, or the earlier actual
    /// plan/lease/request expiry.
    pub fn require_native_clock(
        &self,
        current: RawPairedClockSample,
    ) -> Result<(), BrokerAdmissionError> {
        let effect = &self.admission.effect;
        let provenance = RawClockProvenance::new_untrusted(*effect.clock_provenance())
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        let original = RawPairedClockSample::new_untrusted(
            provenance,
            *effect.host_boot_id(),
            effect.admitted_wall_seconds(),
            effect.admitted_boottime_nanoseconds(),
        )
        .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        original
            .validate_later_sample(current)
            .map_err(|_| BrokerAdmissionError::FenceRejected)?;
        if matches!(&self.input, PreparationInputV1::Nix(selected)
            if current.host_boot_id() != selected.prefix().host_boot_id
                || current.boottime_nanoseconds() >= selected.prefix().deadline_boottime_nanoseconds)
        {
            return Err(BrokerAdmissionError::FenceRejected);
        }
        self.authority.validate_effect_clock(effect, &current)
    }
}
