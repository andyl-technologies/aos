//! Retains actual Root-genesis capacity preparation and recovery custody.
//!
//! Only the ordinary Genesis owner enters these private originals. Canonical
//! record construction and settlement comparisons stay in Broker and Protocol;
//! this module retains the real fixed writer and its reached native checks.

use std::error::Error;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::domain_transaction_custody::capacity_records::{
    self, PreparedCapacityRecordDataV1, RetainedCapacityRecordDataV1,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, reservation_id,
    reservation_key,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::{
    family::require_legacy_reservations, validate_request_with_limits,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use crate::native::authority::{RootAuthorityErrorV1, RootAuthorityOriginalV1};
use crate::native::journal::RootPolicyJournalV1;

use super::super::names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1};

/// Keeps the actual reached preparation before its record can enter an append.
pub(super) struct PreparedRootGenesisCapacityOriginalV1 {
    owner: RootAuthorityNamesOriginalV1,
    preparation: Option<Result<PreparedCapacityRecordDataV1, RootAuthorityErrorV1>>,
    entered: bool,
    reentered: bool,
}

impl PreparedRootGenesisCapacityOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            owner: RootAuthorityNamesOriginalV1::new(),
            preparation: None,
            entered: false,
            reentered: false,
        }
    }

    pub(super) fn prepare_once(
        &mut self,
        authority: &RootAuthorityOriginalV1,
        request: GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
    ) -> Result<(), ()> {
        if self.entered {
            self.reentered = true;
            return Err(());
        }
        self.entered = true;
        let journal = &authority.journal;
        self.preparation = Some((|| {
            journal.require_healthy_native()?;
            if request.purpose.is_first_source_successor() {
                return Err(Mechanical::ProtectedBoundary.into());
            }
            validate_request_with_limits(&request, journal.limits()).map_err(Mechanical::from)?;
            if request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
                return Err(Mechanical::ForeignAuthorityNamespace.into());
            }
            self.owner
                .observe_transient_once_v1(journal, RootAuthorityNameRecipeV1::Owner)
                .map_err(|()| RootAuthorityErrorV1::Stale)?;
            Ok(capacity_records::prepare_capacity_record_v1(
                journal.read_view().historical_view(),
                request,
                admission,
            )
            .map_err(Mechanical::from)?)
        })());
        if self.preparation.as_ref().is_some_and(Result::is_ok) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn data(&self) -> Result<&PreparedCapacityRecordDataV1, Mechanical> {
        if self.reentered {
            return Err(Mechanical::ProtectedBoundary);
        }
        self.preparation
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(Mechanical::ProtectedBoundary)
    }

    pub(super) fn record(&self) -> Result<&JournalRecord, Mechanical> {
        Ok(&self.data()?.record)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        // A native owner failure is represented by the preparation's Stale
        // marker; it is the selected earlier cause, not a later post override.
        self.owner.failure().or_else(|| {
            self.preparation
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _)
        })
    }

    pub(super) fn require_admission_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), Mechanical> {
        let prepared = self.data()?;
        require_claim_v1(journal, transaction)?;
        if transaction.id() != &prepared.admission_transaction_id
            || transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
                .ne([&prepared.record])
        {
            return Err(Mechanical::AuthorityPreflightMismatch);
        }
        Ok(())
    }

    pub(super) fn retained_after_commit_v1(
        &self,
    ) -> Result<RootGenesisCapacityOriginalV1, Mechanical> {
        use sha2::{Digest as _, Sha256};
        let prepared = self.data()?;
        let bytes = prepared
            .record
            .value()
            .ok_or(Mechanical::InvalidTransaction)?;
        Ok(RootGenesisCapacityOriginalV1 {
            data: RetainedCapacityRecordDataV1 {
                request: prepared.request,
                admission_transaction_id: prepared.admission_transaction_id,
                reservation_id: prepared.reservation_id,
                record_digest: Sha256::digest(bytes).into(),
            },
        })
    }
}

/// Holds the original canonical record after real admission or native recovery.
pub(super) struct RootGenesisCapacityOriginalV1 {
    data: RetainedCapacityRecordDataV1,
}

impl RootGenesisCapacityOriginalV1 {
    // No public supplied-record constructor exists. Recovery reads the complete
    // actual journal's canonical capacity snapshot before selecting this row.
    pub(super) fn recover_v1(
        authority: &RootAuthorityOriginalV1,
        identity: [u8; 32],
    ) -> Result<Self, RootAuthorityErrorV1> {
        authority.journal.require_healthy_native()?;
        let decoded = capacity_records::lookup_capacity_record_v1(
            authority.journal.read_view().historical_view(),
            identity,
        )
        .map_err(Mechanical::from)?
        .ok_or(Mechanical::MalformedRecord(
            "capacity reservation is absent",
        ))?;
        if decoded.request.purpose.is_first_source_successor() {
            return Err(Mechanical::ProtectedBoundary.into());
        }
        let data = decoded.compare_provenance().map_err(Mechanical::from)?;
        Ok(Self { data })
    }

    pub(super) fn matches_request_v1(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
    ) -> bool {
        self.data.request == *request && self.data.admission_transaction_id == admission
    }

    pub(super) fn identity_for_v1(
        authority: &RootAuthorityOriginalV1,
        request: &GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
        owner: &mut RootAuthorityNamesOriginalV1,
    ) -> Result<[u8; 32], RootAuthorityErrorV1> {
        owner
            .observe_transient_once_v1(&authority.journal, RootAuthorityNameRecipeV1::Owner)
            .map_err(|()| RootAuthorityErrorV1::Stale)?;
        if request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(Mechanical::ForeignAuthorityNamespace.into());
        }
        let identity = reservation_id(request, admission);
        let retained = Self::recover_v1(authority, identity)?;
        if !retained.matches_request_v1(request, admission) {
            return Err(Mechanical::AuthorityPreflightMismatch.into());
        }
        Ok(identity)
    }

    pub(super) fn request(&self) -> GlobalCapacityReservationRequestV1 {
        self.data.request
    }

    pub(super) fn reservation_id(&self) -> [u8; 32] {
        self.data.reservation_id
    }

    pub(super) fn settlement_record(&self) -> JournalRecord {
        JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.data.reservation_id),
        )
    }

    pub(super) fn compare_terminal_v1<'transaction>(
        &self,
        journal: &RootPolicyJournalV1,
        transaction: &'transaction JournalTransaction,
    ) -> Result<capacity_records::CapacitySettlementComparisonDataV1<'transaction>, Mechanical>
    {
        if self.data.request.purpose.is_first_source_successor() {
            return Err(Mechanical::ProtectedBoundary);
        }
        if self.data.request.future_transactions != 1 {
            return Err(Mechanical::AuthorityPreflightMismatch);
        }
        capacity_records::compare_capacity_settlement_v1(
            journal.read_view().historical_view(),
            self.data,
            transaction,
        )
        .map_err(Mechanical::from)
    }

    pub(super) fn require_settlement_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transaction: &JournalTransaction,
    ) -> Result<(), Mechanical> {
        require_claim_v1(journal, transaction)?;
        if self.data.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
        {
            return Err(Mechanical::ForeignAuthorityNamespace);
        }
        if self.data.request.future_transactions != 1 {
            return Err(Mechanical::AuthorityPreflightMismatch);
        }
        // Keep this comparison's actual borrowed collection alive until the
        // exact Root-specific settlement comparison has also returned.
        let _comparison = capacity_records::compare_capacity_settlement_v1(
            journal.read_view().historical_view(),
            self.data,
            transaction,
        )
        .map_err(Mechanical::from)?;
        aos_sandbox_ledger_replay::replay::root_genesis_capacity::validate_settlement(
            journal.read_view().historical_view(),
            transaction,
            &self.data.request,
            self.data.reservation_id,
        )
    }
}

pub(super) fn require_claim_v1(
    journal: &RootPolicyJournalV1,
    transaction: &JournalTransaction,
) -> Result<(), Mechanical> {
    require_legacy_reservations(journal.read_view().state()).map_err(Mechanical::from)?;
    if transaction.records().iter().any(|record| {
        !matches!(
            record.namespace(),
            RecordNamespace::DesiredState | RecordNamespace::GlobalCapacityReservation,
        )
    }) {
        return Err(Mechanical::ForeignAuthorityNamespace);
    }
    Ok(())
}
