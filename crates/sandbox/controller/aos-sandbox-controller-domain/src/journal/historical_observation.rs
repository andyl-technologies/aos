//! Lends historical rows while retaining their actual native observation owner.
//!
//! The closed owner is either the existing Domain journal or Root's genuine
//! completed readonly model. Saved rows never supply a health or protected
//! check: each such check dispatches to that same continuously borrowed owner.
//! This loan opens nothing and cannot issue a writer, role or admission grant.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use aos_sandbox_model::{ProjectId, RecordNamespace};
#[cfg(target_os = "linux")]
use aos_sandbox_policy::native::{RootReadonlyErrorV1, RootReadonlyModelOriginalsV1};
use aos_sandbox_protocol::domain_ledger::readonly::{
    HistoricalLedgerReadViewV1, HistoricalLedgerRowsDataV2, IdempotencyOutcome,
};
use aos_sandbox_protocol::domain_ledger::transaction::IdempotencyKey;

use super::{Journal, JournalError};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

// Both actual owners use the same current-map representation recipe. Keeping
// this lexical avoids a new forwarding frame on ordinary append callers.
macro_rules! semantic_append_model_data_v2 {
    ($state:expr) => {{
        let encoded = $state.iter().try_fold(0_usize, |total, ((_, key), value)| {
            total.checked_add(key.capacity()).and_then(|n| n.checked_add(value.capacity()))
                .ok_or(JournalError::JournalTooLarge)
        })?;
        super::semantic_receiving::semantic_representation_demand_v1(encoded, $state.len())
    }};
}

pub(super) use semantic_append_model_data_v2;

#[derive(Clone, Copy)]
enum Owner<'read> {
    Journal(&'read Journal),
    #[cfg(target_os = "linux")]
    Root(&'read RootReadonlyModelOriginalsV1),
}

/// Borrows one actual owner and its immutable historical rows and coordinates.
#[derive(Clone, Copy)]
pub(crate) struct HistoricalObservationV1<'read> {
    owner: Owner<'read>,
    rows: HistoricalLedgerRowsDataV2<'read>,
    namespaces: &'read BTreeSet<RecordNamespace>,
    next: u64,
}

impl<'read> HistoricalObservationV1<'read> {
    pub(crate) fn from_journal_v1(journal: &'read Journal) -> Self {
        Self {
            owner: Owner::Journal(journal),
            rows: journal.historical_read_view_v1().rows_data_v2(),
            namespaces: journal.native.committed_namespaces(),
            next: journal.snapshot_sequence(),
        }
    }

    // Only a real model can lend this arm. Its same held maps/index and NEXT
    // remain immutably borrowed; no supplied map or successful stage is accepted.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_root_model_v1(
        original: &'read RootReadonlyModelOriginalsV1,
    ) -> Result<Self, JournalError> {
        let rows = original.historical_rows_data_v2().map_err(root_readonly_error_v1)?;
        let namespaces = original.namespaces_v1().map_err(root_readonly_error_v1)?;
        let next = original.next_sequence_v1().map_err(root_readonly_error_v1)?;
        Ok(Self { owner: Owner::Root(original), rows, namespaces, next })
    }

    pub(crate) fn ensure_healthy(self) -> Result<(), JournalError> {
        match self.owner {
            Owner::Journal(original) => original.ensure_healthy(),
            #[cfg(target_os = "linux")]
            Owner::Root(original) => original.require_healthy_v1().map_err(root_readonly_error_v1),
        }
    }

    pub(crate) fn ensure_protected_authority(self) -> Result<(), JournalError> {
        match self.owner {
            Owner::Journal(original) => original.ensure_protected_authority(),
            #[cfg(target_os = "linux")]
            Owner::Root(original) => original.require_protected_v1().map_err(root_readonly_error_v1),
        }
    }

    pub(crate) fn ensure_controller_v1(self) -> Result<(), JournalError> {
        match self.owner {
            Owner::Journal(original) => super::controller_policy_hold::ensure_controller(original),
            #[cfg(target_os = "linux")]
            Owner::Root(original) => original.require_controller_v1().map_err(root_readonly_error_v1),
        }
    }

    // The CPU comparison receives the actual saved flags and checks them at
    // its original semantic slots. Reading these flags is not a health check.
    pub(crate) fn historical_status_data_v2(self) -> Result<(bool, bool), JournalError> {
        match self.owner {
            Owner::Journal(original) => Ok((original.native.is_poisoned(), original.native.is_protected())),
            #[cfg(target_os = "linux")]
            Owner::Root(original) => original.historical_status_data_v2().map_err(root_readonly_error_v1),
        }
    }

    /// Prices the same current semantic models without authorizing an append.
    pub(crate) fn semantic_append_model_demand_v2(self)
        -> Result<aos_sandbox_model::ResourceVector, JournalError>
    {
        self.ensure_healthy()?;
        semantic_append_model_data_v2!(self.state_v1())
    }

    pub(crate) fn state_v1(self) -> &'read State {
        self.rows.materialized_state_data_v2()
    }

    pub(crate) const fn rows_data_v2(self) -> HistoricalLedgerRowsDataV2<'read> {
        self.rows
    }

    pub(crate) const fn next_sequence_v1(self) -> u64 {
        self.next
    }

    pub(crate) const fn committed_namespaces_v1(self) -> &'read BTreeSet<RecordNamespace> {
        self.namespaces
    }

    pub(crate) fn get(self, namespace: RecordNamespace, key: &[u8]) -> Option<&'read [u8]> {
        self.rows.get_data_v2(namespace, key)
    }

    pub(crate) fn records(
        self,
        namespace: RecordNamespace,
    ) -> impl Iterator<Item = (&'read [u8], &'read [u8])> + 'read {
        self.rows.records_data_v2(namespace)
    }

    pub(crate) fn all_records(
        self,
    ) -> impl Iterator<Item = (RecordNamespace, &'read [u8], &'read [u8])> + 'read {
        self.rows.all_records()
    }

    pub(crate) fn check_idempotency(
        self,
        key: &IdempotencyKey,
        request_digest: [u8; 32],
    ) -> IdempotencyOutcome {
        self.rows.check_idempotency_data_v2(key, request_digest)
    }

    pub(crate) fn require_public_mutation_targets_live_v2(
        self,
        project: ProjectId,
        request: &aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        aos_sandbox_protocol::domain_ledger::delete_batch::new_use::
            require_public_mutation_targets_live_data_v2(
                project, request, self.records(RecordNamespace::DesiredState),
            ).map_err(JournalError::NewUseTombstone)
    }

    /// Prices the new closed loan and actual native-query/error forwarding.
    ///
    /// The containing fixed reader admits this Memory-only quote before its
    /// native entry. Dynamic maps, replay, paths and role models stay separate.
    pub(crate) fn receiving_control_bytes_v1() -> Option<usize> {
        let shared = Self::shared_control_bytes_v1()?;
        #[cfg(target_os = "linux")]
        let native = Self::native_control_bytes_v1()?;
        #[cfg(not(target_os = "linux"))]
        let native = 0;
        shared.max(native).checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    /// Prices only the actual Journal branch for Controller-owned callers.
    pub(crate) fn journal_receiving_control_bytes_v1() -> Option<usize> {
        Self::shared_control_bytes_v1()?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    fn shared_control_bytes_v1() -> Option<usize> {
        let domain_constructor = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<Owner<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<&Journal>().checked_mul(3)?)?
            .checked_add(size_of::<HistoricalLedgerReadViewV1<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<HistoricalLedgerRowsDataV2<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<&BTreeSet<RecordNamespace>>().checked_mul(3)?)?
            .checked_add(size_of::<u64>().checked_mul(3)?)?;

        let observation = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<&Journal>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(size_of::<(bool, bool)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(bool, bool), JournalError>>().checked_mul(3)?)?;

        let query = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<HistoricalLedgerRowsDataV2<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<RecordNamespace>().checked_mul(3)?)?
            .checked_add(size_of::<&[u8]>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&[u8]>>().checked_mul(3)?)?
            .checked_add(size_of::<&State>().checked_mul(3)?)?
            .checked_add(size_of::<&IdempotencyKey>().checked_mul(3)?)?
            .checked_add(size_of::<[u8; 32]>().checked_mul(3)?)?
            .checked_add(size_of::<IdempotencyOutcome>().checked_mul(3)?)?
            .checked_add(record_iterator_bytes_v1(Self::records)?)?
            .checked_add(all_iterator_bytes_v1(Self::all_records)?)?;

        let new_use = observation
            .checked_add(size_of::<ProjectId>().checked_mul(3)?)?
            .checked_add(size_of::<&aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1>().checked_mul(3)?)?
            .checked_add(record_iterator_bytes_v1(Self::records)?)?
            .checked_add(size_of::<Result<(), aos_sandbox_protocol::domain_ledger::delete_batch::new_use::PublicMutationNewUseErrorV2>>().checked_mul(3)?)?;

        domain_constructor.max(observation).max(query).max(new_use)
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }

    #[cfg(target_os = "linux")]
    fn native_control_bytes_v1() -> Option<usize> {
        let constructor = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<Owner<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<&RootReadonlyModelOriginalsV1>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Self, JournalError>>().checked_mul(3)?)?
            .checked_add(size_of::<HistoricalLedgerRowsDataV2<'_>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<HistoricalLedgerRowsDataV2<'_>, RootReadonlyErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<&BTreeSet<RecordNamespace>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<&BTreeSet<RecordNamespace>, RootReadonlyErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<u64>().checked_mul(3)?)?
            .checked_add(size_of::<Result<u64, RootReadonlyErrorV1>>().checked_mul(3)?)?;

        let observation = size_of::<Self>().checked_mul(3)?
            .checked_add(size_of::<&RootReadonlyModelOriginalsV1>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), RootReadonlyErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), JournalError>>().checked_mul(3)?)?
            .checked_add(size_of::<(bool, bool)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(bool, bool), RootReadonlyErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(bool, bool), JournalError>>().checked_mul(3)?)?;

        // A failed native result is moved through the finite old-error bridge;
        // its input and returned cause remain owning values, not pointer slack.
        constructor.max(observation)
            .checked_add(size_of::<RootReadonlyErrorV1>().checked_mul(3)?)?
            .checked_add(size_of::<JournalError>().checked_mul(3)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}

// These method values are never invoked. Inference measures the actual opaque
// iterator returned by each fixed loan method, without fabricating a native
// owner, row map, successful return or runtime observation callback.
fn record_iterator_bytes_v1<'rows, Rows>(
    _method: fn(HistoricalObservationV1<'rows>, RecordNamespace) -> Rows,
) -> Option<usize>
where
    Rows: Iterator<Item = (&'rows [u8], &'rows [u8])>,
{
    size_of::<Rows>().checked_mul(3)?
        .checked_add(size_of::<fn(HistoricalObservationV1<'rows>, RecordNamespace) -> Rows>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
}

fn all_iterator_bytes_v1<'rows, Rows>(
    _method: fn(HistoricalObservationV1<'rows>) -> Rows,
) -> Option<usize>
where
    Rows: Iterator<Item = (RecordNamespace, &'rows [u8], &'rows [u8])>,
{
    size_of::<Rows>().checked_mul(3)?
        .checked_add(size_of::<fn(HistoricalObservationV1<'rows>) -> Rows>().checked_mul(3)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(2)?)
}

/// Moves each exact native readonly cause into its existing Domain error lane.
#[cfg(target_os = "linux")]
pub(crate) fn root_readonly_error_v1(cause: RootReadonlyErrorV1) -> JournalError {
    match cause {
        RootReadonlyErrorV1::Mechanical(cause) => JournalError::from(cause),
        RootReadonlyErrorV1::JournalTooLarge => JournalError::JournalTooLarge,
        RootReadonlyErrorV1::ProtectedBoundary => JournalError::ProtectedBoundary,
        RootReadonlyErrorV1::ReadOnlyNameReceivingFailure(index) => JournalError::ReadOnlyNameReceivingFailure(index),
        RootReadonlyErrorV1::StaleAuthoritySnapshot => JournalError::StaleAuthoritySnapshot,
        RootReadonlyErrorV1::Poisoned => JournalError::Poisoned,
        RootReadonlyErrorV1::LimitExceeded(label) => JournalError::LimitExceeded(label),
        RootReadonlyErrorV1::ReceivingAccounting(cause) => JournalError::ReceivingAccounting(cause),
    }
}
