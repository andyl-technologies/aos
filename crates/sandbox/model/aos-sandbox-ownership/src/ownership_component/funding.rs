//! Lends the sole real service ledger to one retained authenticated operation.
//!
//! Peak growth is charged once and remains charged. Only the actual transport
//! owner may dispose a completed positive request before reusing that peak;
//! failed requests keep their peak and native originals in the failed lane.

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use crate::{Journal, JournalError, JournalTransaction};
use aos_sandbox_broker::receiving::{FixedServiceReceivingCaptureV1, RepresentationDemandDebitV1};
use super::{CLOSED, OwnershipReceivingClosedV1};

#[derive(Debug, thiserror::Error)]
pub(super) enum DemandError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Append(#[from] crate::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    #[error(transparent)]
    Domain(#[from] crate::ownership_authority::DurableOwnershipAuthorityError),
}

#[derive(Default)]
pub(super) struct OperationPayment {
    pub(super) peak: ResourceVector,
    pub(super) fixed: ResourceVector,
    pub(super) demands: [Option<Result<ResourceVector, DemandError>>; 3],
    next: usize,
    pub(super) refusal: Option<AccountingError>,
    pub(super) closed: bool,
    pub(super) audits: [Option<Result<(), crate::journal::LocalOwnershipNativeHistoryErrorV1>>; 2],
    audit_names: [crate::ProtectedJournalCurrentnessOriginalsV1; 2],
    audit_next: usize,
}

impl OperationPayment {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.refusal.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.demands.iter().find_map(|slot| slot.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _)))
            .or_else(|| self.audits.iter().zip(&self.audit_names).find_map(|(slot, names)| slot.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause.first_cause(names))))
    }

    pub(super) fn new(peak: ResourceVector, fixed: ResourceVector) -> Self {
        Self { peak, fixed, ..Default::default() }
    }
}

/// Borrows an entered request and the exact original F; constructors are private.
///
/// The fixed caller has already authenticated the socket/MAC and reserved the
/// schema/signing/transaction representation before invoking the domain owner.
pub(crate) struct OwnershipOperationFundingLoanV1<'a> {
    pub(super) common: &'a mut FixedServiceReceivingCaptureV1<OwnershipReceivingClosedV1>,
    pub(super) opening: &'a crate::journal::OwnershipCapturedJournalOpenV1,
    pub(super) descriptor_bound: &'a mut u64,
    pub(super) descriptor_refusal: &'a mut Option<AccountingError>,
    pub(super) payment: &'a mut OperationPayment,
}

impl OwnershipOperationFundingLoanV1<'_> {
    /// Prices the actual held history before its independent native replay.
    pub(crate) fn before_history_v1(&mut self, journal: &Journal) -> Result<(), OwnershipReceivingClosedV1> {
        self.require_same_journal(journal)?;
        let demand = (|| {
            let shape = journal.first_global_allocation_shape_v1()?;
            let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
                crate::local_ownership::fixed_journal_limits_v1(), shape.native_bytes)?;
            let native = extent.dominant_native_receiving_demand_v1()?;
            let semantic = extent.dominant_semantic_receiving_demand_v1()?;
            let domain = crate::local_ownership::history_capture_demand_v1(journal)?;
            Ok(native.checked_add(semantic)?.checked_add(domain)?)
        })();
        self.admit_demand(demand.and_then(|demand| Ok(demand.checked_add(self.payment.fixed)?)))
    }

    pub(crate) fn audit_history_v1(&mut self, journal: &Journal) -> Result<(), OwnershipReceivingClosedV1> {
        self.before_history_v1(journal)?;
        if self.payment.audit_next >= self.payment.audits.len() {
            self.payment.closed = true;
            return Err(CLOSED);
        }
        let index = self.payment.audit_next;
        self.payment.audit_next += 1;
        self.payment.audits[index] = Some(journal.observe_local_ownership_native_history_v1(&mut self.payment.audit_names[index]));
        if matches!(self.payment.audits[index], Some(Ok(()))) { Ok(()) }
        else { self.payment.closed = true; Err(CLOSED) }
    }

    /// Prices this exact encoded transaction before preflight, audit or append.
    pub(crate) fn before_append_v1(
        &mut self, journal: &Journal, transaction: &JournalTransaction,
    ) -> Result<(), OwnershipReceivingClosedV1> {
        self.require_same_journal(journal)?;
        let demand = journal.append_receiving_demand_v1(transaction.records().iter().map(|record| {
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: record.key().len(), value_bytes: record.value().map(<[u8]>::len),
            }
        })).map_err(DemandError::from);
        self.admit_demand(demand.and_then(|demand| Ok(demand.checked_add(self.payment.fixed)?)))
    }

    pub(crate) fn retain_signing_v1(&mut self) -> Result<(), OwnershipReceivingClosedV1> {
        let Some(demand) = crate::local_ownership::retained_signing_demand_v1() else {
            self.payment.refusal.get_or_insert(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
            self.payment.closed = true;
            return Err(CLOSED);
        };
        self.common.representation.as_mut().ok_or(CLOSED)?.reserve(demand)
            .map_err(|_| { self.payment.closed = true; CLOSED })
    }

    pub(crate) fn retain_append_v1(
        &mut self, transaction: &JournalTransaction, carriers: usize,
    ) -> Result<(), OwnershipReceivingClosedV1> {
        let carriers = transaction.records().len().max(4)
            .checked_mul(std::mem::size_of::<crate::JournalRecord>())
            .and_then(|bytes| bytes.checked_add(carriers));
        let bytes = carriers.and_then(|carriers| transaction.records().iter().try_fold(carriers, |bytes, record| {
            bytes.checked_add(record.key().len())?.checked_add(record.value().map_or(0, <[u8]>::len))
        })).and_then(|bytes| u64::try_from(bytes).ok());
        let Some(bytes) = bytes else {
            self.payment.refusal.get_or_insert(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes });
            self.payment.closed = true;
            return Err(CLOSED);
        };
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::MetadataEntries, transaction.records().len() as u64);
        self.common.representation.as_mut().ok_or(CLOSED)?.reserve(demand)
            .map_err(|_| { self.payment.closed = true; CLOSED })
    }

    fn require_same_journal(&mut self, journal: &Journal) -> Result<(), OwnershipReceivingClosedV1> {
        if self.opening.was_taken_positive_v1() && self.opening.opening_owner_link_v1()
            .is_some_and(|link| link.matches_journal_v1(journal)) { Ok(()) }
        else { self.payment.closed = true; Err(CLOSED) }
    }

    fn admit_demand(&mut self, demand: Result<ResourceVector, DemandError>) -> Result<(), OwnershipReceivingClosedV1> {
        if self.payment.closed || self.payment.next >= self.payment.demands.len() {
            self.payment.closed = true;
            return Err(CLOSED);
        }
        let index = self.payment.next;
        self.payment.next += 1;
        self.payment.demands[index] = Some(demand);
        let Some(Ok(demand)) = self.payment.demands[index].as_ref() else {
            self.payment.closed = true;
            return Err(CLOSED);
        };
        let demand = *demand;
        grow_peak(self.common, self.descriptor_bound, self.descriptor_refusal, self.payment, demand)
    }
}

pub(super) fn grow_peak(
    common: &mut FixedServiceReceivingCaptureV1<OwnershipReceivingClosedV1>,
    descriptor_bound: &mut u64,
    descriptor_refusal: &mut Option<AccountingError>,
    payment: &mut OperationPayment,
    demand: ResourceVector,
) -> Result<(), OwnershipReceivingClosedV1> {
    if payment.closed || common.require_permanent_fd_coverage_v1().is_err() {
        payment.closed = true;
        return Err(CLOSED);
    }
    let (next, delta) = match aos_sandbox_model::component_receiving::complete_bound_delta_v1(payment.peak, demand) {
        Ok(growth) => growth,
        Err(cause) => { payment.refusal.get_or_insert(cause); payment.closed = true; return Err(CLOSED); }
    };
    let permanent = common.permanent_open_files()?;
    let bound = descriptor_bound.checked_add(delta.get(D::OpenFiles));
    if bound.is_none_or(|bound| bound > permanent) {
        let cause = match bound {
            Some(attempted) => AccountingError::LimitExceeded { dimension: D::OpenFiles, limit: permanent, attempted },
            None => AccountingError::ArithmeticOverflow { dimension: D::OpenFiles },
        };
        descriptor_refusal.get_or_insert(cause);
        payment.closed = true;
        return Err(CLOSED);
    }
    if let Err(cause) = common.representation.as_mut().ok_or(CLOSED)?.reserve(delta.with(D::OpenFiles, 0)) {
        payment.refusal.get_or_insert(cause.clone());
        payment.closed = true;
        return Err(CLOSED);
    }
    *descriptor_bound = bound.ok_or(CLOSED)?;
    payment.peak = next;
    Ok(())
}
