//! Admits Cache readonly replay through the same genuine J, U or C17 lender.
//!
//! The native Cache loan alone creates this private binding from its original
//! identity and captured extent. The canonical parser supplies transactions
//! and coordinates; Protocol owns suffix comparisons and LedgerReplay owns the
//! reached semantic geometry. No callback or caller-implemented payer enters.

use std::collections::BTreeMap;

use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerCacheAuditFundingErrorV1, ControllerCacheAuditFundingLoanV1,
    ControllerCacheAuditIdentityDataV1,
};
use aos_sandbox_model::{RecordNamespace, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::{
    HistoryPairNativeChainDataV1, HistoryPairNativeSuffixV1,
};

use super::{JournalError, JournalTransaction};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(crate) enum CacheReadonlySuffixV1<'data, 'progress> {
    None,
    Held(HistoryPairNativeSuffixV1<'data, 'progress>),
    Released(HistoryPairNativeChainDataV1<'data, 'progress, 2>),
}

pub(crate) struct CacheReadonlyReceivingContextV1<'borrow, 'funding, 'profile, 'data> {
    pub(crate) funding: &'borrow mut ControllerCacheAuditFundingLoanV1<'funding, 'profile>,
    pub(crate) identity: ControllerCacheAuditIdentityDataV1,
    pub(crate) complete_base: ResourceVector,
    pub(crate) prepaid_semantic: ResourceVector,
    pub(crate) captured_end: u64,
    pub(crate) suffix: CacheReadonlySuffixV1<'data, 'borrow>,
    pub(crate) geometry: &'borrow mut Option<Result<ResourceVector, JournalError>>,
    pub(crate) admission: &'borrow mut Option<Result<(), ControllerCacheAuditFundingErrorV1>>,
}

impl CacheReadonlyReceivingContextV1<'_, '_, '_, '_> {
    pub(crate) fn require_fixed_named_preparation(&mut self) -> Result<(), JournalError> {
        if self.failed() {
            return Err(JournalError::boundary());
        }
        *self.admission = Some(self.funding.require_named_preparation_v1(self.identity));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn require_captured_file_end(&self, actual_end: u64) -> Result<(), JournalError> {
        if actual_end != self.captured_end || self.failed() {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn before_semantic_replay(
        &mut self,
        state: &State,
        transaction: Option<&JournalTransaction>,
    ) -> Result<(), JournalError> {
        if self.failed() {
            return Err(JournalError::boundary());
        }
        *self.geometry = Some((|| {
            let dynamic = aos_sandbox_ledger_replay::geometry::reached::semantic_demand_v1(
                state, transaction,
            ).map_err(JournalError::from)?;
            let prepaid = self.prepaid_semantic;
            let additional = dynamic.componentwise_max(prepaid).checked_sub(prepaid)
                .map_err(|_| JournalError::limit_exceeded("Cache readonly semantic geometry"))?;
            self.complete_base.checked_add(additional)
                .map_err(|_| JournalError::limit_exceeded("Cache readonly semantic geometry"))
        })());
        let complete = self.geometry.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or_else(JournalError::boundary)?;
        *self.admission = Some(self.funding.admit_complete_v1(self.identity, complete));
        if !matches!(self.admission, Some(Ok(()))) {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    pub(crate) fn observe_native_commit(
        &mut self,
        transaction: &JournalTransaction,
        begin_sequence: u64,
        commit_sequence: u64,
        begin_offset: u64,
        end_offset: u64,
    ) -> Result<(), JournalError> {
        match &mut self.suffix {
            CacheReadonlySuffixV1::None => Ok(()),
            CacheReadonlySuffixV1::Held(suffix) => suffix.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
            CacheReadonlySuffixV1::Released(suffix) => suffix.observe(
                transaction, begin_sequence, commit_sequence, begin_offset, end_offset,
            ),
        }.map_err(|_| JournalError::boundary())
    }

    pub(crate) fn finish_native(
        &mut self,
        durable_next: u64,
        durable_end: u64,
        captured_end: u64,
    ) -> Result<(), JournalError> {
        self.require_captured_file_end(captured_end)?;
        match &mut self.suffix {
            CacheReadonlySuffixV1::None => Ok(()),
            CacheReadonlySuffixV1::Held(suffix) => {
                suffix.finish(durable_next, durable_end, captured_end)
            }
            CacheReadonlySuffixV1::Released(suffix) => {
                suffix.finish(durable_next, durable_end, captured_end)
            }
        }.map_err(|_| JournalError::boundary())
    }

    fn failed(&self) -> bool {
        if matches!(self.geometry, Some(Err(_))) || matches!(self.admission, Some(Err(_))) {
            return true;
        }
        match &self.suffix {
            CacheReadonlySuffixV1::None => false,
            CacheReadonlySuffixV1::Held(suffix) => suffix.failure().is_some(),
            CacheReadonlySuffixV1::Released(suffix) => suffix.failure_v1().is_some(),
        }
    }
}

// Prices the SAME full prefix semantic recipe as the original Domain extent.
// The canonical native extent's similarly named method prices only key-index
// validation. It cannot stand in for typed Ledger row/family representations.
pub(crate) fn full_prefix_semantic_demand_v1(
    extent: &super::ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector, JournalError> {
    let invalid = || JournalError::limit_exceeded("native semantic receiving demand");
    if extent.native_bytes() > extent.limits().maximum_journal_bytes {
        return Err(invalid());
    }
    let physical = usize::try_from(extent.native_bytes()).map_err(|_| invalid())?;
    let rows = physical.checked_div(aos_sandbox_journal::framing::HEADER_BYTES)
        .ok_or_else(invalid)?;
    aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(
        physical, rows,
    ).map_err(JournalError::from)
}

// S is the actual old upper compiled control quote, not payment or a waiver.
// Reached Ledger R is deliberately unchanged; only prefix P includes S.
pub(crate) fn with_semantic_supplement_v1(
    canonical: ResourceVector,
    supplement: ResourceVector,
) -> Result<ResourceVector, JournalError> {
    canonical.checked_add(supplement)
        .map_err(|_| JournalError::limit_exceeded("native history observer representation"))
}

// Preserve each original extent's full-P → upper-S frontier, starting with
// Bootstrap. The actual upper Result remains owned above the crate boundary;
// absence is only a refusal after this extent's full Ledger forecast succeeds.
pub(crate) fn full_prefix_semantic_peak_with_supplement_v1(
    extents: &[super::ProtectedJournalPreopenReplayExtentV1; 5],
    supplement: Option<ResourceVector>,
) -> Result<ResourceVector, JournalError> {
    let mut peak = ResourceVector::ZERO;
    for extent in extents {
        let complete = full_prefix_semantic_with_supplement_v1(extent, supplement)?;
        peak = peak.componentwise_max(complete);
    }
    Ok(peak)
}

// Single-extent form lets actual Delete construction retain its original
// N_i → P_i → S frontier before advancing to the next writer. Both entry forms
// share this sole checked supplement/error-selection body.
pub(crate) fn full_prefix_semantic_with_supplement_v1(
    extent: &super::ProtectedJournalPreopenReplayExtentV1,
    supplement: Option<ResourceVector>,
) -> Result<ResourceVector, JournalError> {
    let full = full_prefix_semantic_demand_v1(extent)?;
    let supplement = supplement.ok_or(JournalError::DeferredUpperSemanticQuote)?;
    with_semantic_supplement_v1(full, supplement)
}

// The actual caller adds these compiled controls to its existing forecast
// invoice. No native file, model allocation, account or Metadata is priced here.
pub(crate) fn full_prefix_peak_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    full_prefix_element_control_bytes_v1()?
        .checked_add(size_of::<Option<ResourceVector>>())?
        .checked_add(size_of::<ResourceVector>().checked_mul(3)?)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<&[super::ProtectedJournalPreopenReplayExtentV1; 5]>())
}

// C1 reaches only the element entry at its original prepared-prefix slot.
// It prices that actual forwarding plane without inventing a five-reader pass.
pub(crate) fn full_prefix_element_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    size_of::<Option<ResourceVector>>()
        .checked_add(size_of::<ResourceVector>().checked_mul(2)?)?
        .checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?)?
        .checked_add(size_of::<&super::ProtectedJournalPreopenReplayExtentV1>())
}

#[cfg(test)]
mod forecast_tests {
    use super::*;
    use aos_sandbox_model::ResourceDimension;

    #[test]
    fn full_prefix_uses_the_same_ledger_geometry_and_adds_only_the_forecast_supplement() {
        let extent = super::super::ProtectedJournalPreopenReplayExtentV1::new(
            super::super::JournalLimits::default(), 0,
        ).unwrap();
        let supplement = ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 13);
        let expected = aos_sandbox_ledger_replay::geometry::semantic_rows::semantic_representation_demand_v1(0, 0)
            .unwrap().checked_add(supplement).unwrap();

        let actual = full_prefix_semantic_with_supplement_v1(&extent, Some(supplement)).unwrap();

        assert_eq!(actual, expected);
        assert!(matches!(full_prefix_semantic_with_supplement_v1(&extent, None),
            Err(JournalError::DeferredUpperSemanticQuote)));
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn full_ledger_overflow_precedes_the_deferred_upper_error() {
        let limits = super::super::JournalLimits {
            maximum_journal_bytes: u64::MAX,
            ..Default::default()
        };
        let extent = super::super::ProtectedJournalPreopenReplayExtentV1::new(limits, u64::MAX).unwrap();
        let first = full_prefix_semantic_demand_v1(&extent).unwrap_err();

        let actual = full_prefix_semantic_with_supplement_v1(&extent, None).unwrap_err();

        assert!(!matches!(actual, JournalError::DeferredUpperSemanticQuote));
        assert_eq!(std::mem::discriminant(&actual), std::mem::discriminant(&first));
    }
}
