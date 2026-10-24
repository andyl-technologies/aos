//! Retains advisory preflight models on the original canonical recipe.
//!
//! These inert destinations grant no protected claim, token, writer or payment.
//! The real caller pays the complete source geometry before entry and keeps
//! this owner beside the actual returned token and independent native posts.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::canonical_journal::preflight::CanonicalPreflightDataOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::super::{ProtectedJournalPreflight, ProtectedJournalPreopenReplayExtentV1};
use super::*;

/// Keeps actual prospective maps, indices and reached encoder prefixes.
///
/// Construction allocates nothing. This once-owned DATA sink cannot substitute
/// for current protected authority, real funding or an effect token. The
/// original advisory preflight still runs every guard and validator.
#[must_use = "retain the failed advisory preflight with its actual native interval"]
pub struct ProtectedJournalPreflightOriginalV2 {
    pub(super) data: CanonicalPreflightDataOriginalV1,
    returned: Option<Result<(), JournalError>>,
    reentry: Option<JournalError>,
    entered: bool,
}

impl Default for ProtectedJournalPreflightOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedJournalPreflightOriginalV2 {
    /// Creates empty fixed destinations without allocation or writer entry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: CanonicalPreflightDataOriginalV1::new(),
            returned: None,
            reentry: None,
            entered: false,
        }
    }

    /// Prices the same source maps and each actual transaction's encoder/index.
    ///
    /// The extent belongs to the actual held prefix. Canonical mechanics quote
    /// the incoming representation; the same upper native and semantic extent
    /// suppliers quote the prospective prefix. This DATA grants no payment.
    ///
    /// # Errors
    /// Refuses invalid native/record geometry or checked representation overflow.
    pub fn receiving_demand_v2(
        extent: &ProtectedJournalPreopenReplayExtentV1,
        transactions: &[JournalTransaction],
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("retained advisory preflight geometry");
        let incoming =
            CanonicalPreflightDataOriginalV1::receiving_data_v1(extent.native_bytes, transactions)?;
        // The lower quote includes its inline sink. Price only this wrapper's
        // extra result, reentry and invocation controls, including padding.
        let wrapper = size_of::<Self>()
            .checked_sub(size_of::<CanonicalPreflightDataOriginalV1>())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let future = super::super::protected_journal_preopen_replay_extent_for_prefix_v1(
            extent.limits,
            incoming.future_native_bytes,
        )?;
        future
            .dominant_native_receiving_demand_v1()?
            .checked_add(future.dominant_semantic_receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(incoming.additional))
            .and_then(|demand| {
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, wrapper))
            })
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Borrows the original reached allocation, validation or native refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.data
            .failure()
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    fn finish_v2<T>(&mut self, result: Result<T, JournalError>) -> Result<T, JournalError> {
        match result {
            Ok(value) => {
                self.returned = Some(Ok(()));
                Ok(value)
            }
            Err(cause) => {
                self.returned = Some(Err(cause));
                Err(JournalError::ProtectedBoundary)
            }
        }
    }
}

impl Journal {
    /// Runs the same advisory preflight with once-owned failed DATA destinations.
    ///
    /// No protected token, mutation or financial receipt is issued. The caller
    /// prepays receiving_demand_v2 and keeps the complete sink after refusal.
    ///
    /// # Errors
    /// Preserves the original preflight cause in original.failure(), returns a
    /// coarse refusal, and refuses reentry without replacing its first prefix.
    ///
    /// # Panics
    /// Preserves the ordinary encoder's allocation and count panic conditions.
    pub fn preflight_transactions_retaining_v2(
        &self,
        transactions: &[JournalTransaction],
        original: &mut ProtectedJournalPreflightOriginalV2,
    ) -> Result<(), JournalError> {
        if original.entered {
            original
                .reentry
                .get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        original.entered = true;
        let result = self.preflight_with_source_selection_engine_v2(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
            None,
            None,
            Some(&mut *original),
        );
        original.finish_v2(result)
    }
}

impl ProtectedJournalAuthority<'_> {
    /// Runs the canonical preflight while retaining its reached DATA.
    ///
    /// The caller prepays and retains `original` with its actual native
    /// interval. The returned token has the ordinary protected snapshot and
    /// transaction binding; the sink grants none.
    ///
    /// # Errors
    /// Refuses the same authority, namespace, native and semantic failures.
    /// The returned error is coarse; `original.failure()` borrows the actual
    /// cause. Reentry preserves the first complete prefix unchanged.
    ///
    /// # Panics
    /// Preserves the ordinary encoder's allocation and count panic conditions.
    pub fn preflight_transactions_retaining_v2(
        &self,
        transactions: &[JournalTransaction],
        original: &mut ProtectedJournalPreflightOriginalV2,
    ) -> Result<ProtectedJournalPreflight, JournalError> {
        if original.entered {
            original
                .reentry
                .get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        original.entered = true;
        let result = (|| {
            self.validate_generic_authority_mutation()?;
            self.journal.ensure_protected_authority()?;
            self.validate_transaction_namespaces(transactions)?;
            self.journal.preflight_with_source_selection_engine_v2(
                PreflightTransactionViewV1::Ordinary(transactions),
                PreflightScope::default(),
                CacheMutationGateV1::Ordinary,
                None,
                None,
                Some(&mut *original),
            )?;
            Ok(ProtectedJournalPreflight {
                snapshot: self.current_snapshot(),
                transaction_digest: super::super::authority_preflight_digest(transactions),
            })
        })();
        original.finish_v2(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_duplicate_retains_prior_projection_frames_and_original_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                b"actual-key".to_vec(),
                b"first-value".to_vec(),
            )],
        )
        .unwrap();
        let second = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                b"later-key".to_vec(),
                b"second-value".to_vec(),
            )],
        )
        .unwrap();
        let transactions = [transaction, second];
        let sequence = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();
        let mut original = ProtectedJournalPreflightOriginalV2::new();

        let ordinary = journal.preflight_transactions(&transactions);
        let retained = journal.preflight_transactions_retaining_v2(&transactions, &mut original);

        assert!(matches!(ordinary, Err(JournalError::DuplicateTransaction)));
        assert!(matches!(retained, Err(JournalError::ProtectedBoundary)));
        assert!(matches!(
            original.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::DuplicateTransaction)
        ));
        let models = original.data.models().unwrap();
        assert_eq!(
            models
                .state
                .get(&(
                    RecordNamespace::BrokerSessionTraffic,
                    b"actual-key".to_vec()
                ))
                .map(Vec::as_slice),
            Some(b"first-value".as_slice())
        );
        assert!(
            !models
                .state
                .contains_key(&(RecordNamespace::BrokerSessionTraffic, b"later-key".to_vec()))
        );
        assert_eq!(models.transaction_ids.len(), 1);
        assert_eq!(original.data.reached_transactions(), 2);
        assert_eq!(original.data.frames(0).unwrap().len(), 3);
        assert!(original.data.frames(1).is_none());
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(
            journal
                .records(RecordNamespace::BrokerSessionTraffic)
                .next()
                .is_none()
        );

        let first_models = original.data.models().unwrap() as *const aos_sandbox_broker::canonical_journal::preflight::CanonicalPreflightModelsDataV1;
        let first_frames = original.data.frames(0).unwrap().as_ptr();
        assert!(
            journal
                .preflight_transactions_retaining_v2(&[], &mut original)
                .is_err()
        );
        assert_eq!(original.data.models().unwrap() as *const aos_sandbox_broker::canonical_journal::preflight::CanonicalPreflightModelsDataV1, first_models);
        assert_eq!(original.data.frames(0).unwrap().as_ptr(), first_frames);
        assert!(matches!(
            original.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::DuplicateTransaction)
        ));
    }
}
