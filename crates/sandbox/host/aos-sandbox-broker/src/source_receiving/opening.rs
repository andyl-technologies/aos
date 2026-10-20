//! Keeps fixed Source acquisition and its same-original replay representation.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_protocol::domain_ledger::readonly::IdempotencyDecisionV1;

use crate::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1,
};
use crate::canonical_journal::coordinator::selected_append::SelectedAppendCustodyV1;
use crate::canonical_journal::{
    CanonicalOpenedWriterDataV1, CanonicalReplayExtentDataV1,
    CanonicalWriterCustodyDataV1, CanonicalWriterOpeningOriginalsV1, NativeJournalDataErrorV1,
};
use crate::controller_receiving::{
    ControllerSourceOriginalRefV1, ControllerSourcePreBankConstructionLoanV1,
};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

use super::append::SourceAppendBodyV1;
use super::recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1, source_journal_limits_v1};
use super::{SourceCoordinatorWriterV1, SourceNativeErrorV1};

/// Retains an inert destination for the actual fixed Source construction.
///
/// No path, UID, opened tuple, profile, account or successful DATA can enter
/// this destination as role provenance. Actual entry requires the genuine
/// continuously held pre-Bank Source construction loan.
#[must_use]
pub struct SourceWriterOpeningOriginalsV1 {
    opening: CanonicalWriterOpeningOriginalsV1,
    index: BTreeMap<Vec<u8>, IdempotencyDecisionV1>,
    replay: CanonicalReplayIndexOriginalsV1,
    entry: Option<Result<(), crate::controller_receiving::ControllerReceivingErrorV1>>,
    fixed: Option<Result<ResourceVector, SourceNativeErrorV1>>,
    preparation: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    uid: Option<u32>,
    extent: Option<Result<CanonicalReplayExtentDataV1, crate::canonical_journal::NativeJournalDataErrorV1>>,
    representation: Option<Result<ResourceVector, SourceNativeErrorV1>>,
    semantic_representation: Option<Result<(ResourceVector, ResourceVector), SourceNativeErrorV1>>,
    semantic_peak: ResourceVector,
    semantic_dynamic: Option<Result<ResourceVector, SourceNativeErrorV1>>,
    tail: Option<Result<(), crate::canonical_journal::NativeJournalDataErrorV1>>,
    opened: Option<CanonicalOpenedWriterDataV1>,
    owner_representation: Option<Result<(ResourceVector, ResourceVector), SourceNativeErrorV1>>,
    durable_end: Option<Result<u64, SourceNativeErrorV1>>,
    original: Option<ControllerSourceOriginalRefV1>,
    custody: Option<Arc<SelectedAppendCustodyV1<SourceAppendBodyV1>>>,
    names: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    names_result: Option<Result<(), NativeJournalDataErrorV1>>,
    existing_only: bool,
    attempted: bool,
    taken: bool,
}

impl SourceWriterOpeningOriginalsV1 {
    /// Creates empty native destinations without opening or claiming anything.
    pub const fn new() -> Self {
        Self {
            opening: CanonicalWriterOpeningOriginalsV1::new(),
            index: BTreeMap::new(),
            replay: CanonicalReplayIndexOriginalsV1::new(),
            entry: None,
            fixed: None,
            preparation: None,
            uid: None,
            extent: None,
            representation: None,
            semantic_representation: None,
            semantic_peak: ResourceVector::ZERO,
            semantic_dynamic: None,
            tail: None,
            opened: None,
            owner_representation: None,
            durable_end: None,
            original: None,
            custody: None,
            names: WriterCurrentnessOriginalsV1::new(),
            names_result: None,
            existing_only: false,
            attempted: false,
            taken: false,
        }
    }

    fn fixed_demand<Outer>() -> Result<ResourceVector, SourceNativeErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Outer>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::semantic_receiving::SourceSemanticReceivingLoanV1<'_>>().checked_mul(2)?))
            // The actual upper constructor allocates one authority-identity
            // Arc at handoff; its counters/alignment are not inline storage.
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or(SourceNativeErrorV1::Closed)?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| SourceNativeErrorV1::Closed)?)
            .checked_add(CanonicalWriterOpeningOriginalsV1::additional_fixed_receiving_demand_v1(
                Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
            )?)?
            .checked_add(WriterCurrentnessOriginalsV1::<NativeJournalDataErrorV1>::fixed_demand_v1(
                Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
            )?)
            .map_err(|_| SourceNativeErrorV1::Closed)
    }

    /// Opens only existing fixed state and rejects interrupted tails.
    ///
    /// Missing state is never created, and replay cannot repair a partial tail.
    /// The same genuine startup loan/original and complete native debit remain
    /// required; this entry changes only the fixed acquisition/recovery recipe.
    ///
    /// # Errors
    /// Retains the same acquisition/replay cause or refuses repeated entry.
    pub fn prepare_existing_once<Outer>(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.attempted { return Err(SourceNativeErrorV1::Closed); }
        self.existing_only = true;
        self.prepare_once::<Outer>(loan)
    }

    /// Enters the actual Source interval and opens only its fixed native recipe.
    ///
    /// The actual loan retains its independently owed Controller post even if
    /// this entered body refuses. Its caller must finish that same loan after
    /// every attempted construction, including an earlier Controller failure.
    ///
    /// `Outer` describes the actual enclosing constructor's compiled inline
    /// representation only. Its width supplies no semantic or native grant.
    ///
    /// # Errors
    /// Retains the first entry, representation, acquisition or extent failure.
    pub fn prepare_once<Outer>(
        &mut self,
        loan: &mut ControllerSourcePreBankConstructionLoanV1<'_>,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.attempted {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.attempted = true;
        self.entry = Some(loan.begin_native_once());
        if !matches!(self.entry, Some(Ok(()))) {
            return Err(SourceNativeErrorV1::Closed);
        }

        self.fixed = Some((|| {
            let fixed = Self::fixed_demand::<Outer>()?;
            loan.require_native_complete(fixed)?;
            Ok(fixed)
        })());
        if !matches!(self.fixed, Some(Ok(_))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        let uid = loan.fixed_writer_uid_data_v1()?;
        self.uid = Some(uid);
        self.preparation = Some(self.opening.prepare_once(
            Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
            source_journal_limits_v1(), uid, !self.existing_only,
        ));
        if !matches!(self.preparation, Some(Ok(()))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.extent = Some(self.opening.prepared_extent());
        self.representation = Some((|| {
            let extent = self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(SourceNativeErrorV1::Closed)?;
            let fixed = self.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(SourceNativeErrorV1::Closed)?;
            let complete = fixed.checked_add(extent.dominant_native_receiving_demand_v1()?)
                .map_err(|_| SourceNativeErrorV1::Closed)?
                .checked_add(extent.dominant_semantic_receiving_demand_v1()?)
                .map_err(|_| SourceNativeErrorV1::Closed)?
                .checked_add(CanonicalReplayIndexOriginalsV1::dynamic_demand_v1(extent)
                    .map_err(index_error)?)
                .map_err(|_| SourceNativeErrorV1::Closed)?;
            loan.require_native_complete(complete)?;
            Ok(complete)
        })());
        if !matches!(self.representation, Some(Ok(_))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.original = Some(loan.take_bound_source_original_once_v1()?);
        Ok(())
    }

    /// Restricts the same original for the actual concrete semantic owner.
    ///
    /// This returns no account, receiving grant, parser completion or success
    /// witness. The private semantic caller derives its complete bounded shape.
    ///
    /// # Errors
    /// Retains repeated, arithmetic or original-capacity refusal before growth.
    pub fn debit_semantic_representation_once(
        &mut self,
        additional: ResourceVector,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.semantic_representation.is_some() || self.taken {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.semantic_representation = Some((|| {
            let previous = self.representation.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(SourceNativeErrorV1::Closed)?;
            let complete = previous.checked_add(additional).map_err(|_| SourceNativeErrorV1::Closed)?;
            self.original.as_ref().ok_or(SourceNativeErrorV1::Closed)?
                .debit_complete_representation_v1(complete)?;
            Ok((complete, additional))
        })());
        if matches!(self.semantic_representation, Some(Ok(_))) { Ok(()) }
        else { Err(SourceNativeErrorV1::Closed) }
    }

    /// Samples the prepaid original Source file before semantic replay starts.
    ///
    /// # Errors
    /// Retains actual identity failure and refuses unfunded or ended entry.
    pub fn prepare_semantic_identity_once(&mut self) -> Result<FileIdentity, SourceNativeErrorV1> {
        if !matches!(self.semantic_representation, Some(Ok(_))) || self.taken {
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(self.opening.prepare_selected_parser_identity_once()?)
    }

    /// Borrows the sole canonical indexed parser on the same fixed Source file.
    ///
    /// # Errors
    /// Retains parser/index failure; no semantic stage is run or skipped here.
    pub fn begin_replay_once(&mut self) -> Result<CanonicalIndexedReplayV1<'_, '_>, SourceNativeErrorV1> {
        if !matches!(self.semantic_representation, Some(Ok(_))) || self.taken {
            return Err(SourceNativeErrorV1::Closed);
        }
        let cursor = self.opening.begin_semantic_replay_once()?;
        Ok(CanonicalIndexedReplayV1::from_supplied_data_v1(cursor, &mut self.index, &mut self.replay))
    }

    /// Lends the actual indexed cursor beside its same-original semantic debt.
    ///
    /// The private role adapter must debit its complete reached-model shape
    /// before entering pure semantic work. This tuple contains no role grant.
    ///
    /// # Errors
    /// Refuses missing fixed semantic admission or an unavailable actual cursor.
    pub fn begin_paid_replay_once(
        &mut self,
    ) -> Result<(
        CanonicalIndexedReplayV1<'_, '_>,
        super::semantic_receiving::SourceSemanticReceivingLoanV1<'_>,
    ), SourceNativeErrorV1> {
        let base = self.semantic_representation.as_ref()
            .and_then(|value| value.as_ref().ok()).map(|value| value.0)
            .ok_or(SourceNativeErrorV1::Closed)?;
        if self.taken || matches!(self.semantic_dynamic, Some(Err(_))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        let original = self.original.as_ref().ok_or(SourceNativeErrorV1::Closed)?;
        let native = self.opening.begin_semantic_replay_once()?;
        let cursor = CanonicalIndexedReplayV1::from_supplied_data_v1(
            native, &mut self.index, &mut self.replay,
        );
        let receiving = super::semantic_receiving::SourceSemanticReceivingLoanV1 {
            original, base, peak: &mut self.semantic_peak, result: &mut self.semantic_dynamic,
        };
        Ok((cursor, receiving))
    }

    /// Borrows the actual first same-original dynamic semantic debit cause.
    pub fn semantic_receiving_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.semantic_dynamic)
    }


    /// Returns the exact compiled Source limits as comparison DATA.
    pub fn fixed_limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        source_journal_limits_v1()
    }

    /// Returns the same admitted captured prefix length as comparison DATA.
    ///
    /// # Errors
    /// Refuses absent or failed actual native-extent admission.
    pub fn captured_native_bytes_data_v1(&self) -> Result<u64, SourceNativeErrorV1> {
        self.extent.as_ref().and_then(|value| value.as_ref().ok())
            .map(|extent| extent.native_bytes()).ok_or(SourceNativeErrorV1::Closed)
    }

    /// Moves completed native custody to the actual trusted semantic coordinator.
    ///
    /// Native completion establishes no Source semantic readiness. The actual
    /// private semantic owner must finish its complete history and final-state
    /// checks before invoking this mechanical transfer.
    ///
    /// # Errors
    /// Retains tail/constructor debit failure and refuses incomplete or repeated transfer.
    pub fn take_coordinator_after_semantic_replay_once<P>(
        &mut self,
        compaction: P,
    ) -> Result<SourceCoordinatorWriterV1<P>, SourceNativeErrorV1> {
        if self.taken || self.failure().is_some() || !self.replay.is_complete() {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.tail = Some(self.opening.finish_replayed_tail_once(if self.existing_only {
            RecoveryTailMode::RejectIncomplete
        } else { RecoveryTailMode::RepairIncomplete }));
        if !matches!(self.tail, Some(Ok(()))) {
            return Err(SourceNativeErrorV1::Closed);
        }
        self.opened = self.opening.take_opened_parts_once();
        self.durable_end = Some((|| {
            let native_bytes = self.extent.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(SourceNativeErrorV1::Closed)?.native_bytes();
            let report = self.opened.as_ref().ok_or(SourceNativeErrorV1::Closed)?.recovery_report();
            native_bytes.checked_sub(report.truncated_bytes).ok_or(SourceNativeErrorV1::Closed)
        })());
        let end = self.durable_end.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(SourceNativeErrorV1::Closed)?;
        self.owner_representation = Some((|| {
            let (complete, additional) = self.semantic_representation.as_ref()
                .and_then(|value| value.as_ref().ok()).copied().ok_or(SourceNativeErrorV1::Closed)?;
            let constructor = SourceCoordinatorWriterV1::<P>::construction_demand()?;
            let complete = complete.checked_add(constructor)?.checked_add(self.semantic_peak)?;
            self.original.as_ref().ok_or(SourceNativeErrorV1::Closed)?
                .debit_complete_representation_v1(complete)?;
            let fixed = self.fixed.as_ref().and_then(|value| value.as_ref().ok())
                .copied().ok_or(SourceNativeErrorV1::Closed)?
                .checked_add(constructor)?.checked_add(additional)?;
            Ok((complete, fixed))
        })());
        let (_complete, fixed) = self.owner_representation.as_ref().and_then(|value| value.as_ref().ok())
            .copied().ok_or(SourceNativeErrorV1::Closed)?;
        let opened = self.opened.take().ok_or(SourceNativeErrorV1::Closed)?;
        let original = self.original.take().ok_or(SourceNativeErrorV1::Closed)?;
        let (physical, _report) = CanonicalWriterCustodyDataV1::from_opened_data_v1(
            opened, std::mem::take(&mut self.index), compaction,
        );
        self.custody = Some(Arc::new(SelectedAppendCustodyV1::new()));
        let custody = Arc::clone(self.custody.as_ref().ok_or(SourceNativeErrorV1::Closed)?);
        self.taken = true;
        Ok(SourceCoordinatorWriterV1::from_fixed_opening(physical, original, fixed, self.semantic_peak, end, custody))
    }

    /// Reports whether the actual fixed native acquisition was entered.
    pub fn has_native_entry_v1(&self) -> bool {
        self.preparation.is_some()
    }

    /// Runs the independent Source-name bookend on its same physical originals.
    ///
    /// An actual completed coordinator supplies the success branch; otherwise
    /// the same partial acquisition supplies its original directory/lock/file.
    /// Native poison never suppresses this already owed observation.
    ///
    /// # Errors
    /// Retains original name failures or refuses a foreign or repeated owner.
    pub fn finish_names_post_once<P>(
        &mut self,
        coordinator: Option<&SourceCoordinatorWriterV1<P>>,
    ) -> Result<(), SourceNativeErrorV1> {
        if self.names_result.is_some() || !self.has_native_entry_v1() {
            return Err(SourceNativeErrorV1::Closed);
        }
        let result = match coordinator {
            Some(coordinator) => (|| {
                let custody = self.custody.as_ref().ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?;
                if !self.taken || !Arc::ptr_eq(custody, &coordinator.custody) {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                }
                self.names.begin(true)?;
                let result = coordinator.physical.observe_names_into(&mut self.names);
                self.names.finish(result)
            })(),
            None => (|| {
                if self.taken {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                }
                self.opening.observe_names_retaining_v1(
                    Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
                    self.uid.ok_or(NativeJournalDataErrorV1::ProtectedBoundary)?, &mut self.names,
                )
            })(),
        };
        self.names_result = Some(result);
        if matches!(self.names_result, Some(Ok(()))) { Ok(()) }
        else { Err(SourceNativeErrorV1::Closed) }
    }

    /// Retires successful opening probes after all real upper Source/C posts.
    ///
    /// The same original coordinator and completed names sample remain held.
    /// Only the trusted Source constructor calls this after its whole semantic
    /// and independent C/profile post success. No semantic flag is accepted.
    ///
    /// # Errors
    /// Refuses foreign, failed, incomplete or repeated native disposition.
    pub fn retire_completed_traversal_after_upper_posts_once_v1<P>(
        &mut self,
        coordinator: &SourceCoordinatorWriterV1<P>,
    ) -> Result<(), SourceNativeErrorV1> {
        let custody = self.custody.as_ref().ok_or(SourceNativeErrorV1::Closed)?;
        if !self.taken || self.failure().is_some() || !Arc::ptr_eq(custody, &coordinator.custody)
            || !matches!(self.names_result, Some(Ok(()))) || !self.names.is_complete()
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        coordinator.require_idle()?;
        self.opening.retire_completed_traversal_once_v1()?;
        self.names.settle_positive_once_v1();
        Ok(())
    }

    /// Borrows only the independently owed Source-name bookend failure.
    pub fn names_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.names.failure().or_else(|| error(&self.names_result))
    }

    /// Reports selection of a genuine Source-loan admission failure.
    ///
    /// This diagnostic selector authorizes no work; it lets the actual caller
    /// borrow the loan's deeper original cause instead of its stopping marker.
    pub fn receiving_failure_is_selected_v1(&self) -> bool {
        matches!(self.entry, Some(Err(_)))
            || matches!(self.fixed, Some(Err(SourceNativeErrorV1::Receiving(_))))
            || matches!(self.representation, Some(Err(SourceNativeErrorV1::Receiving(_))))
            || matches!(self.semantic_representation, Some(Err(SourceNativeErrorV1::Receiving(_))))
            || matches!(self.owner_representation, Some(Err(SourceNativeErrorV1::Receiving(_))))
    }

    /// Borrows the first actual acquisition, debit or replay refusal.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.entry).or_else(|| error(&self.fixed))
            .or_else(|| self.opening.failure()).or_else(|| error(&self.preparation))
            .or_else(|| error(&self.extent)).or_else(|| error(&self.representation))
            .or_else(|| error(&self.semantic_representation))
            .or_else(|| error(&self.semantic_dynamic)).or_else(|| self.replay.failure())
            .or_else(|| error(&self.tail)).or_else(|| error(&self.durable_end))
            .or_else(|| error(&self.owner_representation))
    }
}

impl Default for SourceWriterOpeningOriginalsV1 {
    fn default() -> Self { Self::new() }
}

fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn index_error(cause: CanonicalIndexedReplayErrorV1) -> SourceNativeErrorV1 {
    match cause {
        CanonicalIndexedReplayErrorV1::Native(cause) => SourceNativeErrorV1::Native(cause),
        CanonicalIndexedReplayErrorV1::Closed => SourceNativeErrorV1::Closed,
    }
}
