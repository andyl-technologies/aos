//! Retains a closed Delete or Execution Environment append on the same Source/C cut.
//!
//! The trusted Source semantic caller supplies its already checked transaction
//! and complete reached representation. The same fixed native append engine
//! owns encoding, IO, COMMIT bookkeeping and index application. Publication is
//! DATA; it cannot establish graph authority, Controller acceptance, physical
//! deletion or a terminal Source semantic fence.

use std::error::Error;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::canonical_journal::append_stages::CanonicalAppendPublishedDataV1;
use crate::canonical_journal::coordinator::{
    CanonicalCoordinatorAppendV1, CanonicalCoordinatorNativeV1, CanonicalCoordinatorReadV1,
};
use crate::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1,
    ControllerCoordinatorWriterV1, ControllerOperationIntakeDemandDataV1,
};
use crate::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use crate::source_receiving::{
    SourceNativeErrorV1, SourceNativePostOriginalV1, SourcePreparedAppendV1,
};

use super::{DeleteSourcePurposeV1, ExecutionSourcePurposeV1, Phase,
    SourceScopePurposeV1, SourceOperationScopeV1};

type Scope<'scope, 'original, P, K> = SourceOperationScopeV1<'scope, 'original, P, K>;

/// Retains the existing closed Delete append API.
pub type SourceDeleteAppendOriginalV1<'append, 'scope, 'original, P> =
    SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, DeleteSourcePurposeV1>;
/// Retains the existing closed Delete positive disposal API.
pub type SourceDeleteAppendDisposalV1<'disposal, 'append, 'scope, 'original, P> =
    SourceOperationAppendDisposalV1<'disposal, 'append, 'scope, 'original, P, DeleteSourcePurposeV1>;
/// Names only the genuine Execution scope's mechanical Environment append.
#[doc(hidden)]
pub type SourceExecutionEnvironmentAppendOriginalV1<'append, 'scope, 'original, P> =
    SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, ExecutionSourcePurposeV1>;
/// Keeps its actual native append through upper Environment disposal.
#[doc(hidden)]
pub type SourceExecutionEnvironmentAppendDisposalV1<'disposal, 'append, 'scope, 'original, P> =
    SourceOperationAppendDisposalV1<'disposal, 'append, 'scope, 'original, P, ExecutionSourcePurposeV1>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum PreparationFrontierV1 {
    Immediate,
    AfterSemantics,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AppendPhase {
    Entered,
    Posted,
    Disposal,
    Complete,
}

/// Holds the actual stage and independently owed Source post under its sealed purpose.
///
/// This type has no constructor independent of its genuine sealed Source scope. A
/// failed or abandoned owner terminates before dropping any native prefix.
#[must_use]
pub struct SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, K: SourceScopePurposeV1> {
    scope: &'append mut Scope<'scope, 'original, P, K>,
    transaction_digest: [u8; 32],
    stage: Option<Result<SourcePreparedAppendV1, SourceNativeErrorV1>>,
    post: Option<Result<SourceNativePostOriginalV1, SourceNativeErrorV1>>,
    primary: Option<SourceNativeErrorV1>,
    posted: Option<Result<(), SourceNativeErrorV1>>,
    readback: Option<Result<(), aos_sandbox_linux::protected_file::ExactReadFailure>>,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    phase: AppendPhase,
}

impl<'scope, 'original, P, K: SourceScopePurposeV1> Scope<'scope, 'original, P, K> {
    fn require_operation_append_entry_v1(&self) -> Result<(), SourceNativeErrorV1> {
        if self.purpose != K::purpose() || self.phase != Phase::Active
            || self.failure().is_some() || !matches!(self.before_result, Some(Ok(())))
            || !self.source.delete_scope_active || self.source.has_native_uncertainty_v1()
            || self.source.next_sequence() != self.sequence
            || !self.source.custody.is_idle() || self.source.native_post_active
            || self.source.append_prepaid || !self.source.replacement_custody.is_idle()
            || !self.source.physical.replacement_custody.is_idle()
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

}

impl<'scope, 'original, P> Scope<'scope, 'original, P, DeleteSourcePurposeV1> {
    /// Prepays and enters one same-writer append without releasing this scope.
    ///
    /// `complete` describes every other co-resident upper owner; the method
    /// itself adds its actual construction/post requirement and the supplied
    /// semantic requirement before checking the already consumed C17 vector.
    /// The caller must price transaction construction before supplying it.
    /// Source's existing native/index original separately checks the actual
    /// append representation before the transaction clone or native IO.
    ///
    /// A returned owner may contain a refused preparation. Its independently
    /// armed post must still run and the whole owner must remain resident.
    ///
    /// # Errors
    /// Refuses another purpose, changed Source/NEXT, overlap, a foreign C or a
    /// complete requirement exceeding the same declared operation capacity.
    pub fn prepare_delete_append_once_v1<'append, C>(
        &'append mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
        semantic: ResourceVector,
        complete: ResourceVector,
        upper_interval_bytes: usize,
    ) -> Result<SourceDeleteAppendOriginalV1<'append, 'scope, 'original, P>, ControllerBankLaunchErrorV1> {
        self.enter_operation_append_inner_v1(controller, launch, profile, transaction, semantic, complete, upper_interval_bytes, PreparationFrontierV1::Immediate)
    }

    /// Enters a prepaid semantic append before the shared upper validators.
    ///
    /// Unlike the immediate mechanical adapter, native preparation occurs only
    /// at `prepare_semantic_append_once_v1`, after the sole upper semantic core.
    /// Both routes share one entry, prepayment and independently owed post.
    ///
    /// # Errors
    /// Preserves the same purpose, currentness and complete-demand refusals.
    pub fn enter_delete_semantic_append_once_v1<'append, C>(
        &'append mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
        semantic: ResourceVector,
        complete: ResourceVector,
        upper_interval_bytes: usize,
    ) -> Result<SourceDeleteAppendOriginalV1<'append, 'scope, 'original, P>, ControllerBankLaunchErrorV1> {
        self.enter_operation_append_inner_v1(controller, launch, profile, transaction, semantic, complete, upper_interval_bytes, PreparationFrontierV1::AfterSemantics)
    }

}

impl<'scope, 'original, P> Scope<'scope, 'original, P, ExecutionSourcePurposeV1> {
    /// Enters only the trusted Environment semantic adapter on an actual X18 cut.
    ///
    /// This mechanical port accepts already-paid transaction DATA, not an
    /// Environment proof. The same role-owned semantic engine must validate
    /// its opaque prepared publication before preparation, IO and disposal.
    /// It lends no arbitrary Source writer, new financial original or D scope.
    ///
    /// # Errors
    /// Refuses another purpose, a changed original/NEXT or insufficient funds.
    #[doc(hidden)]
    pub fn enter_execution_environment_semantic_append_once_v1<'append, C>(
        &'append mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
        semantic: ResourceVector,
        complete: ResourceVector,
        upper_interval_bytes: usize,
    ) -> Result<SourceExecutionEnvironmentAppendOriginalV1<'append, 'scope, 'original, P>, ControllerBankLaunchErrorV1> {
        self.enter_operation_append_inner_v1(controller, launch, profile,
            transaction, semantic, complete, upper_interval_bytes, PreparationFrontierV1::AfterSemantics)
    }
}

impl<'scope, 'original, P, K: SourceScopePurposeV1> Scope<'scope, 'original, P, K> {
    fn enter_operation_append_inner_v1<'append, C>(
        &'append mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &JournalTransaction,
        semantic: ResourceVector,
        complete: ResourceVector,
        upper_interval_bytes: usize,
        frontier: PreparationFrontierV1,
    ) -> Result<SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, K>, ControllerBankLaunchErrorV1> {
        self.require_operation_append_entry_v1().map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        let own = SourceOperationAppendOriginalV1::<P, K>::receiving_demand_v1()?;
        let complete = complete.checked_add(semantic)?.checked_add(own)?;
        self.require_complete_v1(controller, launch, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(complete))?;

        // Construct the actual destination before any reached lower operation.
        // After this point failure returns the whole owner, never just a marker.
        let mut owner = SourceOperationAppendOriginalV1 {
            scope: self,
            transaction_digest: aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
                std::slice::from_ref(transaction),
            ),
            stage: None,
            post: None,
            primary: None,
            posted: None,
            readback: None,
            metadata: None,
            phase: AppendPhase::Entered,
        };
        let prepay = owner.scope.source.prepay_semantic_demand_inner_v1(semantic)
            .and_then(|()| owner.scope.source.prepay_append_interval_inner_v1(
                transaction, upper_interval_bytes,
            ));
        if let Err(cause) = prepay {
            owner.primary = Some(cause);
            return Ok(owner);
        }
        owner.post = Some(owner.scope.source.begin_independent_native_post_inner_v1());
        if matches!(frontier, PreparationFrontierV1::Immediate) && matches!(owner.post, Some(Ok(_))) {
            let _prepared = owner.prepare_semantic_append_once_v1(transaction);
        }
        Ok(owner)
    }
}

impl<'append, 'scope, 'original, P, K: SourceScopePurposeV1> SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, K> {
    /// Bounds the actual owner, token construction and additional native post.
    ///
    /// This is passive requirement DATA, excluding the existing native append
    /// stage charged to the same Source original and all supplied upper models.
    ///
    /// # Errors
    /// Refuses checked byte/descriptor arithmetic overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<SourceOperationAppendDisposalV1<'_, '_, '_, '_, P, K>>().checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<Result<Self, ControllerBankLaunchErrorV1>>().checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<Result<SourceOperationAppendDisposalV1<'_, '_, '_, '_, P, K>, SourceNativeErrorV1>>().checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<ResourceVector>().checked_mul(4)?,
            ))
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<CanonicalAppendPublishedDataV1>().checked_mul(2)?,
            ))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let post = SourceNativePostOriginalV1::receiving_demand_v1()
            .map_err(|_| ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes).checked_add(post)?)
    }

    /// Borrows immutable native/index/location DATA from this same owner.
    ///
    /// This performs no IO or health admission and exposes no native writer,
    /// File or descriptor. Only the trusted upper semantic adapter uses it;
    /// the actual stage and all effect/currentness gates remain here.
    #[must_use]
    pub fn semantic_read_view_v1(&self)
        -> crate::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>
    {
        self.scope.source.coordinator_read_view()
    }

    /// Prepares the same stage after the upper semantic validation frontier.
    ///
    /// # Errors
    /// Retains the actual whole preparation or refuses failed/repeated entry.
    pub fn prepare_semantic_append_once_v1(&mut self, transaction: &JournalTransaction)
        -> Result<(), SourceNativeErrorV1>
    {
        self.require_entered_v1()?;
        if self.stage.is_some() || !matches!(self.post, Some(Ok(_)))
            || self.transaction_digest != aos_sandbox_protocol::domain_ledger::transaction::transaction_preflight_comparison_digest_v1(
                std::slice::from_ref(transaction),
            )
        {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        self.stage = Some(self.scope.source.prepare_source_append_inner_v1(transaction));
        if self.stage.as_ref().is_some_and(|stage| stage.as_ref().is_ok_and(|stage| stage.failure().is_none())) {
            Ok(())
        } else {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Retains the actual metadata observation at the old advisory frontier.
    ///
    /// # Errors
    /// Keeps the real IO error, refuses repeat entry and returns only its marker.
    pub fn semantic_metadata_length_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        self.require_entered_v1()?;
        if self.metadata.is_some() {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        self.metadata = Some(self.scope.source.coordinator_read_view().metadata());
        match self.metadata.as_ref() {
            Some(Ok(metadata)) => Ok(metadata.len()),
            _ => {
                self.primary.get_or_insert(SourceNativeErrorV1::Closed);
                Err(SourceNativeErrorV1::Closed)
            }
        }
    }

    /// Retains the existing native poison disposition after an upper refusal.
    pub fn poison_after_semantic_failure_v1(&mut self) {
        self.scope.source.poison();
        self.primary.get_or_insert(SourceNativeErrorV1::Closed);
    }

    // Entry/preparation precedes the prepared-stage guard. Both frontiers
    // still require the actual active Delete scope and its paid armed post.
    fn require_entered_v1(&mut self) -> Result<(), SourceNativeErrorV1> {
        if self.phase != AppendPhase::Entered || self.primary.is_some()
            || self.scope.purpose != K::purpose()
            || self.scope.phase != Phase::Active
            || !matches!(self.post, Some(Ok(_)))
        {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

    fn require_primary(&mut self) -> Result<(), SourceNativeErrorV1> {
        self.require_entered_v1()?;
        if !matches!(self.stage, Some(Ok(_))) {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        Ok(())
    }

    fn retain<T>(&mut self, result: Result<T, SourceNativeErrorV1>) -> Result<T, SourceNativeErrorV1> {
        match result {
            Ok(value) => Ok(value),
            Err(cause) => {
                if self.primary.is_none() { self.primary = Some(cause); }
                Err(SourceNativeErrorV1::Closed)
            }
        }
    }

    /// Borrows the actual prepared transaction and encoded comparison DATA.
    pub fn prepared_v1(&self) -> Option<&SourcePreparedAppendV1> {
        self.stage.as_ref()?.as_ref().ok()
    }

    /// Borrows saved Source DATA while the same actual scope remains held.
    ///
    /// # Errors
    /// Refuses failed/inactive Source custody through the existing scope gate.
    pub fn historical_view_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1>
    {
        self.scope.historical_view_v1()
    }

    /// Reads exact published bytes through the same positioned/EOF engine.
    ///
    /// The caller owns and prepays the whole output and preserves its partial
    /// bytes on failure. This method retains the actual native read result; it
    /// lends no generic native-operation, File or descriptor projection. The
    /// trusted Source role still validates the sole canonical COMMIT/replay
    /// and semantic rules before actual upper positive disposal.
    ///
    /// # Errors
    /// Refuses repeated/unpublished work or an unequal output bound, and keeps
    /// the original content/EOF error beside the actual native append stage.
    pub fn readback_published_once_v1(&mut self, output: &mut [u8])
        -> Result<(), SourceNativeErrorV1>
    {
        self.require_primary()?;
        if self.readback.is_some() {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        let published = self.prepared_v1()
            .and_then(|stage| stage.storage.body())
            .and_then(|body| body.stages.published_coordinates());
        if !published.is_some_and(|published| {
            u64::try_from(output.len()).ok() == Some(published.durable_bytes)
        }) {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        self.readback = Some(self.scope.source.native_operations()
            .read_exact_positioned_retaining_cause(output));
        if matches!(self.readback, Some(Ok(()))) {
            Ok(())
        } else {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Computes the same stage coordinates before native metadata IO.
    ///
    /// # Errors
    /// Retains the actual stage refusal or rejects repeated/out-of-order entry.
    pub fn coordinates_once_v1(&mut self) -> Result<(u64, u64), SourceNativeErrorV1> {
        self.require_primary()?;
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let result = self.scope.source.append_coordinates_once(stage);
        self.retain(result)
    }

    /// Samples the actual same-file expected length at the old native frontier.
    ///
    /// # Errors
    /// Retains the actual native error or rejects an incomplete/changed stage.
    pub fn expected_length_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        self.require_primary()?;
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let result = self.scope.source.expected_append_length_once(stage);
        self.retain(result)
    }

    /// Writes and syncs the same encoded native frames once.
    ///
    /// # Errors
    /// Retains all reached native write/sync results and partial publication.
    pub fn append_once_v1(&mut self) -> Result<u64, SourceNativeErrorV1> {
        self.require_primary()?;
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let result = self.scope.source.append_prepared_once(stage);
        self.retain(result)
    }

    /// Applies the next actual record through the same native/index engine.
    ///
    /// # Errors
    /// Retains native/index failure or refuses repeated/out-of-order entry.
    pub fn apply_next_record_once_v1(&mut self) -> Result<bool, SourceNativeErrorV1> {
        self.require_primary()?;
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let result = self.scope.source.apply_next_record_once(stage);
        self.retain(result)
    }

    /// Publishes only the actual completed native append coordinates.
    ///
    /// # Errors
    /// Retains refusal unless all actual records/index updates completed.
    pub fn publish_once_v1(&mut self) -> Result<CanonicalAppendPublishedDataV1, SourceNativeErrorV1> {
        self.require_primary()?;
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let result = self.scope.source.publish_append_once(stage);
        self.retain(result)
    }

    /// Runs the already-armed Source post even after body/native failure.
    ///
    /// # Errors
    /// Retains the actual post result or refuses repeated/foreign completion.
    pub fn finish_native_once_v1(&mut self) -> Result<(), SourceNativeErrorV1> {
        if self.phase != AppendPhase::Entered {
            self.primary.get_or_insert(SourceNativeErrorV1::Closed);
            return Err(SourceNativeErrorV1::Closed);
        }
        self.phase = AppendPhase::Posted;
        self.posted = Some(match self.post.as_mut() {
            Some(Ok(post)) => self.scope.source.finish_independent_native_post_once(post),
            _ => Err(SourceNativeErrorV1::Closed),
        });
        if self.failure().is_none() && matches!(self.posted, Some(Ok(()))) {
            Ok(())
        } else {
            Err(SourceNativeErrorV1::Closed)
        }
    }

    /// Finishes the outer Source/C debt while this failed append stays owned.
    ///
    /// A negative append cannot release its exclusive scope borrow just to run
    /// the outer posts. The actual failure path calls this after the local
    /// native post, retaining this whole owner and every other upper original
    /// through both already-armed outer samples. It grants no positive release.
    ///
    /// # Errors
    /// Preserves the original outer Source/C refusal or rejects wrong order.
    pub fn finish_outer_scope_once_v1<C>(
        &mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.phase != AppendPhase::Posted {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.scope.finish_native_once_v1(controller, launch, profile)
    }

    /// Borrows the body-native cause independently of later owed posts.
    pub fn primary_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let stage = self.stage.as_ref().and_then(|stage| stage.as_ref().ok());
        let primary = self.primary.as_ref().map(|cause| -> &(dyn Error + 'static) {
            // Only this precise native stop marker resolves through its own
            // original. A concrete earlier error always keeps precedence.
            if matches!(cause, SourceNativeErrorV1::Closed) {
                stage.and_then(SourcePreparedAppendV1::failure)
                    .or_else(|| self.scope.source.retained_append_failure_v1())
                    .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                    .or_else(|| self.readback.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
                    .unwrap_or(cause)
            } else {
                cause
            }
        });
        primary
            .or_else(|| self.post.as_ref().and_then(|post| post.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.stage.as_ref().and_then(|stage| stage.as_ref().err()).map(|cause| -> &(dyn Error + 'static) {
                // Preparation's second actual debit can refuse independently
                // of prepay. Resolve only its stored Closed marker through the
                // SAME Source original; a concrete stage error stays first.
                if matches!(cause, SourceNativeErrorV1::Closed) {
                    self.scope.source.retained_append_failure_v1().unwrap_or(cause)
                } else {
                    cause
                }
            }))
            .or_else(|| stage.and_then(SourcePreparedAppendV1::failure))
            .or_else(|| self.scope.source.retained_append_failure_v1())
    }

    /// Borrows the original body cause before its independently owed posts.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.primary_failure_v1()
            .or_else(|| self.post.as_ref().and_then(|post| post.as_ref().ok()).and_then(SourceNativePostOriginalV1::failure))
            .or_else(|| self.posted.as_ref().and_then(|posted| posted.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.scope.failure())
    }

    /// Keeps the actual append until the trusted upper semantic posts dispose.
    ///
    /// All fallible checks precede the sticky disposal phase. The caller then
    /// disposes its real positive semantic/readback carriers before completing
    /// the returned token. Publication DATA or a success flag cannot replace
    /// the actual stage and native post this token continuously borrows.
    ///
    /// # Errors
    /// Refuses failed/incomplete/foreign publication, changed NEXT or any post.
    pub fn prepare_positive_disposal_v1<'disposal>(&'disposal mut self)
        -> Result<SourceOperationAppendDisposalV1<'disposal, 'append, 'scope, 'original, P, K>, SourceNativeErrorV1>
    {
        if self.phase != AppendPhase::Posted || self.failure().is_some()
            || !matches!(self.posted, Some(Ok(())))
            || !matches!(self.readback, Some(Ok(())))
            || self.scope.purpose != K::purpose()
            || self.scope.phase != Phase::Active
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        let stage = self.stage.as_mut().and_then(|stage| stage.as_mut().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        let published = self.scope.source.require_stage(stage)?.stages.published_coordinates()
            .ok_or(SourceNativeErrorV1::Closed)?;
        if published.head != self.scope.sequence
            || self.scope.source.next_sequence() != published.following
        {
            return Err(SourceNativeErrorV1::Closed);
        }
        let post = self.post.as_ref().and_then(|post| post.as_ref().ok())
            .ok_or(SourceNativeErrorV1::Closed)?;
        self.scope.source.require_native_post_disposal_v1(post)?;
        self.phase = AppendPhase::Disposal;
        Ok(SourceOperationAppendDisposalV1 { owner: self, following: published.following })
    }
}

/// Retains the same exclusive native owner through actual upper disposal.
#[must_use]
pub struct SourceOperationAppendDisposalV1<'disposal, 'append, 'scope, 'original, P, K: SourceScopePurposeV1> {
    owner: &'disposal mut SourceOperationAppendOriginalV1<'append, 'scope, 'original, P, K>,
    following: u64,
}

impl<P, K: SourceScopePurposeV1> SourceOperationAppendDisposalV1<'_, '_, '_, '_, P, K> {
    /// Disposes this completed local append without ending the outer C17 cut.
    ///
    /// Performs no allocation, native IO, fallible check or financial refund.
    /// The next expected sequence comes only from the same published stage.
    pub fn complete_after_disposal_v1(self) {
        let stage = match self.owner.stage.as_mut() {
            Some(Ok(stage)) => stage,
            _ => std::process::abort(),
        };
        let body = match stage.storage.take_body() {
            Some(body) => body,
            None => std::process::abort(),
        };
        let post = match self.owner.post.as_mut() {
            Some(Ok(post)) => post,
            _ => std::process::abort(),
        };
        self.owner.scope.source.complete_native_post_disposal_v1(post);
        drop(body);
        self.owner.scope.source.custody.release_active();
        self.owner.scope.sequence = self.following;
        self.owner.phase = AppendPhase::Complete;
    }
}

impl<P, K: SourceScopePurposeV1> Drop for SourceOperationAppendOriginalV1<'_, '_, '_, P, K> {
    fn drop(&mut self) {
        if self.phase != AppendPhase::Complete { std::process::abort(); }
    }
}
