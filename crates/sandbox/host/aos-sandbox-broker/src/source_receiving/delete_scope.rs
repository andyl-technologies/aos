//! Keeps the actual Source writer exclusive through genuine Delete/Execution C flights.
//!
//! The Source writer and C loan share their original Controller. Two fixed
//! names samples are permanently priced on that C17 subdivision before native
//! entry. The scope lends saved readonly DATA only; Source semantics, public
//! authorization, independent Root floor and deletion effects remain upper.
//! Its joint token keeps both real owners until every upper post completes.

mod append;
mod cache_audit;
pub use append::{SourceDeleteAppendOriginalV1, SourceDeleteAppendDisposalV1,
    SourceExecutionEnvironmentAppendOriginalV1, SourceExecutionEnvironmentAppendDisposalV1};

use std::error::Error;
use std::path::Path;

use aos_sandbox_model::{ResourceDimension, ResourceVector};
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;

use crate::canonical_journal::NativeJournalDataErrorV1;
use crate::canonical_journal::coordinator::CanonicalCoordinatorReadV1;
use crate::controller_receiving::bank_launch::{
    ControllerBankLaunchErrorV1, ControllerBankLaunchOriginalV1,
    ControllerCoordinatorWriterV1, ControllerOperationIntakeDisposalV1,
    ControllerOperationIntakeReceivingLoanV1,
};
use crate::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

use super::SourceCoordinatorWriterV1;
use super::recipe::{SOURCE_DOMAIN_DIRECTORY_V1, SOURCE_DOMAIN_JOURNAL_V1};

type Sample = WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Active,
    Finished,
    Disposal,
    Complete,
}

// Only this module can construct this closed selection of the joint C token.
// Its empty representation carries no public grant or Source authority.
pub(crate) struct SourceDeletePositiveProofV1 {
    _private: (),
}

pub(crate) struct SourceExecutionPositiveProofV1 {
    _private: (),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SourceIntakePurposeV1 {
    Delete,
    Execution,
}

/// Names the closed Delete specialization without constructing a scope.
#[doc(hidden)]
pub struct DeleteSourcePurposeV1 { _private: () }
/// Names the closed Execution specialization without constructing a scope.
#[doc(hidden)]
pub struct ExecutionSourcePurposeV1 { _private: () }

trait SourceScopePurposeV1 {
    fn purpose() -> SourceIntakePurposeV1;
}

impl SourceScopePurposeV1 for DeleteSourcePurposeV1 {
    fn purpose() -> SourceIntakePurposeV1 { SourceIntakePurposeV1::Delete }
}

impl SourceScopePurposeV1 for ExecutionSourcePurposeV1 {
    fn purpose() -> SourceIntakePurposeV1 { SourceIntakePurposeV1::Execution }
}

/// Keeps the original Delete API on the sole native scope engine.
pub type SourceDeleteScopeV1<'scope, 'original, P> = SourceOperationScopeV1<'scope, 'original, P, DeleteSourcePurposeV1>;
/// Keeps the original Delete disposal API on the sole native token engine.
pub type SourceDeleteScopeDisposalV1<'disposal, P> = SourceOperationScopeDisposalV1<'disposal, P, DeleteSourcePurposeV1>;
/// Keeps Source exclusive under the actual same-original Execution18 loan.
pub type SourceExecutionScopeV1<'scope, 'original, P> = SourceOperationScopeV1<'scope, 'original, P, ExecutionSourcePurposeV1>;
/// Keeps both actual Execution18/Source owners through positive disposal.
pub type SourceExecutionScopeDisposalV1<'disposal, P> = SourceOperationScopeDisposalV1<'disposal, P, ExecutionSourcePurposeV1>;


/// Borrows the same Source writer and an actual consumed closed C operation loan.
///
/// This owner has no public constructor, mutable native projection or Source
/// append method. Holding it keeps the actual Source lock and an exclusive
/// Rust borrow of its sole coordinator through Controller atomic acceptance.
/// An abandoned or failed scope terminates with its native originals resident.
#[must_use]
pub struct SourceOperationScopeV1<'scope, 'original, P, K: SourceScopePurposeV1> {
    source: &'scope mut SourceCoordinatorWriterV1<P>,
    receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
    sequence: u64,
    purpose: SourceIntakePurposeV1,
    kind: std::marker::PhantomData<K>,
    before: Sample,
    after: Sample,
    before_result: Option<Result<(), NativeJournalDataErrorV1>>,
    after_result: Option<Result<(), NativeJournalDataErrorV1>>,
    controller_result: Option<Result<(), ControllerBankLaunchErrorV1>>,
    cold_session: Option<Result<std::sync::Arc<crate::controller_receiving::bank_launch::ControllerExecutionColdSessionBudgetV2>, ControllerBankLaunchErrorV1>>,
    cold_reentry: Option<ControllerBankLaunchErrorV1>,
    phase: Phase,
}

impl<P> SourceCoordinatorWriterV1<P> {
    /// Borrows this genuine Source writer under its same original's C17 loan.
    ///
    /// The actual fixed names reservoir and its construction peak are admitted
    /// before either names sample enters. Source's persistent native/index
    /// representation remains charged to its existing construction original.
    /// A returned scope can hold a failed before sample; its caller must retain
    /// it and run the independently owed completion on either body outcome.
    ///
    /// # Errors
    /// Refuses a foreign C, an Execution purpose, insufficient declared C17
    /// capacity, overlap, prior native uncertainty or an inactive receiving loan.
    pub fn borrow_delete_scope_v1<'scope, 'original, C>(
        &'scope mut self,
        receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceDeleteScopeV1<'scope, 'original, P>, ControllerBankLaunchErrorV1> {
        self.borrow_operation_scope_inner_v1::<_, DeleteSourcePurposeV1>(receiving, controller, launch, profile)
    }

    /// Borrows Source under the genuine same-original Execution18 flight.
    ///
    /// # Errors
    /// Refuses another purpose/original, failed Source or inactive financial
    /// loan. Returned native custody must complete its independently owed post.
    pub fn borrow_execution_scope_v1<'scope, 'original, C>(
        &'scope mut self,
        receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceExecutionScopeV1<'scope, 'original, P>, ControllerBankLaunchErrorV1> {
        self.borrow_operation_scope_inner_v1::<_, ExecutionSourcePurposeV1>(receiving, controller, launch, profile)
    }

    fn borrow_operation_scope_inner_v1<'scope, 'original, C, K: SourceScopePurposeV1>(
        &'scope mut self,
        receiving: &'scope mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceOperationScopeV1<'scope, 'original, P, K>, ControllerBankLaunchErrorV1> {
        let purpose = K::purpose();
        if self.is_closed_or_poisoned_v1() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        // Claim-time accounting uses the fixed native selection. Verify the
        // actual monomorphized scope/token geometry before lending or IO;
        // no layout inference, smaller representation or spare credit is used.
        if SourceOperationScopeV1::<P, K>::receiving_demand_v1()?
            != SourceOperationScopeV1::<(), K>::receiving_demand_v1()?
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match purpose {
            SourceIntakePurposeV1::Delete => receiving.enter_delete_source_scope_v1(
                &self.original, controller, launch, profile)?,
            SourceIntakePurposeV1::Execution => receiving.enter_execution_source_scope_v1(
                &self.original, controller, launch, profile)?,
        }

        // This sticky flag also closes fresh entry after mem::forget releases
        // the lexical borrow. It is cleared only by the joint positive token.
        self.delete_scope_active = true;
        let sequence = self.next_sequence();
        let mut scope = SourceOperationScopeV1 {
            source: self,
            receiving,
            sequence,
            purpose,
            kind: std::marker::PhantomData,
            before: Sample::new(),
            after: Sample::new(),
            before_result: None,
            after_result: None,
            controller_result: None,
            cold_session: None,
            cold_reentry: None,
            phase: Phase::Active,
        };
        // No IO occurs while arming either destination. Both actual samples
        // exist before primary native observation can fail or poison anything.
        let after_arm = scope.after.begin(true);
        let before_arm = scope.before.begin(true);
        let result = before_arm.and_then(|()| {
            scope.source.physical.observe_names_into(&mut scope.before)
        });
        scope.before_result = Some(scope.before.finish(result));
        if let Err(cause) = after_arm {
            // A fresh destination cannot normally refuse. Keep that whole
            // result nevertheless, without overwriting a reached observation.
            scope.after_result = Some(Err(cause));
        }
        Ok(scope)
    }
}

impl<P, K: SourceScopePurposeV1> SourceOperationScopeV1<'_, '_, P, K> {
    /// Bounds the actual two native samples and compiled scope/token peak.
    ///
    /// This is passive requirement DATA. The named same-C borrower pays it;
    /// neither this vector nor a historical map can mint a Source scope.
    ///
    /// # Errors
    /// Rejects checked size or fixed Source recipe arithmetic overflow.
    pub fn receiving_demand_v1() -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(
                std::mem::size_of::<SourceOperationScopeDisposalV1<'_, P, K>>().checked_mul(2)?,
            ))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
                crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
                ControllerBankLaunchErrorV1>>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
                ResourceVector, ControllerBankLaunchErrorV1>>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let sample = Sample::fixed_demand_v1(
            Path::new(SOURCE_DOMAIN_DIRECTORY_V1), SOURCE_DOMAIN_JOURNAL_V1,
        )?;
        let views = crate::canonical_journal::coordinator::CanonicalWriterReadViewV1::<P>::receiving_construction_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes.checked_add(views)
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?)
            .checked_add(sample)?.checked_add(sample)?)
    }

    /// Borrows original readonly semantic DATA without opening or releasing it.
    ///
    /// No positive admission is inferred from this view. The actual named D
    /// append entry still checks this scope, original C and complete demand.
    #[must_use]
    pub fn semantic_read_view_v1(&self)
        -> crate::canonical_journal::coordinator::CanonicalWriterReadViewV1<'_, P>
    {
        self.source.coordinator_read_view()
    }

    /// Returns the same retained durable cut as passive sizing DATA.
    #[must_use]
    pub fn durable_end_data_v1(&self) -> u64 { self.source.durable_end }

    /// Borrows the same immutable Source history while its exclusive cut lives.
    ///
    /// The existing Source canonical Tree/Lineage fold consumes this view under
    /// its separately prepaid reached decode/model bound. This view is DATA.
    ///
    /// # Errors
    /// Refuses failed primary observation, completed work or native uncertainty.
    pub fn historical_view_v1(&self)
        -> Result<HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1>
    {
        if self.phase != Phase::Active || !matches!(self.before_result, Some(Ok(())))
            || self.source.has_native_uncertainty_v1()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(self.source.historical_view())
    }

    /// Checks complete reached requirements while the same Source/C cut lives.
    ///
    /// This creates no capacity, currentness, plan or mutation permission. The
    /// actual protected planner supplies the whole co-resident shape before
    /// decode, clone, graph construction or a new native/transport frontier.
    ///
    /// # Errors
    /// Refuses failed/completed entry, changed native custody, a foreign C or
    /// any complete requirement beyond the same already consumed declaration.
    pub fn require_complete_v1<C>(
        &mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        complete: crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.phase != Phase::Active || !matches!(self.before_result, Some(Ok(())))
            || self.failure().is_some() || self.source.has_native_uncertainty_v1()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match self.purpose {
            SourceIntakePurposeV1::Delete => self.receiving.require_delete_complete_v1(controller, launch, profile, complete),
            SourceIntakePurposeV1::Execution => self.receiving.require_execution_complete_v1(controller, launch, profile, complete),
        }
    }

    /// Finishes the prearmed Source post and all actual C native posts once.
    ///
    /// The Source writer remains exclusively held during both observations.
    /// An earlier failed sample or body never suppresses the independent post.
    /// The caller retains its body Result and selects its chronological cause.
    ///
    /// # Errors
    /// Preserves failed names/C completion or refuses repeated/foreign entry.
    pub fn finish_native_once_v1<C>(
        &mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if self.phase != Phase::Active {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.phase = Phase::Finished;
        // No cached cold receiver may begin new native work after these outer
        // posts. Its actual graphs remain charged and retained until Dpositive.
        if let Some(Ok(cold)) = &self.cold_session { cold.end_primary_v2(); }
        if self.after_result.is_none() {
            let result = self.source.physical.observe_names_into(&mut self.after);
            self.after_result = Some(self.after.finish(result));
        }
        self.controller_result = Some(
            self.receiving.finish_native_once_v1(controller, launch, profile),
        );
        if self.failure().is_some() {
            Err(ControllerBankLaunchErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    /// Borrows this scope's actual native cause in observation order.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before.failure()
            .or_else(|| error(&self.before_result))
            .or_else(|| error(&self.cold_session))
            .or_else(|| self.cold_reentry.as_ref().map(|cause| cause as _))
            .or_else(|| self.after.failure())
            .or_else(|| error(&self.after_result))
            .or_else(|| error(&self.controller_result))
    }

    /// Prepares joint positive disposal while all actual upper owners remain.
    ///
    /// Every fallible Source/C check occurs here. The trusted semantic caller
    /// must then dispose its positive input/model/control owners before the
    /// returned token's infallible completion. No body success flag substitutes
    /// for authentication, the Root floor or complete Controller acceptance.
    ///
    /// # Errors
    /// Refuses incomplete/failed posts, changed sequence, native uncertainty,
    /// foreign C, insufficient claim state or repeated preparation.
    pub fn prepare_positive_disposal_v1<'disposal, C>(
        &'disposal mut self,
        controller: &'disposal ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceOperationScopeDisposalV1<'disposal, P, K>, ControllerBankLaunchErrorV1> {
        if self.phase != Phase::Finished || self.failure().is_some()
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !matches!(self.controller_result, Some(Ok(())))
            || self.source.has_native_uncertainty_v1()
            || self.source.next_sequence() != self.sequence
            || !self.source.delete_scope_active
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.phase = Phase::Disposal;
        let controller = match self.purpose {
            SourceIntakePurposeV1::Delete => self.receiving.prepare_delete_source_disposal_v1(
                controller, launch, profile, SourceDeletePositiveProofV1 { _private: () })?,
            SourceIntakePurposeV1::Execution => self.receiving.prepare_execution_source_disposal_v1(
                controller, launch, profile, SourceExecutionPositiveProofV1 { _private: () })?,
        };
        Ok(SourceOperationScopeDisposalV1 {
            controller,
            source: self.source,
            before: &mut self.before,
            after: &mut self.after,
            phase: &mut self.phase,
            cold_session: self.cold_session.as_ref().and_then(|value| value.as_ref().ok()),
            kind: std::marker::PhantomData,
        })
    }
}

/// Keeps both positive native owners through the trusted upper disposal cut.
#[must_use]
pub struct SourceOperationScopeDisposalV1<'disposal, P, K: SourceScopePurposeV1> {
    controller: ControllerOperationIntakeDisposalV1<'disposal>,
    source: &'disposal mut SourceCoordinatorWriterV1<P>,
    before: &'disposal mut Sample,
    after: &'disposal mut Sample,
    phase: &'disposal mut Phase,
    cold_session: Option<&'disposal std::sync::Arc<crate::controller_receiving::bank_launch::ControllerExecutionColdSessionBudgetV2>>,
    kind: std::marker::PhantomData<K>,
}

impl<P, K: SourceScopePurposeV1> SourceOperationScopeDisposalV1<'_, P, K> {
    /// Completes the same Source/C scopes after actual positive upper disposal.
    ///
    /// Performs no allocation, native IO, lock acquisition, fallible post or
    /// refund. The Source lock remains held until its scope itself is dropped.
    pub fn complete_after_disposal_v1(self) {
        if let Some(cold) = self.cold_session {
            // Preparation lends the genuine SDK disposal token while native
            // graphs are resident. Only this final cut requires their Drop.
            if crate::controller_receiving::bank_launch::ControllerExecutionColdSessionBudgetV2::require_last_owner_v2(cold).is_err() {
                std::process::abort();
            }
            cold.end_primary_v2();
        }
        self.before.settle_positive_once_v1();
        self.after.settle_positive_once_v1();
        self.source.delete_scope_active = false;
        *self.phase = Phase::Complete;
        self.controller.complete_after_disposal_v1();
    }
}

impl<P> SourceOperationScopeV1<'_, '_, P, ExecutionSourcePurposeV1> {
    /// Enters one cold Host financial receiver on this actual Source/C18 loan.
    ///
    /// Its finite NoApply profile is chosen later by the shared authenticated
    /// cold engine. Financial entry supplies no Host request or effect grant.
    ///
    /// # Errors
    /// Retains repeated entry, failed Source/currentness or same-flight debt.
    pub fn begin_execution_cold_session_v2<C>(&mut self,
        controller: &ControllerCoordinatorWriterV1<C>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, fixed: ResourceVector,
    ) -> Result<crate::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
        ControllerBankLaunchErrorV1>
    {
        if self.cold_session.is_some() || self.phase != Phase::Active
            || !matches!(self.before_result, Some(Ok(()))) || self.failure().is_some()
            || self.source.has_native_uncertainty_v1() || self.source.next_sequence() != self.sequence
        {
            self.cold_reentry.get_or_insert(ControllerBankLaunchErrorV1::Conflict);
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let result = self.receiving.begin_execution_cold_session_v2(controller, launch, profile, fixed);
        match result {
            Ok((budget, receiving)) => {
                self.cold_session = Some(Ok(budget));
                Ok(receiving)
            }
            Err(cause) => {
                self.cold_session = Some(Err(cause));
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Compares the cold native receiver against this exact Source-held flight.
    ///
    /// # Errors
    /// Refuses another initial/Recover/Source receiver or a closed Source cut.
    pub fn require_execution_cold_session_original_v2(&self,
        receiving: &crate::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let budget = self.cold_session.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        if self.phase != Phase::Active || self.failure().is_some()
            || self.source.next_sequence() != self.sequence || !receiving.matches_execution_cold_v2(budget)
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        budget.require_current_v2().map_err(Into::into)
    }
}

impl<P, K: SourceScopePurposeV1> Drop for SourceOperationScopeV1<'_, '_, P, K> {
    fn drop(&mut self) {
        if self.phase != Phase::Complete {
            // Failed body, uncertain names and forgotten joint token retain
            // their real originals until process termination.
            std::process::abort();
        }
    }
}

fn error<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl<'scope, 'original, P> SourceOperationScopeV1<'scope, 'original, P, DeleteSourcePurposeV1> {
    /// Borrows only the exact retained C17 cause while this Source loan lives.
    ///
    /// This diagnostic performs no healthy reentry or Native IO. A specific
    /// caller selects it only for its actual financial/currentness marker;
    /// earlier concrete transport, decoder or Source errors remain first.
    #[must_use]
    pub fn delete_intake_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<crate::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.receiving.failure_view_v1(profile)
    }

    /// Adds newly reached preaccept debt to this SAME consumed C17 frontier.
    ///
    /// This performs no native IO and grants no Root, Session or effect owner.
    /// The specific caller derives additional DATA from its actual reached
    /// recipe before allocation/IO; previously held debt is retained internally.
    ///
    /// # Errors
    /// Refuses failed/changed Source, C/profile/Launch, overflow or an additional
    /// demand outside the same declaration. Already prepaid posts remain owed.
    pub fn reserve_delete_preaccept_additional_v1<C>(
        &mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.reserve_delete_additional_demand_with_receipt_v2(controller, launch, profile, additional).map(|_| ())
    }

    /// Returns only the cumulative demand from the same successful D reservation.
    ///
    /// This is a checked-demand receipt, never available capacity or a financial
    /// constructor. The genuine continuously held Source/C17 scope remains the
    /// sole payer and currentness owner across the following native work.
    ///
    /// # Errors
    /// Preserves the same active-purpose, original, arithmetic and finite-lane refusal.
    pub fn reserve_delete_additional_demand_with_receipt_v2<C>(
        &mut self,
        controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<ResourceVector, ControllerBankLaunchErrorV1> {
        self.historical_view_v1()?;
        if self.failure().is_some() { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.receiving.reserve_delete_preaccept_with_receipt_v2(
            controller, launch, profile, additional,
        ).map(|receipt| receipt.demand_v1())
    }

    /// Projects the actual canonical D funding without lending a writer or grant.
    ///
    /// # Errors
    /// Refuses failed/finished Source custody or a changed C/profile/Launch.
    pub fn current_delete_funding_data_v3<C>(
        &self,
        controller: &ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, ControllerBankLaunchErrorV1> {
        self.historical_view_v1()?;
        if self.failure().is_some() { return Err(ControllerBankLaunchErrorV1::Conflict); }
        self.receiving.current_delete_funding_data_v3(controller, launch, profile)
    }

    /// Prepays a distinct D-only native turn while this actual Source cut lives.
    ///
    /// The four outer C profile slots are untouched. This borrower owns its
    /// genuine fresh before/after pair, and the caller must keep its upper IO
    /// originals through both posts and actual positive disposal.
    ///
    /// # Errors
    /// Refuses failed/finished Source custody, foreign C/profile/Launch or the
    /// same C17 complete/cumulative-traffic admission before any native IO.
    pub fn prepare_delete_preaccept_turn_v1<'profile, C>(
        &mut self, controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
        complete: crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<crate::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1<'profile>, ControllerBankLaunchErrorV1> {
        self.require_complete_v1(controller, launch, profile, complete)?;
        self.receiving.prepare_delete_preaccept_turn_v1(controller, launch, profile, complete)
    }
}

/// Borrows one actual execution Source cut for its readonly semantic engine.
///
/// Only a held Execution18 Source scope constructs this value. Extracting its
/// historical view supplies DATA; the exclusive Source scope remains borrowed.
#[doc(hidden)]
pub struct SourceExecutionReadViewV1<'read> {
    view: HistoricalLedgerReadViewV1<'read>,
}

impl<'read> SourceExecutionReadViewV1<'read> {
    /// Moves the same readonly view without releasing its original borrow.
    #[must_use]
    pub fn into_historical_view_v1(self) -> HistoricalLedgerReadViewV1<'read> { self.view }
}

/// Reborrows the same consumed execution loan beside readonly Source semantics.
///
/// This is not a second operation or a Source writer. Native completion and
/// positive disposal remain exclusively on the enclosing original Source scope.
#[doc(hidden)]
pub struct SourceExecutionCompleteBorrowV1<'read, 'original, P> {
    source: &'read SourceCoordinatorWriterV1<P>,
    receiving: &'read mut ControllerOperationIntakeReceivingLoanV1<'original>,
    phase: &'read Phase,
    sequence: u64,
}

impl<'scope, 'original, P> SourceOperationScopeV1<'scope, 'original, P, ExecutionSourcePurposeV1> {
    /// Splits disjoint readonly Source and existing financial reborrows.
    ///
    /// The Environment owner can hold the original historical view while the
    /// actual caller checks complete reached demand before another IO frontier.
    /// No Source native owner, loan, capacity, currentness or phase is copied.
    ///
    /// # Errors
    /// Refuses failed/nonactive Source entry, changed sequence or uncertainty.
    pub fn split_execution_read_v1<'read>(&'read mut self)
        -> Result<(SourceExecutionReadViewV1<'read>, SourceExecutionCompleteBorrowV1<'read, 'original, P>), ControllerBankLaunchErrorV1>
    {
        if self.phase != Phase::Active || !matches!(self.before_result, Some(Ok(())))
            || self.failure().is_some() || self.source.has_native_uncertainty_v1()
            || self.source.next_sequence() != self.sequence
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let source = &*self.source;
        Ok((SourceExecutionReadViewV1 { view: source.historical_view() },
            SourceExecutionCompleteBorrowV1 {
                source, receiving: self.receiving, phase: &self.phase, sequence: self.sequence,
            }))
    }
}

impl<P> SourceExecutionCompleteBorrowV1<'_, '_, P> {
    /// Checks the same actual consumed C18 flight before new upper native IO.
    ///
    /// # Errors
    /// Rejects a nonactive Source cut, changed original/sequence/currentness or
    /// a complete reached requirement beyond the same finite declaration.
    pub fn require_complete_v1<C>(
        &mut self, controller: &mut ControllerCoordinatorWriterV1<C>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: crate::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        if *self.phase != Phase::Active || self.source.has_native_uncertainty_v1()
            || self.source.next_sequence() != self.sequence || !self.source.delete_scope_active
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.receiving.require_execution_complete_v1(controller, launch, profile, complete)
    }
}
