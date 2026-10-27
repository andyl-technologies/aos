//! Keeps real U and upper currentness around the same native Released owner.
//!
//! The same live financial borrower survives its old Root/Cache frontiers.
//! Native append and reader stages remain opaque; actual upper Controller,
//! Source, Root and paired-clock results retain their original cause order.

use crate::journal::JournalTransaction;

use super::*;
use crate::controller_resource_reservation::CacheReleaseReceivingLoanV1;
use aos_sandbox_cache::{CacheReleasedOriginalsV1 as NativeReleased, CacheReleasedShapeV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::ContinuationNativeReceiptDataV1, outcome::ReleasedBodyDataV1,
};

/// Preserves the actual upper semantic-supplement or native forecast cause.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheReleaseShapeErrorV1 {
    #[error(transparent)]
    Native(#[from] CacheHeldErrorV1),
    #[error(transparent)]
    Semantic(#[from] crate::JournalError),
}

/// Identifies the original four upper Released currentness observations.
#[derive(Clone, Copy)]
pub(crate) enum CacheReleasedCurrentnessSiteV1 {
    Before,
    Transition,
    FinalCrossing,
    After,
}

#[derive(Clone, Copy)]
enum ReleasedFailure {
    Native,
    NativeInput,
    Semantic,
    Fixed,
    Body,
    Named(usize),
    Control(usize),
    Clock,
    Cutoff,
    Order,
}

/// Keeps native Released custody together with its actual upper causes.
#[derive(Default)]
pub(crate) struct CacheReleasedOriginalsV1 {
    pub(crate) native: NativeReleased,
    first: Option<ReleasedFailure>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    native_input: Option<aos_sandbox_cache::CacheHeldErrorV1>,
    native_returned: Option<Result<(), CacheHeldClosedV1>>,
    semantic_supplement: Option<Result<ResourceVector, crate::JournalError>>,
    body: Option<Result<ReleasedBodyDataV1, ResourceReservationErrorV1>>,
    named: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    controls: [Option<Result<(), ResourceReservationErrorV1>>; 4],
    selected_control: Option<CacheReleasedCurrentnessSiteV1>,
    audit_clock: crate::policy_compiler::RetainedKernelPairedClockAttemptV1,
    audit_clock_result: Option<
        Result<
            aos_sandbox_model::RawPairedClockSample,
            crate::hierarchy::genesis_profile::SourceGenesisErrorV1,
        >,
    >,
    audit_cutoff: Option<Result<(), ResourceReservationErrorV1>>,
    order: Option<ResourceReservationErrorV1>,
    complete: bool,
}

impl CacheReleasedOriginalsV1 {
    pub(crate) fn started(&self) -> bool {
        self.native.started()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(ReleasedFailure::Native) => self
                .native
                .failure()
                .or_else(|| error(&self.native_returned)),
            Some(ReleasedFailure::NativeInput) => {
                self.native_input.as_ref().map(|cause| cause as _)
            }
            Some(ReleasedFailure::Semantic) => error(&self.semantic_supplement),
            Some(ReleasedFailure::Fixed) => error(&self.fixed),
            Some(ReleasedFailure::Body) => error(&self.body),
            Some(ReleasedFailure::Named(index)) => error(&self.named[index]),
            Some(ReleasedFailure::Control(index)) => error(&self.controls[index]),
            Some(ReleasedFailure::Clock) => self
                .audit_clock
                .failure()
                .or_else(|| error(&self.audit_clock_result)),
            Some(ReleasedFailure::Cutoff) => error(&self.audit_cutoff),
            Some(ReleasedFailure::Order) => self.order.as_ref().map(|cause| cause as _),
            None => self.native.failure(),
        }
    }

    pub(crate) fn append_funding_failure_is_selected_v1(&self) -> bool {
        self.native.append_funding_failure_is_selected_v1()
    }

    pub(crate) fn selected_control_v1(&self) -> Option<CacheReleasedCurrentnessSiteV1> {
        self.selected_control
    }

    pub(crate) fn identity_v1(&self) -> Result<CacheHeldIdentityDataV1, CacheHeldClosedV1> {
        self.receipt_v1()?;
        self.native.identity_v1()
    }

    pub(crate) fn receipt_v1(
        &self,
    ) -> Result<ContinuationNativeReceiptDataV1<'_>, CacheHeldClosedV1> {
        if !self.complete || self.first.is_some() {
            return Err(CacheHeldClosedV1);
        }
        self.native.receipt_v1()
    }

    fn fail(&mut self, source: ReleasedFailure) {
        self.first.get_or_insert(source);
    }

    fn refuse(&mut self) {
        self.order
            .get_or_insert(ResourceReservationErrorV1::Conflict);
        self.fail(ReleasedFailure::Order);
        self.native.reject_upper_once_v1();
    }

    fn native_result(&mut self, result: Result<(), CacheHeldClosedV1>) {
        if result.is_err() {
            if self.native_returned.is_none() {
                self.native_returned = Some(result);
            }
            self.fail(ReleasedFailure::Native);
        }
    }
}

impl OriginalCreateStorageCacheLoanV1<'_> {
    pub(crate) fn release_receiving_shape_v1(
        &self,
    ) -> Result<CacheReleasedShapeV1, CacheReleaseShapeErrorV1> {
        let fixed = release_upper_fixed_demand_v1();
        let supplement = crate::journal::cache_native_semantic_supplement_v1();
        let available = supplement.as_ref().ok().copied();
        match self
            .native
            .release_receiving_shape_v1(fixed.as_ref().ok().copied(), available)
        {
            Err(CacheHeldErrorV1::Journal(
                aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperSemanticQuote,
            )) => match supplement {
                Err(cause) => Err(CacheReleaseShapeErrorV1::Semantic(cause)),
                Ok(_) => Err(CacheReleaseShapeErrorV1::Native(CacheHeldErrorV1::Order)),
            },
            Err(CacheHeldErrorV1::Journal(
                aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperFixedQuote,
            )) => Err(CacheReleaseShapeErrorV1::Native(
                fixed.err().unwrap_or(CacheHeldErrorV1::Order),
            )),
            result => result.map_err(CacheReleaseShapeErrorV1::Native),
        }
    }

    pub(crate) fn release_original_held_once(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.started() {
            released.refuse();
            return Err(CacheHeldClosedV1);
        }
        let fixed = release_upper_fixed_demand_v1();
        let upper_fixed = fixed.as_ref().ok().copied();
        if let Err(cause) = fixed {
            released.native_input = Some(cause);
        }
        released.semantic_supplement = Some(crate::journal::cache_native_semantic_supplement_v1());
        let supplement = released
            .semantic_supplement
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied();
        let entered =
            self.native
                .begin_released_once_v1(&mut released.native, upper_fixed, supplement);
        // The native full-prefix recipe runs before the old upper supplement
        // failure is selected. A native prefix error remains the first cause.
        if released.native.failure().is_some_and(|cause| {
            matches!(
                cause.downcast_ref::<CacheHeldErrorV1>(),
                Some(CacheHeldErrorV1::Journal(
                    aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperSemanticQuote
                )),
            )
        }) {
            released.fail(ReleasedFailure::Semantic);
        }
        if released.native.failure().is_some_and(|cause| {
            matches!(
                cause.downcast_ref::<CacheHeldErrorV1>(),
                Some(CacheHeldErrorV1::Journal(
                    aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperFixedQuote
                )),
            )
        }) {
            released.fail(ReleasedFailure::NativeInput);
        }
        released.native_result(entered);
        released.fixed = Some(match released.native.shape_v1() {
            Ok(shape) => receiving.require_cache_release_shape_v1(shape),
            Err(_) => Err(ResourceReservationErrorV1::Conflict),
        });
        if matches!(released.fixed, Some(Err(_))) {
            released.fail(ReleasedFailure::Fixed);
        }
        let before = self
            .native
            .observe_released_before_once_v1(&mut released.native);
        released.native_result(before);
        let primary = self.produce_released_inner(released, receiving);
        let after = self
            .native
            .observe_released_after_once_v1(&mut released.native);
        released.native_result(after);
        // Native refusal and its post debt never suppress this actual upper
        // observation. The first selected body cause remains selected.
        self.released_currentness_once(released, receiving, CacheReleasedCurrentnessSiteV1::After);
        if primary.is_ok() && released.first.is_none() {
            self.audit_released_once(released, receiving)?;
            let finished = self
                .native
                .finish_released_native_once_v1(&mut released.native);
            released.native_result(finished);
            released.complete = finished.is_ok() && released.first.is_none();
        }
        if released.complete {
            Ok(())
        } else {
            Err(CacheHeldClosedV1)
        }
    }

    fn produce_released_inner(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        if released.first.is_some() {
            return Err(CacheHeldClosedV1);
        }
        self.released_currentness_once(released, receiving, CacheReleasedCurrentnessSiteV1::Before);
        if released.first.is_some() {
            return Err(CacheHeldClosedV1);
        }
        let lane = receiving.lane_v1().map_err(|cause| {
            released.body = Some(Err(cause));
            released.fail(ReleasedFailure::Body);
            CacheHeldClosedV1
        })?;
        let predecessor = self
            .native
            .held_predecessor_data_v1(lane)
            .map_err(|cause| {
                released.native_input = Some(cause);
                released.fail(ReleasedFailure::NativeInput);
                CacheHeldClosedV1
            })?;
        released.body = Some(receiving.released_body_v1(predecessor));
        if matches!(released.body, Some(Err(_))) {
            released.fail(ReleasedFailure::Body);
            return Err(CacheHeldClosedV1);
        }
        let body = released
            .body
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(CacheHeldClosedV1)?;
        let encoded = self
            .native
            .encode_released_pair_once_v1(&mut released.native, lane, body);
        released.native_result(encoded);
        if encoded.is_err() {
            return Err(CacheHeldClosedV1);
        }
        let admitted = self
            .native
            .admit_released_append_once_v1(&mut released.native, receiving.native_funding_v1());
        released.native_result(admitted);
        if admitted.is_err() {
            return Err(CacheHeldClosedV1);
        }
        self.append_released_pair_once(released, receiving)?;
        let returned = self
            .native
            .capture_released_returned_pair_once_v1(&mut released.native);
        released.native_result(returned);
        returned
    }

    fn append_released_pair_once(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        let transaction = Arc::clone(
            self.native
                .released_append_transaction_data_v1(&released.native)?,
        );
        let context = self.native.begin_released_append_once_v1(
            &mut released.native,
            &transaction,
            receiving.native_funding_v1(),
        );
        let (mut context, mut gate) = match context {
            Ok(original) => original,
            Err(_) => {
                released.first.get_or_insert(ReleasedFailure::Native);
                return Err(CacheHeldClosedV1);
            }
        };
        // These are the same original order: named U/association first, native
        // crossing with its owed posts, then the independent upper currentness.
        released.named[0] = Some(receiving.require_cache_named_preparation(
            context.currentness_original_v1().original_identity_v1(),
        ));
        if matches!(released.named[0], Some(Err(_))) {
            released.first.get_or_insert(ReleasedFailure::Named(0));
            context.reject_upper_currentness_v1();
        }
        let transition = context.observe_transition_native_once_v1();
        if transition.is_err() {
            released.first.get_or_insert(ReleasedFailure::Native);
        }
        released.controls[1] = Some(receiving.observe_cache_release_currentness_once(
            &context.currentness_original_v1(),
            CacheReleasedCurrentnessSiteV1::Transition,
        ));
        if matches!(released.controls[1], Some(Err(_))) {
            if released.first.is_none() {
                released.selected_control = Some(CacheReleasedCurrentnessSiteV1::Transition);
            }
            released.first.get_or_insert(ReleasedFailure::Control(1));
            context.reject_upper_currentness_v1();
        }
        let result = (|| {
            context.finish_transition_once_v1()?;
            let transaction = transaction.as_ref();
            aos_sandbox_broker::run_canonical_semantic_append_v1! {
                ordinary,
                context: context, transaction: transaction, gate: gate,
                boundary: aos_sandbox_cache::CacheJournalErrorV1::boundary_data_v1(),
                coordinates: (materialized_bytes, commit_sequence, following_sequence, durable_bytes),
                preflight: { context.preflight_native_once_v1(materialized_bytes, following_sequence)?; },
                final_crossing: {
                    released.named[1] = Some(receiving.require_cache_named_preparation(
                        context.currentness_original_v1().original_identity_v1(),
                    ));
                    if matches!(released.named[1], Some(Err(_))) {
                        released.first.get_or_insert(ReleasedFailure::Named(1));
                        context.reject_upper_currentness_v1();
                    }
                    let final_native = context.observe_final_native_once_v1();
                    if final_native.is_err() { released.first.get_or_insert(ReleasedFailure::Native); }
                    released.controls[2] = Some(receiving.observe_cache_release_currentness_once(
                        &context.currentness_original_v1(), CacheReleasedCurrentnessSiteV1::FinalCrossing,
                    ));
                    if matches!(released.controls[2], Some(Err(_))) {
                        if released.first.is_none() { released.selected_control = Some(CacheReleasedCurrentnessSiteV1::FinalCrossing); }
                        released.first.get_or_insert(ReleasedFailure::Control(2));
                        context.reject_upper_currentness_v1();
                    }
                    context.finish_final_crossing_once_v1()?;
                },
                durable_check: {}, published: {},
                completed: { Ok(CommitResult { commit_sequence, durable_bytes }) },
            }
        })();
        let returned = context.retain_result_once_v1(result);
        if returned.is_err() {
            released.first.get_or_insert(ReleasedFailure::Native);
        }
        returned
    }

    fn released_currentness_once(
        &self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
        site: CacheReleasedCurrentnessSiteV1,
    ) {
        let index = match site {
            CacheReleasedCurrentnessSiteV1::Before => 0,
            CacheReleasedCurrentnessSiteV1::Transition => 1,
            CacheReleasedCurrentnessSiteV1::FinalCrossing => 2,
            CacheReleasedCurrentnessSiteV1::After => 3,
        };
        released.controls[index] = Some(
            receiving.observe_cache_release_currentness_once(&self.currentness_original_v1(), site),
        );
        if matches!(released.controls[index], Some(Err(_))) {
            if released.first.is_none() {
                released.selected_control = Some(site);
            }
            released.fail(ReleasedFailure::Control(index));
            released.native.reject_upper_once_v1();
        }
    }

    fn audit_released_once(
        &mut self,
        released: &mut CacheReleasedOriginalsV1,
        receiving: &mut CacheReleaseReceivingLoanV1<'_>,
    ) -> Result<(), CacheHeldClosedV1> {
        while self.native.released_audit_ordinal_data_v1() < 15 {
            let captured = self.native.capture_released_reader_once_v1(
                &mut released.native,
                receiving.native_funding_v1(),
            );
            released.native_result(captured);
            released.audit_clock_result = Some(released.audit_clock.observe_once(None));
            released.audit_cutoff = Some(match &released.audit_clock_result {
                Some(Ok(clock)) => receiving.require_current_clock_v1(*clock),
                _ => Err(ResourceReservationErrorV1::Conflict),
            });
            if released.audit_clock.failure().is_some()
                || matches!(released.audit_clock_result, Some(Err(_)))
            {
                released.fail(ReleasedFailure::Clock);
            }
            if matches!(released.audit_cutoff, Some(Err(_))) {
                released.fail(ReleasedFailure::Cutoff);
            }
            if released.first.is_some() {
                self.native
                    .reject_released_reader_after_upper_clock_v1(&mut released.native);
                return Err(CacheHeldClosedV1);
            }
            let retired = self
                .native
                .retire_released_reader_after_upper_clock_v1(&mut released.native);
            released.native_result(retired);
            retired?;
            drop(std::mem::take(&mut released.audit_clock));
            released.audit_clock_result = None;
            released.audit_cutoff = None;
        }
        Ok(())
    }
}

pub(crate) fn release_upper_fixed_demand_v1() -> Result<ResourceVector, CacheHeldErrorV1> {
    let bytes = std::mem::size_of::<CacheReleasedOriginalsV1>()
        .checked_sub(std::mem::size_of::<NativeReleased>())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| {
            bytes.checked_add(2 * std::mem::size_of::<CacheReleaseReceivingLoanV1<'_>>())
        })
        .and_then(|bytes| {
            bytes.checked_add(crate::Journal::cache_audit_source_original_receiving_bytes_v1()?)
        })
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<(
                [Result<(), ResourceReservationErrorV1>; 3],
                Result<(), CacheHeldClosedV1>,
                Result<ReleasedBodyDataV1, ResourceReservationErrorV1>,
                CacheHeldCurrentnessOriginalV1<'_>,
                [Result<ResourceVector, crate::JournalError>; 2],
                [Result<ResourceVector, CacheHeldErrorV1>; 2],
                [Result<CacheReleasedShapeV1, CacheReleaseShapeErrorV1>; 2],
            )>())
        })
        // Released captures these separate upper fields at the two exact
        // currentness frontiers. The nested primary also captures its guard
        // slot; neither environment is credited to a resident progress field.
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<(
                (
                    &mut aos_sandbox_cache::CacheHeldAppendContextV1<'_, '_, '_>,
                    &Arc<JournalTransaction>,
                    &mut aos_sandbox_cache::CacheHeldAppendGateV1,
                    &mut [Option<Result<(), ResourceReservationErrorV1>>; 2],
                    &mut Option<ReleasedFailure>,
                    &mut [Option<Result<(), ResourceReservationErrorV1>>; 4],
                    &mut Option<CacheReleasedCurrentnessSiteV1>,
                    &mut CacheReleaseReceivingLoanV1<'_>,
                ),
                (
                    &mut aos_sandbox_cache::CacheHeldAppendContextV1<'_, '_, '_>,
                    &JournalTransaction,
                    &mut aos_sandbox_cache::CacheHeldAppendGateV1,
                    &mut [Option<Result<(), ResourceReservationErrorV1>>; 2],
                    &mut Option<ReleasedFailure>,
                    &mut [Option<Result<(), ResourceReservationErrorV1>>; 4],
                    &mut Option<CacheReleasedCurrentnessSiteV1>,
                    &mut CacheReleaseReceivingLoanV1<'_>,
                    &mut Option<aos_sandbox_cache::CacheHeldAppendGuardV1>,
                ),
            )>().checked_mul(2)?)
        })
        .ok_or(CacheHeldErrorV1::Order)?;
    let clock =
        crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or(CacheHeldErrorV1::Order)?;
    Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes,
        u64::try_from(bytes.checked_add(clock).ok_or(CacheHeldErrorV1::Order)?).map_err(|_| CacheHeldErrorV1::Order)?)
        .with(ResourceDimension::OpenFiles, u64::try_from(
            crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1,
        ).map_err(|_| CacheHeldErrorV1::Order)?))
}

pub(crate) fn release_receiving_demand_v1(
    extents: &[aos_sandbox_broker::canonical_journal::CanonicalReplayExtentDataV1; 5],
) -> Result<ResourceVector, CacheReleaseShapeErrorV1> {
    let fixed = release_upper_fixed_demand_v1();
    let supplement = crate::journal::cache_native_semantic_supplement_v1();
    match aos_sandbox_cache::release_receiving_demand_v1(
        extents,
        fixed.as_ref().ok().copied(),
        supplement.as_ref().ok().copied(),
    ) {
        Err(CacheHeldErrorV1::Journal(
            aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperFixedQuote,
        )) => Err(CacheReleaseShapeErrorV1::Native(
            fixed.err().unwrap_or(CacheHeldErrorV1::Order),
        )),
        Err(CacheHeldErrorV1::Journal(
            aos_sandbox_cache::CacheJournalErrorV1::DeferredUpperSemanticQuote,
        )) => match supplement {
            Err(cause) => Err(CacheReleaseShapeErrorV1::Semantic(cause)),
            Ok(_) => Err(CacheReleaseShapeErrorV1::Native(CacheHeldErrorV1::Order)),
        },
        result => result.map_err(CacheReleaseShapeErrorV1::Native),
    }
}
