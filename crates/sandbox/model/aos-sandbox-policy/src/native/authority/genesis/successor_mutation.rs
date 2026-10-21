//! Retains actual successor Prepare/Anchor mutations and their independent posts.
//!
//! Strict and mixed ordinary Root sessions select their original private native
//! recipe. Each entered sampler and append Result stays in the caller's resident
//! reservoir. Shape-only capacity comparison never becomes an archive mutation.

use super::super::{
    RootAuthorityErrorV1,
    names::{RootAuthorityNameRecipeV1, RootAuthorityNamesOriginalV1},
};
use super::successor::{
    floor_key, intent_key, journal_state, project_rows_v3, require_receipt_intent,
    root_capacity_request,
};
use super::{RootSourceGenesisAuthorityV1, native_cut::RootGenesisNativeCrossingOriginalV1};
use crate::native::PolicyNativeJournalErrorV1;
use aos_sandbox_model::{ProjectId, RecordNamespace};
use aos_sandbox_ledger_replay::replay::phase_records::{
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentV2,
};
use aos_sandbox_ledger_replay::replay::root_successor::RootFirstSourceSuccessorArchiveV2;
use aos_sandbox_ledger_replay::replay::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2 as Phase, first_source_successor_capacity_delete_v2,
    first_source_successor_capacity_record_v2, transaction_id,
};
use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::source_genesis_wire::FirstSuccessorWireRecipeV3;

fn original_server_crossing_clock(
    original: &aos_sandbox_model::RawPairedClockSample,
    deadline: &std::time::Instant,
) -> Result<aos_sandbox_model::RawPairedClockSample, RootAuthorityErrorV1> {
    let current = super::clock::observe_original_clock(Some(*original))?;
    if std::time::Instant::now() >= *deadline {
        return Err(RootAuthorityErrorV1::Stale);
    }
    Ok(current)
}

/// Retains one Root mutation's whole native Result and independent post debt.
///
/// A new reservoir is required for Prepare and Anchor. It cannot grant a retry
/// after an ambiguous append or release the actual Root owner on failure.
pub struct RootFirstSuccessorMutationResultsV2 {
    attempted: bool,
    preparation_owner: RootAuthorityNamesOriginalV1,
    shape_before: RootAuthorityNamesOriginalV1,
    shape_after: RootAuthorityNamesOriginalV1,
    advisory: RootGenesisNativeCrossingOriginalV1,
    mutation: RootGenesisNativeCrossingOriginalV1,
    data_names: RootAuthorityNamesOriginalV1,
    transaction: Option<JournalTransaction>,
    preparation: Option<Result<(), RootAuthorityErrorV1>>,
    preflight: Option<Result<(), PolicyNativeJournalErrorV1>>,
    crossing: Option<Result<(), RootAuthorityErrorV1>>,
    crossing_clock: Option<Result<aos_sandbox_model::RawPairedClockSample, RootAuthorityErrorV1>>,
    native: Option<Result<CommitResult, PolicyNativeJournalErrorV1>>,
    post: Option<Result<(), RootAuthorityErrorV1>>,
    clock_post: Option<Result<aos_sandbox_model::RawPairedClockSample, RootAuthorityErrorV1>>,
    data: Option<Result<Option<RootFirstSourceSuccessorIntentV2>, RootAuthorityErrorV1>>,
    data_name_post: Option<Result<(), RootAuthorityErrorV1>>,
    data_watermark_post: Option<Result<(), RootAuthorityErrorV1>>,
}

impl Default for RootFirstSuccessorMutationResultsV2 {
    fn default() -> Self {
        Self {
            attempted: false,
            preparation_owner: RootAuthorityNamesOriginalV1::new(),
            shape_before: RootAuthorityNamesOriginalV1::new(),
            shape_after: RootAuthorityNamesOriginalV1::new(),
            advisory: RootGenesisNativeCrossingOriginalV1::new(),
            mutation: RootGenesisNativeCrossingOriginalV1::new(),
            data_names: RootAuthorityNamesOriginalV1::new(),
            transaction: None,
            preparation: None,
            preflight: None,
            crossing: None,
            crossing_clock: None,
            native: None,
            post: None,
            clock_post: None,
            data: None,
            data_name_post: None,
            data_watermark_post: None,
        }
    }
}

impl RootFirstSuccessorMutationResultsV2 {
    /// Creates an unused local reservoir, not a mutation permission.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the first action cause without moving its owning Result.
    pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.data {
            return Some(error);
        }
        if let Some(Err(error)) = &self.preparation {
            return self.preparation_owner.failure().or(Some(error));
        }
        if let Some(Err(error)) = &self.preflight {
            return self
                .shape_before
                .failure()
                .or_else(|| self.advisory.failure())
                .or_else(|| self.shape_after.failure())
                .or(Some(error));
        }
        if let Some(Err(error)) = &self.crossing {
            return Some(error);
        }
        if let Some(Err(error)) = &self.crossing_clock {
            return Some(error);
        }
        if let Some(Err(error)) = &self.native {
            return self.mutation.failure().or(Some(error));
        }
        if let Some(Err(error)) = &self.post {
            return Some(error);
        }
        if let Some(Err(error)) = &self.clock_post {
            return Some(error);
        }
        if let Some(Err(error)) = &self.data_name_post {
            return self.data_names.failure().or(Some(error));
        }
        if let Some(Err(error)) = &self.data_watermark_post {
            return Some(error);
        }
        None
    }

    /// Borrows later original-owner debt separately from the action cause.
    pub fn post_error(&self) -> Option<&RootAuthorityErrorV1> {
        self.post.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the independent original server-clock Result after any action.
    pub fn clock_post_result(
        &self,
    ) -> Option<&Result<aos_sandbox_model::RawPairedClockSample, RootAuthorityErrorV1>> {
        self.clock_post.as_ref()
    }

    /// Borrows independent DATA owner/name/watermark posts without disposal.
    pub fn project_data_post_results(&self) -> [Option<&Result<(), RootAuthorityErrorV1>>; 3] {
        [
            self.post.as_ref(),
            self.data_name_post.as_ref(),
            self.data_watermark_post.as_ref(),
        ]
    }
}

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn compare_retained_project_successor_v3(
        &self,
        project: ProjectId,
        expected: Option<(
            &RootFirstSourceSuccessorIntentV2,
            &RootFirstSourceSuccessorFloorV2,
        )>,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<Option<RootFirstSourceSuccessorIntentV2>, ()> {
        if results.attempted {
            return Err(());
        }
        results.attempted = true;
        let sequence = self.authority.journal.snapshot_sequence();
        results.data = Some((|| {
            self.recheck()?;
            let retained = project_rows_v3(&journal_state(&self.authority.journal), Some(project))?;
            if let Some((context, floor)) = expected {
                let archive = retained
                    .archives
                    .get(&project)
                    .ok_or(RootAuthorityErrorV1::Conflict)?;
                if &archive.original != context || &archive.floor != floor {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
            }
            Ok(retained.intent.or_else(|| {
                retained
                    .archives
                    .get(&project)
                    .map(|archive| archive.original.clone())
            }))
        })());
        // A failed actual comparison never prevents these independent posts.
        // The same supplied reservoir remains owned by the original caller.
        results.post = Some(self.recheck());
        results.data_name_post = Some(
            results
                .data_names
                .observe_transient_once_v1(
                    &self.authority.journal,
                    RootAuthorityNameRecipeV1::NamesOnly,
                )
                .map_err(|()| RootAuthorityErrorV1::Stale),
        );
        results.data_watermark_post =
            Some(if self.authority.journal.snapshot_sequence() == sequence {
                Ok(())
            } else {
                Err(RootAuthorityErrorV1::Stale)
            });
        if results.error().is_some() {
            return Err(());
        }
        results
            .data
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .cloned()
            .ok_or(())
    }

    /// Writes or exact-replays Prepared under the actual held Root writer.
    ///
    /// # Errors
    /// Returns a marker retaining the whole action/native Result in `results`.
    /// Expired Before without an actual receipt remains fenced, not renewed.
    /// The server clock and deadline borrow the same original Broker attempt;
    /// they are comparison inputs, not admission authority or a fresh epoch.
    pub fn prepare_first_successor_v2(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorIntentV2, ()> {
        self.prepare_successor_with_recipe_v3(
            context,
            controller_packet,
            source_packet,
            original_server_clock,
            original_server_deadline,
            results,
            FirstSuccessorWireRecipeV3::StrictV2,
        )
    }

    /// Prepares the selected project using the same native capacity engine.
    ///
    /// # Errors
    /// Retains the actual failed Result and independent posts in `results`.
    pub fn prepare_project_successor_v3(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorIntentV2, ()> {
        self.prepare_successor_with_recipe_v3(
            context,
            controller_packet,
            source_packet,
            original_server_clock,
            original_server_deadline,
            results,
            FirstSuccessorWireRecipeV3::MixedV3,
        )
    }

    fn prepare_successor_with_recipe_v3(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
        recipe: FirstSuccessorWireRecipeV3,
    ) -> Result<RootFirstSourceSuccessorIntentV2, ()> {
        if results.attempted {
            return Err(());
        }
        results.attempted = true;
        let mut before = false;
        results.preparation = Some((|| {
            self.require_successor_recipe_v3(recipe)?;
            let source =
                self.observe_first_successor_source(context, controller_packet, source_packet)?;
            before = source.phase() == aos_sandbox_ledger_replay::source_signer_data::SourceFirstSuccessorReadbackPhaseV2::Before;
            if before {
                self.require_first_successor_admission(context)?;
            }
            if let Some(original) = self.retained_successor_for_project_v3(context.project())? {
                if &original != context {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                return Ok(());
            }
            if !before || context.nonce() != self.nonce {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            let request = root_capacity_request(context)?;
            let admission = transaction_id(context.approval(), Phase::RootPrepared);
            results.transaction = Some(JournalTransaction::new(
                admission,
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        intent_key(context),
                        context.as_bytes().to_vec(),
                    ),
                    {
                        results
                            .preparation_owner
                            .observe_transient_once_v1(
                                &self.authority.journal,
                                RootAuthorityNameRecipeV1::Owner,
                            )
                            .map_err(|()| RootAuthorityErrorV1::Stale)?;
                        aos_sandbox_protocol::domain_ledger::capacity_family::validate_request_with_limits(
                        &request, self.authority.journal.limits(),
                    ).map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)
                        .map_err(RootAuthorityErrorV1::from)?;
                        let record =
                            first_source_successor_capacity_record_v2(&request, admission)?;
                        if self
                            .authority
                            .journal
                            .read_view()
                            .state()
                            .contains_key(&(record.namespace(), record.key().to_vec()))
                        {
                            return Err(RootAuthorityErrorV1::from(
                            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::DuplicateRecordKey,
                        ));
                        }
                        record
                    },
                ],
            )?);
            Ok(())
        })());
        if matches!(results.preparation, Some(Ok(()))) {
            if let Some(transaction) = &results.transaction {
                let phase = match recipe {
                    FirstSuccessorWireRecipeV3::StrictV2 => Phase::RootPrepared,
                    FirstSuccessorWireRecipeV3::MixedV3 => Phase::MixedRootPrepared,
                };
                results.preflight = Some(self.preflight_successor_shape_v1(
                    transaction,
                    context,
                    phase,
                    &mut results.shape_before,
                    &mut results.advisory,
                    &mut results.shape_after,
                ));
                if matches!(results.preflight, Some(Ok(()))) {
                    results.crossing = Some(self.require_first_successor_admission(context));
                    if matches!(results.crossing, Some(Ok(()))) {
                        results.crossing_clock = Some(original_server_crossing_clock(
                            original_server_clock,
                            original_server_deadline,
                        ));
                    }
                    if matches!(results.crossing_clock, Some(Ok(_))) {
                        let phase = match recipe {
                            FirstSuccessorWireRecipeV3::StrictV2 => Phase::RootPrepared,
                            FirstSuccessorWireRecipeV3::MixedV3 => Phase::MixedRootPrepared,
                        };
                        results.native = Some(self.commit_successor_v1(
                            transaction,
                            context,
                            phase,
                            original_server_clock,
                            original_server_deadline,
                            &mut results.mutation,
                        ));
                    }
                }
            }
        }
        results.post = Some((|| {
            self.recheck()?;
            if self
                .retained_successor_for_project_v3(context.project())?
                .as_ref()
                != Some(context)
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        results.clock_post = Some(original_server_crossing_clock(
            original_server_clock,
            original_server_deadline,
        ));
        if results.error().is_some() {
            Err(())
        } else {
            Ok(context.clone())
        }
    }

    /// Anchors the exact actual receipt and preserves its immutable intent archive.
    ///
    /// # Errors
    /// Returns a retaining marker for any action, native or readback failure.
    /// Historical exact recovery never appends an existing archive again.
    /// The borrowed server cut remains the original recovery attempt's cut,
    /// independent of the immutable persisted admission deadline.
    pub fn anchor_first_successor_v2(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorFloorV2, ()> {
        self.anchor_successor_with_recipe_v3(
            context,
            controller_packet,
            source_packet,
            original_server_clock,
            original_server_deadline,
            results,
            FirstSuccessorWireRecipeV3::StrictV2,
        )
    }

    /// Anchors the exact selected receipt and full immutable archive.
    ///
    /// # Errors
    /// Retains native failure and original-clock debt without redispatch.
    pub fn anchor_project_successor_v3(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<RootFirstSourceSuccessorFloorV2, ()> {
        self.anchor_successor_with_recipe_v3(
            context,
            controller_packet,
            source_packet,
            original_server_clock,
            original_server_deadline,
            results,
            FirstSuccessorWireRecipeV3::MixedV3,
        )
    }

    fn anchor_successor_with_recipe_v3(
        &mut self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        original_server_clock: &aos_sandbox_model::RawPairedClockSample,
        original_server_deadline: &std::time::Instant,
        results: &mut RootFirstSuccessorMutationResultsV2,
        recipe: FirstSuccessorWireRecipeV3,
    ) -> Result<RootFirstSourceSuccessorFloorV2, ()> {
        if results.attempted {
            return Err(());
        }
        results.attempted = true;
        let mut expected = None;
        results.preparation = Some((|| {
            self.require_successor_recipe_v3(recipe)?;
            let source =
                self.observe_first_successor_source(context, controller_packet, source_packet)?;
            let receipt = source.receipt().ok_or(RootAuthorityErrorV1::Conflict)?;
            require_receipt_intent(receipt, context)?;
            let floor =
                RootFirstSourceSuccessorFloorV2::new(RootFirstSourceSuccessorFloorFieldsV2 {
                    predecessor_floor: context.predecessor_floor(),
                    approval: context.approval(),
                    receipt: receipt.clone(),
                    roles: self.authority.pins.digest()?,
                })
                .map_err(RootAuthorityErrorV1::from)?;
            let archive = RootFirstSourceSuccessorArchiveV2 {
                floor: floor.clone(),
                original: context.clone(),
            };
            expected = Some(floor);
            let retained = self.successor_rows_for_project_v3(context.project())?;
            if let Some(existing) = retained.archive {
                if existing != archive {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                return Ok(());
            }
            if retained.intent.as_ref() != Some(context) {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            let request = root_capacity_request(context)?;
            results.transaction = Some(JournalTransaction::new(
                transaction_id(context.approval(), Phase::RootAnchor),
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        floor_key(&archive.floor),
                        archive.bytes(),
                    ),
                    JournalRecord::delete(RecordNamespace::DesiredState, intent_key(context)),
                    {
                        results
                            .preparation_owner
                            .observe_transient_once_v1(
                                &self.authority.journal,
                                RootAuthorityNameRecipeV1::Owner,
                            )
                            .map_err(|()| RootAuthorityErrorV1::Stale)?;
                        first_source_successor_capacity_delete_v2(
                            self.authority.journal.read_view().state(),
                            &request,
                            transaction_id(context.approval(), Phase::RootPrepared),
                        )
                        .map_err(RootAuthorityErrorV1::from)?
                    },
                ],
            )?);
            Ok(())
        })());
        if matches!(results.preparation, Some(Ok(()))) {
            if let Some(transaction) = &results.transaction {
                // Actual receipt heads now exist: this is exact semantic preview,
                // never the earlier conservative shape-only capacity decision.
                let phase = match recipe {
                    FirstSuccessorWireRecipeV3::StrictV2 => Phase::RootAnchor,
                    FirstSuccessorWireRecipeV3::MixedV3 => Phase::MixedRootAnchor,
                };
                results.preflight = Some(self.preflight_successor_v1(
                    transaction,
                    context,
                    phase,
                    &mut results.advisory,
                ));
                if matches!(results.preflight, Some(Ok(()))) {
                    results.crossing = Some(self.recheck());
                    if matches!(results.crossing, Some(Ok(()))) {
                        results.crossing_clock = Some(original_server_crossing_clock(
                            original_server_clock,
                            original_server_deadline,
                        ));
                    }
                    if matches!(results.crossing_clock, Some(Ok(_))) {
                        let phase = match recipe {
                            FirstSuccessorWireRecipeV3::StrictV2 => Phase::RootAnchor,
                            FirstSuccessorWireRecipeV3::MixedV3 => Phase::MixedRootAnchor,
                        };
                        results.native = Some(self.commit_successor_v1(
                            transaction,
                            context,
                            phase,
                            original_server_clock,
                            original_server_deadline,
                            &mut results.mutation,
                        ));
                    }
                }
            }
        }
        results.post = Some((|| {
            self.recheck()?;
            let archive = self
                .successor_rows_for_project_v3(context.project())?
                .archive
                .ok_or(RootAuthorityErrorV1::Stale)?;
            if Some(&archive.floor) != expected.as_ref() || &archive.original != context {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        results.clock_post = Some(original_server_crossing_clock(
            original_server_clock,
            original_server_deadline,
        ));
        if results.error().is_some() {
            Err(())
        } else {
            expected.ok_or(())
        }
    }
}
