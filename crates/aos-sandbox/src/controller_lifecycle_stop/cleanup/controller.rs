//! Commits Stop and Recover metadata on the same genuine Source22 interval.
//!
//! The completed A8 owner supplies logical Stop provenance without rewriting
//! its historical Source lifecycle or failed SDK attempt. The existing healthy
//! three-row Kernel recipe, current Recover success and exact older Recover
//! supersession metadata share one native append carrier; only this closed,
//! funded role enters their common writer.

use super::*;
use crate::closed_controller_append::{
    ClosedControllerAppendFirstV2 as First, ClosedControllerAppendOriginalV2 as Append,
    require_current_map,
};
use crate::journal::{
    JournalError, JournalTransaction, LifecycleTerminalMetadataOriginalV4, RecordNamespace,
};
use crate::lifecycle::StopCleanupSourceAppendOriginalV1 as SourceCompleted;
use aos_sandbox_protocol::domain_ledger::{
    effect_history::{EffectState, decode_effect, encode_lifecycle_effect_receipt_v1},
    execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2 as Cut,
    operation::{decode_operation, effect_key},
    provisioning_root::finality_recover::public_operation::{
        closed_cleanup_terminal_transaction_data_v2, stop_cleanup_operation_v1,
    },
    public_operation::{OperationState, PublicRecoveryKindV1},
};

mod supersession;
use supersession::StopRecoverSupersessionOriginalV1;

pub(super) struct StopCleanupControllerOriginalV1 {
    selected: Option<TerminalFailureV1>,
    pub(super) stage: Append,
    cut: Option<std::result::Result<Cut, JournalError>>,
    model: LifecycleTerminalMetadataOriginalV4,
    model_result: Option<std::result::Result<(), JournalError>>,
    supersession: StopRecoverSupersessionOriginalV1,
    pub(super) metadata: Option<std::result::Result<JournalTransaction, JournalError>>,
    admission: Vec<u8>,
    body: Option<std::result::Result<(), JournalError>>,
    after: Option<std::result::Result<(), JournalError>>,
    pub(super) stop: Option<JournalTransaction>,
    pub(super) expiry: i64,
    pub(super) response: Option<aos_proto::aos::sandbox::v1::Operation>,
    pub(super) recovery: Option<OperationId>,
    reentry: Option<ResourceReservationErrorV1>,
}

#[derive(Clone, Copy)]
enum TerminalFailureV1 {
    Stage,
    Model,
    Cut,
    ModelResult,
    Supersession,
    Metadata,
    Body,
    After,
    Reentry,
}

impl StopCleanupControllerOriginalV1 {
    fn new(expiry: i64) -> Self {
        Self {
            selected: None,
            stage: Append::new(),
            cut: None,
            model: LifecycleTerminalMetadataOriginalV4::new(),
            model_result: None,
            supersession: StopRecoverSupersessionOriginalV1::new(),
            metadata: None,
            admission: Vec::new(),
            body: None,
            after: None,
            stop: None,
            expiry,
            response: None,
            recovery: None,
            reentry: None,
        }
    }

    fn receiving_demand(controller: &Journal, operation: OperationId) -> Result<ResourceVector> {
        let one = Append::fixed_demand(
            controller,
            std::mem::size_of::<StopCleanupControllerAppendContextV1<'_>>()
                .checked_add(std::mem::size_of::<CleanupControllerStagePostsV1<'_, '_, '_>>())
                .ok_or(CLOSED)?,
        )?;
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|n| n.checked_add(
                aos_sandbox_protocol::domain_ledger::public_operation::metadata_complete_projection_receiving_bytes_v1()?))
            .and_then(|n| u64::try_from(n).ok()).ok_or(CLOSED)?;
        Ok(one
            .checked_add(super::completion::receiving_demand_v1()?)?
            .checked_add(crate::journal::stop_cleanup_terminal_model_receiving_demand_v1(
                controller, operation,
            )?)?
            .checked_add(controller.create_storage_semantic_append_demand_v1()?)?
            .checked_add(StopRecoverSupersessionOriginalV1::receiving_demand(controller).ok_or(CLOSED)?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.selected_failure().or_else(|| self.stage
            .failure()
            .or_else(|| self.model.failure())
            .or_else(|| error(&self.cut))
            .or_else(|| error(&self.model_result))
            .or_else(|| self.supersession.failure())
            .or_else(|| error(&self.body))
            .or_else(|| error(&self.metadata))
            .or_else(|| error(&self.after))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _)))
    }

    pub(super) fn selected_failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.selected? {
            TerminalFailureV1::Stage => self.stage.failure(),
            TerminalFailureV1::Model => self.model.failure(),
            TerminalFailureV1::Cut => error(&self.cut),
            TerminalFailureV1::ModelResult => error(&self.model_result),
            TerminalFailureV1::Supersession => self.supersession.failure(),
            TerminalFailureV1::Metadata => error(&self.metadata),
            TerminalFailureV1::Body => error(&self.body),
            TerminalFailureV1::After => error(&self.after),
            TerminalFailureV1::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    // Select the actual retained owner before independent owed observations
    // can fail. The original results stay resident and are never replaced.
    fn select_failure_once(&mut self) {
        if self.selected.is_some() {
            return;
        }
        self.selected = if self.stage.failure().is_some() {
            Some(TerminalFailureV1::Stage)
        } else if self.model.failure().is_some() {
            Some(TerminalFailureV1::Model)
        } else if error(&self.cut).is_some() {
            Some(TerminalFailureV1::Cut)
        } else if error(&self.model_result).is_some() {
            Some(TerminalFailureV1::ModelResult)
        } else if self.supersession.failure().is_some() {
            Some(TerminalFailureV1::Supersession)
        } else if error(&self.metadata).is_some() {
            Some(TerminalFailureV1::Metadata)
        } else if error(&self.body).is_some() {
            Some(TerminalFailureV1::Body)
        } else if error(&self.after).is_some() {
            Some(TerminalFailureV1::After)
        } else if self.reentry.is_some() {
            Some(TerminalFailureV1::Reentry)
        } else {
            None
        };
    }

    pub(super) fn require_complete(&self) -> std::result::Result<Cut, JournalError> {
        positive_journal(&self.body)?;
        positive_journal(&self.after)?;
        positive_journal(&self.metadata)?;
        if self.stop.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        if self.failure().is_some() || self.response.is_none() || self.recovery.is_none() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.stage.after_cut()
    }

    pub(super) fn require_supersession_after_v1(&self, controller: &Journal) -> std::result::Result<(), JournalError> {
        self.supersession.require_after(controller)
    }

    pub(super) fn supersession_rows_v1(&self) -> impl Iterator<Item = &crate::JournalRecord> {
        self.supersession.records()
    }
}

/// Reborrows only genuine native/source fields beside one retained C carrier.
pub(crate) struct StopCleanupControllerAppendContextV1<'turn> {
    operation: OperationId,
    bank: &'turn Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &'turn ProductionControllerNormalRootProfileV1,
    native: &'turn ControllerCreateProvisioningReceivingV1,
    source: &'turn Journal,
    source_turn: &'turn source::StopSourceTurnOriginalV4,
    completed_source: &'turn SourceCompleted,
    carrier: &'turn mut Append,
    model: &'turn LifecycleTerminalMetadataOriginalV4,
    supersession: &'turn StopRecoverSupersessionOriginalV1,
    expected: Cut,
    first: RawPairedClockSample,
    cutoff: u64,
}

// The finite C stage's afters run before the enclosing Source22 post guard
// during unwind. No new native clock or financial account is introduced.
struct CleanupControllerStagePostsV1<'turn, 'owner, 'source> {
    source: &'turn mut ControllerHostStopCleanupSourceLoanV1<'owner, 'source>,
    controller: &'turn mut Journal,
    first: RawPairedClockSample,
    cutoff: u64,
    finished: bool,
}

impl CleanupControllerStagePostsV1<'_, '_, '_> {
    fn finish_once(&mut self, body: std::result::Result<(), JournalError>) -> Result<()> {
        if self.finished {
            return Err(CLOSED);
        }
        self.finished = true;
        self.source
            .finish_cleanup_controller_stage(self.controller, self.first, self.cutoff, body)
    }
}

impl Drop for CleanupControllerStagePostsV1<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            let _retained = self.finish_once(Err(JournalError::ProtectedBoundary));
        }
    }
}

impl StopCleanupControllerAppendContextV1<'_> {
    fn require_current(&self, controller: &Journal) -> std::result::Result<(), JournalError> {
        self.bank
            .lock()
            .map_err(|_| JournalError::ProtectedBoundary)?
            .require_lifecycle_stop_native_current_v4(self.native, controller, self.profile)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.source_turn.require_cleanup_source_current_v1(
            self.operation,
            self.bank,
            self.profile,
            self.native,
            controller,
            self.source,
        )?;
        self.completed_source
            .require_completed_source_prefix_v1(self.source)?;
        self.supersession.require_before(controller)?;
        require_current_map(controller, self.expected)
    }

    pub(crate) fn require_transition_v1(
        &mut self,
        controller: &Journal,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        if self.carrier.transition.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.carrier.transition = Some((|| {
            positive_journal(&self.carrier.before)?;
            positive_journal(&self.carrier.forecast)?;
            positive_journal(&self.carrier.funding)?;
            if self.carrier.transaction.as_ref() != Some(transaction) {
                return Err(JournalError::ProtectedBoundary);
            }
            let [effect, operation, projection, recovery, older @ ..] = transaction.records() else {
                return Err(JournalError::ProtectedBoundary);
            };
            if effect.namespace() != RecordNamespace::Effect
                || operation.namespace() != RecordNamespace::Operation
                || operation.key() != self.operation.as_bytes()
                || projection.namespace() != RecordNamespace::DesiredState
                || recovery.namespace() != RecordNamespace::Operation
                || recovery.key() == operation.key()
                || !older.iter().eq(self.supersession.records()) {
                return Err(JournalError::ProtectedBoundary);
            }
            self.model
                .require_before_v2(controller, self.model.transaction_v2()?)?;
            self.require_current(controller)
        })());
        positive_journal(&self.carrier.transition).map(|_| ())
    }

    pub(crate) fn require_prechecked_transaction_v1(
        &self,
        transaction: &JournalTransaction,
    ) -> std::result::Result<(), JournalError> {
        positive_journal(&self.carrier.transition)?;
        if self.carrier.transaction.as_ref() != Some(transaction) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn final_crossing_v1(
        &mut self,
        controller: &Journal,
    ) -> std::result::Result<(), JournalError> {
        self.require_current(controller)?;
        self.carrier.final_crossing_once(
            controller,
            self.expected,
            self.first.host_boot_id(),
            self.cutoff,
        )
    }
}

impl ControllerHostStopCleanupSourceLoanV1<'_, '_> {
    /// Commits Stop/current Recover success and older pending supersession rows.
    ///
    /// The actual completed A8 native owner is required. Historical Source
    /// attempt bytes remain unchanged; all metadata runs before Source posts
    /// and positive disposal. A durable append with failed afters stays failed.
    ///
    /// # Errors
    /// Retains changed Applying target, incomplete A8/native custody, expired
    /// authority, funding refusal, reentry, append/readback or owed-post failure.
    #[doc(hidden)]
    pub fn complete_controller_terminal_once_v1(
        &mut self,
        controller: &mut Journal,
        completed: &SourceCompleted,
    ) -> Result<()> {
        self.require_current_v1(controller)?;
        completed.require_completed_source_v1(self, controller)?;
        if let Some(terminal) = held_owner_mut(self.owner)
            .cleanup
            .as_mut()
            .and_then(|value| value.terminal.as_deref_mut())
        {
            terminal.reentry.get_or_insert(CLOSED);
            return Err(CLOSED);
        }
        let expiry = completed
            .verified_authority_expiry_data_v1()?
            .min(self.original()?.admission.wall_expiry);
        let reference = self.original()?.admission;
        let raw_len = controller
            .get(RecordNamespace::OperatorRecovery, &reference.key)
            .ok_or(CLOSED)?
            .len();
        let demand =
            StopCleanupControllerOriginalV1::receiving_demand(controller, held_owner(self.owner).operation)?
                .checked_add(ResourceVector::ZERO.with(
                    D::MemoryBytes,
                    u64::try_from(raw_len.checked_mul(3).ok_or(CLOSED)?).map_err(|_| CLOSED)?,
                ))?;
        self.reserve_additional_v1(controller, demand)?;
        held_owner_mut(self.owner).cleanup.as_mut().ok_or(CLOSED)?.terminal =
            Some(Box::new(StopCleanupControllerOriginalV1::new(expiry)));

        // This check precedes the old Stop's change. Later metadata compares
        // the exact native terminal/current cut, never the obsolete Applying target.
        let body = (|| -> std::result::Result<(), JournalError> {
            require_pending_target(controller, held_owner(self.owner).operation)?;
            let raw = controller
                .get(RecordNamespace::OperatorRecovery, &reference.key)
                .ok_or(JournalError::ProtectedBoundary)?;
            if finality_admission_commitment_v1(raw) != reference.commitment {
                return Err(JournalError::ProtectedBoundary);
            }
            let admission =
                Admission::decode_v1(raw).map_err(|_| JournalError::ProtectedBoundary)?;
            let admitted = decode_operation(
                controller
                    .get(RecordNamespace::Operation, &admission.operation)
                    .ok_or(JournalError::ProtectedBoundary)?,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?;
            if admission.target != *held_owner(self.owner).operation.as_bytes()
                || admission.original != reference.original
                || admission.cutoff != reference.cutoff
                || admission.wall_expiry != reference.wall_expiry
                || admitted
                    != stop_cleanup_operation_v1(admission)
                        .map_err(|_| JournalError::ProtectedBoundary)?
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let terminal = held_owner_mut(self.owner)
                .cleanup
                .as_mut()
                .and_then(|value| value.terminal.as_deref_mut())
                .ok_or(JournalError::ProtectedBoundary)?;
            terminal.admission.extend_from_slice(raw);
            terminal.recovery = Some(OperationId::from_bytes(admission.operation));
            Ok(())
        })();
        if body.is_err() {
            let terminal = held_owner_mut(self.owner)
                .cleanup
                .as_mut()
                .and_then(|value| value.terminal.as_deref_mut())
                .ok_or(CLOSED)?;
            terminal.body = Some(body);
            terminal.select_failure_once();
            return Err(CLOSED);
        }
        self.run_cleanup_controller_stage(controller, completed)?;
        let terminal = held_owner_mut(self.owner)
            .cleanup
            .as_mut()
            .and_then(|value| value.terminal.as_deref_mut())
            .ok_or(CLOSED)?;
        let recovery = terminal.recovery.ok_or(CLOSED)?;
        let raw = controller
            .get(RecordNamespace::Operation, recovery.as_bytes())
            .ok_or(CLOSED)?;
        let row = decode_operation(raw).map_err(|_| CLOSED)?;
        terminal.response = Some(row.public_operation().ok_or(CLOSED)?.project(
            recovery,
            OperationState::Succeeded,
            0,
            0,
            false,
            false,
            raw,
            &[],
        ));
        terminal.require_complete()?;
        Ok(())
    }

    fn run_cleanup_controller_stage(
        &mut self,
        controller: &mut Journal,
        completed: &SourceCompleted,
    ) -> Result<()> {
        self.require_current_v1(controller)?;
        let first = *positive(&self.original()?.first)?;
        let cutoff = *positive(&self.original()?.cutoff)?;
        let horizon = (
            first,
            self.original()?.terminal.as_ref().ok_or(CLOSED)?.expiry,
        );
        let mut posts = CleanupControllerStagePostsV1 {
            source: self,
            controller,
            first,
            cutoff,
            finished: false,
        };
        let body = posts.source.run_cleanup_controller_stage_body(
            posts.controller,
            completed,
            first,
            cutoff,
            horizon,
        );
        posts.finish_once(body)
    }

    fn run_cleanup_controller_stage_body(
        &mut self,
        controller: &mut Journal,
        completed: &SourceCompleted,
        first: RawPairedClockSample,
        cutoff: u64,
        horizon: (RawPairedClockSample, i64),
    ) -> std::result::Result<(), JournalError> {
        let expected = {
            let terminal = held_owner_mut(self.owner)
                .cleanup
                .as_mut()
                .and_then(|value| value.terminal.as_deref_mut())
                .ok_or(JournalError::ProtectedBoundary)?;
            let stage = &mut terminal.stage;
            stage.cleanup_horizon = Some(horizon);
            let result = stage.begin_current(controller, first.host_boot_id(), cutoff);
            terminal.cut = Some(result);
            positive_journal(&terminal.cut).copied()
        };
        (|| -> std::result::Result<(), JournalError> {
            let expected = expected?;
            let owner = held_owner_mut(self.owner);
            let original = owner
                .cleanup
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            let terminal = original
                .terminal
                .as_deref_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            let sample = *positive_journal(&terminal.stage.samples[0])?;
            let receipt = encode_lifecycle_effect_receipt_v1(
                owner.operation,
                completed.completed_record_digest_data_v1()?,
            );
            let context = owner
                .accepted
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .and_then(Option::as_ref)
                .ok_or(JournalError::ProtectedBoundary)?;
            terminal.model_result = Some(terminal.model.prepare_stop_success_once_v5(
                controller,
                owner.operation,
                context,
                completed.actual_stop_fence_data_v1()?,
                &receipt,
                sample,
            ));
            positive_journal(&terminal.model_result)?;
            terminal.supersession.observe_once(controller, &terminal.admission, sample)?;
            let stop = terminal.model.transaction_v2()?.clone();
            let admission = Admission::decode_v1(&terminal.admission)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let admitted = decode_operation(
                controller
                    .get(RecordNamespace::Operation, &admission.operation)
                    .ok_or(JournalError::ProtectedBoundary)?,
            )
            .map_err(|_| JournalError::ProtectedBoundary)?;
            terminal.metadata = Some(
                closed_cleanup_terminal_transaction_data_v2(
                    PublicRecoveryKindV1::StopCleanup,
                    admission,
                    admitted,
                    sample,
                )
                .map_err(|_| JournalError::ProtectedBoundary),
            );
            let transaction =
                atomic_cleanup_transaction(&stop, positive_journal(&terminal.metadata)?, &terminal.supersession)?;
            terminal.stop = Some(stop);
            terminal.stage.transaction = Some(transaction.clone());
            terminal.stage.forecast_once(controller)?;
            let demand = *positive_journal(&terminal.stage.forecast)?;
            let funded = self.reserve_additional_v1(controller, demand);
            let owner = held_owner_mut(self.owner);
            let terminal = owner
                .cleanup
                .as_mut()
                .and_then(|value| value.terminal.as_deref_mut())
                .ok_or(JournalError::ProtectedBoundary)?;
            terminal.stage.funding = Some(funded);
            if !matches!(terminal.stage.funding, Some(Ok(()))) {
                terminal.stage.first.get_or_insert(First::Funding);
                return Err(JournalError::ProtectedBoundary);
            }
            let native = owner
                .native
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            let context = StopCleanupControllerAppendContextV1 {
                operation: owner.operation,
                bank: &owner.bank,
                profile: &owner.profile,
                native,
                source: self.source.journal_ref_v1(),
                source_turn: &owner.host_turn,
                completed_source: completed,
                carrier: &mut terminal.stage,
                model: &terminal.model,
                supersession: &terminal.supersession,
                expected,
                first,
                cutoff,
            };
            let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::stop_cleanup_controller_v1(context, &transaction);
            let append = controller.commit_create_provisioning_v1(&transaction, &mut loan);
            let terminal = owner
                .cleanup
                .as_mut()
                .and_then(|value| value.terminal.as_deref_mut())
                .ok_or(JournalError::ProtectedBoundary)?;
            terminal.stage.append = Some(append);
            if !matches!(terminal.stage.append, Some(Ok(_))) {
                terminal.stage.first.get_or_insert(First::Append);
            }
            Ok(())
        })()
    }

    fn finish_cleanup_controller_stage(
        &mut self,
        controller: &Journal,
        first: RawPairedClockSample,
        cutoff: u64,
        body: std::result::Result<(), JournalError>,
    ) -> Result<()> {
        let terminal = held_owner_mut(self.owner)
            .cleanup
            .as_mut()
            .and_then(|value| value.terminal.as_deref_mut())
            .ok_or(CLOSED)?;
        terminal.body = Some(body);
        terminal.select_failure_once();
        let after =
            match terminal
                .cut
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
            {
                Some(cut) if terminal.stage.transaction.is_some() => terminal
                    .stage
                    .finish_append_once(controller, cut, first.host_boot_id(), cutoff),
                Some(cut) => {
                    terminal
                        .stage
                        .finish(controller, cut, first.host_boot_id(), cutoff);
                    Err(JournalError::ProtectedBoundary)
                }
                None => {
                    terminal
                        .stage
                        .finish_failed_entry(controller, first.host_boot_id(), cutoff);
                    Err(JournalError::ProtectedBoundary)
                }
            };
        terminal.after = Some(after);
        terminal.select_failure_once();
        positive_journal(&terminal.body).map_err(|_| CLOSED)?;
        positive_journal(&terminal.after).map_err(|_| CLOSED)?;
        Ok(())
    }
}

// Only this closed Source22 actor commits the N+4 members atomically: the
// current Recover succeeds, while exact older pending admissions explicitly
// become superseded without claiming their work or financial debt completed.
fn atomic_cleanup_transaction(
    stop: &JournalTransaction,
    metadata: &JournalTransaction,
    supersession: &StopRecoverSupersessionOriginalV1,
) -> std::result::Result<JournalTransaction, JournalError> {
    use sha2::{Digest as _, Sha256};
    let [effect, operation, projection] = stop.records() else {
        return Err(JournalError::ProtectedBoundary);
    };
    let [recovery] = metadata.records() else {
        return Err(JournalError::ProtectedBoundary);
    };
    if effect.namespace() != RecordNamespace::Effect
        || operation.namespace() != RecordNamespace::Operation
        || projection.namespace() != RecordNamespace::DesiredState
        || recovery.namespace() != RecordNamespace::Operation
        || operation.key() == recovery.key()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.stop-cleanup.controller-terminal.v1\0");
    for row in stop.records().iter().chain(metadata.records()).chain(supersession.records()) {
        let value = row.value().ok_or(JournalError::ProtectedBoundary)?;
        digest.update([row.namespace() as u8]);
        digest.update(
            u64::try_from(row.key().len())
                .map_err(|_| JournalError::JournalTooLarge)?
                .to_be_bytes(),
        );
        digest.update(row.key());
        digest.update(
            u64::try_from(value.len())
                .map_err(|_| JournalError::JournalTooLarge)?
                .to_be_bytes(),
        );
        digest.update(value);
    }
    let hash = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    JournalTransaction::new(
        id,
        stop.records()
            .iter()
            .chain(metadata.records())
            .chain(supersession.records())
            .cloned()
            .collect(),
    )
    .map_err(Into::into)
}

fn require_pending_target(
    controller: &Journal,
    operation: OperationId,
) -> std::result::Result<(), JournalError> {
    let row = decode_operation(
        controller
            .get(RecordNamespace::Operation, operation.as_bytes())
            .ok_or(JournalError::ProtectedBoundary)?,
    )
    .map_err(|_| JournalError::ProtectedBoundary)?;
    let effect = decode_effect(
        controller
            .get(RecordNamespace::Effect, &effect_key(operation, 0))
            .ok_or(JournalError::ProtectedBoundary)?,
    )
    .map_err(|_| JournalError::ProtectedBoundary)?;
    if row.state() != OperationState::Applying
        || row.effect_count() != 1
        || !matches!(effect.state(), EffectState::Applying { attempt: 1.., .. })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive_journal<T, E>(
    slot: &Option<std::result::Result<T, E>>,
) -> std::result::Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

#[cfg(test)]
mod atomic_data_tests {
    use super::*;
    use crate::journal::JournalRecord;

    // These models are deliberately DATA-only. They never construct a native
    // Stop/Recover payer or bypass the protected semantic append boundary.
    fn models(recovery_key: [u8; 16], recovery_value: u8)
        -> (JournalTransaction, JournalTransaction) {
        let stop = JournalTransaction::new([1; 16], vec![
            JournalRecord::put(RecordNamespace::Effect, effect_key(OperationId::from_bytes([2; 16]), 0).to_vec(), vec![3]),
            JournalRecord::put(RecordNamespace::Operation, vec![2; 16], vec![4]),
            JournalRecord::put(RecordNamespace::DesiredState, b"sandbox-projection".to_vec(), vec![5]),
        ]).unwrap();
        let metadata = JournalTransaction::new([6; 16], vec![
            JournalRecord::put(RecordNamespace::Operation, recovery_key.to_vec(), vec![recovery_value]),
        ]).unwrap();
        (stop, metadata)
    }

    #[test]
    fn both_models_form_one_atomic_four_row_member_set() {
        let (stop, metadata) = models([7; 16], 8);
        let before_stop = stop.clone();
        let before_metadata = metadata.clone();

        let transaction = atomic_cleanup_transaction(&stop, &metadata, &StopRecoverSupersessionOriginalV1::new()).unwrap();

        assert_eq!(transaction.records().len(), 4);
        assert_eq!(&transaction.records()[..3], stop.records());
        assert_eq!(&transaction.records()[3..], metadata.records());
        assert_eq!(stop, before_stop);
        assert_eq!(metadata, before_metadata);
        assert_eq!(atomic_cleanup_transaction(&stop, &metadata, &StopRecoverSupersessionOriginalV1::new()).unwrap(), transaction);
        assert_ne!(transaction.id(), stop.id());
        assert_ne!(transaction.id(), metadata.id());
    }

    #[test]
    fn changed_recovery_member_changes_the_joint_identity_and_alias_refuses() {
        let (stop, metadata) = models([7; 16], 8);
        let (_, different_metadata) = models([7; 16], 9);
        assert_ne!(atomic_cleanup_transaction(&stop, &metadata, &StopRecoverSupersessionOriginalV1::new()).unwrap().id(),
            atomic_cleanup_transaction(&stop, &different_metadata, &StopRecoverSupersessionOriginalV1::new()).unwrap().id());

        let (_, aliases_old_stop) = models([2; 16], 8);
        assert!(atomic_cleanup_transaction(&stop, &aliases_old_stop, &StopRecoverSupersessionOriginalV1::new()).is_err());
        let extra = JournalTransaction::new([10; 16], vec![
            metadata.records()[0].clone(),
            JournalRecord::put(RecordNamespace::Operation, vec![11; 16], vec![12]),
        ]).unwrap();
        assert!(atomic_cleanup_transaction(&stop, &extra, &StopRecoverSupersessionOriginalV1::new()).is_err());
    }

    #[test]
    fn earlier_body_and_model_causes_survive_later_independent_stage_failure() {
        let mut body = StopCleanupControllerOriginalV1::new(1);
        body.body = Some(Err(JournalError::ProtectedBoundary));
        body.select_failure_once();

        // These are passive failed-result slots, not native capabilities.
        body.stage.first = Some(First::Funding);
        body.stage.funding = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        body.select_failure_once();
        assert!(matches!(body.selected, Some(TerminalFailureV1::Body)));
        assert!(body.failure().unwrap().downcast_ref::<JournalError>().is_some());
        assert!(body.stage.failure().is_some());

        let mut model = StopCleanupControllerOriginalV1::new(1);
        model.model_result = Some(Err(JournalError::ProtectedBoundary));
        model.body = Some(Err(JournalError::ProtectedBoundary));
        model.select_failure_once();
        model.stage.first = Some(First::Funding);
        model.stage.funding = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        model.select_failure_once();
        assert!(matches!(model.selected, Some(TerminalFailureV1::ModelResult)));
        assert!(model.failure().unwrap().downcast_ref::<JournalError>().is_some());
    }

    #[test]
    fn actual_earlier_stage_failure_keeps_its_raw_owner() {
        let mut terminal = StopCleanupControllerOriginalV1::new(1);
        terminal.stage.first = Some(First::Funding);
        terminal.stage.funding = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        terminal.body = Some(Err(JournalError::ProtectedBoundary));

        terminal.select_failure_once();
        terminal.after = Some(Err(JournalError::ProtectedBoundary));
        terminal.select_failure_once();

        assert!(matches!(terminal.selected, Some(TerminalFailureV1::Stage)));
        assert!(terminal.failure().unwrap()
            .downcast_ref::<ResourceReservationErrorV1>().is_some());
        assert!(error(&terminal.body).is_some());
        assert!(error(&terminal.after).is_some());
    }
}
