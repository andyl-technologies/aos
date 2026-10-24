//! Writes the final public Delete projection after genuine Root EOF.
//!
//! The historical accepted C witness stays unchanged through Root544. This
//! finite second implementation of the same sealed append borrower admits only
//! the derived Effect/Operation/Sandbox successor on that same Source/C17.

use super::*;
use crate::journal::DeleteSourceFrontierClockV3 as Clock;
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1 as Turn;
use aos_sandbox_protocol::domain_ledger::delete_root::completion::DeleteRootSourceCompletionDataV4 as Frame;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy)]
enum First {
    Funding,
    Entry,
    Before,
    Models,
    AppendFunding,
    Append,
    Readback,
    After,
    Clock,
    Disposal,
}

#[derive(Default)]
pub(crate) struct ControllerDeleteTerminalOriginalV4 {
    funding: Option<Result<(), JournalError>>,
    entry: Option<Result<(), JournalError>>,
    before: Option<Result<(), JournalError>>,
    frame: Option<Frame>,
    models: Option<Result<JournalTransaction, Cause>>,
    append_funding: Option<Result<(), JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    clock: Option<Clock>,
    clock_result: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    completed: bool,
    first: Option<First>,
}

impl ControllerDeleteTerminalOriginalV4 {
    pub(crate) fn financial_failure_is_selected_v4(&self) -> bool {
        let selected = match self.first {
            Some(First::Funding) => self.funding.as_ref(),
            Some(First::Entry) => self.entry.as_ref(),
            Some(First::Before) => self.before.as_ref(),
            Some(First::AppendFunding) => self.append_funding.as_ref(),
            Some(First::After) => self.after.as_ref(),
            Some(First::Disposal) => self.disposal.as_ref(),
            _ => None,
        };
        matches!(selected, Some(Err(JournalError::ControllerNative(_))))
    }

    pub(crate) fn require_completed_v4(&self) -> Result<(), JournalError> {
        if self.first.is_none() && self.completed {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    /// Rejoins this actual terminal append with its current C and held Source.
    ///
    /// This comparison borrows the already completed native owner. Supplied
    /// frame bytes cannot construct it or replace its append and post results.
    ///
    /// # Errors
    /// Refuses incomplete native disposal, another Source frontier, changed
    /// Controller COMMIT position, or any changed terminal successor row.
    pub(crate) fn require_current_readback_v4(
        &self,
        journal: &Journal,
        source: &[u8; 64],
    ) -> Result<(), JournalError> {
        self.require_completed_v4()?;
        journal.ensure_protected_authority()?;
        let frame = self.frame.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let transaction = self.models.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let commit = self.append.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if &frame.source != source
            || commit.commit_sequence.checked_add(1) != Some(journal.snapshot_sequence())
            || commit.durable_bytes != journal.controller_coordinator_for_bank_read_v1()?
                .durable_prefix_end_data_v1()
            || transaction.records().iter()
                .any(|row| journal.get(row.namespace(), row.key()) != row.value())
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(
            value: &Option<Result<T, JournalError>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        match self.first? {
            First::Funding => cause(&self.funding),
            First::Entry => cause(&self.entry),
            First::Before => cause(&self.before),
            First::Models => self
                .models
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::AppendFunding => cause(&self.append_funding),
            First::Append => cause(&self.append),
            First::Readback => cause(&self.readback),
            First::After => cause(&self.after),
            First::Clock => self
                .clock
                .as_ref()
                .and_then(Clock::failure)
                .or_else(|| cause(&self.clock_result)),
            First::Disposal => cause(&self.disposal),
        }
    }

    pub(crate) fn run_once_v4<'profile>(
        root: &RootDeleteClientOriginalV1<'_>,
        journal: &mut Journal,
        fence: &mut SourceDeletePendingFenceV1<'_, '_, '_, '_>,
        accepted: &ControllerDeleteAdmissionOriginalV3,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> (Self, Option<Turn<'profile>>) {
        let mut owner = Self::default();
        owner.funding = Some((|| {
            root.require_terminal_exchange_complete_v4(fence.completion_native_data_v4()?)?;
            let model = model_receiving_demand_v3(journal, fence)
                .map_err(|_| JournalError::JournalTooLarge)?;
            let additional = std::mem::size_of::<Self>()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(544 * 8 + 128))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            let clock = Clock::receiving_demand_v3()?;
            let demand = model
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, additional))
                .and_then(|demand| demand.checked_add(clock))
                .map_err(JournalError::ReceivingAccounting)?;
            fence.reserve_preaccept_additional_v1(journal, launch, profile, demand)
        })());
        if !matches!(owner.funding, Some(Ok(()))) {
            owner.first = Some(First::Funding);
            return (owner, None);
        }
        let mut turn =
            match fence.prepare_preaccept_turn_v1(journal, launch, profile, ResourceVector::ZERO) {
                Ok(turn) => {
                    owner.entry = Some(Ok(()));
                    turn
                }
                Err(cause) => {
                    owner.entry = Some(Err(cause));
                    owner.first = Some(First::Entry);
                    return (owner, None);
                }
            };
        owner.before = Some(
            journal
                .controller_coordinator_for_bank_read_v1()
                .and_then(|writer| {
                    turn.observe_before_once_v1(writer)
                        .map_err(JournalError::ControllerNative)
                }),
        );
        if !matches!(owner.before, Some(Ok(()))) {
            owner.first = Some(First::Before);
        }
        let bound = root.completed_terminal_clock_bound_v4();
        if let Ok(bound) = bound {
            owner.clock = Some(Clock::new(bound));
        }
        if owner.first.is_none() {
            owner.models = Some((|| {
                let native = fence.completion_native_data_v4()?;
                let frame = root.completed_terminal_frame_v4(native)?;
                owner.frame = Some(frame);
                accepted.completed_native_v3(journal, fence)?;
                let plan = &accepted
                    .models
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?
                    .0;
                let clock = owner
                    .clock
                    .as_mut()
                    .ok_or(JournalError::ProtectedBoundary)?;
                clock.observe_frontier_v3()?;
                prepare_models(
                    journal,
                    fence,
                    plan,
                    frame,
                    clock.last_sample_v3()?.wall_seconds(),
                )
            })());
            if !matches!(owner.models, Some(Ok(_))) {
                owner.first = Some(First::Models);
            }
        }
        if owner.first.is_none() {
            if let Some(Ok(transaction)) = owner.models.as_ref() {
                owner.append_funding = Some((|| {
                    let demand = journal
                        .append_receiving_demand_v1(transaction.records().iter().map(|row| {
                            aos_sandbox_journal::geometry::RecordShape {
                                key_bytes: row.key().len(),
                                value_bytes: row.value().map(<[u8]>::len),
                            }
                        }))
                        .map_err(|cause| match cause {
                            super::super::JournalAppendReceivingDemandErrorV1::Journal(cause) => {
                                cause
                            }
                            super::super::JournalAppendReceivingDemandErrorV1::Accounting(
                                cause,
                            ) => JournalError::ReceivingAccounting(cause),
                        })?;
                    fence.reserve_preaccept_additional_v1(journal, launch, profile, demand)
                })());
                if !matches!(owner.append_funding, Some(Ok(()))) {
                    owner.first = Some(First::AppendFunding);
                }
                if owner.first.is_none() {
                    let mut loan = CompletionLoan {
                        root,
                        fence,
                        accepted,
                        transaction,
                        turn: &mut turn,
                        clock: owner.clock.as_mut(),
                        launch,
                        profile,
                    };
                    owner.append = Some(journal.commit_create_storage_original_v1(transaction,
                        super::super::create_storage_append::CreateStorageAppendOriginalV1::DeleteAdmission(&mut loan)));
                    if !matches!(owner.append, Some(Ok(_))) {
                        owner.first = Some(First::Append);
                    }
                    drop(loan);
                    owner.readback = Some((|| {
                        journal.ensure_protected_authority()?;
                        if !matches!(owner.append, Some(Ok(_)))
                            || transaction
                                .records()
                                .iter()
                                .any(|row| journal.get(row.namespace(), row.key()) != row.value())
                        {
                            return Err(JournalError::ProtectedBoundary);
                        }
                        Ok(())
                    })());
                    if !matches!(owner.readback, Some(Ok(()))) {
                        owner.first.get_or_insert(First::Readback);
                    }
                }
            }
        }
        if owner.first.is_some() {
            turn.refuse_primary_v1();
        }
        owner.after = Some(
            journal
                .controller_coordinator_for_bank_read_v1()
                .and_then(|writer| {
                    turn.observe_after_once_v1(writer)
                        .map_err(JournalError::ControllerNative)
                }),
        );
        if !matches!(owner.after, Some(Ok(()))) {
            owner.first.get_or_insert(First::After);
        }
        owner.clock_result = Some(
            owner
                .clock
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)
                .and_then(Clock::observe_frontier_v3),
        );
        if !matches!(owner.clock_result, Some(Ok(()))) {
            owner.first.get_or_insert(First::Clock);
        }
        if owner.first.is_none() {
            owner.disposal = Some((|| {
                let token = turn
                    .prepare_positive_disposal_v1(
                        journal.controller_coordinator_for_bank_read_v1()?,
                    )
                    .map_err(JournalError::ControllerNative)?;
                token.complete_after_upper_disposal_v1();
                Ok(())
            })());
            if !matches!(owner.disposal, Some(Ok(()))) {
                owner.first = Some(First::Disposal);
            }
        }
        if owner.first.is_some() {
            (owner, Some(turn))
        } else {
            owner.completed = true;
            drop(turn);
            (owner, None)
        }
    }
}

struct CompletionLoan<'call, 'fence, 'source, 'original, 'authorization, 'root, 'profile> {
    root: &'call RootDeleteClientOriginalV1<'root>,
    fence: &'call mut SourceDeletePendingFenceV1<'fence, 'source, 'original, 'authorization>,
    accepted: &'call ControllerDeleteAdmissionOriginalV3,
    transaction: &'call JournalTransaction,
    turn: &'call mut Turn<'profile>,
    clock: Option<&'call mut Clock>,
    launch: &'call ControllerBankLaunchOriginalV1,
    profile: &'call ControllerSelfProfileOriginalV1,
}

impl sealed::Sealed for CompletionLoan<'_, '_, '_, '_, '_, '_, '_> {}

impl DeleteAdmissionOriginalV3 for CompletionLoan<'_, '_, '_, '_, '_, '_, '_> {
    fn require_transition_v3(
        &mut self,
        journal: &Journal,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        if transaction != self.transaction {
            return Err(JournalError::ProtectedBoundary);
        }
        self.root
            .require_terminal_exchange_complete_v4(self.fence.completion_native_data_v4()?)?;
        self.accepted
            .completed_native_v3(journal, self.fence)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.fence
            .controller_accepted_cut_v3(journal, self.launch, self.profile, self.accepted)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.turn
            .require_prepaid_delete_plan_signing_frontier_v2()
            .map_err(JournalError::ControllerNative)
    }

    fn matches_identity_v3(
        &self,
        identity: &crate::policy_compiler::create_q04::Q04CutIdentityV1,
    ) -> bool {
        self.accepted
            .identity
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            == Some(identity)
            && self.fence.matches_cleared_create_identity_v3(identity)
    }

    fn final_crossing_v3(&mut self, journal: &Journal) -> Result<(), JournalError> {
        self.require_transition_v3(journal, self.transaction)?;
        self.clock
            .as_deref_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .observe_frontier_v3()
    }
}

fn prepare_models(
    journal: &Journal,
    fence: &SourceDeletePendingFenceV1<'_, '_, '_, '_>,
    plan: &crate::OperationPlan,
    frame: Frame,
    wall: i64,
) -> Result<JournalTransaction, Cause> {
    let batch = aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchViewV1::decode(
        fence.batch_bytes()?,
    )?;
    let aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleResourceV1::Sandbox(
        _sandbox,
    ) = batch.root()?
    else {
        return Err(JournalError::ProtectedBoundary.into());
    };
    if batch.operation() != plan.operation_id() {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let projection = aos_sandbox_protocol::domain_ledger::delete_root::controller_completion::
        prepare_delete_terminal_projection_data_v4(journal.native.state(), batch)?;
    let receipt = aos_sandbox_protocol::domain_ledger::effect_history::EffectReceipt::new(
        frame.encode_v4()?.to_vec(),
    )?;
    let rows = crate::reconciler::completed_delete_effect_operation_records_v4(
        journal, plan, receipt, wall,
    )?;
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.delete.controller-terminal.v4\0")
        .chain_update(batch.operation().as_bytes())
        .chain_update(frame.encode_v4()?)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    let transaction =
        JournalTransaction::new(id, vec![rows[0].clone(), rows[1].clone(), projection])?;
    // The exact canonical producer and replay consumer share this contract;
    // this check runs on the actual original map before any native write.
    aos_sandbox_protocol::domain_ledger::delete_root::controller_completion::
        require_delete_terminal_controller_transition_data_v4(
            journal.native.state(), &transaction, batch, journal.snapshot_sequence(),
        )?;
    Ok(transaction)
}
