//! Retains the paid metadata-finality reads, comparisons and independent posts.
//!
//! The new Recover purpose owns these originals throughout the exchange. Its
//! historical Apply evidence can only select the exact metadata transaction;
//! it cannot produce a plan, broker request, lease or restored old receiver.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    operation::{decode_operation, effect_key, OPERATION_RECORD_V2_BYTES},
    provisioning_root::finality_recover::{
        finality_controller_transaction_commitment_v1,
        public_operation::metadata_complete_terminal_transaction_v1,
        CreateFinalityObservationAdmissionDataV1 as Admission,
        FinalityRecoverAcknowledgementDataV1 as Acknowledgement,
        FinalityRecoverQueryDataV1 as Query,
        FINALITY_RECOVER_ACKNOWLEDGEMENT_BYTES_V1 as ACK_BYTES,
        FINALITY_RECOVER_QUERY_BYTES_V1 as QUERY_BYTES,
    },
    transaction::JournalTransaction,
};
use aos_sandbox_protocol::public_api::projection::{PublicProjectionKindV1, PROJECTION_KEY_PREFIX};

use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{
    create_stopped_metadata_model_receiving_demand_v1, CreateStoppedMetadataTransitionOriginalV1,
    Journal, JournalError, JournalRecord, RecordNamespace,
};
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{
    bounded_stream_io::{DeadlineStreamDirectionV1 as Direction, FixedDeadlineStreamIoV1},
    continuation_policy::{RootContinuationPolicyErrorV1, RootFinalityRecoverPairOriginalV1},
    provisioning_current::create_finality::{
        recovery_models::CreateFinalityRecoveryModelsOriginalV1 as Models,
        session::CreateFinalitySessionOriginalV1 as Session,
        storage_trust::CreateFinalityStorageTrustOriginalV1 as Trust,
    },
    provisioning_current::finality_readonly::{
        RootCreateFinalityReadStageV1, RootCreateFinalityReadonlyOriginalV1 as Readonly,
    },
    provisioning_current::{RootContinuationClockGateV1 as Clock, RootContinuationHorizonDataV1},
    root_policy_prelude::RootPolicyPreludeOriginalV1,
};

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum Phase {
    Query,
    Trust,
    Pair,
    Readonly,
    Session,
    Models,
    Response,
    Send,
}

#[derive(Clone, Copy)]
enum First {
    Phase(Phase),
    Clock,
    Financial,
    OpeningPost,
    Body,
}

#[derive(Clone, Copy)]
enum PostFirst {
    Readonly,
    Trust,
    Pair,
    Peer,
    Clock,
    Relation,
}

pub(super) struct RootFinalityRecoverNativeOriginalV1 {
    phase: Phase,
    first: Option<First>,
    post_first: Option<PostFirst>,
    bytes: [u8; QUERY_BYTES],
    remainder: [u8; QUERY_BYTES - 32],
    remainder_io: FixedDeadlineStreamIoV1<{ QUERY_BYTES - 32 }>,
    eof: [u8; 1],
    eof_io: FixedDeadlineStreamIoV1<1>,
    query: Option<Result<Query, aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::FinalityRecoverDataErrorV1>>,
    clock: Option<Box<Clock>>,
    after_clock: Option<Box<Clock>>,
    after_sample: Option<Result<RawPairedClockSample, JournalError>>,
    trust_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    trust: Trust,
    pair: RootFinalityRecoverPairOriginalV1,
    pair_before: Option<Result<(), RootContinuationPolicyErrorV1>>,
    pair_after: Option<Result<(), RootContinuationPolicyErrorV1>>,
    readonly: Readonly,
    session: Session,
    models_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    models: Models,
    response_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    terminal: CreateStoppedMetadataTransitionOriginalV1,
    joint: Option<Result<JournalTransaction, Cause>>,
    acknowledgement: Option<Result<Acknowledgement, Cause>>,
    response: [u8; ACK_BYTES],
    sent: FixedDeadlineStreamIoV1<ACK_BYTES>,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_disposal: Option<Result<(), NormalRootStartupErrorV1>>,
    body: Option<Result<(), Cause>>,
    posts: Option<Result<(), Cause>>,
    send: Option<Result<(), Cause>>,
}

impl RootFinalityRecoverNativeOriginalV1 {
    pub(super) fn fixed_demand_v1(
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<ResourceVector, Cause> {
        let carrier = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let clock = Clock::controller_authorization_receiving_demand_v1()?;
        // The shared listener already pays the fixed112 request envelope. This
        // purpose adds the remainder of its266-byte query and the one hostile
        // trailing byte that the strict EOF destination can consume on refusal.
        Ok(flight
            .finality_recover_pair_receiving_demand_v1()?
            .checked_add(clock)?
            .checked_add(clock)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier).with(
                D::NetworkBytes,
                u64::try_from(QUERY_BYTES - 112 + 1).map_err(|_| JournalError::JournalTooLarge)?,
            ))?)
    }

    pub(super) fn new() -> Self {
        Self {
            phase: Phase::Query,
            first: None,
            post_first: None,
            bytes: [0; QUERY_BYTES],
            remainder: [0; QUERY_BYTES - 32],
            remainder_io: Default::default(),
            eof: [0; 1],
            eof_io: Default::default(),
            query: None,
            clock: None,
            after_clock: None,
            after_sample: None,
            trust_funding: None,
            trust: Trust::new(),
            pair: Default::default(),
            pair_before: None,
            pair_after: None,
            readonly: Readonly::new(),
            session: Session::new(),
            models_funding: None,
            models: Models::new(),
            response_funding: None,
            terminal: CreateStoppedMetadataTransitionOriginalV1::new(),
            joint: None,
            acknowledgement: None,
            response: [0; ACK_BYTES],
            sent: Default::default(),
            peer_after: None,
            peer_disposal: None,
            body: None,
            posts: None,
            send: None,
        }
    }

    pub(super) fn run_once_v1(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), JournalError> {
        self.body = Some(self.observe_inner_v1(root));
        self.latch_before_posts_v1(root.flight, root.native.failure_after_v1().is_some());
        self.finish_posts_once_v1(root.flight);
        if !matches!(self.body, Some(Ok(()))) || !matches!(self.posts, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.send = Some(self.prepare_and_send_v1(root));
        self.latch_before_posts_v1(root.flight, false);
        // A reached write always owes its actual wall/paired observation, even
        // when the IO result refused. The prior send cause was selected above.
        if self.sent.failure().is_some() || self.sent.completed_exact() {
            if let Some(clock) = self.clock.as_mut() {
                let _owed = clock.check_next_once_v1();
            }
        }
        if matches!(self.send, Some(Ok(()))) && self.failure(root.flight).is_none() {
            self.peer_disposal = Some(
                root.flight
                    .settle_finality_recover_controller_peer_positive_once_v1(),
            );
        }
        self.require_complete_v1(root.flight)
    }

    fn observe_inner_v1(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        let opening_cutoff = root.native.cutoff_v1()?;
        self.bytes[..32].copy_from_slice(root.native.prefix_bytes_v1());
        self.remainder_io.run_once(
            &mut root.original,
            &mut self.remainder,
            opening_cutoff,
            Direction::Read,
        )?;
        self.bytes[32..].copy_from_slice(&self.remainder);
        root.native.finish_opening_if_owed_v1()?;
        self.query = Some(Query::decode_v1(&self.bytes));
        let query = self.query_v1()?;
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(query.original, query.cutoff)?
                .with_wall_expiry_data_v1(query.wall_expiry);
        self.clock = Some(Box::new(Clock::new_controller_authorization_v1(horizon)));
        // The independent final destination is paid before either clock grows.
        // It remains available if any primary frontier poisons the first gate.
        self.after_clock = Some(Box::new(Clock::new_controller_authorization_v1(horizon)));
        self.clock_v1()?.check_next_once_v1()?;
        self.eof_io.run_once(
            &mut root.original,
            &mut self.eof,
            query.cutoff.min(opening_cutoff),
            Direction::Eof,
        )?;

        self.phase = Phase::Trust;
        {
            let mut stage = root.flight.finality_recover_stage_receiving_v1()?;
            self.trust_funding = Some(stage.admit_finality_recover_trust_fixed_once_v1(
                RootContinuationDemandV1::from_demand_v1(Trust::fixed_demand_v1()?),
            ));
            if !matches!(self.trust_funding, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            self.trust.observe_once_v1(
                &mut stage,
                self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            )?;
        }
        self.phase = Phase::Pair;
        self.clock_v1()?.check_next_once_v1()?;
        self.pair_before = Some(
            root.flight
                .begin_finality_recover_pair_once_v1(&mut self.pair),
        );
        if !matches!(self.pair_before, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }

        self.phase = Phase::Readonly;
        let (node, partition) = {
            let mut stage = root.flight.finality_recover_stage_receiving_v1()?;
            let identity = (
                stage.enrolled_node_v1()?,
                stage.controller_baseline_partition_v1()?,
            );
            self.readonly.observe_once_v1(
                &mut RootCreateFinalityReadStageV1::Recover(&mut stage),
                self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            )?;
            identity
        };
        self.phase = Phase::Session;
        self.clock_v1()?.check_next_once_v1()?;
        self.session.observe_once_v1(
            self.readonly.session_v1()?,
            self.trust.manifest_v1()?,
            query,
            node,
            query.original.host_boot_id(),
        )?;

        self.phase = Phase::Models;
        let demand = {
            let (controller, source) = self.readonly.journals_v1()?;
            Models::receiving_demand_v1(controller, source, query)?
        };
        self.clock_v1()?.check_next_once_v1()?;
        self.models_funding = Some(
            root.flight
                .finality_recover_stage_receiving_v1()?
                .admit_finality_recover_models_once_v1(RootContinuationDemandV1::from_demand_v1(
                    demand,
                )),
        );
        if !matches!(self.models_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (controller, source) = self.readonly.journals_v1()?;
        self.models.observe_once_v1(
            controller,
            source,
            &self.session,
            query,
            node,
            partition,
            root.flight,
        )?;

        self.phase = Phase::Response;
        let demand = response_receiving_demand_v1(self.readonly.controller_v1()?, query)?;
        self.clock_v1()?.check_next_once_v1()?;
        self.response_funding = Some(
            root.flight
                .finality_recover_stage_receiving_v1()?
                .admit_finality_recover_response_once_v1(RootContinuationDemandV1::from_demand_v1(
                    demand,
                )),
        );
        if !matches!(self.response_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn finish_posts_once_v1(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts.is_some() {
            return;
        }
        self.readonly.finish_posts_once_v1();
        if self.readonly.failure().is_some() {
            self.post_first.get_or_insert(PostFirst::Readonly);
        }
        self.trust.finish_posts_once_v1();
        if self.trust.failure().is_some() {
            self.post_first.get_or_insert(PostFirst::Trust);
        }
        if self.pair_before.is_some() {
            self.pair_after = Some(flight.finish_finality_recover_pair_once_v1(&mut self.pair));
            if self.pair.failure().is_some() {
                self.post_first.get_or_insert(PostFirst::Pair);
            }
        }
        self.peer_after = Some(flight.finish_finality_recover_controller_peer_posts_once_v1());
        if matches!(self.peer_after, Some(Err(_))) {
            self.post_first.get_or_insert(PostFirst::Peer);
        }
        if let Some(clock) = self.after_clock.as_mut() {
            self.after_sample = Some(clock.check_next_once_v1());
            if matches!(self.after_sample, Some(Err(_))) {
                self.post_first.get_or_insert(PostFirst::Clock);
            }
        }
        self.posts = Some((|| {
            self.readonly.require_complete_v1()?;
            self.trust.require_complete_v1()?;
            self.pair.require_complete_v1()?;
            if !matches!(self.peer_after, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let sample = self
                .after_sample
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.clock
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .require_final_sample_v1(sample)?;
            Ok(())
        })());
        if matches!(self.posts, Some(Err(_))) {
            self.post_first.get_or_insert(PostFirst::Relation);
        }
    }

    fn prepare_and_send_v1(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        let query = self.query_v1()?;
        let sample = self
            .after_sample
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let controller = self.readonly.completed_controller_v1()?;
        let raw = controller
            .get(RecordNamespace::OperatorRecovery, &query.admission_key)
            .ok_or(JournalError::ProtectedBoundary)?;
        let admission = Admission::decode_v1(raw)?;
        let fields = self.models.controller_v1()?.resources.fields_v1();
        self.terminal.prepare_once_v1(
            controller,
            aos_sandbox_core::OperationId::from_bytes(admission.target),
            fields.project,
            fields.sandbox,
            self.models.receipt_bytes_v1()?,
            sample,
        )?;
        let admitted = decode_operation(
            controller
                .get(RecordNamespace::Operation, &admission.operation)
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        self.joint = Some(
            metadata_complete_terminal_transaction_v1(
                self.terminal.transaction_v1()?,
                admission,
                fields.sandbox,
                admitted,
                sample,
            )
            .map_err(|cause| Box::new(cause) as Cause),
        );
        let transaction = self
            .joint
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let cutoff = query.cutoff.min(
            sample
                .conservative_expiry_deadline_data_v1(query.wall_expiry)
                .ok_or(JournalError::ProtectedBoundary)?,
        );
        self.acknowledgement = Some(Ok(Acknowledgement {
            nonce: query.nonce,
            admission: query.admission,
            target: admission.target,
            source_terminal: self.models.source_terminal_commitment_v1()?,
            inventory: query.inventory,
            controller_transaction: finality_controller_transaction_commitment_v1(transaction)?,
            sample,
            cutoff,
            wall_expiry: query.wall_expiry,
        }));
        let acknowledgement = *self
            .acknowledgement
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.response = acknowledgement.encode_v1()?;
        self.phase = Phase::Send;
        self.clock_v1()?.check_next_once_v1()?;
        self.sent.run_once(
            &mut root.original,
            &mut self.response,
            cutoff,
            Direction::Write,
        )?;
        Ok(())
    }

    fn query_v1(&self) -> Result<Query, JournalError> {
        self.query
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn clock_v1(&mut self) -> Result<&mut Clock, JournalError> {
        self.clock
            .as_deref_mut()
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn phase_failure_v1(&self, phase: Phase) -> Option<&(dyn Error + 'static)> {
        match phase {
            Phase::Query => self
                .remainder_io
                .failure()
                .or_else(|| self.eof_io.failure())
                .or_else(|| cause(&self.query)),
            Phase::Trust => cause(&self.trust_funding).or_else(|| self.trust.failure()),
            Phase::Pair => self.pair.failure().or_else(|| cause(&self.pair_before)),
            Phase::Readonly => self.readonly.failure(),
            Phase::Session => self.session.failure(),
            Phase::Models => cause(&self.models_funding).or_else(|| self.models.failure()),
            Phase::Response => cause(&self.response_funding)
                .or_else(|| self.terminal.failure())
                .or_else(|| cause_box(&self.joint))
                .or_else(|| cause_box(&self.acknowledgement)),
            Phase::Send => self.sent.failure(),
        }
    }

    fn funding_failed_v1(&self) -> bool {
        matches!(self.trust_funding, Some(Err(_)))
            || self.trust.typed_funding_failed_v1()
            || self.readonly.selected_funding_failed_v1()
            || matches!(self.models_funding, Some(Err(_)))
            || matches!(self.response_funding, Some(Err(_)))
    }

    fn latch_before_posts_v1(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        opening_after: bool,
    ) {
        self.latch_body_source_v1(
            self.funding_failed_v1() && flight.failure().is_some(),
            opening_after,
        );
    }

    fn latch_body_source_v1(&mut self, original_funding_cause: bool, opening_after: bool) {
        if self.first.is_some()
            || (!matches!(self.body, Some(Err(_))) && !matches!(self.send, Some(Err(_))))
        {
            return;
        }
        self.first = Some(if opening_after && matches!(self.phase, Phase::Query) {
            First::OpeningPost
        } else if original_funding_cause {
            First::Financial
        } else if self.phase_failure_v1(self.phase).is_some() {
            First::Phase(self.phase)
        } else if self
            .clock
            .as_ref()
            .and_then(|clock| clock.failure())
            .is_some()
        {
            First::Clock
        } else {
            First::Body
        });
    }

    pub(super) fn require_complete_v1(
        &self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), JournalError> {
        if self.failure(flight).is_none()
            && matches!(self.body, Some(Ok(())))
            && matches!(self.posts, Some(Ok(())))
            && matches!(self.send, Some(Ok(())))
            && matches!(self.peer_disposal, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn peer_post_entered_v1(&self) -> bool {
        self.peer_after.is_some()
    }

    pub(super) fn selects_opening_post_v1(&self) -> bool {
        matches!(self.first, Some(First::OpeningPost))
    }

    pub(super) fn selects_peer_failure_v1(&self) -> bool {
        self.first.is_none()
            && (matches!(self.post_first, Some(PostFirst::Peer))
                || (self.post_first.is_none() && matches!(self.peer_disposal, Some(Err(_)))))
    }

    pub(super) fn require_disposed_complete_v1(&self) -> Result<(), JournalError> {
        if self.first.is_none()
            && self.owned_failure_v1().is_none()
            && matches!(self.body, Some(Ok(())))
            && matches!(self.posts, Some(Ok(())))
            && matches!(self.send, Some(Ok(())))
            && matches!(self.peer_disposal, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn failure<'cause>(
        &'cause self,
        flight: &'cause RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.first, Some(First::Financial)) {
            return flight.failure().or_else(|| self.owned_failure_v1());
        }
        if self.selects_peer_failure_v1() {
            return flight.failure().or_else(|| self.owned_failure_v1());
        }
        self.owned_failure_v1()
    }

    pub(super) fn owned_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        let first = match self.first {
            Some(First::Financial) => None,
            Some(First::OpeningPost) => None,
            Some(First::Phase(phase)) => self.phase_failure_v1(phase),
            Some(First::Clock) => self.clock.as_ref().and_then(|clock| clock.failure()),
            Some(First::Body) => cause_box(&self.body).or_else(|| cause_box(&self.send)),
            None => None,
        };
        let post = match self.post_first {
            Some(PostFirst::Readonly) => self.readonly.failure(),
            Some(PostFirst::Trust) => self.trust.failure(),
            Some(PostFirst::Pair) => self.pair.failure(),
            Some(PostFirst::Peer) => cause(&self.peer_after),
            Some(PostFirst::Clock) => self
                .after_clock
                .as_ref()
                .and_then(|clock| clock.failure())
                .or_else(|| cause(&self.after_sample)),
            Some(PostFirst::Relation) => cause_box(&self.posts),
            None => None,
        };
        first
            .or_else(|| cause_box(&self.body))
            .or_else(|| cause_box(&self.send))
            .or(post)
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.readonly.failure())
            .or_else(|| self.trust.failure())
            .or_else(|| self.pair.failure())
            .or_else(|| cause(&self.peer_after))
            .or_else(|| self.after_clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| cause(&self.after_sample))
            .or_else(|| cause_box(&self.posts))
            .or_else(|| cause(&self.peer_disposal))
    }
}

fn response_receiving_demand_v1(
    controller: &Journal,
    query: Query,
) -> Result<ResourceVector, Cause> {
    let admission = Admission::decode_v1(
        controller
            .get(RecordNamespace::OperatorRecovery, &query.admission_key)
            .ok_or(JournalError::ProtectedBoundary)?,
    )?;
    let target = aos_sandbox_core::OperationId::from_bytes(admission.target);
    let effect = controller
        .get(RecordNamespace::Effect, &effect_key(target, 0))
        .ok_or(JournalError::ProtectedBoundary)?
        .len();
    let operation = controller
        .get(RecordNamespace::Operation, target.as_bytes())
        .ok_or(JournalError::ProtectedBoundary)?
        .len();
    let projection = controller
        .records(RecordNamespace::DesiredState)
        .filter(|(key, _)| {
            key.starts_with(PROJECTION_KEY_PREFIX)
                && key.get(PROJECTION_KEY_PREFIX.len())
                    == Some(&(PublicProjectionKindV1::Sandbox as u8))
        })
        .map(|(_, value)| value.len())
        .max()
        .ok_or(JournalError::ProtectedBoundary)?;
    // The canonical joint constructor clones exactly the old three members and
    // retains one new fixed-width Operation. Its Vec and Result carriers are
    // separate from the same original three-row model owner's demand.
    let clone_bytes = effect
        .checked_add(operation)
        .and_then(|bytes| bytes.checked_add(projection))
        .and_then(|bytes| bytes.checked_add(10 + 24 + 16 + PROJECTION_KEY_PREFIX.len() + 17))
        .and_then(|bytes| bytes.checked_add(OPERATION_RECORD_V2_BYTES + 16))
        .and_then(|bytes| {
            bytes.checked_add(4 * size_of::<JournalRecord>() + size_of::<JournalTransaction>())
        })
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(JournalError::JournalTooLarge)?;
    Ok(
        create_stopped_metadata_model_receiving_demand_v1(controller, target)?.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, clone_bytes)
                .with(D::NetworkBytes, ACK_BYTES as u64)
                .with(D::OutputBytes, ACK_BYTES as u64),
        )?,
    )
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn cause_box<T>(value: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| &**cause)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;

    #[test]
    fn real_wall_expiry_cause_stays_selected_before_later_owed_post_errors() {
        let original = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
            [9; 16],
            100,
            10_000_000_000,
        )
        .unwrap();
        let expired = RawPairedClockSample::new_untrusted(
            original.provenance(),
            [9; 16],
            102,
            12_000_000_000,
        )
        .unwrap();
        let horizon =
            RootContinuationHorizonDataV1::from_original_data_v1(original, 20_000_000_000)
                .unwrap()
                .with_wall_expiry_data_v1(102);
        let mut native = RootFinalityRecoverNativeOriginalV1::new();
        native.phase = Phase::Response;
        native.body = Some(Err(Box::new(
            horizon.require_sample_v1(expired).unwrap_err(),
        )));
        native.latch_body_source_v1(false, false);
        let first = native.owned_failure_v1().unwrap() as *const (dyn Error + 'static);

        native.peer_after = Some(Err(NormalRootStartupErrorV1::Service));
        native.after_sample = Some(Err(JournalError::Io(std::io::Error::other(
            "later owed clock",
        ))));
        native.posts = Some(Err(Box::new(JournalError::JournalTooLarge)));
        native.post_first = Some(PostFirst::Peer);

        assert!(std::ptr::eq(first, native.owned_failure_v1().unwrap()));
        assert!(!native.selects_peer_failure_v1());
        assert!(native.require_disposed_complete_v1().is_err());
    }
}
