//! Compares pre-Planned local Transfer absence on a genuine fresh Root flight.
//!
//! This purpose reads the actual fixed C/Source predecessors and the same
//! namespace/active Ownership engines as pending Delete. No pending native64,
//! candidate batch, floor, remote service, or decoded proof is manufactured.

use aos_sandbox_policy::native::{RootFinalityReadOriginalV1 as Target, RootFinalityReadKindV1 as Kind};
use crate::journal::historical_observation::root_readonly_error_v1 as project_read;
mod challenge;
pub(crate) use challenge::RootDeletePlanningChallengeOriginalV1;
mod shape;

use super::RootDeleteErrorV1;
use super::transfer_namespace::{
    OwnershipProfileClosedV1, RootOwnershipProfileOriginalV1, TransferNamespaceNativeOriginalV1,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;

use crate::policy_compiler::root_policy_prelude::{
    RootPolicyDispositionGuardV1, RootPolicyPreludeNativeOriginalV1, RootPolicyPreludeOriginalV1,
    RootPolicyPurposeV1,
};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::{
    delete_root::planning::{
        DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2,
        DELETE_ROOT_PLANNING_OPEN_BYTES_V3, DeleteRootPlanningDataErrorV3,
        DeleteRootPlanningNativeDataV2, DeleteRootPlanningObservationDataV2, DeleteRootPlanningOpenDataV3,
    },
    resource_bank::{ResourceBankDataError},
};
use std::error::Error;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy)]
pub(crate) enum RootDeletePlanningAdmissionPhaseV1 {
    ControllerNative,
    ControllerSemantic,
    SourceNative,
    SourceSemantic,
    BootstrapTrust,
}

impl RootDeletePlanningAdmissionPhaseV1 {
    fn index(self) -> usize {
        match self {
            Self::ControllerNative => 0,
            Self::ControllerSemantic => 1,
            Self::SourceNative => 2,
            Self::SourceSemantic => 3,
            Self::BootstrapTrust => 4,
        }
    }
}

#[derive(Clone, Copy)]
enum First {
    Enrollment,
    Serving,
    Peer,
    OpeningPermit,
    Remainder,
    Open,
    OpeningClock,
    Challenge,
    SendChallenge,
    Arm,
    Before,
    Permit(usize),
    Controller,
    Source,
    Compare,
    OwnershipBefore,
    NamespaceBefore,
    BootstrapTrust,
    BootstrapPost,
    NamespaceAfter,
    OwnershipAfter,
    ControllerPost,
    SourcePost,
    After,
    PeerAfter,
    ClockAfter,
    Observation,
    SendObservation,
    Eof,
    Settlement,
    Reentry,
}

#[derive(Debug, thiserror::Error)]
enum ObservationError {
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Ownership(#[from] OwnershipProfileClosedV1),
    #[error(transparent)]
    Wire(#[from] DeleteRootPlanningDataErrorV3),
    #[error(transparent)]
    Original(#[from] NormalRootStartupErrorV1),
}

#[derive(Debug, thiserror::Error)]
enum ComparisonError {
    #[error(transparent)]
    Native(#[from] JournalError),
    #[error(transparent)]
    Bank(#[from] ResourceBankDataError),
    #[error("the actual planning C17/Source predecessor differs")]
    Changed,
}

/// Retains the entire genuine authorized planning comparison flight.
///
/// The sole constructor consumes a successfully classified whole Prelude.
/// Native failures retain the first field's fail-closed disposition guard.
/// A comparison result cannot lift the surrounding lifecycle or pending gate.
pub(crate) struct RootDeletePlanningDispatchOriginalV1 {
    disposition: RootPolicyDispositionGuardV1,
    original: UnixStream,
    prelude: RootPolicyPreludeNativeOriginalV1,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    opening_permit: Option<Result<(), ResourceReservationErrorV1>>,
    serving: Option<Result<(), NormalRootStartupErrorV1>>,
    remainder_io: FixedDeadlineStreamIoV1<{ DELETE_ROOT_PLANNING_OPEN_BYTES_V3 - 32 }>,
    remainder_bytes: [u8; DELETE_ROOT_PLANNING_OPEN_BYTES_V3 - 32],
    remainder: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    bytes: [u8; DELETE_ROOT_PLANNING_OPEN_BYTES_V3],
    decoded: Option<Result<DeleteRootPlanningOpenDataV3, DeleteRootPlanningDataErrorV3>>,
    opening_clock:
        Option<Result<(), crate::policy_compiler::root_policy_prelude::RootPolicyPreludeErrorV1>>,
    challenge: RootDeletePlanningChallengeOriginalV1,
    prepared: Option<Result<(), NormalRootStartupErrorV1>>,
    challenge_bytes: [u8; DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3],
    challenge_encoding: Option<Result<(), DeleteRootPlanningDataErrorV3>>,
    challenge_io: FixedDeadlineStreamIoV1<DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3>,
    challenge_sent: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    posts: RootDeleteChunkPostsV1,
    armed: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    controller: Target,
    source: Target,
    capture: [Option<Result<(), JournalError>>; 2],
    native: [Option<Result<ResourceVector, JournalError>>; 2],
    semantic: [Option<Result<ResourceVector, JournalError>>; 2],
    phase: Option<RootDeletePlanningAdmissionPhaseV1>,
    permits: [Option<Result<(), ResourceReservationErrorV1>>; 5],
    compared: Option<Result<(), ComparisonError>>,
    enrollment: Option<Result<(), ResourceReservationErrorV1>>,
    namespace: TransferNamespaceNativeOriginalV1,
    namespace_before: Option<Result<(), JournalError>>,
    namespace_after: Option<Result<(), JournalError>>,
    bootstrap_demand: Option<Result<ResourceVector, JournalError>>,
    bootstrap_read: Option<Result<(), JournalError>>,
    bootstrap_post: Option<Result<(), JournalError>>,
    ownership: Option<RootOwnershipProfileOriginalV1>,
    ownership_before: Option<Result<(), OwnershipProfileClosedV1>>,
    ownership_after: Option<Result<(), OwnershipProfileClosedV1>>,
    whole_peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_after: Option<Result<(), NormalRootStartupErrorV1>>,
    observation: Option<Result<DeleteRootPlanningObservationDataV2, ObservationError>>,
    response: [u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
    response_encoding: Option<Result<(), DeleteRootPlanningDataErrorV3>>,
    eof_io: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    eof: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
    response_io: FixedDeadlineStreamIoV1<DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2>,
    response_sent: Option<
        Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1>,
    >,
    entered: bool,
    comparing: bool,
    complete: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeletePlanningDispatchOriginalV1 {
    fn new(
        disposition: RootPolicyDispositionGuardV1,
        original: UnixStream,
        native: RootPolicyPreludeNativeOriginalV1,
    ) -> Self {
        Self {
            disposition,
            original,
            prelude: native,
            peer: None,
            opening_permit: None,
            serving: None,
            remainder_io: Default::default(),
            remainder_bytes: [0; DELETE_ROOT_PLANNING_OPEN_BYTES_V3 - 32],
            remainder: None,
            bytes: [0; DELETE_ROOT_PLANNING_OPEN_BYTES_V3],
            decoded: None,
            opening_clock: None,
            challenge: Default::default(),
            prepared: None,
            challenge_bytes: [0; DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3],
            challenge_encoding: None,
            challenge_io: Default::default(),
            challenge_sent: None,
            posts: Default::default(),
            armed: None,
            before: None,
            after: None,
            controller: Target::new(Kind::Controller),
            source: Target::new(Kind::Source),
            capture: [None, None],
            native: [None, None],
            semantic: [None, None],
            phase: None,
            permits: [None, None, None, None, None],
            compared: None,
            enrollment: None,
            namespace: Default::default(),
            namespace_before: None,
            namespace_after: None,
            bootstrap_demand: None,
            bootstrap_read: None,
            bootstrap_post: None,
            ownership: None,
            ownership_before: None,
            ownership_after: None,
            whole_peer_after: None,
            clock_after: None,
            observation: None,
            response: [0; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
            response_encoding: None,
            response_io: Default::default(),
            response_sent: None,
            eof_io: Default::default(),
            eof_byte: [0],
            eof: None,
            settlement: None,
            entered: false,
            comparing: false,
            complete: false,
            first: None,
            closed: None,
        }
    }

    fn receive_opening_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            return self.refuse_reentry();
        }
        self.entered = true;
        let primary = self.receive_inner(flight);
        self.opening_clock = Some(self.prelude.finish_opening_once_v1());
        if !matches!(self.opening_clock, Some(Ok(()))) {
            self.first.get_or_insert(First::OpeningClock);
        }
        if primary.is_err() || self.first.is_some() {
            self.finish_owed(flight);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn receive_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootDeleteErrorV1> {
        let cutoff = self
            .prelude
            .cutoff_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.bytes[..32].copy_from_slice(self.prelude.prefix_bytes_v1());
        self.peer = Some(flight.admit_delete_controller_peer_once_v1());
        self.require(matches!(self.peer, Some(Ok(()))), First::Peer)?;
        self.serving = Some(flight.require_delete_planning_serving_pair_v1());
        self.require(matches!(self.serving, Some(Ok(()))), First::Serving)?;
        self.opening_permit = Some(flight.admit_delete_planning_opening_once_v1(self));
        self.require(
            matches!(self.opening_permit, Some(Ok(()))),
            First::OpeningPermit,
        )?;
        self.remainder = Some(self.remainder_io.run_once(
            &mut self.original,
            &mut self.remainder_bytes,
            cutoff,
            DeadlineStreamDirectionV1::Read,
        ));
        self.require(matches!(self.remainder, Some(Ok(()))), First::Remainder)?;
        self.bytes[32..].copy_from_slice(&self.remainder_bytes);
        self.decoded = Some(DeleteRootPlanningOpenDataV3::decode_v3(&self.bytes));
        self.require(matches!(self.decoded, Some(Ok(_))), First::Open)?;
        let open = self.open_v3()?;
        self.prepared = Some(self.challenge.prepare_once_v1(flight, open));
        self.require(matches!(self.prepared, Some(Ok(()))), First::Challenge)?;
        self.challenge_encoding = Some(self.challenge.data_v1().map_err(|_| DeleteRootPlanningDataErrorV3::Wire(
            aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association))
            .and_then(|data| data.encode_v3()).map(|bytes| self.challenge_bytes = bytes));
        self.require(
            matches!(self.challenge_encoding, Some(Ok(()))),
            First::Challenge,
        )?;
        let deadline = self
            .challenge
            .current_cutoff_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?
            .min(cutoff);
        self.challenge_sent = Some(self.challenge_io.run_once(
            &mut self.original,
            &mut self.challenge_bytes,
            deadline,
            DeadlineStreamDirectionV1::Write,
        ));
        self.require(
            matches!(self.challenge_sent, Some(Ok(()))),
            First::SendChallenge,
        )
    }

    fn compare_originals_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if !self.entered
            || self.comparing
            || self.first.is_some()
            || !matches!(self.challenge_sent, Some(Ok(())))
        {
            return self.refuse_reentry();
        }
        self.comparing = true;
        let primary = self.compare_inner(flight);
        self.finish_owed(flight);
        if primary.is_err() || self.first.is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.observation = Some((|| {
            let open = self
                .open_v3()
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let challenge = self.challenge.data_v1()?;
            let namespace = self.namespace.planning_data_v1()?;
            let ownership = self
                .ownership
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .planning_data_v1()?;
            let data = DeleteRootPlanningNativeDataV2 {
                open: open.digest_v3()?,
                challenge: challenge.digest_v3()?,
                clock: self.challenge.final_clock_v1()?,
                namespace,
                ownership,
            };
            let data = DeleteRootPlanningObservationDataV2 {
                native: data,
                trust: self.namespace.bootstrap_trust_data_v2()?,
            };
            data.require_exchange_v2(open, challenge)?;
            Ok(data)
        })());
        self.require(matches!(self.observation, Some(Ok(_))), First::Observation)?;
        self.complete = true;
        Ok(())
    }

    fn compare_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.armed =
            Some(flight.arm_delete_planning_chunk_posts_once_v1(&self.challenge, &mut self.posts));
        self.require(matches!(self.armed, Some(Ok(()))), First::Arm)?;
        self.enrollment = Some(flight.require_delete_planning_funding_original_v3(self));
        self.require(matches!(self.enrollment, Some(Ok(()))), First::Enrollment)?;
        self.before = Some(
            self.posts
                .observe_planning_before_once_v1(flight, &self.challenge),
        );
        self.require(matches!(self.before, Some(Ok(()))), First::Before)?;
        let ids = flight
            .delete_cut_startup_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities;
        self.read_controller(flight, ids[0])?;
        self.read_source(flight, ids[0])?;
        self.compared = Some((|| {
            let open = self.open_v3().map_err(|_| ComparisonError::Changed)?;
            let controller = self.controller.replay_native_v1().map_err(project_read)?;
            let source = self.source.replay_native_v1().map_err(project_read)?;
            if (controller.next, controller.end) != (open.controller_next, open.controller_end)
                || (source.next, source.end) != (open.source_next, open.source_end)
            {
                return Err(ComparisonError::Changed);
            }
            open.funding.require_bank_record_v1(controller.state)?;
            Ok(())
        })());
        self.require(matches!(self.compared, Some(Ok(()))), First::Compare)?;
        let cutoff = self
            .challenge
            .current_cutoff_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.ownership = Some(RootOwnershipProfileOriginalV1::new(
            [ids[0], ids[1]],
            cutoff,
        ));
        self.ownership_before = self
            .ownership
            .as_mut()
            .map(RootOwnershipProfileOriginalV1::begin_once_v1);
        self.require(
            matches!(self.ownership_before, Some(Ok(()))),
            First::OwnershipBefore,
        )?;
        self.namespace_before = Some(self.namespace.begin_once());
        self.require(
            matches!(self.namespace_before, Some(Ok(()))),
            First::NamespaceBefore,
        )?;
        self.bootstrap_demand = Some(self.namespace.bootstrap_trust_demand_v2());
        self.require(matches!(self.bootstrap_demand, Some(Ok(_))), First::BootstrapTrust)?;
        self.admit(flight, RootDeletePlanningAdmissionPhaseV1::BootstrapTrust)?;
        self.bootstrap_read = Some(self.namespace.read_bootstrap_trust_once_v2());
        self.require(matches!(self.bootstrap_read, Some(Ok(()))), First::BootstrapTrust)?;
        self.eof = Some(self.eof_io.run_once(
            &mut self.original,
            &mut self.eof_byte,
            cutoff,
            DeadlineStreamDirectionV1::Eof,
        ));
        self.require(matches!(self.eof, Some(Ok(()))), First::Eof)
    }

    fn read_controller(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        uid: u32,
    ) -> Result<(), RootDeleteErrorV1> {
        self.controller.construct_reader_once_v1().map_err(|_| RootDeleteErrorV1::Original)?;
        self.controller.capture_once(uid);
        self.capture[0] = Some(self.controller.require_captured_v1().map_err(project_read));
        self.require(matches!(self.capture[0], Some(Ok(()))), First::Controller)?;
        self.native[0] = Some(self.controller.replay_demand_v1().map_err(project_read));
        self.require(matches!(self.native[0], Some(Ok(_))), First::Controller)?;
        self.admit(flight, RootDeletePlanningAdmissionPhaseV1::ControllerNative)?;
        self.controller.audit_once();
        self.semantic[0] = Some(self.controller.additional_semantic_demand_v1().map_err(project_read));
        self.require(matches!(self.semantic[0], Some(Ok(_))), First::Controller)?;
        self.admit(
            flight,
            RootDeletePlanningAdmissionPhaseV1::ControllerSemantic,
        )?;
        self.controller.replay_once();
        self.require(self.controller.failure().is_none(), First::Controller)
    }

    fn read_source(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        uid: u32,
    ) -> Result<(), RootDeleteErrorV1> {
        self.source.construct_reader_once_v1().map_err(|_| RootDeleteErrorV1::Original)?;
        self.source.capture_once(uid);
        self.capture[1] = Some(self.source.require_captured_v1().map_err(project_read));
        self.require(matches!(self.capture[1], Some(Ok(()))), First::Source)?;
        self.native[1] = Some(self.source.replay_demand_v1().map_err(project_read));
        self.require(matches!(self.native[1], Some(Ok(_))), First::Source)?;
        self.admit(flight, RootDeletePlanningAdmissionPhaseV1::SourceNative)?;
        self.source.audit_once();
        self.semantic[1] = Some(self.source.additional_semantic_demand_v1().map_err(project_read));
        self.require(matches!(self.semantic[1], Some(Ok(_))), First::Source)?;
        self.admit(flight, RootDeletePlanningAdmissionPhaseV1::SourceSemantic)?;
        self.source.replay_once();
        self.require(self.source.failure().is_none(), First::Source)
    }

    fn admit(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        phase: RootDeletePlanningAdmissionPhaseV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.phase = Some(phase);
        self.permits[phase.index()] = Some(flight.admit_delete_planning_read_once_v1(self));
        self.require(
            matches!(self.permits[phase.index()], Some(Ok(()))),
            First::Permit(phase.index()),
        )
    }

    fn finish_owed(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.bootstrap_read.is_some() && self.bootstrap_post.is_none() {
            self.bootstrap_post = Some(self.namespace.finish_bootstrap_trust_if_owed_v2());
            if !matches!(self.bootstrap_post, Some(Ok(()))) {
                self.first.get_or_insert(First::BootstrapPost);
            }
        }
        if self.namespace_before.is_some() && self.namespace_after.is_none() {
            self.namespace_after = Some(self.namespace.finish_once());
            if !matches!(self.namespace_after, Some(Ok(()))) {
                self.first.get_or_insert(First::NamespaceAfter);
            }
        }
        if let Some(ownership) = self.ownership.as_mut() {
            if self.ownership_after.is_none() {
                self.ownership_after = Some(ownership.finish_if_owed_v1());
                if !matches!(self.ownership_after, Some(Ok(()))) {
                    self.first.get_or_insert(First::OwnershipAfter);
                }
            }
        }
        self.controller.finish_post_once();
        self.source.finish_post_once();
        if self.controller.post_failure().is_some() {
            self.first.get_or_insert(First::ControllerPost);
        }
        if self.source.post_failure().is_some() {
            self.first.get_or_insert(First::SourcePost);
        }
        if self.armed.is_some() && self.after.is_none() {
            self.after = Some(
                self.posts
                    .observe_planning_after_once_v1(flight, &self.challenge),
            );
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
        }
        if matches!(self.peer, Some(Ok(()))) && self.whole_peer_after.is_none() {
            self.whole_peer_after = Some(flight.finish_delete_controller_peer_posts_once_v1());
            if !matches!(self.whole_peer_after, Some(Ok(()))) {
                self.first.get_or_insert(First::PeerAfter);
            }
        }
        if self.clock_after.is_none() {
            self.clock_after = Some(self.challenge.finish_once_v1());
            if !matches!(self.clock_after, Some(Ok(()))) {
                self.first.get_or_insert(First::ClockAfter);
            }
        }
    }

    fn publish_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) -> Result<(), RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.response_sent.is_some() {
            return self.refuse_reentry();
        }
        self.response_encoding = Some(
            self.observation
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(RootDeleteErrorV1::Original)?
                .encode()
                .map(|bytes| self.response = bytes),
        );
        self.require(
            matches!(self.response_encoding, Some(Ok(()))),
            First::Observation,
        )?;
        let cutoff = self
            .challenge
            .current_cutoff_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.response_sent = Some(self.response_io.run_once(
            &mut self.original,
            &mut self.response,
            cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        self.require(
            matches!(self.response_sent, Some(Ok(()))),
            First::SendObservation,
        )?;
        self.settlement = Some(flight.settle_delete_controller_peer_positive_once_v1());
        self.require(matches!(self.settlement, Some(Ok(()))), First::Settlement)
    }

    pub(crate) fn require_same_complete_v1(
        &self,
        native: &aos_linux_descriptors::unix_stream::RetainedUnixStream,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if !self.complete
            || self.first.is_some()
            || self.failure().is_some()
            || !matches!(self.response_sent, Some(Ok(())))
            || !self.response_io.completed_exact()
            || !self.eof_io.completed_exact()
            || !matches!(self.settlement, Some(Ok(())))
            || !matches!(self.namespace_after, Some(Ok(())))
            || !matches!(self.bootstrap_post, Some(Ok(())))
            || self.namespace.bootstrap_trust_data_v2().is_err()
            || !matches!(self.ownership_after, Some(Ok(())))
            || self.controller.terminal_native_v1().map_err(project_read).is_err()
            || self.source.terminal_native_v1().map_err(project_read).is_err()
            || self.posts.require_positive_v1().is_err()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        native
            .require_same_endpoint_v1(self.original.as_fd())
            .map_err(|_| NormalRootStartupErrorV1::Service)
    }

    // Only the actual same-R financial terminal calls this after its token
    // preparation; all genuine upper native owners are physically destroyed.
    pub(crate) fn complete_upper_disposal_v1(mut self) {
        self.disposition.handed_off = true;
        drop(self);
    }

    fn open_v3(&self) -> Result<DeleteRootPlanningOpenDataV3, RootDeleteErrorV1> {
        self.decoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(RootDeleteErrorV1::Opening)
    }

    fn require(&mut self, positive: bool, first: First) -> Result<(), RootDeleteErrorV1> {
        if positive {
            return Ok(());
        }
        self.first.get_or_insert(first);
        Err(RootDeleteErrorV1::Opening)
    }

    fn refuse_reentry(&mut self) -> Result<(), RootDeleteErrorV1> {
        self.first.get_or_insert(First::Reentry);
        self.closed.get_or_insert(RootDeleteErrorV1::Original);
        Err(RootDeleteErrorV1::Original)
    }

    pub(crate) fn peer_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Peer | First::PeerAfter))
    }

    pub(crate) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::OpeningPermit | First::Permit(_)))
            || matches!(self.first, Some(First::Challenge))
                && self.challenge.funding_failure_is_selected_v1()
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::OwnershipBefore | First::OwnershipAfter => {
                self.ownership.as_ref()?.property_failure_view_v1()
            }
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(crate) fn format_failure_v1(
        &self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        if self.financial_failure_is_selected_v1() {
            if let Some(view) = flight.delete_exchange_financial_failure_view_v1() {
                return std::fmt::Display::fmt(&view, f);
            }
        }
        if self.peer_failure_is_selected_v1() {
            if let Some(view) = flight.delete_controller_property_failure_view_v1() {
                return std::fmt::Debug::fmt(&view, f);
            }
        }
        if let Some(view) = self.property_failure_view_v1() {
            return std::fmt::Debug::fmt(&view, f);
        }
        match self.failure() {
            Some(cause) => std::fmt::Display::fmt(cause, f),
            None => f.write_str("Delete planning failure is unavailable"),
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Enrollment => error(&self.enrollment),
            First::Serving => error(&self.serving),
            First::Peer => error(&self.peer),
            First::OpeningPermit => error(&self.opening_permit),
            First::Remainder => self
                .remainder_io
                .failure()
                .or_else(|| error(&self.remainder)),
            First::Open => error(&self.decoded),
            First::OpeningClock => self
                .prelude
                .failure_after_v1()
                .or_else(|| error(&self.opening_clock)),
            First::Challenge => self
                .challenge
                .failure()
                .or_else(|| error(&self.challenge_encoding))
                .or_else(|| error(&self.prepared)),
            First::SendChallenge => self
                .challenge_io
                .failure()
                .or_else(|| error(&self.challenge_sent)),
            First::Arm => self
                .posts
                .before_failure_v1()
                .or_else(|| error(&self.armed)),
            First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| error(&self.before)),
            First::Permit(4) => error(&self.bootstrap_demand).or_else(|| error(&self.permits[4])),
            First::Permit(index) => error(&self.native[index / 2])
                .or_else(|| error(&self.semantic[index / 2]))
                .or_else(|| error(&self.permits[index])),
            First::Controller => self
                .controller
                .failure()
                .or_else(|| error(&self.capture[0]))
                .or_else(|| error(&self.native[0]))
                .or_else(|| error(&self.semantic[0])),
            First::Source => self
                .source
                .failure()
                .or_else(|| error(&self.capture[1]))
                .or_else(|| error(&self.native[1]))
                .or_else(|| error(&self.semantic[1])),
            First::Compare => error(&self.compared),
            First::BootstrapTrust | First::BootstrapPost => self.namespace.bootstrap_trust_failure_v2()
                .or_else(|| error(&self.bootstrap_demand))
                .or_else(|| error(&self.bootstrap_read))
                .or_else(|| error(&self.bootstrap_post)),
            First::OwnershipBefore | First::OwnershipAfter => self
                .ownership
                .as_ref()
                .and_then(RootOwnershipProfileOriginalV1::failure)
                .or_else(|| error(&self.ownership_before))
                .or_else(|| error(&self.ownership_after)),
            First::NamespaceBefore => self
                .namespace
                .before_failure()
                .or_else(|| error(&self.namespace_before)),
            First::NamespaceAfter => self
                .namespace
                .after_failure()
                .or_else(|| error(&self.namespace_after)),
            First::ControllerPost => self.controller.post_failure(),
            First::SourcePost => self.source.post_failure(),
            First::After => self.posts.after_failure_v1().or_else(|| error(&self.after)),
            First::PeerAfter => error(&self.whole_peer_after),
            First::ClockAfter => self
                .challenge
                .failure()
                .or_else(|| error(&self.clock_after)),
            First::Observation => {
                error(&self.observation).or_else(|| error(&self.response_encoding))
            }
            First::SendObservation => self
                .response_io
                .failure()
                .or_else(|| error(&self.response_sent)),
            First::Eof => self.eof_io.failure().or_else(|| error(&self.eof)),
            First::Settlement => error(&self.settlement),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

/// Keeps the whole planning work beside its genuine exclusive Root flight.
#[must_use]
pub(crate) struct RootDeletePlanningReceivingV1<'flight, 'listener, 'startup> {
    work: Option<RootDeletePlanningDispatchOriginalV1>,
    flight: &'flight mut RootPolicyAcceptedFlightV1<'listener, 'startup>,
}

impl<'flight, 'listener, 'startup> RootDeletePlanningReceivingV1<'flight, 'listener, 'startup> {
    pub(in crate::policy_compiler) fn from_prelude_v1(
        prelude: RootPolicyPreludeOriginalV1<'flight, 'listener, 'startup>,
    ) -> Self {
        if prelude.purpose_v1() != Some(RootPolicyPurposeV1::DeletePlanning) {
            std::process::abort();
        }
        let RootPolicyPreludeOriginalV1 {
            disposition,
            original,
            flight,
            native,
            ..
        } = prelude;
        Self {
            work: Some(RootDeletePlanningDispatchOriginalV1::new(
                disposition,
                original,
                native,
            )),
            flight,
        }
    }

    pub(crate) fn receive_opening_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        self.work
            .as_mut()
            .ok_or(RootDeleteErrorV1::Original)?
            .receive_opening_once_v1(self.flight)
    }

    pub(crate) fn compare_originals_once_v1(&mut self) -> Result<(), RootDeleteErrorV1> {
        self.work
            .as_mut()
            .ok_or(RootDeleteErrorV1::Original)?
            .compare_originals_once_v1(self.flight)
    }

    pub(crate) fn finish_once_v1(mut self) -> Result<(), NormalRootStartupErrorV1> {
        let work = self
            .work
            .as_mut()
            .ok_or(NormalRootStartupErrorV1::Service)?;
        if work.publish_once_v1(self.flight).is_err() {
            work.finish_owed(self.flight);
        }
        let work = self.work.take().ok_or(NormalRootStartupErrorV1::Service)?;
        self.flight.finish_delete_planning_dispatch_once_v1(work)
    }

    pub(crate) fn failure_view_v1(&self) -> impl std::fmt::Display + '_ {
        PlanningFailureViewV1(self)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.work
            .as_ref()
            .and_then(RootDeletePlanningDispatchOriginalV1::failure)
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

struct PlanningFailureViewV1<'owner, 'flight, 'listener, 'startup>(
    &'owner RootDeletePlanningReceivingV1<'flight, 'listener, 'startup>,
);

impl std::fmt::Display for PlanningFailureViewV1<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.work.as_ref() {
            Some(work) => work.format_failure_v1(self.0.flight, f),
            None => f.write_str("Delete planning work was transferred to its owning flight"),
        }
    }
}
