//! Holds a fresh authorized-before-Planned Root opening on its genuine pair.
//!
//! The connection, peer samples and strict subject chunks use the existing
//! native engines. Only the actual authorized C17/Source scope constructs this
//! owner. A completed challenge stage supplies no Transfer observation, floor,
//! six-owner acceptance or lifecycle disposition.

use super::peer_receiving::sample::PeerSampleV1;
use super::peer_receiving::{CreateStorageRootPeerReceivingOriginalsV1, StableRootPeerV1};
use super::root_connection::ControllerRootConnectionOriginalV1;
use super::strict_chunk::RootStrictChunkOriginalV1;
use super::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::journal::{Journal, JournalError};
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use crate::public_mutation_compiler::delete_admission::{
    ControllerDeleteSourceAuthorizedScopeV1, PlanningNonce,
};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerDeletePreacceptTurnOriginalV1,
};
use aos_sandbox_model::ResourceVector;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::HistoryErrorV1,
    delete_root::planning::{
        DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2,
        DELETE_ROOT_PLANNING_OPEN_BYTES_V3, DeleteRootPlanningChallengeDataV3,
        DeleteRootPlanningDataErrorV3, DeleteRootPlanningObservationDataV2,
        DeleteRootPlanningOpenDataV3,
    },
};
use std::error::Error;

mod shape;

#[derive(Debug, thiserror::Error)]
#[error("the original authorized Delete Root planning exchange is incomplete")]
pub(crate) struct RootDeletePlanningClientClosedV1;

#[derive(Clone, Copy)]
enum First {
    Before,
    Nonce,
    Cut,
    Encoding,
    Connect,
    PeerBefore,
    Reporting,
    Send,
    EndRequest,
    Preparation,
    Admission,
    Chunk,
    Challenge,
    PeerAfter,
    After,
    NonceAfter,
    Settlement,
    Disposal,
    Observation,
    Copy,
    Association,
    Gate,
}

#[derive(Clone, Copy)]
enum ReadStage {
    Challenge,
    Observation,
}

/// Keeps actual authorized predecessor, Root socket and all failed originals.
///
/// Its sole constructor requires the continuously held genuine authorized pair.
/// No decoded opening, nonce, native coordinates or challenge is adopted.
#[must_use]
pub(crate) struct RootDeletePlanningClientOriginalV1<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    connection: ControllerRootConnectionOriginalV1,
    stable: Option<StableRootPeerV1>,
    nonce: Option<PlanningNonce>,
    turn: Option<ControllerDeletePreacceptTurnOriginalV1<'profile>>,
    local: Option<Box<OpeningLocal>>,
    read_stage: Option<ReadStage>,
    open: Option<Result<DeleteRootPlanningOpenDataV3, JournalError>>,
    encoded: Option<Result<(), DeleteRootPlanningDataErrorV3>>,
    open_bytes: [u8; DELETE_ROOT_PLANNING_OPEN_BYTES_V3],
    challenge: Option<Result<DeleteRootPlanningChallengeDataV3, DeleteRootPlanningDataErrorV3>>,
    observation: Option<Result<DeleteRootPlanningObservationDataV2, DeleteRootPlanningDataErrorV3>>,
    raw: Option<
        Result<[u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2], std::array::TryFromSliceError>,
    >,
    association: Option<Result<(), JournalError>>,
    gate_clock: Option<rustix::time::Timespec>,
    gate: Option<Result<std::time::Duration, HistoryErrorV1>>,
    before: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    nonce_before: Option<Result<(), JournalError>>,
    nonce_after: Option<Result<(), JournalError>>,
    admission: Option<Result<(), JournalError>>,
    disposal: Option<Result<(), JournalError>>,
    first: Option<First>,
    opening_complete: bool,
    terminal_complete: bool,
    closed: RootDeletePlanningClientClosedV1,
}

struct OpeningLocal {
    connected: Option<Result<(), HistoryErrorV1>>,
    peer_before: PeerSampleV1,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_after: PeerSampleV1,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    send: FixedDeadlineStreamIoV1<DELETE_ROOT_PLANNING_OPEN_BYTES_V3>,
    sent: Option<Result<(), HistoryErrorV1>>,
    request_end: Option<Result<(), rustix::io::Errno>>,
    received: RetainedSubjectStreamReadV1,
    prepared: [Option<Result<(), SubjectStreamReadErrorV1>>; 2],
    response: RetainedSubjectStreamReadV1,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl OpeningLocal {
    fn new() -> Self {
        Self {
            connected: None,
            peer_before: PeerSampleV1::new(),
            before: None,
            peer_after: PeerSampleV1::new(),
            after: None,
            reporting: None,
            send: Default::default(),
            sent: None,
            request_end: None,
            received: Default::default(),
            prepared: [None, None],
            response: Default::default(),
            chunk: None,
            settlement: None,
        }
    }
}

impl<'profile> RootDeletePlanningClientOriginalV1<'profile> {
    /// Enters the genuine authorized pair's distinct planning opening.
    ///
    /// # Errors
    /// Returns only a preconstruction financial or same-owner refusal. All
    /// reached native failures instead remain in the returned owning attempt.
    pub(crate) fn begin_authorized_once_v1(
        scope: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Result<Self, JournalError> {
        let fixed = Self::fixed_demand_v1(profile)?;
        let cut = ControllerDeleteSourceAuthorizedScopeV1::planning_root_fixed_demand_v1()?;
        let posts = Self::peer_traffic_v1(2)?;
        let complete = fixed
            .checked_add(cut)
            .and_then(|sum| sum.checked_add(posts))
            .map_err(JournalError::ReceivingAccounting)?;
        scope.reserve_planning_root_additional_v1(
            controller,
            launch,
            profile.lower_original_v1(),
            complete,
        )?;
        let turn =
            scope.prepare_planning_root_turn_v1(controller, launch, profile.lower_original_v1())?;
        let nonce = scope.new_planning_root_nonce_v1();
        let mut owner = Self {
            profile,
            connection: Default::default(),
            stable: None,
            nonce: Some(nonce),
            turn: Some(turn),
            local: Some(Box::new(OpeningLocal::new())),
            read_stage: None,
            open: None,
            encoded: None,
            open_bytes: [0; DELETE_ROOT_PLANNING_OPEN_BYTES_V3],
            challenge: None,
            observation: None,
            raw: None,
            association: None,
            gate_clock: None,
            gate: None,
            before: None,
            after: None,
            nonce_before: None,
            nonce_after: None,
            admission: None,
            disposal: None,
            first: None,
            opening_complete: false,
            terminal_complete: false,
            closed: RootDeletePlanningClientClosedV1,
        };
        owner.open_once(scope, controller, launch);
        Ok(owner)
    }

    fn open_once(
        &mut self,
        scope: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) {
        self.before = Some((|| {
            self.turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_before_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.before, Some(Ok(()))) {
            self.first = Some(First::Before);
        }
        if self.first.is_none() {
            self.nonce_before = self.nonce.as_mut().map(PlanningNonce::begin_once);
            if !matches!(self.nonce_before, Some(Ok(()))) {
                self.first = Some(First::Nonce);
            }
        }
        if self.first.is_none() && self.open_primary(scope, controller, launch).is_err() {
            self.first.get_or_insert(First::Cut);
        }

        // These independent afters were all paid before native construction.
        // Partial IO and later admission refusal cannot suppress reached posts.
        self.observe_root_after();
        self.after = Some((|| {
            self.turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .observe_after_once_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)
        })());
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        self.nonce_after = self.nonce.as_mut().map(PlanningNonce::finish_once);
        if !matches!(self.nonce_after, Some(Ok(()))) {
            self.first.get_or_insert(First::NonceAfter);
        }
        if self.first.is_none() {
            self.association = Some(self.require_same_authorized(scope, controller, launch));
            if !matches!(self.association, Some(Ok(()))) {
                self.first = Some(First::Association);
            }
        }
        if self.first.is_none() {
            self.settle_opening(controller);
        }
    }

    fn open_primary(
        &mut self,
        scope: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), RootDeletePlanningClientClosedV1> {
        self.open = Some((|| {
            let cut = scope.planning_root_cut_data_v1(
                controller,
                launch,
                self.profile.lower_original_v1(),
            )?;
            let (nonce, cutoff) = self
                .nonce
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .coordinates()?;
            Ok(DeleteRootPlanningOpenDataV3 {
                project: cut.project,
                caller: cut.caller,
                input: cut.input_digest,
                authorization_clock: cut.clock,
                authorization_expires: cut.expires,
                controller_nonce: nonce,
                controller_cutoff: cutoff,
                controller_next: cut.controller_next,
                controller_end: cut.controller_end,
                source_next: cut.source_next,
                source_end: cut.source_end,
                funding: cut.funding,
            })
        })());
        self.require(matches!(self.open, Some(Ok(_))), First::Cut)?;
        let open = *self
            .open
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(RootDeletePlanningClientClosedV1)?;
        self.encoded = Some(open.encode_v3().map(|bytes| self.open_bytes = bytes));
        self.require(matches!(self.encoded, Some(Ok(()))), First::Encoding)?;
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        local.connected = Some(self.connection.connect_once());
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.connected, Some(Ok(())))),
            First::Connect,
        )?;
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        local.before = Some(
            local.peer_before.observe_delete_once_v1(
                self.profile,
                self.connection
                    .stream()
                    .map_err(|_| RootDeletePlanningClientClosedV1)?,
                None,
                None,
                false,
                open.controller_cutoff,
            ),
        );
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.before, Some(Ok(())))),
            First::PeerBefore,
        )?;
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        local.reporting = Some(
            self.connection
                .stream_mut()
                .map_err(|_| RootDeletePlanningClientClosedV1)?
                .enable_subject_reporting().map_err(aos_sandbox_linux::seqpacket::SeqpacketError::from),
        );
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.reporting, Some(Ok(())))),
            First::Reporting,
        )?;
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        local.sent = Some(
            local.send.run_once(
                self.connection
                    .stream_mut()
                    .map_err(|_| RootDeletePlanningClientClosedV1)?,
                &mut self.open_bytes,
                open.controller_cutoff,
                DeadlineStreamDirectionV1::Write,
            ),
        );
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.sent, Some(Ok(())))),
            First::Send,
        )?;
        use std::os::fd::AsFd as _;
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        local.request_end = Some(rustix::net::shutdown(
            self.connection
                .stream()
                .map_err(|_| RootDeletePlanningClientClosedV1)?
                .as_fd(),
            rustix::net::Shutdown::Write,
        ));
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.request_end, Some(Ok(())))),
            First::EndRequest,
        )?;
        self.receive_fixed(
            scope,
            controller,
            launch,
            open.controller_cutoff,
            ReadStage::Challenge,
        )?;
        let local = self
            .local
            .as_ref()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        self.challenge = Some(
            DeleteRootPlanningChallengeDataV3::decode_v3(local.received.bytes()).and_then(
                |challenge| {
                    challenge.require_open_v3(open)?;
                    Ok(challenge)
                },
            ),
        );
        self.require(matches!(self.challenge, Some(Ok(_))), First::Challenge)?;
        self.receive_fixed(
            scope,
            controller,
            launch,
            open.controller_cutoff,
            ReadStage::Observation,
        )?;
        let challenge = *self
            .challenge
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(RootDeletePlanningClientClosedV1)?;
        let local = self
            .local
            .as_ref()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        self.raw = Some(local.response.bytes().try_into());
        self.require(matches!(self.raw, Some(Ok(_))), First::Copy)?;
        self.observation = Some(
            DeleteRootPlanningObservationDataV2::decode(
                self.raw
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(RootDeletePlanningClientClosedV1)?,
            )
            .and_then(|observation| {
                observation.require_exchange_v2(open, challenge)?;
                Ok(observation)
            }),
        );
        self.require(matches!(self.observation, Some(Ok(_))), First::Observation)
    }

    fn receive_fixed(
        &mut self,
        scope: &mut ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        cutoff: u64,
        stage: ReadStage,
    ) -> Result<(), RootDeletePlanningClientClosedV1> {
        self.read_stage = Some(stage);
        let local = self
            .local
            .as_mut()
            .ok_or(RootDeletePlanningClientClosedV1)?;
        let (index, length) = match stage {
            ReadStage::Challenge => (0, DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3),
            ReadStage::Observation => (1, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2),
        };
        local.prepared[index] = Some(match stage {
            ReadStage::Challenge => local.received.prepare_exact_once(length),
            ReadStage::Observation => local.response.prepare_exact_once(length),
        });
        self.require(
            self.local
                .as_ref()
                .is_some_and(|local| matches!(local.prepared[index], Some(Ok(())))),
            First::Preparation,
        )?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| RootDeletePlanningClientClosedV1)?;
        loop {
            let local = self
                .local
                .as_ref()
                .ok_or(RootDeletePlanningClientClosedV1)?;
            let complete = match stage {
                ReadStage::Challenge => local.received.completed_exact(),
                ReadStage::Observation => local.response.completed_exact(),
            };
            if complete {
                return Ok(());
            }
            self.admission = Some(Self::peer_traffic_v1(1).and_then(|traffic| {
                scope.reserve_planning_root_additional_v1(
                    controller,
                    launch,
                    self.profile.lower_original_v1(),
                    traffic,
                )
            }));
            self.require(matches!(self.admission, Some(Ok(()))), First::Admission)?;
            let local = self
                .local
                .as_mut()
                .ok_or(RootDeletePlanningClientClosedV1)?;
            local.chunk = Some(Box::new(RootStrictChunkOriginalV1::default()));
            let buffer = match stage {
                ReadStage::Challenge => &mut local.received,
                ReadStage::Observation => &mut local.response,
            };
            let result = local
                .chunk
                .as_mut()
                .ok_or(RootDeletePlanningClientClosedV1)?
                .receive_once(
                    buffer,
                    self.connection
                        .stream_mut()
                        .map_err(|_| RootDeletePlanningClientClosedV1)?,
                    &local.peer_before,
                    self.profile,
                    &geometry,
                    cutoff,
                );
            self.require(result.is_ok(), First::Chunk)?;
            drop(self.local.as_mut().and_then(|local| local.chunk.take()));
        }
    }

    fn observe_root_after(&mut self) {
        let Some(local) = self.local.as_mut() else {
            return;
        };
        let Ok(stream) = self.connection.stream() else {
            return;
        };
        let cutoff = self
            .open
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map_or(0, |open| open.controller_cutoff);
        local.after = Some(if matches!(local.before, Some(Ok(()))) {
            local.peer_after.observe_delete_against_sample_once_v1(
                self.profile,
                stream,
                &local.peer_before,
                None,
                true,
                cutoff,
            )
        } else {
            local
                .peer_after
                .observe_delete_once_v1(self.profile, stream, None, None, true, cutoff)
        });
        if !matches!(local.after, Some(Ok(()))) {
            self.first.get_or_insert(First::PeerAfter);
        }
    }

    fn settle_opening(&mut self, controller: &Journal) {
        let Some(local) = self.local.as_mut() else {
            self.first = Some(First::Settlement);
            return;
        };
        local.settlement = Some(
            local
                .peer_before
                .settle_positive_once()
                .and_then(|()| local.peer_after.settle_positive_once()),
        );
        if !matches!(local.settlement, Some(Ok(()))) {
            self.first = Some(First::Settlement);
            return;
        }
        self.stable = local.peer_before.take_initial_binding();
        if self.stable.is_none() {
            self.first = Some(First::Settlement);
            return;
        }
        self.disposal = Some((|| {
            let token = self
                .turn
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?
                .prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?)
                .map_err(JournalError::ControllerNative)?;
            drop(self.local.take());
            drop(self.nonce.take());
            token.complete_after_upper_disposal_v1();
            Ok(())
        })());
        if !matches!(self.disposal, Some(Ok(()))) {
            self.first = Some(First::Disposal);
            return;
        }
        drop(self.turn.take());
        self.opening_complete = true;
        // This completes only the paid planning comparison. It cannot retire
        // the surrounding actual C17/Source scope or any lifecycle guard.
        self.terminal_complete = true;
    }

    fn require_same_authorized(
        &self,
        scope: &ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<(), JournalError> {
        let open = self
            .open
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let cut = scope.planning_root_cut_data_v1(
            controller,
            launch,
            self.profile.lower_original_v1(),
        )?;
        if open.project != cut.project
            || open.caller != cut.caller
            || open.input != cut.input_digest
            || open.authorization_clock != cut.clock
            || open.authorization_expires != cut.expires
            || open.funding != cut.funding
            || open.controller_next != cut.controller_next
            || open.controller_end != cut.controller_end
            || open.source_next != cut.source_next
            || open.source_end != cut.source_end
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Lends the full observation only from this actual completed native client.
    ///
    /// The same genuine authorization/predecessor and original five-second
    /// horizon remain mandatory. This borrow is historical planning evidence;
    /// it is neither a six-cut proof nor a pending/preaccept authorization.
    pub(crate) fn borrow_observation_v1<'borrow>(
        &'borrow mut self,
        scope: &ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
    ) -> Result<RootDeletePlanningObservationLoanV1<'borrow>, RootDeletePlanningClientClosedV1>
    {
        if !self.opening_complete || !self.terminal_complete || self.first.is_some() {
            return Err(RootDeletePlanningClientClosedV1);
        }
        self.association = Some(self.require_same_authorized(scope, controller, launch));
        self.require(matches!(self.association, Some(Ok(()))), First::Association)?;
        let open = self
            .open
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(RootDeletePlanningClientClosedV1)?;
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.gate_clock = Some(now);
        self.gate = Some(aos_sandbox_broker::bounded_stream_io::remaining(
            now,
            open.controller_cutoff,
        ));
        self.require(matches!(self.gate, Some(Ok(_))), First::Gate)?;
        Ok(RootDeletePlanningObservationLoanV1 {
            bytes: self
                .raw
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(RootDeletePlanningClientClosedV1)?,
            open: self
                .open
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(RootDeletePlanningClientClosedV1)?,
            challenge: self
                .challenge
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(RootDeletePlanningClientClosedV1)?,
            observation: self
                .observation
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(RootDeletePlanningClientClosedV1)?,
        })
    }

    fn require(
        &mut self,
        positive: bool,
        first: First,
    ) -> Result<(), RootDeletePlanningClientClosedV1> {
        if positive {
            return Ok(());
        }
        self.first.get_or_insert(first);
        Err(RootDeletePlanningClientClosedV1)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let local = self.local.as_deref();
        let cause =
            match self.first? {
                First::Before => error(&self.before),
                First::Nonce | First::NonceAfter => self
                    .nonce
                    .as_ref()
                    .and_then(PlanningNonce::failure)
                    .or_else(|| error(&self.nonce_before))
                    .or_else(|| error(&self.nonce_after)),
                First::Cut => error(&self.open),
                First::Encoding => error(&self.encoded),
                First::Connect => self.connection.failure(),
                First::Admission => error(&self.admission),
                First::Challenge => error(&self.challenge),
                First::Observation => error(&self.observation),
                First::Copy => error(&self.raw),
                First::Association => error(&self.association),
                First::Gate => error(&self.gate),
                First::After => error(&self.after),
                First::Disposal => error(&self.disposal),
                First::PeerBefore => local
                    .and_then(|local| local.peer_before.failure().or_else(|| error(&local.before))),
                First::PeerAfter => local
                    .and_then(|local| local.peer_after.failure().or_else(|| error(&local.after))),
                First::Reporting => local.and_then(|local| error(&local.reporting)),
                First::EndRequest => local.and_then(|local| error(&local.request_end)),
                First::Send => {
                    local.and_then(|local| local.send.failure().or_else(|| error(&local.sent)))
                }
                First::Preparation => local.and_then(|local| {
                    let (buffer, index) = match self.read_stage? {
                        ReadStage::Challenge => (&local.received, 0),
                        ReadStage::Observation => (&local.response, 1),
                    };
                    buffer.failure().or_else(|| error(&local.prepared[index]))
                }),
                First::Chunk => local.and_then(|local| {
                    let buffer = match self.read_stage? {
                        ReadStage::Challenge => &local.received,
                        ReadStage::Observation => &local.response,
                    };
                    local.chunk.as_ref()?.failure(buffer)
                }),
                First::Settlement => local.and_then(|local| {
                    local
                        .peer_before
                        .failure()
                        .or_else(|| local.peer_after.failure())
                        .or_else(|| error(&local.settlement))
                }),
            };
        cause.or(Some(&self.closed))
    }

    pub(crate) fn intake_failure_view_v1<'cause>(
        &'cause self,
        scope: &'cause ControllerDeleteSourceAuthorizedScopeV1<'_, '_>,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>>{
        if matches!(self.first, Some(First::Admission)) {
            return scope.planning_root_intake_failure_view_v1(self.profile.lower_original_v1());
        }
        if matches!(
            self.first,
            Some(First::Before | First::After | First::Disposal)
        ) {
            return self.turn.as_ref()?.failure_view_v1();
        }
        None
    }

    pub(crate) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let local = self.local.as_deref()?;
        match self.first? {
            First::PeerBefore => local.peer_before.property_failure_view_v1(),
            First::PeerAfter => local.peer_after.property_failure_view_v1(),
            First::Chunk => local.chunk.as_ref()?.property_failure_view_v1(),
            First::Settlement => local
                .peer_before
                .property_failure_view_v1()
                .or_else(|| local.peer_after.property_failure_view_v1()),
            _ => None,
        }
    }
}

/// Keeps a short borrow of the genuine completed planning comparison only.
pub(crate) struct RootDeletePlanningObservationLoanV1<'borrow> {
    bytes: &'borrow [u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2],
    open: &'borrow DeleteRootPlanningOpenDataV3,
    challenge: &'borrow DeleteRootPlanningChallengeDataV3,
    observation: &'borrow DeleteRootPlanningObservationDataV2,
}

impl RootDeletePlanningObservationLoanV1<'_> {
    pub(crate) fn bytes_v2(&self) -> &[u8; DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2] {
        self.bytes
    }
    pub(crate) fn open_v3(&self) -> &DeleteRootPlanningOpenDataV3 {
        self.open
    }
    pub(crate) fn challenge_v3(&self) -> &DeleteRootPlanningChallengeDataV3 {
        self.challenge
    }
    pub(crate) fn observation_v2(&self) -> &DeleteRootPlanningObservationDataV2 {
        self.observation
    }
}

impl Drop for RootDeletePlanningClientOriginalV1<'_> {
    fn drop(&mut self) {
        if !self.terminal_complete {
            std::process::abort();
        }
    }
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
