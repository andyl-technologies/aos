//! Independently reads the explicit C17 cut on Root's fixed Controller view.
//!
//! Complete native/indexed/Cold replay and its independent mount/name/file
//! posts remain on the same paid D flight. This comparison creates no Source
//! pending proof, six-owner conjunction, accepted floor or lifecycle grant.

mod broker_trust;
use broker_trust::RootDeleteBrokerTrustOriginalV2;

mod fresh;

pub(in crate::policy_compiler::delete_root) mod sessions;
use sessions::RootDeleteInitialSessionsOriginalV2;

mod capabilities;
use capabilities::RootDeleteCapabilityCensusOriginalV2;

mod authorization;
use authorization::RootDeleteControllerAuthorizationOriginalV2;

use super::{RootDeleteChallengeOriginalsV1, RootDeleteErrorV1};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::create_storage_current::controller_readonly::native_read::{RootFixedNativeReadOriginalsV1, RootFixedCompletedReadDataV2, RootFixedNativeReadbackV1};
use crate::policy_compiler::{
    RetainedKernelPairedClockAttemptV1, root_subject_chunk::RootSubjectChunkReceivingV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::{
    seqpacket::SeqpacketError,
    unix_stream::{
        RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
    },
};
use aos_sandbox_protocol::domain_ledger::{
    delete_root::{
        controller_cut::{
            DELETE_ROOT_CONTROLLER_CUT_BYTES_V3, DeleteRootControllerCutDataV3,
            DeleteRootControllerCutErrorV3,
        },
        transport::DeleteRootChallengeDataV2,
    },
    resource_bank::{ResourceBankDataError},
};
use std::error::Error;
use std::os::unix::net::UnixStream;

#[derive(Clone, Copy)]
pub(crate) enum RootDeleteControllerAdmissionPhaseV1 {
    Fixed = 0,
    Native = 1,
    Semantic = 2,
    AuthorizationHeader = 3,
    AuthorizationBody = 4,
    BrokerTrust = 5,
    SessionFixed = 6,
    SessionNative = 7,
    SessionModels = 8,
    MountSessionFixed = 9,
    MountSessionNative = 10,
    MountSessionModels = 11,
    StorageSessionFixed = 12,
    StorageSessionNative = 13,
    StorageSessionModels = 14,
    NetworkSessionFixed = 15,
    NetworkSessionNative = 16,
    NetworkSessionModels = 17,
    CapabilityCensus = 18,
}
#[derive(Clone, Copy)]
enum First {
    Permit(usize),
    Geometry,
    Preparation,
    Frame,
    Decode,
    Association,
    Enrollment,
    Arm,
    Before,
    ClockBefore,
    Capture,
    NativeDemand,
    SemanticDemand,
    Replay,
    Compare,
    NativePost,
    After,
    ClockAfter,
    Authorization,
    BrokerTrust,
    Sessions,
    Retirement,
    Capabilities,
    Reentry,
}
#[derive(Debug, thiserror::Error)]
enum ComparisonError {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Bank(#[from] ResourceBankDataError),
    #[error("Root's actual Controller native cut differs from the C17 owner")]
    Changed,
}

pub(crate) struct RootDeleteControllerCurrentOriginalV1 {
    phase: RootDeleteControllerAdmissionPhaseV1,
    fresh_predecessor: Option<Result<fresh::FreshControllerPredecessorV2, JournalError>>,
    permits: [Option<Result<(), ResourceReservationErrorV1>>; 19],
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    buffer: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunk: RootSubjectChunkReceivingV1,
    received: Option<Result<(), crate::policy_compiler::RootCreateStorageCurrentErrorV1>>,
    frame: Option<Result<DeleteRootControllerCutDataV3, DeleteRootControllerCutErrorV3>>,
    association: Option<Result<(), DeleteRootControllerCutErrorV3>>,
    enrollment: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_before_original: RetainedKernelPairedClockAttemptV1,
    clock_before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_before_binding: Option<Result<(), JournalError>>,
    clock_after_original: RetainedKernelPairedClockAttemptV1,
    clock_after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_after_binding: Option<Result<(), JournalError>>,
    reader: Option<RootFixedNativeReadOriginalsV1>,
    completed_reader: Option<RootFixedCompletedReadDataV2>,
    retirement: Option<Result<(), JournalError>>,
    capture: Option<Result<(), JournalError>>,
    native_demand: Option<Result<ResourceVector, JournalError>>,
    semantic_demand: Option<Result<ResourceVector, JournalError>>,
    compared: Option<Result<(), ComparisonError>>,
    named_cut: Option<Result<[u8; 32], ResourceBankDataError>>,
    capabilities: RootDeleteCapabilityCensusOriginalV2,
    authorization: RootDeleteControllerAuthorizationOriginalV2,
    broker_trust: RootDeleteBrokerTrustOriginalV2,
    sessions: RootDeleteInitialSessionsOriginalV2,
    first: Option<First>,
    entered: bool,
    native_entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteControllerCurrentOriginalV1 {
    fn default() -> Self {
        Self {
            phase: RootDeleteControllerAdmissionPhaseV1::Fixed,
            fresh_predecessor: None,
            permits: std::array::from_fn(|_| None),
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            buffer: Default::default(),
            preparation: None,
            chunk: Default::default(),
            received: None,
            frame: None,
            association: None,
            enrollment: None,
            posts: Default::default(),
            arm: None,
            before: None,
            after: None,
            clock_before_original: Default::default(),
            clock_before: None,
            clock_before_binding: None,
            clock_after_original: Default::default(),
            clock_after: None,
            clock_after_binding: None,
            reader: Some(RootFixedNativeReadOriginalsV1::controller_current_v1()),
            completed_reader: None,
            retirement: None,
            capture: None,
            native_demand: None,
            semantic_demand: None,
            compared: None,
            named_cut: None,
            capabilities: Default::default(),
            authorization: Default::default(),
            broker_trust: Default::default(),
            sessions: Default::default(),
            first: None,
            entered: false,
            native_entered: false,
            complete: false,
            closed: None,
        }
    }
}

impl RootDeleteControllerCurrentOriginalV1 {
    pub(super) fn observe_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        let primary = self.observe_inner(flight, original, challenge);
        if self.native_entered {
            // The SAME reader owes its independent native post even after
            // capture, geometry, parsing, payment or comparison uncertainty.
            if let Some(reader) = self.reader.as_mut() {
                reader.finish_post_once();
                if reader.post_failure().is_some() {
                    self.first.get_or_insert(First::NativePost);
                }
            }
            self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
            if !matches!(self.after, Some(Ok(()))) {
                self.first.get_or_insert(First::After);
            }
            self.clock_after = Some(self.clock_after_original.observe_once(None));
            self.clock_after_binding = Some((|| {
                let before = *positive(&self.clock_before)?;
                let after = *positive(&self.clock_after)?;
                before
                    .validate_later_sample(after)
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                challenge.require_current_clock_v1(after)
            })());
            if !matches!(self.clock_after_binding, Some(Ok(()))) {
                self.first.get_or_insert(First::ClockAfter);
            }
        }
        if primary.is_err() || self.first.is_some() || self.failure().is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.retirement = Some(self.retire_reader_once_v2());
        if !matches!(self.retirement, Some(Ok(()))) {
            self.first = Some(First::Retirement);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.capabilities.geometry = Some(self.capability_census_demand_v2());
        if !matches!(self.capabilities.geometry, Some(Ok(_))) {
            self.first = Some(First::Capabilities);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.admit(flight, challenge, RootDeleteControllerAdmissionPhaseV1::CapabilityCensus)?;
        self.capabilities.census = Some(self.capture_capability_census_v2());
        if !matches!(self.capabilities.census, Some(Ok(_))) {
            self.first = Some(First::Capabilities);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.complete = true;
        Ok(())
    }

    pub(crate) fn current_assignment_rows_v2(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>, JournalError> {
        self.retained_receiving_demand_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.initial_session_cuts_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        self.completed_reader.as_ref().ok_or(JournalError::ProtectedBoundary)?
            .historical_rows_data_v2()
    }

    pub(in crate::policy_compiler::delete_root) fn current_assignment_state_v2(&self)
        -> Result<&std::collections::BTreeMap<(crate::journal::RecordNamespace, Vec<u8>), Vec<u8>>, JournalError> {
        self.current_assignment_rows_v2()?;
        Ok(self.readback_v2()?.state)
    }

    fn readback_v2(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        match &self.completed_reader {
            Some(data) => data.readback_v2(),
            None => self.reader.as_ref().ok_or(JournalError::ProtectedBoundary)?.terminal_native_v1(),
        }
    }

    fn retire_reader_once_v2(&mut self) -> Result<(), JournalError> {
        if self.completed_reader.is_some() { return Err(JournalError::ProtectedBoundary); }
        let reader = self.reader.take().ok_or(JournalError::ProtectedBoundary)?;
        match reader.into_completed_data_v2() {
            Ok(data) => { self.completed_reader = Some(data); Ok(()) }
            Err(reader) => { self.reader = Some(reader); Err(JournalError::ProtectedBoundary) }
        }
    }

    fn admit(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        phase: RootDeleteControllerAdmissionPhaseV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.phase = phase;
        let index = phase as usize;
        self.permits[index] = Some(if self.fresh_predecessor.is_some() {
            flight.admit_delete_fresh_controller_current_v2(challenge, self)
        } else {
            flight.admit_delete_controller_current_v1(challenge, self)
        });
        if !matches!(self.permits[index], Some(Ok(()))) {
            self.first = Some(First::Permit(index));
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn observe_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::Fixed,
        )?;
        if self.geometry.is_err() {
            self.first = Some(First::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.preparation = Some(
            self.buffer
                .prepare_exact_once(DELETE_ROOT_CONTROLLER_CUT_BYTES_V3),
        );
        if !matches!(self.preparation, Some(Ok(()))) {
            self.first = Some(First::Preparation);
            return Err(RootDeleteErrorV1::Opening);
        }
        let geometry = self
            .geometry
            .as_ref()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        self.received = Some(self.chunk.receive_delete_exact_v1(
            flight,
            original,
            &mut self.buffer,
            geometry,
            challenge,
        ));
        if !matches!(self.received, Some(Ok(()))) {
            self.first = Some(First::Frame);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.frame = Some(DeleteRootControllerCutDataV3::decode_v3(self.buffer.bytes()));
        let frame = match positive(&self.frame) {
            Ok(frame) => *frame,
            Err(_) => {
                self.first = Some(First::Decode);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        self.association = Some(
            DeleteRootChallengeDataV2::decode_v2(
                challenge
                    .challenge_bytes_v1()
                    .map_err(|_| RootDeleteErrorV1::Opening)?,
            )
            .map_err(DeleteRootControllerCutErrorV3::from)
            .and_then(|own| frame.require_challenge_v2(own)),
        );
        if !matches!(self.association, Some(Ok(()))) {
            self.first = Some(First::Association);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.enrollment = Some(flight.require_delete_controller_funding_original_v3(self));
        if !matches!(self.enrollment, Some(Ok(()))) {
            self.first = Some(First::Enrollment);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.native_entered = true;
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(First::Arm);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.clock_before = Some(self.clock_before_original.observe_once(None));
        self.clock_before_binding = Some(
            positive(&self.clock_before)
                .and_then(|clock| challenge.require_current_clock_v1(*clock)),
        );
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.clock_before_binding, Some(Ok(()))) {
            self.first = Some(First::ClockBefore);
            return Err(RootDeleteErrorV1::Opening);
        }
        if !matches!(self.before, Some(Ok(()))) {
            self.first = Some(First::Before);
            return Err(RootDeleteErrorV1::Opening);
        }
        let uid = flight
            .delete_cut_startup_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?
            .native_startup_original_v1()
            .fields()
            .profile
            .identities[0];
        self.reader.as_mut().ok_or(RootDeleteErrorV1::Original)?.capture_once(uid);
        self.capture = Some(self.reader.as_ref().ok_or(RootDeleteErrorV1::Original)?.captured_extent_v1().map(|_| ()));
        if !matches!(self.capture, Some(Ok(()))) {
            self.first = Some(First::Capture);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.native_demand = Some(self.reader.as_ref().ok_or(RootDeleteErrorV1::Original)?.replay_demand_v1());
        if !matches!(self.native_demand, Some(Ok(_))) {
            self.first = Some(First::NativeDemand);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::Native,
        )?;
        self.reader.as_mut().ok_or(RootDeleteErrorV1::Original)?.audit_once();
        self.semantic_demand = Some(self.reader.as_ref().ok_or(RootDeleteErrorV1::Original)?.additional_semantic_demand_v1());
        if !matches!(self.semantic_demand, Some(Ok(_))) {
            self.first = Some(First::SemanticDemand);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.admit(
            flight,
            challenge,
            RootDeleteControllerAdmissionPhaseV1::Semantic,
        )?;
        self.reader.as_mut().ok_or(RootDeleteErrorV1::Original)?.replay_once();
        if self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::failure).is_some() {
            self.first = Some(First::Replay);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.compared = Some((|| {
            let actual = self.reader.as_ref().ok_or(JournalError::ProtectedBoundary)?.replay_native_v1()?;
            if (actual.next, actual.end) != (frame.next, frame.end) {
                return Err(ComparisonError::Changed);
            }
            frame.funding.require_bank_record_v1(actual.state)?;
            if let Some(predecessor) = &self.fresh_predecessor {
                let predecessor = predecessor.as_ref()
                    .map_err(|_| JournalError::ProtectedBoundary)?;
                predecessor.require_same_controller_v2(frame, &actual)?;
            }
            Ok(())
        })());
        if !matches!(self.compared, Some(Ok(()))) {
            self.first = Some(First::Compare);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.named_cut = Some(frame.funding.controller_funding_cut_data_v3(frame.next, frame.end));
        if !matches!(self.named_cut, Some(Ok(_))) {
            self.first = Some(First::Compare);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(crate) fn controller_funding_v3(
        &self,
    ) -> Result<
        &aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1,
        ResourceReservationErrorV1,
    > {
        if !self.entered
            || !matches!(self.received, Some(Ok(())))
            || !matches!(self.association, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.frame
            .as_ref()
            .and_then(|frame| frame.as_ref().ok())
            .map(|frame| &frame.funding)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.permits[self.phase as usize].is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v1()
    }

    pub(crate) fn verified_named_cut_data_v2(&self) -> Result<[u8; 32], RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some()
            || self.readback_v2().is_err() {
            return Err(RootDeleteErrorV1::Original);
        }
        self.named_cut.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(crate) fn retained_receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.complete || self.first.is_some() || self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v1()
    }

    fn receiving_recipe_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::Conflict;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * DELETE_ROOT_CONTROLLER_CUT_BYTES_V3))
            .and_then(|bytes| bytes.checked_add(3 * aos_sandbox_protocol::domain_ledger::resource_bank::CLAIM_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<sha2::Sha256>()))
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let fixed = RootFixedNativeReadOriginalsV1::controller_current_fixed_demand_v1()
            .map_err(|_| invalid())?;
        let fixed = if self.completed_reader.is_some() && self.reader.is_none() {
            fixed.with(D::OpenFiles, 0)
        } else { fixed };
        let mut demand = fixed.checked_add(
                RootSubjectChunkReceivingV1::delete_receiving_demand_v1().map_err(|_| invalid())?,
            )?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(
                D::OpenFiles,
                2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64,
            ))?;
        for value in [&self.native_demand, &self.semantic_demand] {
            if let Some(Ok(additional)) = value {
                demand = demand.checked_add(*additional)?;
            }
        }
        if let Some(Ok(dynamic)) = &self.capabilities.geometry {
            demand = demand.checked_add(*dynamic)?;
        }
        if let Some(Ok(dynamic)) = &self.authorization.dynamic {
            demand = demand.checked_add(*dynamic)?;
        }
        // Both message buffers remain held; positive strict leaves retire their
        // native scratch after their own posts, while failures stop progression.
        let auth_fixed = (2 * 3 * std::mem::size_of::<sha2::Sha256>())
            .checked_add(3 * aos_sandbox_protocol::domain_ledger::delete_root::authorization::DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        demand = demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, auth_fixed))?;
        let sessions = self.sessions.demand_v2()?;
        demand = demand.checked_add(sessions.with(D::OutputBytes, 0).with(D::NetworkBytes, 0).with(D::LogBytes, 0))?;
        if self.phase as usize >= RootDeleteControllerAdmissionPhaseV1::SessionFixed as usize {
            demand = demand.with(D::OutputBytes, sessions.get(D::OutputBytes));
        }
        let trust = self.broker_trust.demand_v2()?;
        let resident_trust = trust.with(D::OutputBytes, 0).with(D::NetworkBytes, 0)
            .with(D::LogBytes, 0);
        demand = demand.checked_add(resident_trust)?;
        if matches!(self.phase, RootDeleteControllerAdmissionPhaseV1::BrokerTrust) {
            demand = demand.with(D::OutputBytes, trust.get(D::OutputBytes));
        }
        if matches!(self.phase, RootDeleteControllerAdmissionPhaseV1::AuthorizationHeader) {
            demand = demand.with(D::NetworkBytes,
                aos_sandbox_protocol::domain_ledger::delete_root::authorization::DELETE_ROOT_AUTHORIZATION_HEADER_BYTES_V2 as u64);
        } else if matches!(self.phase, RootDeleteControllerAdmissionPhaseV1::AuthorizationBody) {
            demand = demand.with(D::NetworkBytes, self.authorization.body_wire_bytes()?);
        } else if matches!(self.phase, RootDeleteControllerAdmissionPhaseV1::Fixed) {
            demand = demand.with(D::NetworkBytes, DELETE_ROOT_CONTROLLER_CUT_BYTES_V3 as u64);
        }
        Ok(demand)
    }

    pub(super) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Sessions)) && self.sessions.funding_failed()
            || matches!(self.first, Some(First::BrokerTrust)) && self.broker_trust.funding_failed()
            || matches!(self.first, Some(First::Authorization)) && self.authorization.funding_failed()
            || matches!(self.first, Some(First::Permit(_)))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
            || matches!(self.first, Some(First::Frame))
                && self.chunk.financial_failure_is_selected_v1()
    }

    pub(super) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Sessions => self.sessions.property_failure_view(),
            First::BrokerTrust => self.broker_trust.property_failure_view(),
            First::Authorization => self.authorization.property_failure_view(),
            First::Frame => self.chunk.property_failure_view_v1(&self.buffer),
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Sessions => self.sessions.failure(),
            First::Capabilities => self.capabilities.failure_v2(),
            First::Retirement => self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::failure)
                .or_else(|| cause(&self.retirement)),
            First::BrokerTrust => self.broker_trust.failure(),
            First::Authorization => self.authorization.failure(),
            First::Permit(index) => cause(&self.permits[index]),
            First::Geometry => self.geometry.as_ref().err().map(|cause| cause as _),
            First::Preparation => self.buffer.failure().or_else(|| cause(&self.preparation)),
            First::Frame => self
                .chunk
                .failure_with_buffer(&self.buffer)
                .or_else(|| cause(&self.received)),
            First::Decode => cause(&self.frame),
            First::Enrollment => cause(&self.enrollment),
            First::Association => cause(&self.association),
            First::Arm | First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.arm))
                .or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::ClockBefore => self
                .clock_before_original
                .failure()
                .or_else(|| cause(&self.clock_before))
                .or_else(|| cause(&self.clock_before_binding)),
            First::ClockAfter => self
                .clock_after_original
                .failure()
                .or_else(|| cause(&self.clock_after))
                .or_else(|| cause(&self.clock_after_binding)),
            First::Capture => self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::failure).or_else(|| cause(&self.capture)),
            First::NativeDemand => self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::failure).or_else(|| cause(&self.native_demand)),
            First::SemanticDemand => self
                .reader
                .as_ref()
                .and_then(RootFixedNativeReadOriginalsV1::failure)
                .or_else(|| cause(&self.semantic_demand)),
            First::Replay => self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::failure),
            First::Compare => cause(&self.fresh_predecessor)
                .or_else(|| cause(&self.compared)).or_else(|| cause(&self.named_cut)),
            First::NativePost => self.reader.as_ref().and_then(RootFixedNativeReadOriginalsV1::post_failure),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}
fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
