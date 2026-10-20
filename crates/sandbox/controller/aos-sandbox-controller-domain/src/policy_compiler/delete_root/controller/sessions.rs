//! Verifies each initial Session before retiring its completed native prefix.
//!
//! The same paid D/R flight opens one fixed Session at a time. Each role has a
//! distinct native reader, Root before/after and paired clocks. Its whole native
//! owner is dropped only after complete packet/model verification and every
//! independently owed after succeeds. Signed histories, models and cuts remain
//! resident; a failed prefix stays owned and prevents another role from opening.

pub(in crate::policy_compiler::delete_root) mod model;
use super::*;
use aos_sandbox_protocol::domain_ledger::delete_batch::DeleteBatchOwnerCutDataV2;
use model::{DeleteBrokerRoleV2, DeleteSessionModelsOriginalV2};

const ROLES: [DeleteBrokerRoleV2; 4] = [
    DeleteBrokerRoleV2::Runtime,
    DeleteBrokerRoleV2::Mount,
    DeleteBrokerRoleV2::Storage,
    DeleteBrokerRoleV2::Network,
];
const PHASES: [[RootDeleteControllerAdmissionPhaseV1; 3]; 4] = [
    [
        RootDeleteControllerAdmissionPhaseV1::SessionFixed,
        RootDeleteControllerAdmissionPhaseV1::SessionNative,
        RootDeleteControllerAdmissionPhaseV1::SessionModels,
    ],
    [
        RootDeleteControllerAdmissionPhaseV1::MountSessionFixed,
        RootDeleteControllerAdmissionPhaseV1::MountSessionNative,
        RootDeleteControllerAdmissionPhaseV1::MountSessionModels,
    ],
    [
        RootDeleteControllerAdmissionPhaseV1::StorageSessionFixed,
        RootDeleteControllerAdmissionPhaseV1::StorageSessionNative,
        RootDeleteControllerAdmissionPhaseV1::StorageSessionModels,
    ],
    [
        RootDeleteControllerAdmissionPhaseV1::NetworkSessionFixed,
        RootDeleteControllerAdmissionPhaseV1::NetworkSessionNative,
        RootDeleteControllerAdmissionPhaseV1::NetworkSessionModels,
    ],
];

#[derive(Clone, Copy)]
enum SessionFirst {
    Startup,
    Arm,
    ClockBefore,
    Before,
    Capture,
    NativeDemand,
    PacketsDemand,
    Replay,
    NativePost,
    Packets,
    ModelsDemand,
    Model,
    After,
    ClockAfter,
    Retirement,
}

// Each array destination is entered once. Taking a positive owner irreversibly
// retires that role; no replacement reader or rearmed post is installed there.
#[derive(Default)]
pub(super) struct RootDeleteInitialSessionsOriginalV2 {
    native: [Option<Box<SessionNativeOriginalV2>>; 4],
    models: [DeleteSessionModelsOriginalV2; 4],
    retained: [ResourceVector; 4],
    retired: [bool; 4],
    query: Option<Result<aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1, NormalRootStartupErrorV1>>,
    failed: Option<usize>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

struct SessionNativeOriginalV2 {
    reader: RootFixedNativeReadOriginalsV1,
    captured: bool,
    native: Option<Result<ResourceVector, JournalError>>,
    packets: Option<Result<ResourceVector, JournalError>>,
    model_demand: Option<Result<ResourceVector, JournalError>>,
    posts: RootDeleteChunkPostsV1,
    startup: Option<Result<u32, NormalRootStartupErrorV1>>,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clock_before_original: RetainedKernelPairedClockAttemptV1,
    clock_before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    clock_after_original: RetainedKernelPairedClockAttemptV1,
    clock_after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    first: Option<SessionFirst>,
    retirement: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
}

impl SessionNativeOriginalV2 {
    fn new(role: DeleteBrokerRoleV2) -> Self {
        let reader = match role {
            DeleteBrokerRoleV2::Runtime => RootFixedNativeReadOriginalsV1::host_session_v2(),
            DeleteBrokerRoleV2::Mount => RootFixedNativeReadOriginalsV1::mount_session_v2(),
            DeleteBrokerRoleV2::Storage => RootFixedNativeReadOriginalsV1::default(),
            DeleteBrokerRoleV2::Network => RootFixedNativeReadOriginalsV1::network_session_v2(),
        };
        Self {
            reader,
            captured: false,
            native: None,
            packets: None,
            model_demand: None,
            posts: Default::default(),
            startup: None,
            arm: None,
            before: None,
            after: None,
            clock_before_original: Default::default(),
            clock_before: None,
            before_binding: None,
            clock_after_original: Default::default(),
            clock_after: None,
            after_binding: None,
            first: None,
            retirement: None,
        }
    }

    fn begin(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        role: DeleteBrokerRoleV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(SessionFirst::Arm);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.clock_before = Some(self.clock_before_original.observe_once(None));
        self.before_binding = Some(
            positive(&self.clock_before)
                .and_then(|sample| challenge.require_current_clock_v1(*sample)),
        );
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.before_binding, Some(Ok(()))) {
            self.first = Some(SessionFirst::ClockBefore);
        }
        if !matches!(self.before, Some(Ok(()))) {
            self.first.get_or_insert(SessionFirst::Before);
        }
        if self.first.is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        self.startup = Some(flight.delete_cut_startup_v1().map(|startup| {
            startup
                .native_startup_original_v1()
                .fields()
                .profile
                .identities[0]
        }));
        let uid = match positive(&self.startup) {
            Ok(uid) => *uid,
            Err(_) => {
                self.first = Some(SessionFirst::Startup);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        self.captured = true;
        self.reader.capture_once(uid);
        if self.reader.require_captured_v1().is_err() {
            self.first = Some(SessionFirst::Capture);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.native = Some(self.reader.replay_demand_v1());
        if !matches!(self.native, Some(Ok(_))) {
            self.first = Some(SessionFirst::NativeDemand);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.packets = Some((|| {
            let prefix = self.reader.captured_extent_v1()?.native_bytes;
            let prefix = usize::try_from(prefix).map_err(|_| JournalError::JournalTooLarge)?;
            DeleteSessionModelsOriginalV2::packet_demand_v2(prefix, role)
        })());
        if !matches!(self.packets, Some(Ok(_))) {
            self.first = Some(SessionFirst::PacketsDemand);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn replay(&mut self) -> Result<(), RootDeleteErrorV1> {
        self.reader.replay_once();
        if self.reader.replay_native_v1().is_err() {
            self.first = Some(SessionFirst::Replay);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn finish_reader(&mut self) {
        if self.captured {
            self.reader.finish_post_once();
            if self.reader.post_failure().is_some() {
                self.first.get_or_insert(SessionFirst::NativePost);
            }
        }
    }

    fn finish_posts(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) {
        // Financial refusal before arm owes no native post. Every attempted
        // arm otherwise drives both independent after owners even on failure.
        if self.arm.is_none() {
            return;
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(SessionFirst::After);
        }
        self.clock_after = Some(self.clock_after_original.observe_once(None));
        self.after_binding = Some((|| {
            let before = *positive(&self.clock_before)?;
            let after = *positive(&self.clock_after)?;
            before
                .validate_later_sample(after)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(after)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(SessionFirst::ClockAfter);
        }
    }

    fn dynamic_demand(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let mut demand = ResourceVector::ZERO;
        for value in [&self.native, &self.packets, &self.model_demand] {
            if let Some(Ok(additional)) = value {
                demand = demand.checked_add(*additional)?;
            }
        }
        Ok(demand)
    }

    fn failure<'borrow>(
        &'borrow self,
        model: &'borrow DeleteSessionModelsOriginalV2,
    ) -> Option<&'borrow (dyn Error + 'static)> {
        match self.first? {
            SessionFirst::Startup => cause(&self.startup),
            SessionFirst::Arm => self.posts.before_failure_v1().or_else(|| cause(&self.arm)),
            SessionFirst::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.before)),
            SessionFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            SessionFirst::ClockBefore => self
                .clock_before_original
                .failure()
                .or_else(|| cause(&self.clock_before))
                .or_else(|| cause(&self.before_binding)),
            SessionFirst::ClockAfter => self
                .clock_after_original
                .failure()
                .or_else(|| cause(&self.clock_after))
                .or_else(|| cause(&self.after_binding)),
            SessionFirst::Capture | SessionFirst::Replay => self.reader.failure(),
            SessionFirst::NativePost => self.reader.post_failure(),
            SessionFirst::NativeDemand => cause(&self.native),
            SessionFirst::PacketsDemand => cause(&self.packets),
            SessionFirst::Packets | SessionFirst::Model => model.failure(),
            SessionFirst::ModelsDemand => cause(&self.model_demand),
            SessionFirst::Retirement => cause(&self.retirement),
        }
    }
}

impl RootDeleteInitialSessionsOriginalV2 {
    pub(super) fn demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        // Keep every old memory plane conservatively charged, including all
        // four signed histories/models. Only one native phase can be live.
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<SessionNativeOriginalV2>().checked_mul(12)?)
            })
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(8)?))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(12)?)
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let mut demand = ResourceVector::ZERO.with(D::MemoryBytes, bytes);
        let mut native_files = 0;
        for fixed in [
            RootFixedNativeReadOriginalsV1::host_session_fixed_demand_v2(),
            RootFixedNativeReadOriginalsV1::mount_session_fixed_demand_v2(),
            RootFixedNativeReadOriginalsV1::fixed_demand_v1(),
            RootFixedNativeReadOriginalsV1::network_session_fixed_demand_v2(),
        ] {
            let fixed = fixed.map_err(|_| invalid())?;
            native_files = native_files.max(fixed.get(D::OpenFiles));
            demand = demand.checked_add(fixed.with(D::OpenFiles, 0))?;
        }
        if !self.complete {
            let clocks =
                u64::try_from(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                    .map_err(|_| invalid())?
                    .checked_mul(2)
                    .ok_or_else(invalid)?;
            demand = demand.with(
                D::OpenFiles,
                native_files.checked_add(clocks).ok_or_else(invalid)?,
            );
        }
        for (index, retired) in self.retained.iter().enumerate() {
            demand = demand.checked_add(*retired)?;
            if let Some(native) = &self.native[index] {
                demand = demand.checked_add(native.dynamic_demand()?)?;
            }
        }
        Ok(demand)
    }

    pub(super) fn funding_failed(&self) -> bool {
        self.failed
            .and_then(|index| self.native[index].as_ref())
            .is_some_and(|native| {
                matches!(native.first, Some(SessionFirst::Arm)) && native.posts.funding_failed_v1()
            })
    }

    pub(super) fn property_failure_view(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let index = self.failed?;
        let native = self.native[index].as_ref()?;
        match native.first? {
            SessionFirst::Before | SessionFirst::After => {
                native.posts.property_failure_view_v1(self.failure()?)
            }
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(index) = self.failed {
            if let Some(native) = &self.native[index] {
                return native
                    .failure(&self.models[index])
                    .or_else(|| self.closed.as_ref().map(|cause| cause as _));
            }
        }
        cause(&self.query).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl RootDeleteControllerCurrentOriginalV1 {
    pub(in crate::policy_compiler::delete_root) fn observe_initial_sessions_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_session_engine_once_v2(flight, challenge, None)
    }

    pub(in crate::policy_compiler::delete_root) fn observe_fresh_sessions_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        initial: &Self,
    ) -> Result<(), RootDeleteErrorV1> {
        self.require_fresh_controller_v2(initial)?;
        initial.initial_session_cuts_v2()?;
        self.observe_session_engine_once_v2(flight, challenge, Some(initial))
    }

    fn observe_session_engine_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        initial: Option<&Self>,
    ) -> Result<(), RootDeleteErrorV1> {
        match initial {
            Some(initial) => { initial.broker_manifests_v2()?; }
            None => { self.broker_manifests_v2()?; }
        }
        if self.sessions.entered || self.first.is_some() {
            self.sessions
                .closed
                .get_or_insert(RootDeleteErrorV1::Original);
            self.first.get_or_insert(First::Sessions);
            return Err(RootDeleteErrorV1::Original);
        }
        self.sessions.entered = true;
        self.sessions.query = Some(challenge.source_query_v1());
        let query = match positive(&self.sessions.query) {
            Ok(query) => *query,
            Err(_) => {
                self.first = Some(First::Sessions);
                return Err(RootDeleteErrorV1::Opening);
            }
        };
        // Each next capture follows physical disposal of the complete previous
        // native phase. Every admission and Root service debit remains on SAME R.
        for index in 0..4 {
            self.admit(flight, challenge, PHASES[index][0])?;
            self.sessions.native[index] =
                Some(Box::new(SessionNativeOriginalV2::new(ROLES[index])));
            let primary = self.observe_initial_session(flight, challenge, index, query, initial);
            if let Some(native) = self.sessions.native[index].as_mut() {
                native.finish_reader();
                native.finish_posts(flight, challenge);
            }
            let complete = primary.is_ok()
                && self.sessions.native[index].as_ref().is_some_and(|native| {
                    native.first.is_none()
                        && native.failure(&self.sessions.models[index]).is_none()
                        && native.reader.terminal_native_v1().is_ok()
                        && self.sessions.models[index].cut_v2().is_ok()
                });
            if !complete {
                self.sessions.failed = Some(index);
                self.first.get_or_insert(First::Sessions);
                return Err(RootDeleteErrorV1::Opening);
            }
            let native = self.sessions.native[index]
                .as_mut()
                .ok_or(RootDeleteErrorV1::Original)?;
            native.retirement = Some(native.dynamic_demand());
            let retained = match native
                .retirement
                .as_ref()
                .and_then(|value| value.as_ref().ok())
            {
                Some(demand) => *demand,
                None => {
                    native.first = Some(SessionFirst::Retirement);
                    self.sessions.failed = Some(index);
                    self.first.get_or_insert(First::Sessions);
                    return Err(RootDeleteErrorV1::Opening);
                }
            };
            // Full packet/model/cut owners are fields of sessions, not of this
            // consumed native phase. Failed phases never reach this take/drop.
            drop(self.sessions.native[index].take());
            self.sessions.retained[index] = retained;
            self.sessions.retired[index] = true;
        }
        self.sessions.complete = true;
        Ok(())
    }

    fn observe_initial_session(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        index: usize,
        query: aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1,
        initial: Option<&Self>,
    ) -> Result<(), RootDeleteErrorV1> {
        let native = self.sessions.native[index]
            .as_mut()
            .ok_or(RootDeleteErrorV1::Original)?;
        native.begin(flight, challenge, ROLES[index])?;
        self.admit(flight, challenge, PHASES[index][1])?;
        let native = self.sessions.native[index]
            .as_mut()
            .ok_or(RootDeleteErrorV1::Original)?;
        let replay = native.replay();
        native.finish_reader();
        replay?;
        if native.first.is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        // Manifest storage order is Host/Mount/Network/Storage. Reader/cut order
        // is Runtime/Mount/Storage/Network, unchanged from the complete fold.
        let manifest = match initial {
            Some(initial) => initial.broker_trust.manifest([0, 1, 3, 2][index])?,
            None => self.broker_trust.manifest([0, 1, 3, 2][index])?,
        };
        let actual = native
            .reader
            .terminal_native_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        if self.sessions.models[index]
            .observe_packets_once_v2(actual, ROLES[index], manifest, query.cutoff, query.boot)
            .is_err()
        {
            native.first = Some(SessionFirst::Packets);
            return Err(RootDeleteErrorV1::Opening);
        }
        native.model_demand = Some(self.sessions.models[index].model_demand_v2(ROLES[index]));
        if !matches!(native.model_demand, Some(Ok(_))) {
            native.first = Some(SessionFirst::ModelsDemand);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.admit(flight, challenge, PHASES[index][2])?;
        let native = self.sessions.native[index]
            .as_mut()
            .ok_or(RootDeleteErrorV1::Original)?;
        let actual = native
            .reader
            .terminal_native_v1()
            .map_err(|_| RootDeleteErrorV1::Opening)?;
        if self.sessions.models[index]
            .finish_model_once_v2(actual, ROLES[index], query.boot)
            .is_err()
        {
            native.first = Some(SessionFirst::Model);
            return Err(RootDeleteErrorV1::Opening);
        }
        if let Some(initial) = initial {
            if self.sessions.models[index].require_fresh_after_v2(
                &initial.sessions.models[index], query.nonce, query.cutoff,
            ).is_err() {
                native.first = Some(SessionFirst::Model);
                return Err(RootDeleteErrorV1::Opening);
            }
        }
        Ok(())
    }

    pub(in crate::policy_compiler::delete_root) fn current_storage_inventory_data_v2(&self)
        -> Result<&aos_sandbox_protocol::ValidatedStorageInventory, RootDeleteErrorV1>
    {
        // This intrinsically requires all four actual native Session intervals,
        // canonical histories and independent afters, including the fresh cut.
        self.initial_session_cuts_v2()?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) {
            return Err(RootDeleteErrorV1::Original);
        }
        self.sessions.models[2].storage_inventory_data_v2()
    }

    pub(in crate::policy_compiler::delete_root) fn current_storage_lifecycle_data_v2(&self)
        -> Result<&crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1, RootDeleteErrorV1>
    {
        self.current_storage_inventory_data_v2()?;
        self.sessions.models[2].storage_lifecycle_data_v2()
    }

    pub(in crate::policy_compiler::delete_root) fn require_cleanup_host_successor_v4(&self,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        position: [u8; 64],
    ) -> Result<(), crate::journal::JournalError> {
        self.initial_session_cuts_v2().map_err(|_| crate::journal::JournalError::ProtectedBoundary)?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) {
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        self.sessions.models[0].require_cleanup_host_successor_v4(outcome, position)
    }

    pub(in crate::policy_compiler::delete_root) fn current_network_inventory_data_v4(&self)
        -> Result<&aos_sandbox_protocol::ValidatedNetworkInventory, RootDeleteErrorV1> {
        self.initial_session_cuts_v2()?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) { return Err(RootDeleteErrorV1::Original); }
        self.sessions.models[3].network_inventory_data_v4()
    }

    pub(in crate::policy_compiler::delete_root) fn current_mount_inventory_data_v4(&self)
        -> Result<&aos_sandbox_protocol::ValidatedDestinationSlotInventory, RootDeleteErrorV1> {
        self.initial_session_cuts_v2()?;
        if !matches!(self.fresh_predecessor, Some(Ok(_))) { return Err(RootDeleteErrorV1::Original); }
        self.sessions.models[1].mount_inventory_data_v4()
    }

    pub(in crate::policy_compiler::delete_root) fn current_network_lifecycle_data_v4(&self)
        -> Result<&crate::lifecycle::LifecycleAuthenticatedBrokerDomainInventoryV1, RootDeleteErrorV1> {
        self.current_network_inventory_data_v4()?;
        self.sessions.models[3].network_lifecycle_data_v4()
    }

    pub(in crate::policy_compiler::delete_root) fn initial_session_cuts_v2(
        &self,
    ) -> Result<[DeleteBatchOwnerCutDataV2; 4], RootDeleteErrorV1> {
        if !self.sessions.complete
            || !self.sessions.retired.into_iter().all(|retired| retired)
            || self.sessions.native.iter().any(Option::is_some)
            || self.first.is_some()
            || self.sessions.failure().is_some()
        {
            return Err(RootDeleteErrorV1::Original);
        }
        let [a, b, c, d] = self.sessions.models.each_ref().map(|model| model.cut_v2());
        Ok([
            a.map_err(|_| RootDeleteErrorV1::Original)?,
            b.map_err(|_| RootDeleteErrorV1::Original)?,
            c.map_err(|_| RootDeleteErrorV1::Original)?,
            d.map_err(|_| RootDeleteErrorV1::Original)?,
        ])
    }
}
