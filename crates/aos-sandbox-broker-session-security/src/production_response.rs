//! Bounded production completion for committed responses and exact replays.
//!
//! Every ordinary public completion consumes the authenticated session. Success returns
//! that same session for the next request. Failure drops the socket and all
//! in-memory custody, forcing reconnect/replay against the protected journal
//! instead of allowing a caller to continue after ambiguous transport.
//! Deadline checks bracket sends even when the socket never blocks. A packet
//! sent just before an expiry observation may have reached the client; closing
//! that session does not undo the committed outcome or permit a new effect.

use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CaptureResponseCauseV1 {
    Clock(usize),
    Session(usize),
    Source(usize),
    LateClock(usize),
    Send,
    Readiness,
    Closed,
}

#[derive(Debug, thiserror::Error)]
#[error("original capture response is closed with its terminal custody retained")]
struct CaptureResponseClosedV1;

/// Keeps selected method-41 response custody beside the borrowed real Session.
///
/// This calls the same authenticated sender and readiness helper as ordinary
/// completion. It never recovers/re-signs a failed terminal or dispatches the
/// read-only source a second time. Whole native returns park before postchecks.
pub(crate) struct OriginalCaptureCandidateResponseV1 {
    committed: Option<crate::ProtectedBrokerOutcomeCommittedAdvancementV1>,
    send: Option<Result<crate::DormantBrokerResponseSendProgressV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    readiness: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    current: [Option<Result<(), crate::BrokerSessionSecurityError>>; 3],
    source: [Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>; 3],
    late_clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    first: Option<CaptureResponseCauseV1>,
    attempted: bool,
}

impl OriginalCaptureCandidateResponseV1 {
    pub(crate) const fn empty() -> Self {
        Self {
            committed: None,
            send: None,
            readiness: None,
            clock: [None, None, None],
            current: [None, None, None],
            source: [None, None, None],
            late_clock: [None, None, None],
            first: None,
            attempted: false,
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CaptureResponseCauseV1::Clock(index) => self.clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CaptureResponseCauseV1::Session(index) => self.current[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CaptureResponseCauseV1::Source(index) => match self.source[index].as_ref()?.as_ref().err()? {
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                    custody.original_cause().or_else(|| custody.postcheck_debt()),
                error => Some(error),
            },
            CaptureResponseCauseV1::LateClock(index) => self.late_clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CaptureResponseCauseV1::Send => match &self.send {
                Some(Err(error)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. })) => Some(error),
                _ => Some(&CaptureResponseClosedV1),
            },
            CaptureResponseCauseV1::Readiness => self.readiness.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CaptureResponseCauseV1::Closed => Some(&CaptureResponseClosedV1),
        }
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for index in 0..3 {
            if self.first != Some(CaptureResponseCauseV1::Clock(index)) {
                if let Some(Err(error)) = &self.clock[index] { return Some(error); }
            }
            if self.first != Some(CaptureResponseCauseV1::Session(index)) {
                if let Some(Err(error)) = &self.current[index] { return Some(error); }
            }
            if self.first != Some(CaptureResponseCauseV1::Source(index)) {
                if let Some(Err(error)) = &self.source[index] {
                    return match error {
                        aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                            custody.original_cause().or_else(|| custody.postcheck_debt()),
                        error => Some(error),
                    };
                }
            }
            if self.first != Some(CaptureResponseCauseV1::LateClock(index)) {
                if let Some(Err(error)) = &self.late_clock[index] { return Some(error); }
            }
        }
        for result in &self.source {
            if let Some(Err(aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody))) = result {
                if let Some(error) = custody.postcheck_debt() { return Some(error); }
            }
        }
        None
    }

    pub(crate) fn locally_sent(&self) -> bool {
        self.first.is_none() && self.postcheck_debt().is_none()
            && matches!(&self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Sent(_))))
    }

    fn bookend(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        deadline: u64,
        index: usize,
    ) -> bool {
        self.clock[index] = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if matches!(&self.clock[index], Some(Err(_))) {
            self.first.get_or_insert(CaptureResponseCauseV1::Clock(index));
            if index == 0 { return false; }
        }
        self.current[index] = Some(session.recheck_original_nix_generation_session());
        if matches!(&self.current[index], Some(Err(_))) {
            self.first.get_or_insert(CaptureResponseCauseV1::Session(index));
        }
        self.source[index] = Some(storage.recheck_original_capture_candidate_v1(output, false));
        if matches!(&self.source[index], Some(Err(_))) {
            self.first.get_or_insert(CaptureResponseCauseV1::Source(index));
        }
        self.late_clock[index] = Some(crate::dormant_handshake::check_production_deadline(deadline));
        if matches!(&self.late_clock[index], Some(Err(_))) {
            self.first.get_or_insert(CaptureResponseCauseV1::LateClock(index));
        }
        self.first.is_none()
    }

    pub(crate) fn send_once(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        committed: crate::ProtectedBrokerOutcomeCommittedAdvancementV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        deadline: u64,
    ) {
        if self.attempted {
            self.first.get_or_insert(CaptureResponseCauseV1::Closed);
            return;
        }
        self.attempted = true;
        self.committed = Some(committed);
        if !self.bookend(session, storage, output, deadline, 0) { return; }
        let Some(committed) = self.committed.take() else { return; };
        self.send = Some(session.send_authenticated_response(committed));
        if matches!(&self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
            self.first = Some(CaptureResponseCauseV1::Send);
        }
        if !self.bookend(session, storage, output, deadline, 1) { return; }

        while matches!(&self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(_)))) {
            self.readiness = Some(crate::production_service::wait_output_original(session, true, deadline));
            if matches!(&self.readiness, Some(Err(_))) {
                self.first = Some(CaptureResponseCauseV1::Readiness);
            }
            if !self.bookend(session, storage, output, deadline, 2) { return; }
            let pending = match self.send.take() {
                Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(pending))) => pending,
                retained => {
                    self.send = retained;
                    self.first.get_or_insert(CaptureResponseCauseV1::Closed);
                    return;
                }
            };
            // Only successful Pending custody moves forward to the identical
            // packet's next send. Errors and postcheck debt are never replaced.
            self.send = Some(session.send_authenticated_response(pending));
            if matches!(&self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
                self.first = Some(CaptureResponseCauseV1::Send);
            }
            if !self.bookend(session, storage, output, deadline, 2) { return; }
        }
    }
}

// The original Acquire and both fixed successor requests are retained beside
// these closed reservoirs, never converted to BeforeEffect. Conflict closes
// only transport stop-and-wait, not native custody; inventory is observation.
pub(crate) struct OriginalMountNonadmittingTerminalV1 {
    preparation: crate::endpoint::RetainedOriginalBrokerOutcomeV1,
    prepared: Option<Result<bool, crate::BrokerSessionSecurityError>>,
    committed: Option<ProtectedBrokerOutcomeCommitResultV1>,
    native_send: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    owner_post: Option<Result<(), crate::BrokerSessionSecurityError>>,
    clock_post: Option<Result<u64, crate::BrokerSessionSecurityError>>,
    stage: OriginalMountTerminalStageV1,
    first_stage: Option<OriginalMountTerminalStageV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum OriginalMountTerminalStageV1 {
    Prepare,
    Sign,
    Commit,
    Send,
    Sent,
    Ended,
}

impl OriginalMountNonadmittingTerminalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            preparation: crate::endpoint::RetainedOriginalBrokerOutcomeV1::new(),
            prepared: None,
            committed: None,
            native_send: None,
            owner_post: None,
            clock_post: None,
            stage: OriginalMountTerminalStageV1::Prepare,
            first_stage: None,
        }
    }

    pub(crate) fn stage(&self) -> OriginalMountTerminalStageV1 { self.stage }

    pub(crate) fn has_committed(&self) -> bool {
        matches!(self.committed, Some(ProtectedBrokerOutcomeCommitResultV1::Committed(_)))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_stage {
            Some(OriginalMountTerminalStageV1::Prepare | OriginalMountTerminalStageV1::Sign) => {
                self.preparation.failure().map(|cause| cause as &dyn std::error::Error)
                    .or_else(|| self.prepared.as_ref().and_then(|result| result.as_ref().err())
                        .map(|cause| cause as &dyn std::error::Error))
            }
            Some(OriginalMountTerminalStageV1::Commit) => match self.committed.as_ref() {
                Some(ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) => Some(error),
                _ => None,
            },
            Some(OriginalMountTerminalStageV1::Send) => self.native_send.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            _ => None,
        }
    }

    pub(crate) fn post_failure(&self) -> Option<&crate::BrokerSessionSecurityError> {
        self.owner_post.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.clock_post.as_ref().and_then(|result| result.as_ref().err()))
    }

    pub(crate) fn prepare(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &crate::DormantReceivedBrokerRequestV1,
    ) -> bool {
        if self.stage != OriginalMountTerminalStageV1::Prepare || self.prepared.is_some() {
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Ended;
        self.prepared = Some(session.prepare_original_nonadmitting_terminal(request, &mut self.preparation));
        if !matches!(self.prepared, Some(Ok(true))) {
            self.refuse(OriginalMountTerminalStageV1::Prepare);
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Sign;
        true
    }

    pub(crate) fn sign(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &crate::DormantReceivedBrokerRequestV1,
    ) -> bool {
        if self.stage != OriginalMountTerminalStageV1::Sign {
            return false;
        }
        // Irreversible purpose prearm precedes even a returned signing refusal.
        self.stage = OriginalMountTerminalStageV1::Ended;
        if !session.sign_original_nonadmitting_terminal(request, &mut self.preparation) {
            self.refuse(OriginalMountTerminalStageV1::Sign);
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Commit;
        true
    }

    pub(crate) fn prepare_inventory(
        &mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        request: &crate::DormantReceivedBrokerRequestV1,
        body: &mut Option<Vec<u8>>,
    ) -> bool {
        if self.stage != OriginalMountTerminalStageV1::Prepare || self.prepared.is_some()
            || self.preparation.endpoint.message.is_some() || body.is_none()
        {
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Ended;
        self.prepared = Some(session.prepare_original_inventory_outcome(request, &mut self.preparation, body));
        if !matches!(self.prepared, Some(Ok(true))) {
            self.refuse(OriginalMountTerminalStageV1::Prepare);
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Sign;
        true
    }

    pub(crate) fn commit(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        if self.stage != OriginalMountTerminalStageV1::Commit || self.committed.is_some() {
            return false;
        }
        // All receiver occupancy checks precede the infallible immediate park.
        let Some(pending) = self.preparation.take_pending() else { return false; };
        self.stage = OriginalMountTerminalStageV1::Ended;
        self.committed = Some(session.commit_broker_outcome(pending));
        if !matches!(self.committed, Some(ProtectedBrokerOutcomeCommitResultV1::Committed(_))) {
            self.refuse(OriginalMountTerminalStageV1::Commit);
            return false;
        }
        self.stage = OriginalMountTerminalStageV1::Send;
        true
    }

    pub(crate) fn recheck(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        let Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = self.committed.as_ref() else {
            return false;
        };
        if self.post_failure().is_some() {
            return false;
        }
        self.owner_post = Some(session.compare_original_nonadmitting_outcome(committed));
        // Owner refusal never skips the original paired-clock observation.
        self.clock_post = Some(DormantAuthenticatedBrokerSessionV1::original_nonadmitting_clock(committed));
        self.post_failure().is_none()
    }

    pub(crate) fn send(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1) -> bool {
        if self.stage != OriginalMountTerminalStageV1::Send || self.native_send.is_some() {
            return false;
        }
        let Some(ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = self.committed.as_ref() else {
            return false;
        };
        self.stage = OriginalMountTerminalStageV1::Ended;
        let sent = session.send_original_nonadmitting_packet(committed, &mut self.native_send);
        if !sent { self.refuse(OriginalMountTerminalStageV1::Send); }
        let current = self.recheck(session);
        if sent && current {
            self.stage = OriginalMountTerminalStageV1::Sent;
            return true;
        }
        false
    }

    fn refuse(&mut self, stage: OriginalMountTerminalStageV1) {
        if self.first_stage.is_none() { self.first_stage = Some(stage); }
        self.stage = OriginalMountTerminalStageV1::Ended;
    }
}

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorCommitResultV1,
    DormantBrokerDescriptorSendProgressV1, DormantBrokerDescriptorTerminalReplayRecoveryProgressV1,
    DormantBrokerDescriptorTerminalReplaySendProgressV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerExecutionFailureV1, DormantBrokerFailureV1, DormantBrokerResponseSendProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantBrokerTerminalReplaySendProgressV1,
    DormantBrokerTerminalReplayV1, DormantHostBrokerEffectAdapterV1,
    ProtectedBrokerOutcomeCommitResultV1,
};

/// Reports a fail-closed production response completion failure.
///
/// The associated completion method consumes and closes the authenticated
/// session on every error. A client may reconnect and replay its exact request;
/// the protected journal remains the sole recovery authority.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerResponseErrorV1 {
    /// A protected outcome commit remained ambiguous after exact readback.
    #[error("broker response commit requires process restart and exact replay")]
    CommitRecovery,
    /// Host descriptor receipt finalization remained ambiguous.
    #[error("Host descriptor response finalization requires exact replay")]
    HostFinalization,
    /// A protected Host descriptor replay could not be reopened exactly.
    #[error("Host descriptor terminal replay could not be reopened")]
    DescriptorReplay,
    /// An effect began without a sealed observation that was safe to recommit.
    #[error("broker effect outcome requires reconnect and exact replay")]
    OutcomeRecovery,
    /// A pre-effect rejection could not be signed and committed exactly.
    #[error("broker rejection could not be committed: {0}")]
    Terminalization(#[from] crate::BrokerSessionSecurityError),
    /// Protected currentness or transport failed while sending a response.
    #[error("broker response transport failed: {0}")]
    Transport(#[from] DormantBrokerSessionHandshakeErrorV1),
    /// A coverage response has no actual domain owner for fresh bookends.
    #[error("coverage response requires its original domain owner")]
    CoverageOwnerMissing,
    /// The same Mount owner rejected a fresh response bookend.
    #[error(transparent)]
    CoverageMount(aos_sandbox_mount::DormantMountBrokerCallErrorV1),
    /// The same Storage/output owners rejected a fresh response bookend.
    #[error(transparent)]
    CoverageStorage(aos_sandbox_storage::DormantStorageBrokerCallErrorV1),
}

// These are concrete loans into the two existing sealed owners, not a caller
// predicate or a detached fence token. The ordinary recipe remains None.
pub(crate) enum GitCoverageResponseOwnerV1<'owner> {
    Mount(&'owner mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1),
    Storage {
        storage: &'owner mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &'owner aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    },
}

impl GitCoverageResponseOwnerV1<'_> {
    fn recheck(&mut self, deadline: u64) -> Result<(), ProductionBrokerResponseErrorV1> {
        crate::dormant_handshake::check_production_deadline(deadline)?;
        match self {
            Self::Mount(mount) => mount.recheck_git_coverage_response_v1(deadline)
                .map_err(ProductionBrokerResponseErrorV1::CoverageMount)?,
            Self::Storage { storage, output } => storage
                .recheck_git_coverage_response_v1(output, deadline)
                .map_err(ProductionBrokerResponseErrorV1::CoverageStorage)?,
        }
        crate::dormant_handshake::check_production_deadline(deadline)?;
        Ok(())
    }
}

fn is_coverage_method(method: aos_proto::aos::sandbox::local::v1::BrokerMethod) -> bool {
    crate::dormant_handshake::git_coverage::is_mount(method)
        || crate::dormant_handshake::git_coverage::is_storage(method)
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Completes one ordinary domain dispatch without weakening effect ambiguity.
    ///
    /// A pre-effect rejection is the only failure eligible for a newly signed
    /// terminal error. Once domain dispatch begins, this method retries only a
    /// sealed observation already retained by the session owner. An unobserved
    /// or still-indeterminate effect consumes the session so reconnect and
    /// exact request replay must resolve it through protected state.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when terminal error commit,
    /// observed-success recovery, protected response commit, or transport does
    /// not complete exactly before the boot-time deadline.
    pub fn finish_ordinary_dispatch<Domain>(
        self,
        dispatched: Result<
            ProtectedBrokerOutcomeCommitResultV1,
            DormantBrokerExecutionFailureV1<Domain>,
        >,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        self.finish_dispatch_with_coverage_v1(dispatched, deadline_boottime_nanoseconds, None)
    }

    pub(crate) fn finish_dispatch_with_coverage_v1<Domain>(
        mut self,
        dispatched: Result<
            ProtectedBrokerOutcomeCommitResultV1,
            DormantBrokerExecutionFailureV1<Domain>,
        >,
        deadline_boottime_nanoseconds: u64,
        owner: Option<GitCoverageResponseOwnerV1<'_>>,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let committed = match dispatched {
            Ok(committed) => committed,
            Err(DormantBrokerExecutionFailureV1::BeforeEffect { request, .. }) => self
                .commit_authenticated_error_response(
                    request,
                    DormantBrokerFailureV1::InvalidRequest,
                )?,
            Err(DormantBrokerExecutionFailureV1::OutcomeUnknown { custody, .. }) => self
                .retry_observed_success_and_commit(custody)
                .map_err(|_| ProductionBrokerResponseErrorV1::OutcomeRecovery)?,
        };

        self.finish_response_with_coverage_v1(committed, deadline_boottime_nanoseconds, owner)
    }

    /// Completes protected readback and atomically sends an ordinary response.
    ///
    /// Backpressure is retried only with the identical committed packet and is
    /// bounded by `deadline_boottime_nanoseconds`. Any ambiguous commit,
    /// currentness failure, or fatal transport consumes the session so a caller
    /// cannot dispatch another request on uncertain state.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when exact commit readback
    /// remains ambiguous, transport currentness fails, or the boot-time
    /// deadline expires.
    pub fn finish_authenticated_response(
        self,
        committed: ProtectedBrokerOutcomeCommitResultV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        self.finish_response_with_coverage_v1(committed, deadline_boottime_nanoseconds, None)
    }

    fn finish_response_with_coverage_v1(
        mut self,
        committed: ProtectedBrokerOutcomeCommitResultV1,
        deadline_boottime_nanoseconds: u64,
        mut owner: Option<GitCoverageResponseOwnerV1<'_>>,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let committed = match committed {
            ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => committed,
            ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { recovery, .. } => {
                match self.recover_broker_outcome_commit(recovery) {
                    ProtectedBrokerOutcomeCommitResultV1::Committed(committed) => committed,
                    ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. } => {
                        return Err(ProductionBrokerResponseErrorV1::CommitRecovery);
                    }
                }
            }
        };

        if is_coverage_method(committed.method()) && owner.is_none() {
            return Err(ProductionBrokerResponseErrorV1::CoverageOwnerMissing);
        }
        let mut pending = committed;
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            if let Some(owner) = &mut owner {
                owner.recheck(deadline_boottime_nanoseconds)?;
            }
            let sent = self.send_authenticated_response(pending);
            // Keep the actual owning send result through the independent
            // domain bookend. A transport error remains the first cause.
            let postchecked = match &mut owner {
                Some(owner) => owner.recheck(deadline_boottime_nanoseconds),
                None => Ok(()),
            };
            let progress = sent?;
            postchecked?;
            match progress {
                DormantBrokerResponseSendProgressV1::Sent(_) => {
                    return self.finish_sent_response(deadline_boottime_nanoseconds);
                }
                DormantBrokerResponseSendProgressV1::Pending(retained) => {
                    self.wait_for_response_readiness(deadline_boottime_nanoseconds)?;
                    pending = retained;
                }
                DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. } => {
                    return Err(error.into());
                }
            }
        }
    }

    /// Completes and sends one Host scope response with exact descriptors.
    ///
    /// The sealed Host callsite is used only when the terminal CAS committed
    /// but its Host receipt still needs finalization. Backpressure retains the
    /// committed packet and descriptor order exactly.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session for unresolved commit or
    /// Host receipt ambiguity, protected-currentness failure, fatal ancillary
    /// transport, or an expired boot-time deadline.
    pub fn finish_host_descriptor_response(
        mut self,
        committed: DormantBrokerDescriptorCommitResultV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let committed = match committed {
            DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
            DormantBrokerDescriptorCommitResultV1::RecoveryRequired(recovery) => {
                match self.recover_descriptor_response_commit(recovery) {
                    DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
                    DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(retained) => {
                        match self.recover_host_scope_terminal_finalization(
                            retained,
                            DormantHostBrokerEffectAdapterV1::new(host, artifacts),
                        ) {
                            DormantBrokerDescriptorCommitResultV1::Committed(committed) => {
                                committed
                            }
                            _ => return Err(ProductionBrokerResponseErrorV1::HostFinalization),
                        }
                    }
                    DormantBrokerDescriptorCommitResultV1::RecoveryRequired(_) => {
                        return Err(ProductionBrokerResponseErrorV1::CommitRecovery);
                    }
                }
            }
            DormantBrokerDescriptorCommitResultV1::HostFinalizationRequired(retained) => match self
                .recover_host_scope_terminal_finalization(
                    retained,
                    DormantHostBrokerEffectAdapterV1::new(host, artifacts),
                ) {
                DormantBrokerDescriptorCommitResultV1::Committed(committed) => committed,
                _ => return Err(ProductionBrokerResponseErrorV1::HostFinalization),
            },
        };

        let mut pending = committed;
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            match self.send_authenticated_descriptor_response(pending)? {
                DormantBrokerDescriptorSendProgressV1::Sent(_) => {
                    return self.finish_sent_response(deadline_boottime_nanoseconds);
                }
                DormantBrokerDescriptorSendProgressV1::Pending(retained) => {
                    self.wait_for_response_readiness(deadline_boottime_nanoseconds)?;
                    pending = retained;
                }
                DormantBrokerDescriptorSendProgressV1::RecoveryRequired(retained) => {
                    return Err(retained.into_error().into());
                }
            }
        }
    }

    /// Resends one descriptor-free protected terminal response byte-for-byte.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session for descriptor-bearing
    /// replay, changed currentness, fatal transport, or deadline expiry.
    pub fn finish_authenticated_terminal_replay(
        self,
        replay: DormantBrokerTerminalReplayV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        self.finish_replay_with_coverage_v1(replay, deadline_boottime_nanoseconds, None)
    }

    pub(crate) fn finish_replay_with_coverage_v1(
        mut self,
        replay: DormantBrokerTerminalReplayV1,
        deadline_boottime_nanoseconds: u64,
        mut owner: Option<GitCoverageResponseOwnerV1<'_>>,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        if is_coverage_method(replay.method()) && owner.is_none() {
            return Err(ProductionBrokerResponseErrorV1::CoverageOwnerMissing);
        }
        let mut pending = replay;
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            if let Some(owner) = &mut owner {
                owner.recheck(deadline_boottime_nanoseconds)?;
            }
            let sent = self.send_authenticated_terminal_replay(pending);
            let postchecked = match &mut owner {
                Some(owner) => owner.recheck(deadline_boottime_nanoseconds),
                None => Ok(()),
            };
            let progress = sent?;
            postchecked?;
            match progress {
                DormantBrokerTerminalReplaySendProgressV1::Sent(_) => {
                    return self.finish_sent_response(deadline_boottime_nanoseconds);
                }
                DormantBrokerTerminalReplaySendProgressV1::Pending(retained) => {
                    self.wait_for_response_readiness(deadline_boottime_nanoseconds)?;
                    pending = retained;
                }
                DormantBrokerTerminalReplaySendProgressV1::RecoveryRequired { error, .. } => {
                    return Err(error.into());
                }
                DormantBrokerTerminalReplaySendProgressV1::DescriptorRecoveryRequired(_) => {
                    return Err(ProductionBrokerResponseErrorV1::DescriptorReplay);
                }
            }
        }
    }

    /// Reopens and resends one Host descriptor terminal replay exactly.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when Host readback cannot
    /// reproduce the exact terminal body and descriptor roles, protected
    /// currentness fails, transport is fatal, or the deadline expires.
    pub async fn finish_host_descriptor_terminal_replay(
        mut self,
        replay: DormantBrokerDescriptorTerminalReplayV1,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        let ready = match self
            .reopen_host_scope_terminal_replay(
                replay,
                DormantHostBrokerEffectAdapterV1::new(host, artifacts),
            )
            .await
        {
            DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::Ready(ready) => ready,
            DormantBrokerDescriptorTerminalReplayRecoveryProgressV1::RecoveryRequired {
                ..
            } => return Err(ProductionBrokerResponseErrorV1::DescriptorReplay),
        };

        let mut pending = ready;
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            match self.send_authenticated_descriptor_terminal_replay(pending) {
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Sent(_) => {
                    return self.finish_sent_response(deadline_boottime_nanoseconds);
                }
                DormantBrokerDescriptorTerminalReplaySendProgressV1::Pending(retained) => {
                    self.wait_for_response_readiness(deadline_boottime_nanoseconds)?;
                    pending = retained;
                }
                DormantBrokerDescriptorTerminalReplaySendProgressV1::RecoveryRequired {
                    error,
                    ..
                } => return Err(error.into()),
            }
        }
    }

    // A sent packet may have reached its peer even when the deadline just expired.
    fn finish_sent_response(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerResponseErrorV1> {
        crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
        Ok(self)
    }

    fn wait_for_response_readiness(
        &self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(), ProductionBrokerResponseErrorV1> {
        crate::dormant_handshake::wait_for_handshake_readiness(
            self.as_fd()?,
            true,
            deadline_boottime_nanoseconds,
        )?;
        Ok(())
    }
}
