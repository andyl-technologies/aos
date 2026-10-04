//! Bounded production receipt for authenticated broker requests.
//!
//! The public receipt methods consume the authenticated session. A successful
//! receipt returns that session beside one normalized request or replay event;
//! every error drops both transport and protected in-memory custody so the
//! service must reconnect and reopen the fixed journal.
//! Ready sockets and successful durable readbacks still require a live deadline
//! before a request is handed to the effect dispatcher. Expiry never erases an
//! admitted request; its protected record remains available for exact recovery.

use crate::{
    DormantAuthenticatedBrokerSessionV1, DormantBrokerDescriptorInFlightReplayV1,
    DormantBrokerDescriptorRequestReceiveProgressV1, DormantBrokerDescriptorTerminalReplayV1,
    DormantBrokerOutcomeUnknownV1, DormantBrokerRequestReceiveProgressV1,
    DormantBrokerSessionHandshakeErrorV1, DormantBrokerTerminalReplayV1,
    DormantReceivedBrokerDescriptorRequestV1, DormantReceivedBrokerRequestV1,
};

use std::os::fd::{AsFd, OwnedFd};

/// Reports a fail-closed production request-receipt failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerReceiveErrorV1 {
    /// Protected request installation remained ambiguous after exact readback.
    #[error("broker request admission requires process restart and exact replay")]
    AdmissionRecovery,
    /// Protected currentness or request transport failed.
    #[error("broker request transport failed: {0}")]
    Transport(#[from] DormantBrokerSessionHandshakeErrorV1),
}

/// Retains one normalized descriptor-free production receipt.
#[must_use = "dispatch, recover, or replay the authenticated request event"]
pub enum ProductionBrokerRequestEventV1 {
    /// A new request is durably admitted and ready for method dispatch.
    Request(DormantReceivedBrokerRequestV1),
    /// The request exactly repeats an effect whose outcome remains unknown.
    InFlightReplay(DormantBrokerOutcomeUnknownV1),
    /// The request exactly repeats a protected descriptor-free terminal result.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The terminal result must reopen its Host-owned descriptors before resend.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
}

/// Retains one normalized Host production receipt.
#[must_use = "dispatch, recover, or replay the authenticated Host request event"]
pub enum ProductionHostBrokerRequestEventV1 {
    /// A new request and its authenticated method-selected FD table are admitted.
    Request(DormantReceivedBrokerDescriptorRequestV1),
    /// The request exactly repeats an effect whose outcome remains unknown.
    InFlightReplay(DormantBrokerDescriptorInFlightReplayV1),
    /// The request exactly repeats a protected descriptor-free terminal result.
    TerminalReplay(DormantBrokerTerminalReplayV1),
    /// The terminal result must reopen its Host-owned descriptors before resend.
    DescriptorTerminalReplay(DormantBrokerDescriptorTerminalReplayV1),
}

/// Retains one original Mount request receipt and its same-queue negative alias.
///
/// This purpose-closed owner starts from the genuine authenticated session. It
/// parks returned progress before the post-receive deadline check. Ambiguous
/// admission and replay remain resident and terminal: this route does not call
/// the ordinary consuming recovery APIs, synthesize Live, or authorize Acquire.
/// Lower receive prefixes that never return and allocation funding are outside
/// this returned-owner boundary. The alias adds one selected descriptor.
pub struct ProductionOriginalMountReceiptV1 {
    alias: Option<Result<OwnedFd, std::io::Error>>,
    session: DormantAuthenticatedBrokerSessionV1,
    progress: Option<DormantBrokerRequestReceiveProgressV1>,
    deadline: u64,
    attempted: bool,
    ended: bool,
    first_failure: Option<ProductionBrokerReceiveErrorV1>,
    shutdown_failure: Option<std::io::Error>,
    live_verification: Option<Result<crate::DormantBrokerOutcomeVerificationV1, crate::BrokerSessionSecurityError>>,
    live_clock: Option<Result<u64, crate::BrokerSessionSecurityError>>,
    live: Option<Result<aos_sandbox_protocol::LiveValidatedAcquireMountSourceRequest, aos_sandbox_protocol::ProtocolValidationError>>,
    body: Option<Vec<u8>>,
    authority: Option<aos_sandbox_mount::broker::OriginalMountAcquireAuthorityV1>,
    live_attempted: bool,
    terminal: crate::production_response::OriginalMountNonadmittingTerminalV1,
    terminal_owner_post: Option<Result<crate::DormantBrokerOutcomeVerificationV1, crate::BrokerSessionSecurityError>>,
    terminal_clock_post: Option<Result<u64, crate::BrokerSessionSecurityError>>,
    inventory_progress: [Option<DormantBrokerRequestReceiveProgressV1>; 2],
    inventory_receive: [Option<Result<(), ProductionBrokerReceiveErrorV1>>; 2],
    inventory_bodies: [Option<Vec<u8>>; 2],
    inventory_actions: [Option<Result<(), aos_sandbox_mount::MountError>>; 2],
    inventory_responses: [crate::production_response::OriginalMountNonadmittingTerminalV1; 2],
    inventory_index: usize,
    inventory_first_failure: Option<usize>,
    terminal_shutdown: Option<Result<(), std::io::Error>>,
    diagnostic_phase: OriginalMountDiagnosticPhaseV1,
    selected_first_source: Option<OriginalMountFirstFailureSourceV1>,
    selected_crossing: Option<OriginalMountSelectedCrossingV1>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalMountDiagnosticPhaseV1 {
    Acquire,
    Selected,
}

// Prearmed at the actual delegate, so negative end can find a returned cause
// even when an independent post observation unwinds before the wrapper returns.
#[derive(Clone, Copy)]
enum OriginalMountSelectedCrossingV1 {
    Terminal,
    InventoryReceive(usize),
    InventoryAction(usize),
    InventoryResponse(usize),
    ReceiptPost,
}

// Only a source/index is retained. The actual cause stays in its owning Result,
// so later authority.stop() and independent debt cannot replace its chronology.
#[derive(Clone, Copy)]
enum OriginalMountFirstFailureSourceV1 {
    Alias,
    Receive,
    AcquireOwner,
    AcquireClock,
    Live,
    Authority,
    TerminalAction,
    TerminalPost,
    OwnerPost,
    ClockPost,
    InventoryReceive(usize),
    InventoryAction(usize),
    InventoryResponse(usize),
    InventoryPost(usize),
}

impl std::fmt::Debug for ProductionOriginalMountReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductionOriginalMountReceiptV1([original receipt])")
    }
}

/// Borrows an actual original receipt failure without copying its owning cause.
pub enum ProductionOriginalMountReceiptFailureV1<'owner> {
    /// Same-queue alias duplication failed before receiving a request.
    Alias(&'owner std::io::Error),
    /// Deadline, transport, purpose or durable admission failed.
    Receive(&'owner ProductionBrokerReceiveErrorV1),
    /// The same protected request or clock verification failed.
    Currentness(&'owner crate::BrokerSessionSecurityError),
    /// The sole Live decoder rejected the original body.
    Protocol(&'owner aos_sandbox_protocol::ProtocolValidationError),
    /// Independent signed-domain admission retained its original first cause.
    Authority(aos_sandbox_mount::broker::OriginalMountAcquireAuthorityFailureV1<'owner>),
    /// The selected terminal retains its actual signing, commit or native cause.
    Terminal(&'owner (dyn std::error::Error + 'static)),
    /// An independent terminal owner or original-clock observation failed.
    TerminalPost(&'owner crate::BrokerSessionSecurityError),
    /// The original owner ended without a returned cause, including unwind.
    Ended,
}

impl std::fmt::Debug for ProductionOriginalMountReceiptFailureV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Alias(_) => "ProductionOriginalMountReceiptFailureV1::Alias",
            Self::Receive(_) => "ProductionOriginalMountReceiptFailureV1::Receive",
            Self::Currentness(_) => "ProductionOriginalMountReceiptFailureV1::Currentness",
            Self::Protocol(_) => "ProductionOriginalMountReceiptFailureV1::Protocol",
            Self::Authority(_) => "ProductionOriginalMountReceiptFailureV1::Authority",
            Self::Terminal(_) => "ProductionOriginalMountReceiptFailureV1::Terminal",
            Self::TerminalPost(_) => "ProductionOriginalMountReceiptFailureV1::TerminalPost",
            Self::Ended => "ProductionOriginalMountReceiptFailureV1::Ended",
        })
    }
}

struct OriginalMountReceiptBoundaryV1<'owner> {
    owner: &'owner mut ProductionOriginalMountReceiptV1,
    completed: bool,
}

impl Drop for OriginalMountReceiptBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl ProductionOriginalMountReceiptV1 {
    /// Receives once while retaining every returned progress and first cause.
    ///
    /// # Errors
    ///
    /// Returns a borrowed terminal failure for alias, deadline, transport,
    /// non-Acquire, replay or ambiguous admission. No later call observes again.
    pub fn receive_once(&mut self) -> Result<(), ProductionOriginalMountReceiptFailureV1<'_>> {
        if self.attempted || self.ended {
            self.end();
            return Err(self.failure_or_ended());
        }
        self.attempted = true;

        let succeeded = {
            let mut boundary = OriginalMountReceiptBoundaryV1 {
                owner: self,
                completed: false,
            };
            let result = boundary.owner.receive_inner();
            match result {
                Ok(()) => {
                    boundary.completed = true;
                    true
                }
                Err(cause) => {
                    boundary.owner.end();
                    if boundary.owner.first_failure.is_none() {
                        boundary.owner.first_failure = Some(cause);
                    }
                    false
                }
            }
        };

        if succeeded {
            Ok(())
        } else {
            Err(self.failure_or_ended())
        }
    }

    fn receive_inner(&mut self) -> Result<(), ProductionBrokerReceiveErrorV1> {
        // The entire session is already resident before this fallible borrow
        // and duplication. The alias is never used to receive or retry traffic.
        if !self.arm_original_fence() {
            return Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery);
        }

        loop {
            self.session.receive_production_request_progress(
                self.deadline,
                &mut self.progress,
            )?;
            match self.progress.as_ref() {
                Some(DormantBrokerRequestReceiveProgressV1::Pending) => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.session.as_fd()?,
                        false,
                        self.deadline,
                    )?;
                    // Pending contains no returned request/recovery owner. Only
                    // this empty progress may be replaced on the same session.
                    self.progress = None;
                }
                Some(DormantBrokerRequestReceiveProgressV1::Received(request))
                    if request.method()
                        == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_ACQUIRE_SOURCE =>
                {
                    return Ok(());
                }
                _ => return Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery),
            }
        }
    }

    pub(crate) fn arm_original_fence(&mut self) -> bool {
        if self.ended {
            return false;
        }
        if self.alias.is_some() { return matches!(self.alias, Some(Ok(_))); }
        match self.session.as_fd() {
            Ok(original) => {
                self.alias = Some(rustix::io::fcntl_dupfd_cloexec(original, 0).map_err(std::io::Error::from));
                if matches!(self.alias, Some(Ok(_))) { return true; }
            }
            Err(cause) => {
                if self.first_failure.is_none() {
                    self.first_failure = Some(ProductionBrokerReceiveErrorV1::Transport(cause));
                }
            }
        }
        self.end();
        false
    }

    /// Borrows the actual received request without releasing the original owner.
    #[must_use]
    pub fn request(&self) -> Option<&DormantReceivedBrokerRequestV1> {
        if self.ended || self.first_failure.is_some() {
            return None;
        }
        match self.progress.as_ref() {
            Some(DormantBrokerRequestReceiveProgressV1::Received(request)) => Some(request),
            _ => None,
        }
    }

    /// Admits the original body through the same Live and signed-domain engines.
    ///
    /// The protected BSA gate, clock, decoded Live and exact copied body are
    /// resident before moving complete inputs into their inline authority slot.
    /// The original request remains resident throughout. Allocation of the
    /// bounded body copy is a funding exclusion, not universal unwind closure.
    ///
    /// # Errors
    ///
    /// Lends the actual retained first decoder, currentness or domain cause and
    /// ends the original queue on refusal. No readback permits retry or replay.
    pub fn admit_original_acquire<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<(), ProductionOriginalMountReceiptFailureV1<'_>> {
        if self.ended || self.live_attempted {
            self.end();
            return Err(self.failure_or_ended());
        }
        self.live_attempted = true;
        let succeeded = {
            let mut boundary = OriginalMountReceiptBoundaryV1 {
                owner: self,
                completed: false,
            };
            let succeeded = boundary.owner.admit_original_acquire_inner(broker);
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded { Ok(()) } else { Err(self.failure_or_ended()) }
    }

    fn admit_original_acquire_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.progress.as_ref() else {
            return false;
        };
        if !self.session.park_original_mount_live(
            request,
            &mut self.live_verification,
            &mut self.live_clock,
            &mut self.live,
        ) {
            return false;
        }
        self.body = Some(request.body().to_vec());
        if self.authority.is_some() || !matches!(self.live, Some(Ok(_))) || self.body.is_none() {
            return false;
        }
        match (self.live.take(), self.body.take()) {
            (Some(Ok(live)), Some(body)) => {
                self.authority = Some(aos_sandbox_mount::broker::OriginalMountAcquireAuthorityV1::new(live, body));
            }
            (actual_live, actual_body) => {
                self.live = actual_live;
                self.body = actual_body;
                return false;
            }
        }
        let Some(artifacts) = request.authorization_artifacts() else { return false; };
        match self.authority.as_mut() {
            Some(authority) => broker.prepare_original_acquire_authority(authority, artifacts).is_ok(),
            None => false,
        }
    }

    pub(crate) fn authority_mut(&mut self) -> Option<&mut aos_sandbox_mount::broker::OriginalMountAcquireAuthorityV1> {
        if self.ended { None } else { self.authority.as_mut() }
    }

    pub(crate) fn recheck_original_request(&mut self) -> bool {
        if self.ended || self.authority.is_none() { return false; }
        let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.progress.as_ref() else {
            self.end();
            return false;
        };
        if !self.session.recheck_original_mount_request(request, &mut self.live_verification, &mut self.live_clock) {
            self.end();
            return false;
        }
        true
    }

    pub(crate) fn terminal_stage(&self) -> crate::production_response::OriginalMountTerminalStageV1 {
        self.terminal.stage()
    }

    pub(crate) fn advance_nonadmitting_terminal(&mut self) -> bool {
        self.arm_selected_diagnostics();
        self.retain_selected_authority_failure();
        if self.selected_first_source.is_some() {
            return false;
        }
        self.selected_crossing = Some(OriginalMountSelectedCrossingV1::Terminal);
        let advanced = self.advance_nonadmitting_terminal_inner();
        self.capture_selected_crossing();
        self.retain_selected_authority_failure();
        advanced
    }

    fn advance_nonadmitting_terminal_inner(&mut self) -> bool {
        use crate::production_response::OriginalMountTerminalStageV1 as Stage;
        if self.ended { return false; }
        match self.terminal.stage() {
            Stage::Prepare | Stage::Sign => {
                let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.progress.as_ref() else {
                    return false;
                };
                if self.terminal.stage() == Stage::Prepare {
                    self.terminal.prepare(&mut self.session, request)
                } else {
                    self.terminal.sign(&mut self.session, request)
                }
            }
            Stage::Commit => self.terminal.commit(&mut self.session),
            Stage::Send => self.terminal.send(&mut self.session),
            Stage::Sent => true,
            Stage::Ended => false,
        }
    }

    pub(crate) fn recheck_nonadmitting_terminal(&mut self) -> bool {
        // This is the first receipt-owned selected bookend. Outer Root/startup
        // causes remain separately owned by the cycle's existing first-stage.
        self.arm_selected_diagnostics();
        self.retain_selected_authority_failure();
        let current = self.recheck_nonadmitting_terminal_inner();
        self.capture_selected_crossing();
        current
    }

    fn recheck_nonadmitting_terminal_inner(&mut self) -> bool {
        let active = self.inventory_index.min(1);
        if self.inventory_progress[active].is_some() {
            if self.inventory_responses[active].has_committed() {
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(active));
                return self.inventory_responses[active].recheck(&mut self.session);
            }
            if let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.inventory_progress[active].as_ref() {
                let Some(Ok(initial)) = self.live_verification.as_ref() else { return false; };
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::ReceiptPost);
                return self.session.observe_original_mount_terminal_prefix(
                    request, initial, &mut self.terminal_owner_post, &mut self.terminal_clock_post,
                );
            }
        }
        if self.inventory_index == 1 && self.inventory_progress[1].is_none() {
            self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(0));
            return self.inventory_responses[0].recheck(&mut self.session);
        }
        if self.terminal.has_committed() {
            self.selected_crossing = Some(OriginalMountSelectedCrossingV1::Terminal);
            return self.terminal.recheck(&mut self.session);
        }
        let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.progress.as_ref() else {
            return false;
        };
        let Some(Ok(initial)) = self.live_verification.as_ref() else { return false; };
        self.selected_crossing = Some(OriginalMountSelectedCrossingV1::ReceiptPost);
        self.session.observe_original_mount_terminal_prefix(
            request, initial, &mut self.terminal_owner_post, &mut self.terminal_clock_post,
        )
    }

    pub(crate) fn advance_original_inventory<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
        root: &mut crate::ProductionSelectedRootMountSourceProviderV1,
    ) -> bool {
        self.arm_selected_diagnostics();
        self.retain_selected_authority_failure();
        if self.selected_first_source.is_some() {
            return false;
        }
        let index = self.inventory_index.min(1);
        let succeeded = self.advance_original_inventory_inner(broker, root);
        self.capture_selected_crossing();
        self.retain_selected_authority_failure();
        if !succeeded && self.inventory_first_failure.is_none() {
            self.inventory_first_failure = Some(index);
        }
        succeeded
    }

    fn advance_original_inventory_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
        root: &mut crate::ProductionSelectedRootMountSourceProviderV1,
    ) -> bool {
        use aos_proto::aos::sandbox::local::v1::BrokerMethod;
        use crate::production_response::OriginalMountTerminalStageV1 as Stage;
        if self.ended || self.terminal.stage() != Stage::Sent {
            return false;
        }
        if self.inventory_index == 2 {
            return true;
        }
        let index = self.inventory_index;
        if self.inventory_progress[index].is_none() {
            self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryReceive(index));
            self.inventory_receive[index] = Some(self.session.receive_production_request_progress(
                self.deadline, &mut self.inventory_progress[index],
            ));
            self.capture_selected_crossing();
            if !matches!(self.inventory_receive[index], Some(Ok(()))) {
                return false;
            }
            if matches!(self.inventory_progress[index], Some(DormantBrokerRequestReceiveProgressV1::Pending)) {
                self.inventory_progress[index] = None;
                return true;
            }
        }
        let Some(DormantBrokerRequestReceiveProgressV1::Received(request)) = self.inventory_progress[index].as_ref() else {
            return false;
        };
        let method = if index == 0 { BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES }
            else { BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_SOURCE_ACQUISITIONS };
        let previous = if index == 0 {
            self.progress.as_ref()
        } else {
            self.inventory_progress[0].as_ref()
        };
        let Some(DormantBrokerRequestReceiveProgressV1::Received(previous)) = previous else { return false; };
        if !request.is_original_mount_inventory_successor(previous, method) {
            return false;
        }

        let response = &mut self.inventory_responses[index];
        match response.stage() {
            Stage::Prepare => {
                if self.inventory_actions[index].is_none() {
                    self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryAction(index));
                    if index == 0 {
                        match broker.inventory_resources() {
                            Ok(body) => {
                                self.inventory_bodies[index] = Some(body);
                                self.inventory_actions[index] = Some(Ok(()));
                            }
                            Err(cause) => self.inventory_actions[index] = Some(Err(cause)),
                        }
                    } else {
                        let (Some(authority), Some(session)) = (self.authority.as_mut(), root.borrow_current_session()) else { return false; };
                        self.inventory_actions[index] = Some(broker.inventory_original_terminal_sources_v1(
                            authority, session, &mut self.inventory_bodies[index],
                        ));
                    }
                    self.capture_selected_crossing();
                    return matches!(self.inventory_actions[index], Some(Ok(())));
                }
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(index));
                response.prepare_inventory(&mut self.session, request, &mut self.inventory_bodies[index])
            }
            Stage::Sign => {
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(index));
                response.sign(&mut self.session, request)
            }
            Stage::Commit => {
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(index));
                response.commit(&mut self.session)
            }
            Stage::Send => {
                self.selected_crossing = Some(OriginalMountSelectedCrossingV1::InventoryResponse(index));
                response.send(&mut self.session)
            }
            Stage::Sent => {
                self.inventory_index += 1;
                true
            }
            Stage::Ended => false,
        }
    }

    fn arm_selected_diagnostics(&mut self) {
        use aos_sandbox_mount::broker::OriginalMountAcquireAuthorityFailureV1 as AuthorityFailure;
        use OriginalMountFirstFailureSourceV1 as Source;
        use ProductionOriginalMountReceiptFailureV1 as Failure;

        if self.diagnostic_phase == OriginalMountDiagnosticPhaseV1::Selected {
            return;
        }
        // Consult the unchanged Acquire priority before changing disposition.
        // A stopped-without-cause status is not a new owning error source.
        let earlier = match self.failure() {
            Some(Failure::Alias(_)) => Some(Source::Alias),
            Some(Failure::Receive(_)) => Some(Source::Receive),
            Some(Failure::Currentness(_)) => {
                if matches!(self.live_verification, Some(Err(_))) {
                    Some(Source::AcquireOwner)
                } else {
                    Some(Source::AcquireClock)
                }
            }
            Some(Failure::Protocol(_)) => Some(Source::Live),
            Some(Failure::Authority(AuthorityFailure::Ended)) => None,
            Some(Failure::Authority(_)) => Some(Source::Authority),
            _ => None,
        };
        self.diagnostic_phase = OriginalMountDiagnosticPhaseV1::Selected;
        self.selected_first_source = earlier;
    }

    fn retain_selected_source(&mut self, source: OriginalMountFirstFailureSourceV1) {
        if self.selected_first_source.is_none() {
            self.selected_first_source = Some(source);
        }
    }

    fn retain_selected_authority_failure(&mut self) {
        use aos_sandbox_mount::broker::OriginalMountAcquireAuthorityFailureV1 as AuthorityFailure;

        if self.selected_first_source.is_some() {
            return;
        }
        let genuine_cause = self.authority.as_ref()
            .and_then(|authority| authority.failure())
            .is_some_and(|cause| !matches!(cause, AuthorityFailure::Ended));
        if genuine_cause {
            self.retain_selected_source(OriginalMountFirstFailureSourceV1::Authority);
        }
    }

    fn capture_selected_crossing(&mut self) {
        use OriginalMountSelectedCrossingV1 as Crossing;
        use OriginalMountFirstFailureSourceV1 as Source;

        if self.diagnostic_phase != OriginalMountDiagnosticPhaseV1::Selected
            || self.selected_first_source.is_some()
        {
            return;
        }
        // Nested failure() follows its own owning first_stage, not a guessed
        // field priority. Native Send refusal therefore precedes its posts.
        let source = match self.selected_crossing {
            Some(Crossing::Terminal) if self.terminal.failure().is_some() => {
                Some(Source::TerminalAction)
            }
            Some(Crossing::Terminal) if self.terminal.post_failure().is_some() => {
                Some(Source::TerminalPost)
            }
            Some(Crossing::InventoryReceive(index))
                if matches!(self.inventory_receive[index], Some(Err(_))) =>
            {
                Some(Source::InventoryReceive(index))
            }
            Some(Crossing::InventoryAction(index))
                if matches!(self.inventory_actions[index], Some(Err(_))) =>
            {
                Some(Source::InventoryAction(index))
            }
            Some(Crossing::InventoryResponse(index))
                if self.inventory_responses[index].failure().is_some() =>
            {
                Some(Source::InventoryResponse(index))
            }
            Some(Crossing::InventoryResponse(index))
                if self.inventory_responses[index].post_failure().is_some() =>
            {
                Some(Source::InventoryPost(index))
            }
            Some(Crossing::ReceiptPost) if matches!(self.terminal_owner_post, Some(Err(_))) => {
                Some(Source::OwnerPost)
            }
            Some(Crossing::ReceiptPost) if matches!(self.terminal_clock_post, Some(Err(_))) => {
                Some(Source::ClockPost)
            }
            _ => None,
        };
        if let Some(source) = source {
            self.retain_selected_source(source);
        }
    }

    fn selected_failure(&self) -> Option<ProductionOriginalMountReceiptFailureV1<'_>> {
        use OriginalMountFirstFailureSourceV1 as Source;
        use ProductionOriginalMountReceiptFailureV1 as Failure;

        match self.selected_first_source? {
            Source::Alias => self.alias.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::Alias),
            Source::Receive => self.first_failure.as_ref().map(Failure::Receive),
            Source::AcquireOwner => self.live_verification.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::Currentness),
            Source::AcquireClock => self.live_clock.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::Currentness),
            Source::Live => self.live.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::Protocol),
            Source::Authority => self.authority.as_ref().and_then(|authority| authority.failure())
                .map(Failure::Authority),
            Source::TerminalAction => self.terminal.failure().map(Failure::Terminal),
            Source::TerminalPost => self.terminal.post_failure().map(Failure::TerminalPost),
            Source::OwnerPost => self.terminal_owner_post.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::TerminalPost),
            Source::ClockPost => self.terminal_clock_post.as_ref().and_then(|result| result.as_ref().err())
                .map(Failure::TerminalPost),
            Source::InventoryReceive(index) => self.inventory_receive[index].as_ref()
                .and_then(|result| result.as_ref().err()).map(Failure::Receive),
            Source::InventoryAction(index) => self.inventory_actions[index].as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| Failure::Terminal(cause)),
            Source::InventoryResponse(index) => self.inventory_responses[index].failure()
                .map(Failure::Terminal),
            Source::InventoryPost(index) => self.inventory_responses[index].post_failure()
                .map(Failure::TerminalPost),
        }
    }

    /// Borrows the first failure without observation, recovery or renewal.
    #[must_use]
    pub fn failure(&self) -> Option<ProductionOriginalMountReceiptFailureV1<'_>> {
        if self.diagnostic_phase == OriginalMountDiagnosticPhaseV1::Selected {
            return self.selected_failure()
                .or_else(|| self.ended.then_some(ProductionOriginalMountReceiptFailureV1::Ended));
        }
        if let Some(Err(cause)) = self.alias.as_ref() {
            return Some(ProductionOriginalMountReceiptFailureV1::Alias(cause));
        }
        if let Some(cause) = self.first_failure.as_ref() {
            return Some(ProductionOriginalMountReceiptFailureV1::Receive(cause));
        }
        if let Some(Err(cause)) = self.live_verification.as_ref() {
            return Some(ProductionOriginalMountReceiptFailureV1::Currentness(cause));
        }
        if let Some(Err(cause)) = self.live_clock.as_ref() {
            return Some(ProductionOriginalMountReceiptFailureV1::Currentness(cause));
        }
        if let Some(Err(cause)) = self.live.as_ref() {
            return Some(ProductionOriginalMountReceiptFailureV1::Protocol(cause));
        }
        if let Some(cause) = self.authority.as_ref().and_then(|authority| authority.failure()) {
            return Some(ProductionOriginalMountReceiptFailureV1::Authority(cause));
        }
        if let Some(cause) = self.terminal.failure() {
            return Some(ProductionOriginalMountReceiptFailureV1::Terminal(cause));
        }
        if let Some(index) = self.inventory_first_failure {
            if let Some(Err(cause)) = self.inventory_receive[index].as_ref() {
                return Some(ProductionOriginalMountReceiptFailureV1::Receive(cause));
            }
            if let Some(Err(cause)) = self.inventory_actions[index].as_ref() {
                return Some(ProductionOriginalMountReceiptFailureV1::Terminal(cause));
            }
            if let Some(cause) = self.inventory_responses[index].failure() {
                return Some(ProductionOriginalMountReceiptFailureV1::Terminal(cause));
            }
        }
        if let Some(cause) = self.terminal.post_failure()
            .or_else(|| self.terminal_owner_post.as_ref().and_then(|result| result.as_ref().err()))
            .or_else(|| self.terminal_clock_post.as_ref().and_then(|result| result.as_ref().err()))
        {
            return Some(ProductionOriginalMountReceiptFailureV1::TerminalPost(cause));
        }
        for index in 0..2 {
            if let Some(Err(cause)) = self.inventory_receive[index].as_ref() {
                return Some(ProductionOriginalMountReceiptFailureV1::Receive(cause));
            }
            if let Some(Err(cause)) = self.inventory_actions[index].as_ref() {
                return Some(ProductionOriginalMountReceiptFailureV1::Terminal(cause));
            }
            if let Some(cause) = self.inventory_responses[index].failure() {
                return Some(ProductionOriginalMountReceiptFailureV1::Terminal(cause));
            }
            if let Some(cause) = self.inventory_responses[index].post_failure() {
                return Some(ProductionOriginalMountReceiptFailureV1::TerminalPost(cause));
            }
        }
        self.ended.then_some(ProductionOriginalMountReceiptFailureV1::Ended)
    }

    fn failure_or_ended(&self) -> ProductionOriginalMountReceiptFailureV1<'_> {
        self.failure().unwrap_or(ProductionOriginalMountReceiptFailureV1::Ended)
    }

    // This closed borrower exposes only a latched owning selected cause. The
    // cycle may use it when its action note_failure was bypassed by unwind.
    pub(super) fn selected_failure_for_cycle(&self) -> Option<ProductionOriginalMountReceiptFailureV1<'_>> {
        use aos_sandbox_mount::broker::OriginalMountAcquireAuthorityFailureV1 as AuthorityFailure;
        use ProductionOriginalMountReceiptFailureV1 as Failure;

        if self.diagnostic_phase != OriginalMountDiagnosticPhaseV1::Selected {
            return None;
        }
        match self.selected_failure()? {
            Failure::Ended | Failure::Authority(AuthorityFailure::Ended) => None,
            cause => Some(cause),
        }
    }

    /// Ends the original queue before any returned request or recovery drops.
    pub fn end(&mut self) {
        if self.diagnostic_phase == OriginalMountDiagnosticPhaseV1::Selected {
            self.capture_selected_crossing();
            self.retain_selected_authority_failure();
        }
        self.ended = true;
        if let Some(authority) = self.authority.as_mut() {
            authority.stop();
        }
        if self.terminal_stage() != crate::production_response::OriginalMountTerminalStageV1::Prepare {
            if self.terminal_shutdown.is_none() {
                if let Some(Ok(alias)) = self.alias.as_ref() {
                    self.terminal_shutdown = Some(rustix::net::shutdown(
                        alias.as_fd(), rustix::net::Shutdown::Both,
                    ).map_err(std::io::Error::from));
                }
            }
            return;
        }
        if let Some(Ok(alias)) = self.alias.as_ref() {
            if let Err(cause) = rustix::net::shutdown(alias.as_fd(), rustix::net::Shutdown::Both) {
                if self.shutdown_failure.is_none() {
                    self.shutdown_failure = Some(cause.into());
                }
            }
        } else if let Ok(original) = self.session.as_fd() {
            if let Err(cause) = rustix::net::shutdown(original, rustix::net::Shutdown::Both) {
                if self.shutdown_failure.is_none() { self.shutdown_failure = Some(cause.into()); }
            }
        }
    }

    /// Lends shutdown debt separately; it never proves peer or descriptor drain.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown_failure.as_ref().or_else(|| self.terminal_shutdown.as_ref().and_then(|result| result.as_ref().err()))
    }
}

impl Drop for ProductionOriginalMountReceiptV1 {
    fn drop(&mut self) {
        self.end();
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks a genuine session for the closed original Mount receipt route.
    ///
    /// Construction performs no I/O. The caller retains this whole owner before
    /// receiving; no caller-supplied descriptor or request can create it.
    #[must_use]
    pub fn retain_original_mount_receipt(
        self,
        deadline_boottime_nanoseconds: u64,
    ) -> ProductionOriginalMountReceiptV1 {
        ProductionOriginalMountReceiptV1 {
            alias: None,
            session: self,
            progress: None,
            deadline: deadline_boottime_nanoseconds,
            attempted: false,
            ended: false,
            first_failure: None,
            shutdown_failure: None,
            live_verification: None,
            live_clock: None,
            live: None,
            body: None,
            authority: None,
            live_attempted: false,
            terminal: crate::production_response::OriginalMountNonadmittingTerminalV1::new(),
            terminal_owner_post: None,
            terminal_clock_post: None,
            inventory_progress: [None, None],
            inventory_receive: [None, None],
            inventory_bodies: [None, None],
            inventory_actions: [None, None],
            inventory_responses: [crate::production_response::OriginalMountNonadmittingTerminalV1::new(), crate::production_response::OriginalMountNonadmittingTerminalV1::new()],
            inventory_index: 0,
            inventory_first_failure: None,
            terminal_shutdown: None,
            diagnostic_phase: OriginalMountDiagnosticPhaseV1::Acquire,
            selected_first_source: None,
            selected_crossing: None,
        }
    }

    // Both receipt recipes use these literal old pre/receive/post crossings.
    // Only the retained route keeps the returned progress through postcheck.
    fn receive_production_request_progress(
        &mut self,
        deadline: u64,
        returned: &mut Option<DormantBrokerRequestReceiveProgressV1>,
    ) -> Result<(), ProductionBrokerReceiveErrorV1> {
        crate::dormant_handshake::check_production_deadline(deadline)?;
        *returned = Some(self.receive_authenticated_request()?);
        crate::dormant_handshake::check_production_deadline(deadline)?;
        Ok(())
    }

    /// Receives one descriptor-free production request before a boot-time deadline.
    ///
    /// Retryable socket backpressure waits on the same adopted socket. An
    /// ambiguous initial or successor admission receives one exact protected
    /// readback; continued ambiguity consumes the session and requires process
    /// restart so no later request can overtake uncertain durable state.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when transport,
    /// currentness, deadline, or exact protected readback fails.
    pub fn receive_production_request(
        mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(Self, ProductionBrokerRequestEventV1), ProductionBrokerReceiveErrorV1> {
        loop {
            let mut progress = None;
            self.receive_production_request_progress(
                deadline_boottime_nanoseconds,
                &mut progress,
            )?;
            let progress = progress.ok_or(ProductionBrokerReceiveErrorV1::AdmissionRecovery)?;
            match progress {
                DormantBrokerRequestReceiveProgressV1::Pending => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        false,
                        deadline_boottime_nanoseconds,
                    )?;
                }
                DormantBrokerRequestReceiveProgressV1::Received(request) => {
                    return Ok((self, ProductionBrokerRequestEventV1::Request(request)));
                }
                DormantBrokerRequestReceiveProgressV1::InFlightReplay(custody) => {
                    return Ok((
                        self,
                        ProductionBrokerRequestEventV1::InFlightReplay(custody),
                    ));
                }
                DormantBrokerRequestReceiveProgressV1::TerminalReplay(replay) => {
                    return Ok((self, ProductionBrokerRequestEventV1::TerminalReplay(replay)));
                }
                DormantBrokerRequestReceiveProgressV1::DescriptorTerminalReplay(replay) => {
                    return Ok((
                        self,
                        ProductionBrokerRequestEventV1::DescriptorTerminalReplay(replay),
                    ));
                }
                DormantBrokerRequestReceiveProgressV1::InitializationRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_initialization(recovery, request);
                    return normalize_ordinary_recovery(
                        self,
                        recovered,
                        deadline_boottime_nanoseconds,
                    );
                }
                DormantBrokerRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_successor(recovery, request);
                    return normalize_ordinary_recovery(
                        self,
                        recovered,
                        deadline_boottime_nanoseconds,
                    );
                }
            }
        }
    }

    /// Receives one Host request and its method-selected descriptor table.
    ///
    /// The authenticated request decoder, rather than caller input or packet
    /// peeking, selects whether the exact table is empty or contains the sole
    /// catalog or execution-spec descriptor. Durable ambiguity is read back
    /// once and otherwise fails closed as in [`Self::receive_production_request`].
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when transport,
    /// descriptor shape, currentness, deadline, or protected readback fails.
    pub fn receive_production_host_request(
        mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<(Self, ProductionHostBrokerRequestEventV1), ProductionBrokerReceiveErrorV1> {
        loop {
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            let progress = self.receive_authenticated_host_request()?;
            crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
            match progress {
                DormantBrokerDescriptorRequestReceiveProgressV1::Pending => {
                    crate::dormant_handshake::wait_for_handshake_readiness(
                        self.as_fd()?,
                        false,
                        deadline_boottime_nanoseconds,
                    )?;
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::Received(request) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::Request(request),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::InFlightReplay(custody) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::InFlightReplay(custody),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::TerminalReplay(replay) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::TerminalReplay(replay),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::DescriptorTerminalReplay(
                    replay,
                ) => {
                    return Ok((
                        self,
                        ProductionHostBrokerRequestEventV1::DescriptorTerminalReplay(replay),
                    ));
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::InitializationRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered =
                        self.recover_received_descriptor_initialization(recovery, request);
                    return normalize_host_recovery(self, recovered, deadline_boottime_nanoseconds);
                }
                DormantBrokerDescriptorRequestReceiveProgressV1::SuccessorRecoveryRequired {
                    recovery,
                    request,
                    ..
                } => {
                    let recovered = self.recover_received_descriptor_successor(recovery, request);
                    return normalize_host_recovery(self, recovered, deadline_boottime_nanoseconds);
                }
            }
        }
    }
}

fn normalize_ordinary_recovery(
    session: DormantAuthenticatedBrokerSessionV1,
    recovered: DormantBrokerRequestReceiveProgressV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<
    (
        DormantAuthenticatedBrokerSessionV1,
        ProductionBrokerRequestEventV1,
    ),
    ProductionBrokerReceiveErrorV1,
> {
    crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
    match recovered {
        DormantBrokerRequestReceiveProgressV1::Received(request) => {
            Ok((session, ProductionBrokerRequestEventV1::Request(request)))
        }
        _ => Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery),
    }
}

fn normalize_host_recovery(
    session: DormantAuthenticatedBrokerSessionV1,
    recovered: DormantBrokerDescriptorRequestReceiveProgressV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<
    (
        DormantAuthenticatedBrokerSessionV1,
        ProductionHostBrokerRequestEventV1,
    ),
    ProductionBrokerReceiveErrorV1,
> {
    crate::dormant_handshake::check_production_deadline(deadline_boottime_nanoseconds)?;
    match recovered {
        DormantBrokerDescriptorRequestReceiveProgressV1::Received(request) => Ok((
            session,
            ProductionHostBrokerRequestEventV1::Request(request),
        )),
        _ => Err(ProductionBrokerReceiveErrorV1::AdmissionRecovery),
    }
}
