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
        if self.ended { return false; }
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

    /// Borrows the first failure without observation, recovery or renewal.
    #[must_use]
    pub fn failure(&self) -> Option<ProductionOriginalMountReceiptFailureV1<'_>> {
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
        self.ended.then_some(ProductionOriginalMountReceiptFailureV1::Ended)
    }

    fn failure_or_ended(&self) -> ProductionOriginalMountReceiptFailureV1<'_> {
        self.failure().unwrap_or(ProductionOriginalMountReceiptFailureV1::Ended)
    }

    /// Ends the original queue before any returned request or recovery drops.
    pub fn end(&mut self) {
        self.ended = true;
        if let Some(authority) = self.authority.as_mut() {
            authority.stop();
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
        self.shutdown_failure.as_ref()
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
