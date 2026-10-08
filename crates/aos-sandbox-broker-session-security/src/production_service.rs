//! Complete one production request on an authenticated broker session.
//!
//! These entry points join bounded receipt to the method-closed domain
//! dispatcher and bounded response delivery. Each operation consumes the
//! session on failure, so a daemon cannot accidentally continue traffic after
//! uncertain admission, effect, commit, or transport state.

use std::time::Duration;

use crate::{
    DormantAuthenticatedBrokerSessionV1, ProductionBrokerReceiveErrorV1,
    ProductionBrokerResponseErrorV1,
};

/// Reports failure while deriving an absolute broker-session deadline.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerDeadlineErrorV1 {
    /// The kernel returned a boottime value outside the supported range.
    #[error("kernel boottime is outside the supported range")]
    Kernel,
    /// The duration cannot be represented as an absolute nanosecond deadline.
    #[error("broker-session deadline overflowed")]
    Overflow,
}

/// Derives an absolute `CLOCK_BOOTTIME` deadline after `duration`.
///
/// # Errors
///
/// Returns an error when the kernel clock is invalid or the duration cannot be
/// represented without overflow.
pub fn production_deadline_after(
    duration: Duration,
) -> Result<u64, ProductionBrokerDeadlineErrorV1> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| ProductionBrokerDeadlineErrorV1::Kernel)?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).map_err(|_| ProductionBrokerDeadlineErrorV1::Kernel)?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ProductionBrokerDeadlineErrorV1::Overflow)?;
    let duration = u64::try_from(duration.as_nanos())
        .map_err(|_| ProductionBrokerDeadlineErrorV1::Overflow)?;
    now.checked_add(duration)
        .ok_or(ProductionBrokerDeadlineErrorV1::Overflow)
}

/// Reports a fail-closed production request-cycle failure.
#[derive(Debug, thiserror::Error)]
pub enum ProductionBrokerServiceErrorV1 {
    /// Authenticated request receipt or protected admission failed.
    #[error("broker request receipt failed: {0}")]
    Receive(#[from] ProductionBrokerReceiveErrorV1),
    /// Domain completion, protected commit, replay, or response delivery failed.
    #[error("broker request completion failed: {0}")]
    Response(#[from] ProductionBrokerResponseErrorV1),
}

/// Borrows the complete Mount-owned production composition for one request.
pub struct ProductionMountBrokerOwnersV1<'owners> {
    /// The sealed Mount effect and inventory callsite.
    pub mount: &'owners mut dyn aos_sandbox_mount::DormantMountBrokerCallsiteV1,
    /// The optional Host-sealed catalog scope for catalog preparation.
    pub catalog_scope: Option<aos_sandbox_mount::host_scope::ObservedMountScope>,
}

/// Retains the closed selected Mount original cycle through local Root1 send.
///
/// A genuine authenticated Mount session enters this owner before receiving.
/// The same fixed Root opening and delivered catalog originals remain resident
/// through independent domain admission and the existing native runtime. This
/// route sends no public success and proves neither Ready nor terminal drain.
/// After real native terminal readback, the named continuation may commit only
/// fixed Conflict and the two current inventory responses on the same Session.
/// The selected installed caller supplies the genuine
/// exclusive table/PID1-image owner, which is bookended at protected crossings.
/// The compatibility constructor supplies no such owner. Source's independent
/// initial entry chain, lower unreturned prefixes and allocation funding remain
/// separate functional bounds.
pub struct ProductionOriginalMountCycleV1 {
    startup: Option<aos_sandbox::mount_manager_startup::SelectedMountStartupV2>,
    image_attempt: Option<aos_systemd::OwnUnitPid1ImageAttemptV1>,
    image: Option<aos_systemd::CompletedOwnUnitPid1ImageV1>,
    image_runtime: Option<std::io::Result<tokio::runtime::Runtime>>,
    receipt: crate::ProductionOriginalMountReceiptV1,
    root: crate::ProductionSelectedRootMountSourceProviderV1,
    publication: Option<Vec<u8>>,
    catalog: Option<Vec<u8>>,
    selection: Option<Vec<u8>>,
    mount_result: Option<Result<bool, aos_sandbox_mount::MountError>>,
    response_result: Option<Result<aos_sandbox_mount::broker::OriginalMountResponseProgressV5, aos_sandbox_mount::MountError>>,
    response_postcheck_failed: bool,
    deadline_result: Option<Result<u64, crate::ProductionBrokerSessionActivationErrorV1>>,
    deadline: u64,
    attempted: bool,
    ended: bool,
    locally_sent: bool,
    first_stage: Option<OriginalMountCycleStageV1>,
}

#[derive(Clone, Copy)]
enum OriginalMountCycleStageV1 {
    Startup,
    Image,
    Runtime,
    Root,
    Receipt,
    Mount,
    Deadline,
}

impl std::fmt::Debug for ProductionOriginalMountCycleV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductionOriginalMountCycleV1([resident original cycle])")
    }
}

/// Lends an original cycle's genuine first returned cause without recovery.
pub enum ProductionOriginalMountCycleFailureV1<'owner> {
    /// The same admitted startup owner retains the genuine kernel/image cause.
    Startup(aos_sandbox::mount_manager_startup::SelectedMountStartupFailureRefV2<'owner>),
    /// The genuine same-unit observer retains both raw image-message prefixes.
    Image(&'owner aos_systemd::OwnUnitPid1ImageAttemptV1),
    /// Constructing the selected observation runtime returned this native error.
    Runtime(&'owner std::io::Error),
    /// The fixed Root opening, Session or delivered catalog failed.
    Root(crate::ProductionSelectedRootMountSourceProviderFailureV1<'owner>),
    /// The original Mount receipt or signed-domain admission failed.
    Receipt(crate::ProductionOriginalMountReceiptFailureV1<'owner>),
    /// The same broker/native runtime retained this returned failure.
    Mount(&'owner aos_sandbox_mount::MountError),
    /// The original absolute deadline expired or could not be sampled.
    Deadline(&'owner crate::ProductionBrokerSessionActivationErrorV1),
    /// A closed association failed or the original unwound without a cause.
    Ended,
}

impl std::fmt::Debug for ProductionOriginalMountCycleFailureV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Startup(_) => "ProductionOriginalMountCycleFailureV1::Startup",
            Self::Image(_) => "ProductionOriginalMountCycleFailureV1::Image",
            Self::Runtime(_) => "ProductionOriginalMountCycleFailureV1::Runtime",
            Self::Root(_) => "ProductionOriginalMountCycleFailureV1::Root",
            Self::Receipt(_) => "ProductionOriginalMountCycleFailureV1::Receipt",
            Self::Mount(_) => "ProductionOriginalMountCycleFailureV1::Mount",
            Self::Deadline(_) => "ProductionOriginalMountCycleFailureV1::Deadline",
            Self::Ended => "ProductionOriginalMountCycleFailureV1::Ended",
        })
    }
}

struct OriginalMountCycleBoundaryV1<'owner> {
    owner: &'owner mut ProductionOriginalMountCycleV1,
    completed: bool,
}

impl Drop for OriginalMountCycleBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl ProductionOriginalMountCycleV1 {
    /// Parks the genuine session and original deadline without I/O.
    #[must_use]
    pub fn new(session: DormantAuthenticatedBrokerSessionV1, deadline: u64) -> Self {
        Self::new_inner(session, deadline, None)
    }

    /// Parks the completed selected startup beside the same original request.
    ///
    /// This accepts only the actual move-only Core owner. It does not complete
    /// an initial table from DATA, duplicate an image flight or grant Acquire.
    #[must_use]
    pub fn with_selected_startup(
        session: DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        startup: aos_sandbox::mount_manager_startup::SelectedMountStartupV2,
    ) -> Self {
        Self::new_inner(session, deadline, Some(startup))
    }

    fn new_inner(
        session: DormantAuthenticatedBrokerSessionV1,
        deadline: u64,
        startup: Option<aos_sandbox::mount_manager_startup::SelectedMountStartupV2>,
    ) -> Self {
        Self {
            startup,
            image_attempt: None,
            image: None,
            image_runtime: None,
            receipt: session.retain_original_mount_receipt(deadline),
            root: crate::ProductionSelectedRootMountSourceProviderV1::new(deadline),
            publication: None,
            catalog: None,
            selection: None,
            mount_result: None,
            response_result: None,
            response_postcheck_failed: false,
            deadline_result: None,
            deadline,
            attempted: false,
            ended: false,
            locally_sent: false,
            first_stage: None,
        }
    }

    /// Runs once through the existing original native stage engine.
    ///
    /// Successful local send keeps this whole owner and the broker's runtime;
    /// it cannot be converted into a generic response, success or retry permit.
    /// The caller must retain both until an independently implemented terminal
    /// continuation or intentional failed invocation. Ordinary dispatch is not
    /// changed or opened by this method.
    ///
    /// # Errors
    ///
    /// Lends a resident cause after ending both original queues. No subsequent
    /// call observes, reconnects, renews, re-admits or reconstructs the request.
    pub fn run_once<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<(), ProductionOriginalMountCycleFailureV1<'_>> {
        if self.attempted || self.ended {
            self.end();
            return Err(self.failure_or_ended());
        }
        self.attempted = true;
        let succeeded = {
            let mut boundary = OriginalMountCycleBoundaryV1 {
                owner: self,
                completed: false,
            };
            let succeeded = boundary.owner.run_inner(broker);
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded {
            Ok(())
        } else {
            Err(self.failure_or_ended())
        }
    }

    /// Advances a response only after this SAME selected cycle sent Root1.
    ///
    /// The original deadline, receipt, Root Session, signed-domain owner,
    /// broker writer/runtime and selected kernel/image owner stay resident.
    /// Successful local Root4 selects the same Source7/Root13 continuation;
    /// neither local send is retried or implies peer receipt or settlement.
    ///
    /// # Errors
    ///
    /// Ends the original queues before lending a resident failure on missing
    /// association, expired deadline, stale catalog/startup or native refusal.
    pub fn advance_selected_response_once<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<aos_sandbox_mount::broker::OriginalMountResponseProgressV5, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || !self.attempted
            || !self.locally_sent || self.startup.is_none()
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let progress = {
            let mut boundary = OriginalMountCycleBoundaryV1 {
                owner: self,
                completed: false,
            };
            let progress = boundary.owner.advance_response_inner(broker);
            boundary.completed = progress.is_some();
            progress
        };
        match progress {
            Some(progress) => Ok(progress),
            None => Err(self.failure_or_ended()),
        }
    }

    fn advance_response_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<aos_sandbox_mount::broker::OriginalMountResponseProgressV5> {
        if !self.bookend(broker) {
            return None;
        }
        if !self.advance_native_response(broker) {
            return None;
        }

        // The action is resident before the slower outer catalog/kernel/image
        // checks. Native failure is not replaced by their separately held debt.
        if !self.bookend(broker) {
            self.response_postcheck_failed = true;
            return None;
        }
        self.response_result.as_ref().and_then(|result| result.as_ref().ok()).copied()
    }

    fn advance_native_response<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        let (Some(authority), Some(session)) = (
            self.receipt.authority_mut(), self.root.borrow_current_session(),
        ) else {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        };
        self.response_result = Some(broker.advance_signed_original_response_v5(authority, session));
        if !matches!(self.response_result, Some(Ok(_))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
        }

        true
    }

    /// Advances the fixed nonadmitting terminal on the original transport.
    ///
    /// The actual stored Root terminal is reobserved through its already-sent
    /// branch. Conflict does not assert an absent effect or physical Release.
    /// The original Acquire, writers and both same queues remain owned here.
    ///
    /// # Errors
    /// Ends both queues on a stale owner, failed original cutoff, signing,
    /// commit ambiguity or native send refusal. No signature or send is retried.
    pub fn advance_selected_nonadmitting_terminal<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<bool, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || self.startup.is_none()
            || !self.locally_sent || !self.attempted
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let succeeded = {
            let mut boundary = OriginalMountCycleBoundaryV1 { owner: self, completed: false };
            let succeeded = boundary.owner.advance_nonadmitting_inner(broker);
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded {
            Ok(self.receipt.terminal_stage() == crate::production_response::OriginalMountTerminalStageV1::Sent)
        } else {
            Err(self.failure_or_ended())
        }
    }

    fn advance_nonadmitting_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.nonadmitting_bookend(broker) {
            return false;
        }
        // A historical DATA flag is insufficient: this is the genuine native
        // phase7 readback and retained same-Session already-sent observation.
        let native = self.advance_native_response(broker);
        if !native || !matches!(self.response_result, Some(Ok(aos_sandbox_mount::broker::OriginalMountResponseProgressV5::RootTerminalRecordedSent))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
            // A returned native refusal remains first; it does not suppress
            // the independent owner and original-clock negative observations.
            if !self.nonadmitting_bookend(broker) {
                self.response_postcheck_failed = true;
            }
            return false;
        }
        if !self.nonadmitting_bookend(broker) {
            return false;
        }
        let action = if self.receipt.terminal_stage() == crate::production_response::OriginalMountTerminalStageV1::Sent {
            self.receipt.advance_original_inventory(broker, &mut self.root)
        } else {
            self.receipt.advance_nonadmitting_terminal()
        };
        if !action { self.note_failure(OriginalMountCycleStageV1::Receipt); }
        // These posts are independently attempted even after the actual action
        // failed; first cause stays resident before any negative disposition.
        let post = self.nonadmitting_bookend(broker);
        if !post { self.response_postcheck_failed = true; }
        action && post
    }

    fn nonadmitting_bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        let root = self.root.recheck_catalog();
        if !root { self.note_failure(OriginalMountCycleStageV1::Root); }
        let startup = match self.startup.as_mut() {
            Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
            None => false,
        };
        if !startup { self.note_failure(OriginalMountCycleStageV1::Startup); }
        let receipt = self.receipt.recheck_nonadmitting_terminal();
        if !receipt { self.note_failure(OriginalMountCycleStageV1::Receipt); }
        let clock = self.check_deadline();
        receipt && root && startup && clock
    }

    /// Reports only the completed channel prefix for private routing.
    #[must_use]
    pub fn original_release_channel_settled(&self) -> bool {
        !self.ended && self.receipt.original_release_channel_settled()
    }

    /// Advances independently authorized Release on the SAME retained owners.
    ///
    /// The fixed intake cut starts only after all three authentic exchanges.
    /// Once the actual Release is admitted, its genuine reopened effect and
    /// original paired clock replace the historical Acquire crossing. Local
    /// send is DATA only: it permits neither cleanup nor descriptor release.
    ///
    /// # Errors
    /// Ends both queues before diagnostic/drop on receive, admission, native
    /// reservation, signing, send or independent owner/clock refusal.
    pub fn advance_selected_original_release<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Result<aos_sandbox_mount::broker::OriginalMountReleaseProgressV1, ProductionOriginalMountCycleFailureV1<'_>> {
        if self.ended || self.first_stage.is_some() || self.startup.is_none()
            || !self.attempted || !self.locally_sent
            || !self.receipt.original_release_channel_settled()
        {
            self.end();
            return Err(self.failure_or_ended());
        }
        let progress = {
            let mut boundary = OriginalMountCycleBoundaryV1 { owner: self, completed: false };
            let owner = &mut *boundary.owner;
            // Before a receive can block, retain the one new intake cut and
            // observe the genuine startup/catalog owners. The Root bookend's
            // final clock is that fixed cut, never the historical Acquire D.
            let intake_current = if owner.receipt.original_release_admitted() {
                true
            } else if !owner.receipt.prepare_original_release_intake() {
                owner.note_failure(OriginalMountCycleStageV1::Receipt);
                false
            } else {
                let startup = match owner.startup.as_mut() {
                    Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
                    None => false,
                };
                if !startup {
                    owner.note_failure(OriginalMountCycleStageV1::Startup);
                }
                let root = owner.receipt.original_release_intake_cut()
                    .is_some_and(|cut| owner.root.recheck_catalog_for_original_release_intake(cut));
                if !root {
                    owner.note_failure(OriginalMountCycleStageV1::Root);
                }
                startup && root
            };
            let progress = if intake_current {
                owner.receipt.advance_original_release(broker, &mut owner.root)
            } else {
                None
            };
            if progress.is_none() {
                owner.note_failure(if owner.receipt.original_release_root_loan_pending() {
                    OriginalMountCycleStageV1::Root
                } else {
                    OriginalMountCycleStageV1::Receipt
                });
            }
            // These independent posts also run after an actual action Err.
            // The receipt's selected crossing was armed before dispatch, so
            // caught unwind still lends its already resident cause on end.
            let root_receipt = owner.receipt.recheck_original_release(broker, &mut owner.root);
            if !root_receipt {
                if owner.root.failure().is_some() {
                    owner.note_failure(OriginalMountCycleStageV1::Root);
                } else {
                    owner.note_failure(OriginalMountCycleStageV1::Receipt);
                }
            }
            let startup = match owner.startup.as_mut() {
                Some(startup) => broker.recheck_selected_mount_startup(startup).is_ok(),
                None => false,
            };
            if !startup {
                owner.note_failure(OriginalMountCycleStageV1::Startup);
            }
            boundary.completed = progress.is_some() && root_receipt && startup;
            if boundary.completed { progress } else { None }
        };
        progress.ok_or_else(|| self.failure_or_ended())
    }

    /// Lends the actual native Release cause without copying or rechecking it.
    #[must_use]
    pub fn release_failure<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        broker.original_release_failure_v1()
    }

    /// Lends independent native Release posts without replacing its first cause.
    #[must_use]
    pub fn release_postcheck_debt<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<&'owner (dyn std::error::Error + 'static)> {
        broker.original_release_postcheck_debt_v1()
    }

    /// Borrows the actual response cause from its SAME broker runtime owner.
    ///
    /// This performs no observation, retry, extraction or cause cloning. The
    /// cycle's status error and later outer bookend debt remain separate.
    #[must_use]
    pub fn response_failure<'owner, W: aos_sandbox_mount::worker::MountWorker>(
        &self,
        broker: &'owner aos_sandbox_mount::broker::MountBroker<W>,
    ) -> Option<aos_sandbox_mount::broker::OriginalMountResponseFailureV5<'owner>> {
        broker.original_response_failure_v5()
    }

    /// Lends an actual later outer bookend refusal without another observation.
    #[must_use]
    pub fn response_postcheck_debt(&self) -> Option<ProductionOriginalMountCycleFailureV1<'_>> {
        if !self.response_postcheck_failed {
            return None;
        }
        // This is the shared bookend's literal check order, not a second probe.
        if let Some(cause) = self.deadline_result.as_ref().and_then(|result| result.as_ref().err()) {
            return Some(ProductionOriginalMountCycleFailureV1::Deadline(cause));
        }
        if let Some(cause) = self.receipt.failure() {
            return Some(ProductionOriginalMountCycleFailureV1::Receipt(cause));
        }
        if let Some(cause) = self.root.failure() {
            return Some(ProductionOriginalMountCycleFailureV1::Root(cause));
        }
        self.startup.as_ref().and_then(|startup| startup.failure())
            .map(ProductionOriginalMountCycleFailureV1::Startup)
    }

    fn check_deadline(&mut self) -> bool {
        self.deadline_result = Some(crate::production_activation::remaining_duration(self.deadline));
        if matches!(self.deadline_result, Some(Ok(_))) {
            return true;
        }
        self.note_failure(OriginalMountCycleStageV1::Deadline);
        false
    }

    fn note_failure(&mut self, stage: OriginalMountCycleStageV1) {
        if self.first_stage.is_none() {
            self.first_stage = Some(stage);
        }
    }

    fn startup_bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if self.startup.is_none() {
            return true;
        }
        if !self.check_deadline() {
            return false;
        }
        let Some(startup) = self.startup.as_mut() else {
            return false;
        };
        if broker.recheck_selected_mount_startup(startup).is_err() {
            self.note_failure(OriginalMountCycleStageV1::Startup);
            return false;
        }
        // Charge the slow fixed five-second observation to the SAME original D.
        self.check_deadline()
    }

    fn bookend<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.check_deadline() {
            return false;
        }
        if !self.receipt.recheck_original_request() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.root.recheck_catalog() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        self.startup_bookend(broker)
    }

    fn capture_launcher_image<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if self.startup.is_some() {
            // The actual Core producer already owns both original image
            // Messages. Reuse it rather than accumulate a second image pair.
            return self.startup_bookend(broker);
        }
        // The installed caller has already completed exclusive initial-table
        // handling before entering this cycle. This observer cannot complete
        // that table or construct the missing Core executed-image bridge.
        if self.image_attempt.is_some() || self.image.is_some() || self.image_runtime.is_some() {
            return false;
        }
        self.image_attempt = Some(aos_systemd::OwnUnitPid1ImageAttemptV1::mount());
        self.image_runtime = Some(tokio::runtime::Builder::new_current_thread().enable_all().build());
        let Some(Ok(runtime)) = self.image_runtime.as_ref() else {
            self.note_failure(OriginalMountCycleStageV1::Runtime);
            return false;
        };
        let Some(attempt) = self.image_attempt.as_mut() else {
            return false;
        };
        if runtime.block_on(attempt.capture_once()).is_err() {
            self.note_failure(OriginalMountCycleStageV1::Image);
            return false;
        }
        if self.image.is_some() {
            return false;
        }
        match self.image_attempt.take() {
            Some(attempt) => match attempt.into_completed() {
                Ok(image) => self.image = Some(image),
                Err(attempt) => {
                    self.image_attempt = Some(attempt);
                    self.note_failure(OriginalMountCycleStageV1::Image);
                    return false;
                }
            },
            None => return false,
        }
        // Both original Messages and their exact FDs remain resident. Their
        // existence alone is no image/currentness/Root authority conversion.
        true
    }

    fn run_inner<W: aos_sandbox_mount::worker::MountWorker>(
        &mut self,
        broker: &mut aos_sandbox_mount::broker::MountBroker<W>,
    ) -> bool {
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.receipt.arm_original_fence() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.check_deadline() {
            return false;
        }
        if !self.capture_launcher_image(broker) || !self.check_deadline() {
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.root.connect_once().is_err() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if !self.root.read_catalog_once() {
            self.note_failure(OriginalMountCycleStageV1::Root);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.receipt.receive_once().is_err() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.startup_bookend(broker) {
            return false;
        }
        if self.receipt.admit_original_acquire(broker).is_err() {
            self.note_failure(OriginalMountCycleStageV1::Receipt);
            return false;
        }
        if !self.bookend(broker) {
            return false;
        }
        let Some((publication, catalog)) = self.root.catalog_pair() else {
            return false;
        };
        // These are bounded comparison DATA copies; the original delivered
        // files and bytes remain in root.catalog. Allocation funding is not
        // upgraded into original custody or a hard-memory reservation here.
        self.publication = Some(publication.to_vec());
        self.catalog = Some(catalog.to_vec());
        if !self.bookend(broker) {
            return false;
        }

        let (Some(authority), Some(session)) = (self.receipt.authority_mut(), self.root.borrow_current_session()) else {
            self.first_stage.get_or_insert(OriginalMountCycleStageV1::Root);
            return false;
        };
        self.mount_result = Some(broker.begin_signed_original_acquire(
            authority, session, &mut self.publication, &mut self.catalog, &mut self.selection,
        ).map(|()| false));
        if !matches!(self.mount_result, Some(Ok(_))) {
            self.note_failure(OriginalMountCycleStageV1::Mount);
            return false;
        }
        if !self.bookend(broker) {
            return false;
        }

        loop {
            if !self.bookend(broker) {
                return false;
            }
            let (Some(authority), Some(session)) = (self.receipt.authority_mut(), self.root.borrow_current_session()) else {
                self.first_stage.get_or_insert(OriginalMountCycleStageV1::Root);
                return false;
            };
            self.mount_result = Some(broker.advance_signed_original_acquire(authority, session));
            if !matches!(self.mount_result, Some(Ok(_))) {
                self.note_failure(OriginalMountCycleStageV1::Mount);
                return false;
            }
            if !self.bookend(broker) {
                return false;
            }
            if matches!(self.mount_result, Some(Ok(true))) {
                self.locally_sent = true;
                return true;
            }
            // Existing nonblocking Query/send backpressure, using the same
            // original absolute deadline rather than a renewed timer.
            std::thread::sleep(Duration::from_nanos(2_000_000));
        }
    }

    /// Reports local sends only; it is not a terminal or public success witness.
    #[must_use]
    pub fn locally_sent(&self) -> bool {
        self.locally_sent && !self.ended
    }

    /// Lends the actual retained failure without any new observation.
    #[must_use]
    pub fn failure(&self) -> Option<ProductionOriginalMountCycleFailureV1<'_>> {
        let failure = match self.first_stage {
            Some(OriginalMountCycleStageV1::Startup) => self.startup.as_ref()
                .and_then(|startup| startup.failure()).map(ProductionOriginalMountCycleFailureV1::Startup),
            Some(OriginalMountCycleStageV1::Image) => self.image_attempt.as_ref().map(ProductionOriginalMountCycleFailureV1::Image),
            Some(OriginalMountCycleStageV1::Runtime) => self.image_runtime.as_ref().and_then(|result| result.as_ref().err()).map(ProductionOriginalMountCycleFailureV1::Runtime),
            Some(OriginalMountCycleStageV1::Root) => self.root.failure().map(ProductionOriginalMountCycleFailureV1::Root),
            Some(OriginalMountCycleStageV1::Receipt) => self.receipt.failure().map(ProductionOriginalMountCycleFailureV1::Receipt),
            Some(OriginalMountCycleStageV1::Mount) => {
                // The broker's status error intentionally carries no copied
                // cause. Prefer the actual admission/runtime cause kept with
                // the receipt's same original domain owner.
                match self.receipt.failure() {
                    Some(crate::ProductionOriginalMountReceiptFailureV1::Authority(cause)) => {
                        Some(ProductionOriginalMountCycleFailureV1::Receipt(
                            crate::ProductionOriginalMountReceiptFailureV1::Authority(cause),
                        ))
                    }
                    _ => self.mount_result.as_ref()
                        .and_then(|result| result.as_ref().err())
                        .or_else(|| self.response_result.as_ref().and_then(|result| result.as_ref().err()))
                        .map(ProductionOriginalMountCycleFailureV1::Mount),
                }
            }
            Some(OriginalMountCycleStageV1::Deadline) => self.deadline_result.as_ref().and_then(|result| result.as_ref().err()).map(ProductionOriginalMountCycleFailureV1::Deadline),
            None if self.receipt.original_release_root_loan_pending() => self.root.failure()
                .map(ProductionOriginalMountCycleFailureV1::Root),
            None => self.receipt.selected_failure_for_cycle()
                .map(ProductionOriginalMountCycleFailureV1::Receipt),
        };
        failure.or_else(|| self.ended.then_some(ProductionOriginalMountCycleFailureV1::Ended))
    }

    fn failure_or_ended(&self) -> ProductionOriginalMountCycleFailureV1<'_> {
        self.failure().unwrap_or(ProductionOriginalMountCycleFailureV1::Ended)
    }

    /// Ends both same-original queues before any descendant prefix drops.
    pub fn end(&mut self) {
        self.ended = true;
        if let Some(startup) = self.startup.as_mut() {
            startup.end();
        }
        if let Some(image) = self.image.as_ref() {
            image.end();
        }
        if let Some(attempt) = self.image_attempt.as_ref() {
            attempt.end();
        }
        self.root.end();
        self.receipt.end();
    }
}

impl Drop for ProductionOriginalMountCycleV1 {
    fn drop(&mut self) {
        self.end();
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    /// Parks this genuine Storage session before receiving selected output work.
    ///
    /// The returned cycle retains every returned request, Host flight and
    /// terminal result. Its legacy receive/handshake engines still own their
    /// unreturned prefixes; this constructor is not whole-prefix retention,
    /// physical output capture, admission, or terminal drain.
    #[must_use]
    pub fn begin_original_storage_output_cycle(
        self,
    ) -> ProductionOriginalStorageOutputCycleV1 {
        ProductionOriginalStorageOutputCycleV1::begin(self)
    }

    /// Receives and completes one Storage request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Storage effect, recovery, commit, or response step fails.
    pub fn serve_production_storage_request(
        self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_storage_request_event(event, storage, deadline_boottime_nanoseconds)
            .map_err(Into::into)
    }

    /// Parks the original selected Storage Session before any receive or clock.
    ///
    /// The fixed daemon mode supplies this Session through its genuine retained
    /// HELLO. This custody adds no readiness, physical mutation or Drain claim.
    #[must_use]
    pub fn begin_original_nix_generation_cycle(self) -> ProductionOriginalNixGenerationCycleV1 {
        ProductionOriginalNixGenerationCycleV1::begin(self)
    }

    /// Receives and completes one Network request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Network effect, recovery, commit, or response step fails.
    pub fn serve_production_network_request(
        self,
        network: &mut dyn aos_sandbox_network::DormantNetworkBrokerCallsiteV1,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_network_request_event(event, network, deadline_boottime_nanoseconds)
            .map_err(Into::into)
    }

    /// Receives and completes one Mount request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Mount effect, recovery, commit, or response step fails.
    pub fn serve_production_mount_request(
        self,
        owners: ProductionMountBrokerOwnersV1<'_>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) = self.receive_production_request(deadline_boottime_nanoseconds)?;
        session
            .complete_mount_request_event(
                event,
                owners.mount,
                owners.catalog_scope,
                deadline_boottime_nanoseconds,
            )
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NixGenerationCycleCauseV1 {
    Receive,
    Dispatch,
    Send,
    Readiness,
    Clock(usize),
    Session(usize),
    LateClock(usize),
    Poll,
    Closed,
}

/// Retains one installed selected request, its actual Session and returned results.
///
/// Ordinary methods keep the existing consuming completion engine. Method57
/// uses a short mutable Session loan and retains native domain and response
/// results before its independent original-cutoff/currentness bookends. No
/// failed request is replaced, and successful Prepared still remains pending.
/// Lower consuming pre-return prefixes and allocation funding remain distinct.
#[must_use = "retain the selected original until its later genuine handoff"]
pub struct ProductionOriginalNixGenerationCycleV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    previous_receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    event: Option<crate::ProductionBrokerRequestEventV1>,
    ordinary: Option<Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1>>,
    dispatch: Option<Result<
        crate::ProtectedBrokerOutcomeCommitResultV1,
        crate::DormantBrokerExecutionFailureV1<crate::ProductionStorageBrokerDispatchErrorV1>,
    >>,
    send: Option<Result<
        crate::DormantBrokerResponseSendProgressV1,
        crate::DormantBrokerSessionHandshakeErrorV1,
    >>,
    readiness: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    receive_deadline: Option<Result<u64, ProductionBrokerDeadlineErrorV1>>,
    clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    late_clock: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 3],
    current: [Option<Result<(), crate::BrokerSessionSecurityError>>; 3],
    poll_error: Option<rustix::io::Errno>,
    first: Option<NixGenerationCycleCauseV1>,
    deadline: u64,
    selected: bool,
    ended: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("original Nix generation cycle is closed with its custody resident")]
struct NixGenerationCycleClosedV1;

impl Drop for ProductionOriginalNixGenerationCycleV1 {
    fn drop(&mut self) {
        if self.selected || self.first.is_some() || self.postcheck_debt().is_some() {
            // A local send cannot dispose of a pending generation or an
            // ambiguous original. Abort before this parent's fields drop.
            std::process::abort();
        }
    }
}

impl ProductionOriginalNixGenerationCycleV1 {
    fn begin(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            session: Some(session),
            receipt: None,
            previous_receipt: None,
            event: None,
            ordinary: None,
            dispatch: None,
            send: None,
            readiness: None,
            receive_deadline: None,
            clock: [None, None, None],
            late_clock: [None, None, None],
            current: [None, None, None],
            poll_error: None,
            first: None,
            deadline: 0,
            selected: false,
            ended: false,
        }
    }

    /// Borrows the same carrier for the existing daemon poll without extracting it.
    ///
    /// # Errors
    /// Rejects a missing original; an ended request cannot accept another frame.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, crate::DormantBrokerSessionHandshakeErrorV1> {
        if self.ended {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        if let Some(session) = &self.session {
            return session.as_fd();
        }
        if let Some(Ok(session)) = &self.ordinary {
            return session.as_fd();
        }
        Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)
    }

    /// Borrows the chronological returned cause without moving retained custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            NixGenerationCycleCauseV1::Receive => {
                if let Some(Err(error)) = &self.receive_deadline { return Some(error); }
                self.receipt.as_ref()?.failure()
            }
            NixGenerationCycleCauseV1::Dispatch => match self.dispatch.as_ref()? {
                Err(crate::DormantBrokerExecutionFailureV1::BeforeEffect { error, .. }) => Some(error),
                Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. }) => Some(error),
                Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&NixGenerationCycleClosedV1),
            },
            NixGenerationCycleCauseV1::Send => match self.send.as_ref()? {
                Err(error) => Some(error),
                Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { error, .. }) => Some(error),
                _ => Some(&NixGenerationCycleClosedV1),
            },
            NixGenerationCycleCauseV1::Readiness => self.readiness.as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Clock(index) => self.clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Session(index) => self.current[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::LateClock(index) => self.late_clock[index].as_ref()?.as_ref().err()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Poll => self.poll_error.as_ref()
                .map(|error| error as &(dyn std::error::Error + 'static)),
            NixGenerationCycleCauseV1::Closed => {
                if let Some(Err(error)) = &self.ordinary { return Some(error); }
                Some(&NixGenerationCycleClosedV1)
            }
        }
    }

    /// Borrows final comparison debt independently of an earlier action error.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.as_ref().and_then(|receipt| receipt.postcheck_debt()) {
            return Some(error);
        }
        for index in 1..3 {
            if self.first != Some(NixGenerationCycleCauseV1::Clock(index)) {
                if let Some(Err(error)) = &self.clock[index] { return Some(error); }
            }
            if self.first != Some(NixGenerationCycleCauseV1::Session(index)) {
                if let Some(Err(error)) = &self.current[index] { return Some(error); }
            }
            if self.first != Some(NixGenerationCycleCauseV1::LateClock(index)) {
                if let Some(Err(error)) = &self.late_clock[index] { return Some(error); }
            }
        }
        None
    }

    /// Parks a genuine daemon poll error and permanently fences the same request.
    pub fn close_on_poll_failure(&mut self, error: rustix::io::Errno) {
        self.poll_error.get_or_insert(error);
        self.first.get_or_insert(NixGenerationCycleCauseV1::Poll);
        self.ended = true;
    }

    /// Reports only a locally sent Prepared whose original owners remain pending.
    ///
    /// This diagnostic is not completion, a release permission or physical Drain.
    #[must_use]
    pub fn has_prepared_pending(&self) -> bool {
        self.selected && self.first.is_none() && self.postcheck_debt().is_none()
            && matches!(self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Sent(_))))
    }

    fn bookend(&mut self, index: usize) -> bool {
        self.clock[index] = Some(crate::dormant_handshake::check_production_deadline(self.deadline));
        if self.clock[index].as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(NixGenerationCycleCauseV1::Clock(index));
            if index == 0 {
                return false;
            }
        }
        let Some(session) = self.session.as_mut() else {
            return false;
        };
        self.current[index] = Some(session.recheck_original_nix_generation_session());
        if self.current[index].as_ref().is_some_and(Result::is_err) {
            self.first.get_or_insert(NixGenerationCycleCauseV1::Session(index));
        }
        // A slow named/native comparison may cross the original cutoff.
        let late = crate::dormant_handshake::check_production_deadline(self.deadline);
        if index == 0 {
            if late.is_err() {
                self.clock[index] = Some(late);
                self.first.get_or_insert(NixGenerationCycleCauseV1::Clock(index));
            }
        } else {
            // Post-action observations are independent. Keep the first clock
            // result even on failure, and retain the final sample separately.
            self.late_clock[index] = Some(late);
            if self.late_clock[index].as_ref().is_some_and(Result::is_err) {
                self.first.get_or_insert(NixGenerationCycleCauseV1::LateClock(index));
            }
        }
        self.first.is_none()
    }

    /// Drives one actual request without replacing its original Session or deadline.
    ///
    /// A unit return is not Prepared. Original results and errors remain owned;
    /// the installed caller terminates before dropping failed or selected custody.
    pub fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        receive_deadline: Result<u64, ProductionBrokerDeadlineErrorV1>,
    ) {
        if self.ended || self.selected {
            return;
        }
        if let Some(ordinary) = self.ordinary.take() {
            match ordinary {
                Ok(session) => self.session = Some(session),
                Err(error) => {
                    self.ordinary = Some(Err(error));
                    self.first = Some(NixGenerationCycleCauseV1::Closed);
                    self.ended = true;
                    return;
                }
            }
        }
        self.receive_deadline = Some(receive_deadline);
        let Some(Ok(deadline)) = &self.receive_deadline else {
            self.first = Some(NixGenerationCycleCauseV1::Receive);
            self.ended = true;
            return;
        };
        self.deadline = *deadline;
        self.previous_receipt = self.receipt.take();
        self.receipt = Some(crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1::empty());
        self.ended = true;
        let (Some(session), Some(receipt)) = (self.session.as_mut(), self.receipt.as_mut()) else {
            return;
        };
        // The existing receipt engine checks fixed Storage/NodeController
        // originals; it is not an Output-operation authority constructor.
        self.event = session.receive_original_output_request(receipt, self.deadline);
        if self.event.is_none() {
            self.first = Some(NixGenerationCycleCauseV1::Receive);
            return;
        }
        // The same parser authenticated the current predecessor before the
        // prior successful ordinary receipt can be disposed of.
        self.previous_receipt = None;
        if !self.event.as_ref().is_some_and(|event| event.is_nix_generation()) {
            let (Some(event), Some(session)) = (self.event.take(), self.session.take()) else {
                return;
            };
            self.ordinary = Some(session.complete_storage_request_event(event, storage, self.deadline));
            self.ended = !matches!(self.ordinary, Some(Ok(_)));
            if self.ended {
                self.first = Some(NixGenerationCycleCauseV1::Closed);
            }
            return;
        }

        self.selected = true;
        // A terminal or ambiguous repeat remains resident and closed. No new
        // effect, receipt or replacement dispatch is inferred from replay.
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.as_ref() else {
            self.first = Some(NixGenerationCycleCauseV1::Closed);
            return;
        };
        self.deadline = self.deadline.min(request.original_nix_generation_deadline());
        if !self.bookend(0) {
            return;
        }
        let Some(crate::ProductionBrokerRequestEventV1::Request(request)) = self.event.take() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.dispatch = Some(session.dispatch_storage_request_and_commit(request, storage));
        if matches!(
            self.dispatch.as_ref(),
            Some(Err(_))
                | Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. }))
        ) {
            self.first = Some(NixGenerationCycleCauseV1::Dispatch);
        }
        if !self.bookend(1) {
            return;
        }
        let committed = match self.dispatch.take() {
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) => committed,
            retained => {
                self.dispatch = retained;
                self.first.get_or_insert(NixGenerationCycleCauseV1::Dispatch);
                return;
            }
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        self.send = Some(session.send_authenticated_response(committed));
        if matches!(self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
            self.first = Some(NixGenerationCycleCauseV1::Send);
        }
        if !self.bookend(2) {
            return;
        }
        while matches!(self.send, Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(_)))) {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            self.readiness = Some(wait_output_original(session, true, self.deadline));
            if self.readiness.as_ref().is_some_and(Result::is_err) {
                self.first = Some(NixGenerationCycleCauseV1::Readiness);
            }
            if !self.bookend(2) {
                return;
            }
            let pending = match self.send.take() {
                Some(Ok(crate::DormantBrokerResponseSendProgressV1::Pending(pending))) => pending,
                retained => {
                    self.send = retained;
                    return;
                }
            };
            let Some(session) = self.session.as_mut() else {
                return;
            };
            self.send = Some(session.send_authenticated_response(pending));
            if matches!(self.send, Some(Err(_)) | Some(Ok(crate::DormantBrokerResponseSendProgressV1::RecoveryRequired { .. }))) {
                self.first = Some(NixGenerationCycleCauseV1::Send);
            }
            if !self.bookend(2) {
                return;
            }
        }
    }
}

/// Retains one request's original Storage/Host carriers and returned results.
///
/// Local terminal transmission does not release the pending original. Only a
/// genuine authenticated successor admitted by the same journal can retire a
/// successful predecessor. A failed request is never replaced or retried.
/// Blank deployment, floor provisioning and physical capture remain distinct
/// prerequisites; this owner does not change method-46's installed floor gate.
/// Dropping failed custody or a selected request before its authenticated
/// successor aborts the process before those original fields are destroyed.
#[must_use = "retain selected custody until an authenticated successor retires it"]
pub struct ProductionOriginalStorageOutputCycleV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: Option<crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1>,
    event: Option<crate::ProductionBrokerRequestEventV1>,
    ordinary: Option<Result<DormantAuthenticatedBrokerSessionV1, ProductionBrokerResponseErrorV1>>,
    selected: Option<OriginalStorageOutputRequestV1>,
    capture_candidate: Option<OriginalStorageCaptureRequestV1>,
    receive_deadline: Option<Result<u64, ProductionBrokerDeadlineErrorV1>>,
    poll_failure: Option<rustix::io::Errno>,
    deadline: u64,
    started: bool,
    ended: bool,
}

impl Drop for ProductionOriginalStorageOutputCycleV1 {
    fn drop(&mut self) {
        // The daemon uses explicit exit for a reported first cause. Unwind or
        // premature disposal must not release its original writers/carriers.
        if self.selected.is_some() || self.capture_candidate.is_some() || self.failure().is_some() || self.postcheck_debt().is_some() {
            std::process::abort();
        }
    }
}

struct OriginalStorageOutputRequestV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    registration: aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    original: Option<Result<aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1, aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    host_custody: Option<Result<crate::ProtectedBrokerSessionFixedCustodyV1, crate::BrokerSessionSecurityError>>,
    host_session: Option<Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    host: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1,
    preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1,
    nomination: Option<aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1>,
    host_body: Option<Result<Vec<u8>, aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptErrorV1>>,
    host_checks: [Option<Result<(), crate::BrokerSessionSecurityError>>; 2],
    readiness: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
    terminal: crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    deadline: u64,
    attempted: bool,
    ended: bool,
}

struct OriginalStorageCaptureRequestV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
    dispatch: Option<Result<
        crate::ProtectedBrokerOutcomeCommitResultV1,
        crate::DormantBrokerExecutionFailureV1<crate::ProductionStorageBrokerDispatchErrorV1>,
    >>,
    retirement: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    dispatch_postcheck: Option<Result<(), aos_sandbox_storage::DormantStorageBrokerCallErrorV1>>,
    terminal: crate::production_response::OriginalCaptureCandidateResponseV1,
    deadline: u64,
    attempted: bool,
}

impl OriginalStorageCaptureRequestV1 {
    fn begin(
        session: DormantAuthenticatedBrokerSessionV1,
        receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        deadline: u64,
    ) -> Self {
        Self {
            session: Some(session),
            receipt,
            dispatch: None,
            retirement: None,
            dispatch_postcheck: None,
            terminal: crate::production_response::OriginalCaptureCandidateResponseV1::empty(),
            deadline,
            attempted: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.failure() { return Some(error); }
        match &self.dispatch {
            Some(Err(crate::DormantBrokerExecutionFailureV1::BeforeEffect { error, .. })) => return Some(error),
            Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown { error, .. })) => {
                return match error {
                    crate::DormantBrokerExecutionErrorV1::Domain(crate::ProductionStorageBrokerDispatchErrorV1::Operation(
                        aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody),
                    )) => custody.original_cause().or_else(|| custody.postcheck_debt()),
                    error => Some(error),
                };
            }
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { error, .. })) => return Some(error),
            _ => {}
        }
        if let Some(error) = self.terminal.failure() { return Some(error); }
        if let Some(Err(error)) = &self.dispatch_postcheck {
            return match error {
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                    custody.original_cause().or_else(|| custody.postcheck_debt()),
                error => Some(error),
            };
        }
        if let Some(Err(error)) = &self.retirement { return Some(error); }
        None
    }

    fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.postcheck_debt() { return Some(error); }
        if let Some(Err(error)) = &self.dispatch_postcheck {
            return match error {
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody) =>
                    custody.original_cause().or_else(|| custody.postcheck_debt()),
                error => Some(error),
            };
        }
        if let Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown {
            error: crate::DormantBrokerExecutionErrorV1::Domain(crate::ProductionStorageBrokerDispatchErrorV1::Operation(
                aos_sandbox_storage::DormantStorageBrokerCallErrorV1::CaptureCandidate(custody),
            )), ..
        })) = &self.dispatch {
            if let Some(error) = custody.postcheck_debt() { return Some(error); }
        }
        self.terminal.postcheck_debt()
    }

    fn advance(
        &mut self,
        request: crate::DormantReceivedBrokerRequestV1,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) {
        if self.attempted { return; }
        self.attempted = true;
        let Some(session) = &mut self.session else { return; };
        self.dispatch = Some(session.dispatch_storage_capture_candidate_and_commit_v1(request, storage, output));
        // A terminal/currentness failure owns chronological priority. Still
        // compare the actual source after that native signing/commit boundary;
        // an already failed domain recipe is not reopened or retried.
        if matches!(&self.dispatch,
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::RecoveryRequired { .. }))
            | Some(Err(crate::DormantBrokerExecutionFailureV1::OutcomeUnknown {
                error: crate::DormantBrokerExecutionErrorV1::Currentness(_), ..
            }))
        ) {
            self.dispatch_postcheck = Some(storage.recheck_original_capture_candidate_v1(output, false));
        }
        let committed = match self.dispatch.take() {
            Some(Ok(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed))) => committed,
            retained => {
                self.dispatch = retained;
                return;
            }
        };
        self.terminal.send_once(session, committed, storage, output, self.deadline);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("original Storage output request is closed with its returned custody resident")]
struct OriginalStorageOutputClosedV1;

impl ProductionOriginalStorageOutputCycleV1 {
    fn begin(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            session: Some(session),
            receipt: None,
            event: None,
            ordinary: None,
            selected: None,
            capture_candidate: None,
            receive_deadline: None,
            poll_failure: None,
            deadline: 0,
            started: false,
            ended: false,
        }
    }

    /// Borrows the actual same-session descriptor for the existing daemon poll.
    ///
    /// # Errors
    /// Rejects a closed cycle or an unavailable original carrier.
    pub fn as_fd(&self) -> Result<std::os::fd::BorrowedFd<'_>, crate::DormantBrokerSessionHandshakeErrorV1> {
        if self.ended {
            return Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole);
        }
        if let Some(capture) = &self.capture_candidate {
            if let Some(session) = &capture.session { return session.as_fd(); }
        }
        if let Some(selected) = &self.selected {
            return selected.session.as_ref().ok_or(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)?.as_fd();
        }
        if let Some(Ok(session)) = &self.ordinary {
            return session.as_fd();
        }
        if let Some(session) = &self.session {
            return session.as_fd();
        }
        Err(crate::DormantBrokerSessionHandshakeErrorV1::EndpointRole)
    }

    /// Borrows the genuine first returned cause, never an erased replacement.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.poll_failure { return Some(error); }
        if let Some(Err(error)) = &self.receive_deadline { return Some(error); }
        if let Some(receipt) = &self.receipt {
            if let Some(error) = receipt.failure() { return Some(error); }
        }
        if let Some(Err(error)) = &self.ordinary { return Some(error); }
        if let Some(capture) = &self.capture_candidate {
            if let Some(error) = capture.failure() { return Some(error); }
            if capture.postcheck_debt().is_some() { return None; }
        }
        if let Some(selected) = &self.selected {
            if let Some(error) = selected.failure() { return Some(error); }
            if self.postcheck_debt().is_some() { return None; }
        }
        self.ended.then_some(&OriginalStorageOutputClosedV1 as &dyn std::error::Error)
    }

    /// Borrows later currentness debt independently of an earlier action error.
    #[must_use]
    pub fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(receipt) = &self.receipt {
            if let Some(error) = receipt.postcheck_debt() { return Some(error); }
        }
        if let Some(capture) = &self.capture_candidate {
            if let Some(error) = capture.postcheck_debt() { return Some(error); }
        }
        let selected = self.selected.as_ref()?;
        if let Some(error) = selected.receipt.postcheck_debt() { return Some(error); }
        if let Some(session) = &selected.session {
            if let Some(error) = session.output_preparation_postcheck_debt(&selected.preparation) { return Some(error); }
        }
        if let Some(Ok(session)) = &selected.host_session {
            if let Some(error) = session.output_client_flight_postcheck_debt(&selected.host) { return Some(error); }
        }
        if let Some(error) = selected.registration.postcheck_debt() { return Some(error); }
        if selected.host_checks[1].is_some() {
            if let Some(Ok(session)) = &selected.host_session {
                if let Some(witness) = session.output_terminal_witness_debt_before_protected() { return Some(witness); }
            }
        }
        if let Some(Err(error)) = &selected.host_checks[1] {
            return Some(error);
        }
        if let Some(Ok(session)) = &selected.host_session {
            if let Some(witness) = session.output_terminal_witness_debt() { return Some(witness); }
        }
        selected.terminal.postcheck_debt().map(|error| error as &dyn std::error::Error)
    }

    /// Parks the daemon's actual poll error before any later bookend or return.
    pub fn close_on_poll_failure(&mut self, error: rustix::io::Errno) {
        self.ended = true;
        if self.poll_failure.is_none() {
            self.poll_failure = Some(error);
        }
    }

    /// Drives the same request engines without replacing a failed attempt.
    /// Unit return is not success; diagnostics and original results stay owned.
    pub fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
        next_receive_deadline: Result<u64, ProductionBrokerDeadlineErrorV1>,
    ) {
        if self.ended {
            return;
        }
        // The real Session was parked before the daemon's clock call. A new
        // receive cut is only for a subsequent authenticated request; it never
        // replaces the predecessor's resident request deadline or ambiguity.
        self.receive_deadline = Some(next_receive_deadline);
        let Some(Ok(next_receive_deadline)) = &self.receive_deadline else {
            self.ended = true;
            return;
        };
        let next_receive_deadline = *next_receive_deadline;
        if self.started {
            // The predecessor remains resident while the sole authenticated
            // receiver admits its signed successor against the terminal head.
            if let Some(capture) = self.capture_candidate.as_mut() {
                if !capture.terminal.locally_sent() || capture.failure().is_some() || capture.postcheck_debt().is_some() {
                    self.ended = true;
                    return;
                }
                self.session = capture.session.take();
            } else if let Some(selected) = self.selected.as_mut() {
                if !selected.terminal.locally_sent() {
                    self.ended = true;
                    return;
                }
                self.session = selected.session.take();
            } else if matches!(&self.ordinary, Some(Ok(_))) {
                let Some(Ok(session)) = self.ordinary.take() else {
                    self.ended = true;
                    return;
                };
                self.session = Some(session);
            } else {
                self.ended = true;
                return;
            }
            self.deadline = next_receive_deadline;
        }
        if !self.started {
            self.deadline = next_receive_deadline;
        }
        self.started = true;
        // The actual Session remains resident through the borrowed receiver.
        // This native record and admission use the sole parser/CAS engine.
        self.ended = true;
        self.receipt = Some(crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1::empty());
        let Some(session) = &mut self.session else { return; };
        let Some(receipt) = &mut self.receipt else { return; };
        self.event = session.receive_original_output_request(receipt, self.deadline);
        if self.event.is_none() { return; }
        // A selected repeat stays resident and closed. It cannot enter the
        // ordinary resend/recovery adapter or mint another signing attempt.
        if self.event.as_ref().is_some_and(|event| event.is_original_output_replay()) {
            return;
        }
        if self.event.as_ref().is_some_and(|event| event.is_original_capture_candidate_replay()) {
            return;
        }

        if let Some(capture) = &mut self.capture_candidate {
            let Some(crate::ProductionBrokerRequestEventV1::Request(successor)) = &self.event else { return; };
            let Some(original) = storage.original_capture_candidate_request() else { return; };
            if !successor.is_original_output_successor(original) { return; }
            capture.retirement = Some(successor.retire_original_storage_capture_candidate(storage));
            if !matches!(&capture.retirement, Some(Ok(()))) { return; }
            // The real receipt has authenticated the signed predecessor. Both
            // successful source and terminal custody may now retire together.
            self.capture_candidate = None;
        }

        if let Some(predecessor) = &self.selected {
            let original = predecessor.registration.original_request();
            let Some(crate::ProductionBrokerRequestEventV1::Request(successor)) = &self.event else { return; };
            if !successor.is_original_output_successor(original) { return; }
            // A current signed successor, not local send success, is the
            // coordination point that retires the previous successful attempt.
        }
        let Some(event) = self.event.take() else { return; };
        let Some(session) = self.session.take() else { return; };
        match event {
            crate::ProductionBrokerRequestEventV1::Request(request)
                if request.method() == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE =>
            {
                let deadline = self.deadline.min(request.original_capture_candidate_deadline());
                let Some(receipt) = self.receipt.take() else { return; };
                self.selected = None;
                self.capture_candidate = Some(OriginalStorageCaptureRequestV1::begin(session, receipt, deadline));
                let Some(capture) = &mut self.capture_candidate else { return; };
                capture.advance(request, storage, output);
                self.ended = !capture.terminal.locally_sent() || capture.failure().is_some() || capture.postcheck_debt().is_some();
            }
            crate::ProductionBrokerRequestEventV1::Request(request)
                if matches!(request.method(),
                    aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT) =>
            {
                let registration = request.into_original_output_registration(storage);
                let deadline = self.deadline.min(registration.original_request().deadline_boottime_nanoseconds());
                let Some(receipt) = self.receipt.take() else { return; };
                self.selected = Some(OriginalStorageOutputRequestV1::begin(session, receipt, registration, deadline));
                let Some(selected) = self.selected.as_mut() else { return; };
                selected.advance(storage, output);
                self.ended = selected.failure().is_some() || self.postcheck_debt().is_some();
            }
            ordinary => {
                self.selected = None;
                // The ordinary consuming completion engine and its errors are
                // unchanged. Only its returned whole result is additionally held.
                self.ordinary = Some(session.complete_storage_request_event(ordinary, storage, self.deadline));
                self.ended = !matches!(&self.ordinary, Some(Ok(_)));
            }
        }
    }
}

impl OriginalStorageOutputRequestV1 {
    fn begin(
        session: DormantAuthenticatedBrokerSessionV1,
        receipt: crate::handshake::output_registration_continuation::OriginalOutputServerReceiptV1,
        registration: aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
        deadline: u64,
    ) -> Self {
        Self {
            session: Some(session),
            receipt,
            registration,
            original: None,
            host_custody: None,
            host_session: None,
            host: crate::handshake::output_registration_continuation::OriginalOutputClientFlightV1::empty(),
            preparation: crate::handshake::output_registration_continuation::OutputPreparationCustodyV1::empty(),
            nomination: None,
            host_body: None,
            host_checks: std::array::from_fn(|_| None),
            readiness: std::array::from_fn(|_| None),
            terminal: crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1::empty(),
            deadline,
            attempted: false,
            ended: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = self.receipt.failure() { return Some(error); }
        if let Some(Err(error)) = &self.original { return Some(error); }
        if let Some(Err(error)) = &self.host_custody { return Some(error); }
        if let Some(Err(error)) = &self.host_session { return Some(error); }
        let host_failure = match &self.host_session {
            Some(Ok(session)) => session.output_client_flight_failure(&self.host),
            _ => self.host.failure(),
        };
        if let Some(error) = host_failure { return Some(error); }
        if let Some(Err(error)) = &self.host_body { return Some(error); }
        let preparation_failure = match &self.session {
            Some(session) => session.output_preparation_failure(&self.preparation),
            None => self.preparation.failure(),
        };
        if let Some(error) = preparation_failure { return Some(error); }
        for result in self.readiness.iter().flatten() {
            if let Err(error) = result { return Some(error); }
        }
        if self.host_checks[0].is_some() {
            if let Some(Ok(session)) = &self.host_session {
                if let Some(witness) = session.output_terminal_witness_failure() { return Some(witness); }
            }
        }
        if let Some(Err(error)) = &self.host_checks[0] {
            return Some(error);
        }
        if let Some(error) = self.registration.failure() { return Some(error); }
        if let Some(error) = self.terminal.failure() { return Some(error); }
        let witness_debt = self.host_session.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(DormantAuthenticatedBrokerSessionV1::output_terminal_witness_debt).is_some();
        (self.ended && !witness_debt && !self.host.has_postcheck_debt() && !self.preparation.has_postcheck_debt())
            .then_some(&OriginalStorageOutputClosedV1 as &dyn std::error::Error)
    }

    fn advance(
        &mut self,
        storage: &mut aos_sandbox_storage::DormantStorageApplyCompositionV1,
        output: &mut aos_sandbox_storage::execution_output_credential::StorageExecutionOutputCustodyV1,
    ) {
        if self.attempted {
            self.ended = true;
            return;
        }
        self.attempted = true;
        self.ended = true;
        if self.registration.original_request().method()
            == aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
        {
            if let Some(session) = &mut self.session {
                {
                    let mut transport = session.output_registration_transport(
                        self.registration.original_request(), &mut self.preparation,
                    );
                    if transport.recheck(self.registration.original_request()).is_err() { return; }
                    storage.query_original_execution_output(output, &mut self.registration);
                    if transport.finish_action_turn(self.registration.original_request()).is_err() { return; }
                }
                finish_original_output_terminal(
                    session, &self.registration, &mut self.terminal,
                    &mut self.readiness[4], self.deadline,
                );
            }
            self.ended = !self.terminal.locally_sent();
            return;
        }
        self.original = Some(aos_sandbox::controller_storage_output_reserve_attempt::ControllerStorageOutputReserveAttemptV1::from_authenticated_captured_request(
            self.registration.original_request(),
        ));
        if !matches!(&self.original, Some(Ok(_))) { return; }
        self.host_custody = Some(crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::StorageHostClient,
        ));
        if !matches!(&self.host_custody, Some(Ok(_))) { return; }
        let Some(Ok(custody)) = self.host_custody.take() else { return; };
        self.host_session = Some(custody.connect_output_client_session(self.deadline));
        let Some(Ok(host_session)) = &mut self.host_session else { return; };
        host_session.park_output_client_coordinates(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT,
            self.deadline, &mut self.host,
        );
        let Some(Ok(coordinates)) = &self.host.coordinates else { return; };
        let Some(Ok(original)) = &self.original else { return; };
        self.host_body = Some(original.captured_host_readback_body(coordinates.request_header()));
        let Some(Ok(body)) = &self.host_body else { return; };
        let Some(session) = &mut self.session else { return; };
        let request = self.registration.original_request();
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        let Ok(head) = transport.original_head(request) else { return; };
        self.nomination = Some(aos_proto::aos::sandbox::local::v1::StorageOutputRegistrationPreparationV1 {
            version: 1, stage: 1,
            original_storage_request_id: request.request_id().to_vec(),
            original_storage_session_binding: request.session_binding().to_vec(),
            original_signed_request_digest: request.signed_request_digest().to_vec(),
            original_semantic_request_digest: request.semantic_commitment().to_vec(),
            storage_pending_head: head.to_vec(),
            canonical_host_readback_request: body.clone(),
            ..Default::default()
        });
        if transport.finish_turn(request).is_err() { return; }
        self.readiness[0] = Some(wait_output_original(session, true, self.deadline));
        if !matches!(&self.readiness[0], Some(Ok(()))) { return; }
        let Some(nomination) = &self.nomination else { return; };
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        if transport.send(request, nomination).is_err() || transport.finish_turn(request).is_err() { return; }
        self.readiness[1] = Some(wait_output_original(session, false, self.deadline));
        if !matches!(&self.readiness[1], Some(Ok(()))) { return; }
        let mut transport = session.output_registration_transport(request, &mut self.preparation);
        if transport.receive(request, 2).is_err() || transport.finish_turn(request).is_err() { return; }
        let Some(authorization) = self.preparation.record(2) else { return; };
        if !aos_sandbox_protocol::storage_output_reserve::continuation::matches_nomination_v1(authorization, nomination) { return; }
        let message = aos_proto::aos::sandbox::local::v1::BrokerRequestEnvelope {
            method: aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT.into(),
            body: body.clone(),
            authorization: authorization.host_authorization.clone(),
            ..Default::default()
        };
        if !host_session.park_output_client_request(&mut self.host, message) { return; }
        self.readiness[2] = Some(wait_output_original(host_session, true, self.deadline));
        if !matches!(&self.readiness[2], Some(Ok(())))
            || !host_session.send_original_output_client_request(&mut self.host)
        { return; }
        self.readiness[3] = Some(wait_output_original(host_session, false, self.deadline));
        if !matches!(&self.readiness[3], Some(Ok(())))
            || !host_session.receive_original_output_client_terminal(&mut self.host)
        { return; }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(committed)) = &self.host.committed else { return; };
        {
            let mut transport = session.output_registration_transport(
                request, &mut self.preparation,
            );
            if transport.recheck(request).is_err() { return; }
            host_session.register_original_storage_output_with_host(
                committed, storage, output, &mut self.registration, &mut self.host_checks,
            );
            if transport.finish_action_turn(self.registration.original_request()).is_err() { return; }
        }
        if !matches!(&self.host_checks[0], Some(Ok(())))
            || !matches!(&self.host_checks[1], Some(Ok(())))
            || host_session.output_terminal_witness_failure().is_some()
            || host_session.output_terminal_witness_debt().is_some()
        { return; }
        finish_original_output_terminal(
            session, &self.registration, &mut self.terminal,
            &mut self.readiness[4], self.deadline,
        );
        self.ended = !self.terminal.locally_sent();
    }
}

fn finish_original_output_terminal(
    session: &mut DormantAuthenticatedBrokerSessionV1,
    registration: &aos_sandbox_storage::execution_output_credential::OriginalExecutionOutputRegistrationV1,
    terminal: &mut crate::handshake::output_registration_continuation::OriginalOutputServerTerminalV1,
    readiness: &mut Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    deadline: u64,
) {
    let Some(body) = registration.response() else { return; };
    session.commit_original_output_server_terminal(registration.original_request(), body, terminal);
    if terminal.failure().is_some() { return; }
    *readiness = Some(wait_output_original(session, true, deadline));
    if !matches!(readiness, Some(Ok(()))) { return; }
    session.send_original_output_server_terminal(terminal);
}

pub(crate) fn wait_output_original(
    session: &DormantAuthenticatedBrokerSessionV1,
    write: bool,
    deadline: u64,
) -> Result<(), crate::DormantBrokerSessionHandshakeErrorV1> {
    crate::dormant_handshake::wait_for_handshake_readiness(session.as_fd()?, write, deadline)
}
