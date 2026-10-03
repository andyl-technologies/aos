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
/// route sends no public success, completes no BSA outcome, and proves neither
/// Ready nor terminal drain. The selected installed caller supplies the genuine
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
                        .map(ProductionOriginalMountCycleFailureV1::Mount),
                }
            }
            Some(OriginalMountCycleStageV1::Deadline) => self.deadline_result.as_ref().and_then(|result| result.as_ref().err()).map(ProductionOriginalMountCycleFailureV1::Deadline),
            None => None,
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
    /// Receives and completes one Host request or exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error after consuming the session when any receive,
    /// admission, Host effect, recovery, commit, or response step fails.
    pub async fn serve_production_host_request(
        self,
        host: &mut dyn aos_sandbox_host::DormantHostBrokerCallsiteV1,
        publisher: &aos_sandbox_host::catalog::FileHostCatalogPublisher,
        agent: Option<&mut aos_sandbox_host::live_agent::HostAgentLiveSessionV1>,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<Self, ProductionBrokerServiceErrorV1> {
        let (session, event) =
            self.receive_production_host_request(deadline_boottime_nanoseconds)?;
        session
            .complete_host_request_event(
                event,
                host,
                publisher,
                agent,
                deadline_boottime_nanoseconds,
            )
            .await
            .map_err(Into::into)
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
