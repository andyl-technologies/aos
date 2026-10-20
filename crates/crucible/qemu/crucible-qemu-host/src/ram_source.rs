//! Retains immutable backing authority for independently owned lazy RAM sources.
//!
//! The source thread serves only a separately authenticated root and namespace.
//! A child or restored process receives a fresh endpoint and binding. Immutable
//! backing may be shared, while mutable request cursors, cancellation, and
//! supervision guards belong to each source separately. Cancellation closes
//! admission and transport; it never supplies substitute page bytes.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use crucible_host_resources::host_services::native_join::{
    NativeJoinError, NativeJoinObservation, NativeJoinOwner,
};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible_host_resources::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationState, HostOperationSupervisor,
    HostSupervisionError,
};
use crucible_qemu_protocol::ram_page::{
    RAM_PAGE_REQUEST_BYTES, RamPageBinding, RamPageProtocolError, RamPageRequest, RamPageResponse,
    RamPageStatus,
};
use crucible_ram::{RootRecord, Scope};
use thiserror::Error;

mod worker_failure;
mod worker_outcome;
pub use worker_failure::QemuRamWorkerFailure;
pub use worker_outcome::QemuRamWorkerPanic;

const SOURCE_STACK_BYTES: usize = 256 * 1024;

/// Fixed branch-private page source socket inherited by a guarded child.
pub const QEMU_RAM_SOURCE_TARGET_FD: i32 = 10;

/// Immutable page lookup authority with a live descendant backing lease.
///
/// Implementations retain the complete root and its storage descendants for
/// their entire lifetime, including the resident admission obtained before
/// decoding that root. Sharing a backing authority shares its retained root
/// allocation; each source separately admits its worker and page-proof scratch.
/// The root record is immutable. Every lookup observes
/// operational boundaries while traversing storage and returns a logical proof;
/// neither a root digest nor an unleased storage handle satisfies this trait.
pub trait QemuRamBacking: Send + Sync {
    /// Returns the canonical retained storage-root identifier without transferring a lease.
    fn root_object_id(&self) -> &str;

    /// Returns the complete authenticated root retained by this authority.
    fn root_record(&self) -> &RootRecord;

    /// Authenticates one page and consumes it under its original allocation custody.
    ///
    /// Successful sources deliver exactly one completion before returning. The
    /// worker independently retains consumption failures and rejects missing or
    /// duplicate deliveries before another publication. The source retains the
    /// original page, proof, encoding, and resource owners until consumption ends.
    ///
    /// # Errors
    ///
    /// Returns an error for absent coordinates, unavailable or corrupt backing,
    /// cancellation, resource limits, or an operational deadline.
    fn with_page_response(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamReadBoundaryError>,
        consumer: &mut QemuRamResponseConsumer<'_>,
    ) -> Result<(), QemuRamSourceError>;

    /// Takes one authored transport adversary after normal page authentication.
    ///
    /// The test-support worker retains its original page, proof, namespace,
    /// resource credits, and supervision while sending the damaged completion.
    /// Ordinary builds have no transport injection surface.
    #[cfg(any(test, feature = "test-support"))]
    fn take_response_fault_for_test(&self) -> Option<QemuRamResponseFault> {
        None
    }
}

/// Borrows the actual page-in operation's continuation check.
pub type QemuRamReadBoundary<'a> = dyn FnMut() -> Result<(), QemuRamReadBoundaryError> + 'a;

/// Consumes a borrowed completion while its source retains original custody.
///
/// The callback returns no failure to the provider: the worker retains its
/// original result independently, so a provider cannot replace that first cause.
pub type QemuRamResponseConsumer<'a> =
    dyn FnMut(crucible_ram::BorrowedPageResponse<'_>, &mut QemuRamReadBoundary<'_>) + 'a;

/// A closed test-support adversary applied to one real authenticated response.
///
/// This type never crosses a process boundary. The worker uses the ordinary
/// versioned page protocol and its existing admitted transport buffer.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuRamResponseFault {
    /// Changes one encoded page byte while retaining its authentic proof.
    ChangedPageByte,
    /// Sends the authentic header and part of the body before write-side EOF.
    TruncatedBody,
    /// Closes the response direction before writing its header.
    DisconnectBeforeHeader,
    /// Changes only the source generation of an otherwise authentic response.
    StaleSourceGeneration,
}

/// Reports the actual native page worker's closed operational boundary refusal.
#[derive(Debug, Error)]
pub enum QemuRamReadBoundaryError {
    /// Sticky source cancellation stopped the current backing read.
    #[error("RAM source canceled")]
    Canceled,
    /// The same original page-in operation's supervision refused continuation.
    #[error(transparent)]
    Supervision(#[from] HostSupervisionError),
}

impl QemuRamReadBoundaryError {
    /// Returns the original operational category without diagnostic parsing.
    #[must_use]
    pub fn operational_kind(&self) -> crucible_engine::BackendOperationalFailureKind {
        use crucible_engine::BackendOperationalFailureKind as Kind;
        match self {
            Self::Canceled
            | Self::Supervision(HostSupervisionError::Terminal {
                state: HostOperationState::Canceled,
            }) => Kind::Canceled,
            Self::Supervision(
                HostSupervisionError::DeadlineExpired { .. }
                | HostSupervisionError::Terminal {
                    state: HostOperationState::Expired,
                },
            ) => Kind::Expired,
            Self::Supervision(HostSupervisionError::CapacityExhausted) => Kind::CapacityExhausted,
            Self::Supervision(_) => Kind::Terminal,
        }
    }
}

impl From<QemuRamReadBoundaryError> for QemuRamSourceError {
    fn from(source: QemuRamReadBoundaryError) -> Self {
        match source {
            QemuRamReadBoundaryError::Canceled => Self::Canceled,
            QemuRamReadBoundaryError::Supervision(source) => Self::Supervision(source),
        }
    }
}

/// A typed operational source failure, separate from guest outcomes.
#[derive(Debug, Error)]
pub enum QemuRamSourceError {
    /// A source namespace, sequence, or logical root did not match.
    #[error("RAM source namespace or request ownership does not match")]
    Ownership,
    /// The immutable content realization was absent, corrupt, or unavailable.
    #[error("RAM backing lookup failed: {0}")]
    Backing(String),
    /// A concrete backing failure retains its typed cause and resource custody.
    #[error("RAM backing lookup failed: {source}")]
    BackingFailure {
        /// Operational category supplied by the concrete authenticated store.
        kind: crucible_engine::BackendOperationalFailureKind,
        /// Original store error without diagnostic conversion or clone loss.
        #[source]
        source: crucible_engine::BackendOperationalCause,
    },
    /// Complete RAM storage and cleanup failure from a native backing read.
    #[error("RAM backing lookup failed: {source}")]
    RamBackingFailure {
        /// Original first refusal category, or the complete storage category.
        kind: crucible_engine::BackendOperationalFailureKind,
        /// Complete RAM error, including actual SQL outcome and cleanup causes.
        #[source]
        source: crucible_store::ram::RamStoreError,
        /// First original page worker boundary refusal, if storage also failed.
        first: Option<QemuRamReadBoundaryError>,
    },
    /// A logical proof failed verification against the admitted root.
    #[error("RAM source proof validation failed: {0}")]
    Proof(String),
    /// Sticky source cancellation closed admission.
    #[error("RAM source canceled")]
    Canceled,
    /// The source transport or worker could not be constructed or completed.
    #[error("RAM source transport failed: {0}")]
    Io(#[from] io::Error),
    /// The independently implementable page protocol rejected a record.
    #[error(transparent)]
    Protocol(#[from] RamPageProtocolError),
    /// An operational allowance or ownership guard failed.
    #[error(transparent)]
    Supervision(#[from] HostSupervisionError),
    /// The owned source worker panicked while retaining its backing.
    #[error("RAM source worker panicked")]
    WorkerPanicked,
    /// The original completed worker failure remains shared by every observer.
    #[error("RAM source worker failed: {0}")]
    WorkerFailed(#[source] QemuRamWorkerFailure),
    /// This target lacks the audited unique nonblocking native-join boundary.
    #[error("RAM source requires GNU/Linux native thread return")]
    NativeJoinUnsupported,
    /// Explicit host service task or descriptor admission failed.
    #[error(transparent)]
    Services(#[from] crucible_host_resources::host_services::HostServiceError),
}

/// Linear source service retained through process termination or quarantine.
#[must_use = "retain the source and its backing authority through process disposition"]
pub struct QemuRamSourceService {
    stop: stop::StopState,
    binding: RamPageBinding,
    backing: Arc<dyn QemuRamBacking>,
    cancellation: Arc<AtomicBool>,
    wake: UnixStream,
    worker: Option<SourceWorker>,
    startup: Option<UnixStream>,
    spawn_attempted: bool,
    spawn_returned: bool,
    worker_started: bool,
    birth_before: Option<HostSupervisionError>,
    birth_after: Option<HostSupervisionError>,
    supervisor: HostOperationSupervisor,
    failure: worker_outcome::WorkerOutcome,
    service_lease: crucible_host_resources::host_services::HostServiceLease,
    launch_join: Option<crate::launch_cleanup::LaunchSourceJoin>,
}

/// Retains the actual socket and immutable input before Service construction.
pub(crate) struct SourceInput {
    socket: UnixStream,
    backing: Arc<dyn QemuRamBacking>,
    binding: RamPageBinding,
}

impl std::fmt::Debug for SourceInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceInput")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl SourceInput {
    pub(crate) fn new(
        socket: UnixStream,
        backing: Arc<dyn QemuRamBacking>,
        binding: RamPageBinding,
    ) -> Self {
        Self {
            socket,
            backing,
            binding,
        }
    }
}

// The actual native task and its result/loan cannot move independently.
struct SourceWorker {
    native: NativeJoinOwner,
    outcome: worker_outcome::WorkerOutcome,
}

impl std::fmt::Debug for QemuRamSourceService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuRamSourceService")
            .field("binding", &self.binding)
            .field("service_lease", &self.service_lease)
            .field("canceled", &self.cancellation.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl QemuRamSourceService {
    /// Starts a component-owned source without asserting a Main or Source role.
    ///
    /// # Errors
    /// Refuses invalid source material, unavailable resources, or actual birth.
    #[cfg(test)]
    pub(crate) fn start_component(
        socket: UnixStream,
        backing: Arc<dyn QemuRamBacking>,
        binding: RamPageBinding,
        supervisor: HostOperationSupervisor,
        services: crucible_host_resources::host_services::HostServiceAllocator,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Result<Self, QemuRamSourceError> {
        let mut input = Some(SourceInput::new(socket, backing, binding));
        let mut service = Self::prepare(&mut input, supervisor, services)?;
        service.spawn_attempted = true;
        service.spawn_retained(cleanup)?;
        Ok(service)
    }

    /// Creates the paid source body without creating any worker.
    pub(crate) fn prepare(
        input: &mut Option<SourceInput>,
        supervisor: HostOperationSupervisor,
        services: crucible_host_resources::host_services::HostServiceAllocator,
    ) -> Result<Self, QemuRamSourceError> {
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (input, supervisor, services);
            return Err(QemuRamSourceError::NativeJoinUnsupported);
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let pending = input.as_ref().ok_or(QemuRamSourceError::Ownership)?;
            let binding = pending.binding;
            let backing = &pending.backing;
            binding.validate()?;
            if binding.root_digest != *backing.root_record().digest().as_bytes()
                || !matches!(
                    backing.root_record().scope(),
                    Scope::Exact | Scope::Lifecycle
                )
            {
                return Err(QemuRamSourceError::Ownership);
            }
            // One worker, its wake descriptor, and one sequential backing read.
            // Three response envelopes cover the page, decoded/encoded proof and
            // transport overlap. The backing's predecode credit owns its retained
            // root; bounded CAS traversal scratch has a separate node entitlement.
            let worker_metadata_bytes = QemuRamWorkerFailure::startup_metadata_bytes()?;
            let service_lease = services.reserve_resources(
                1,
                2,
                SOURCE_STACK_BYTES as u64
                    + 3 * crucible_qemu_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64
                    + worker_metadata_bytes,
            )?;

            let wake = pending.socket.try_clone()?;
            let cancellation = Arc::new(AtomicBool::new(false));
            let failure = worker_outcome::WorkerOutcome::new(service_lease.clone());
            // All fallible work leaves the caller's SAME input untouched.
            // The final transfer into its retained Service is a pure move.
            let SourceInput {
                socket,
                backing,
                binding,
            } = input.take().ok_or(QemuRamSourceError::Ownership)?;
            Ok(Self {
                stop: stop::StopState::new(),
                binding,
                backing,
                cancellation,
                wake,
                worker: None,
                startup: Some(socket),
                spawn_attempted: false,
                spawn_returned: false,
                worker_started: false,
                birth_before: None,
                birth_after: None,
                supervisor,
                failure,
                service_lease,
                launch_join: None,
            })
        }
    }

    /// Publishes only a body already stored in its actual containing owner.
    pub(crate) fn publish_retained(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Result<(), QemuRamSourceError> {
        if self.spawn_attempted || self.stop.join_returned() {
            return Err(QemuRamSourceError::Ownership);
        }
        self.spawn_attempted = true;
        self.birth_before = original.wait_slice().err();
        let result = if self.birth_before.is_none() {
            self.spawn_retained(cleanup)
        } else {
            self.failure.no_birth(None);
            self.spawn_returned = true;
            Ok(())
        };
        let result = match result {
            Err(first) if !self.spawn_returned => {
                // An error before Builder returned has no born task. Retain
                // its actual typed cause in the same paid result allocation.
                self.spawn_returned = true;
                let first = QemuRamWorkerFailure::new(first, self.service_lease.clone());
                self.failure.no_birth(Some(first.clone()));
                Err(QemuRamSourceError::WorkerFailed(first))
            }
            result => result,
        };
        // The body retains its actual native owner and result before this post.
        self.birth_after = original.wait_slice().err();
        if let Some(first) = self.birth_before {
            return Err(first.into());
        }
        result?;
        if let Some(post) = self.birth_after {
            return Err(post.into());
        }
        Ok(())
    }

    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    fn spawn_retained(
        &mut self,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Result<(), QemuRamSourceError> {
        let _ = cleanup;
        Err(QemuRamSourceError::NativeJoinUnsupported)
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn spawn_retained(
        &mut self,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Result<(), QemuRamSourceError> {
        self.launch_join = cleanup
            .as_ref()
            .map(crate::launch_cleanup::LaunchCleanup::source_join)
            .transpose()
            .map_err(|_| QemuRamSourceError::Ownership)?;
        let socket = self.startup.take().ok_or(QemuRamSourceError::Ownership)?;
        let worker_backing = Arc::clone(&self.backing);
        let worker_cancellation = Arc::clone(&self.cancellation);
        let worker_supervisor = self.supervisor.clone();
        let binding = self.binding;
        let worker_outcome = self.failure.clone();
        let worker_scope = worker_failure::WorkerScope::new(self.service_lease.clone(), cleanup);
        let worker = thread::Builder::new()
            .name("crucible-ram-source".to_owned())
            .stack_size(SOURCE_STACK_BYTES)
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let result = serve_pages(
                        socket,
                        worker_backing,
                        binding,
                        worker_cancellation,
                        worker_supervisor,
                    );
                    worker_scope.finish(result)
                }));
                worker_outcome.deliver(outcome);
            });
        match worker {
            Ok(worker) => {
                self.worker = Some(SourceWorker {
                    native: NativeJoinOwner::from_worker(worker),
                    outcome: self.failure.clone(),
                });
                self.worker_started = true;
                self.spawn_returned = true;
                Ok(())
            }
            Err(first) => {
                if let Some(join) = &mut self.launch_join {
                    join.joined();
                }
                self.spawn_returned = true;
                let first = QemuRamWorkerFailure::new(first.into(), self.service_lease.clone());
                self.failure.no_birth(Some(first.clone()));
                Err(QemuRamSourceError::WorkerFailed(first))
            }
        }
    }

    /// Returns the exact independently owned endpoint namespace.
    #[must_use]
    pub const fn binding(&self) -> RamPageBinding {
        self.binding
    }

    /// Checks that the owned source has not failed before process disposition.
    ///
    /// # Errors
    ///
    /// Returns an error for a failed or canceled source, uncertain failure
    /// inventory, or an unexpected terminal worker. Callers contain the process
    /// before retiring this source; its failure is never guest behavior.
    pub fn check_health(&self) -> Result<(), QemuRamSourceError> {
        let outcome = self.failure.snapshot();
        if let Some(error) = outcome.failure {
            return Err(QemuRamSourceError::WorkerFailed(error));
        }
        if outcome.panic.is_some() {
            return Err(QemuRamSourceError::WorkerPanicked);
        }
        if outcome.uncertain {
            return Err(QemuRamSourceError::Ownership);
        }
        if self.cancellation.load(Ordering::Acquire) {
            return Err(QemuRamSourceError::Canceled);
        }
        if self.worker.is_none() || outcome.delivered {
            return Err(QemuRamSourceError::Backing(
                "source worker ended unexpectedly".to_owned(),
            ));
        }
        Ok(())
    }

    /// Retains an immutable backing claim for a separately bound child source.
    ///
    /// # Errors
    ///
    /// Returns an error unless both session and owner incarnation are fresh and
    /// the logical root matches. No mutable source cursor is shared or copied.
    pub fn child_backing(
        &self,
        child: RamPageBinding,
    ) -> Result<Arc<dyn QemuRamBacking>, QemuRamSourceError> {
        child.validate()?;
        if child.session == self.binding.session
            || child.owner_incarnation == self.binding.owner_incarnation
            || child.root_digest != self.binding.root_digest
        {
            return Err(QemuRamSourceError::Ownership);
        }
        Ok(Arc::clone(&self.backing))
    }

    /// Closes request admission while preserving the owned backing claim.
    pub fn cancel(&self) {
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.native.belongs_to_current_process())
        {
            return;
        }
        self.cancellation.store(true, Ordering::Release);
        let _ = self.wake.shutdown(Shutdown::Both);
    }
}

impl Drop for QemuRamSourceService {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn serve_pages(
    mut socket: UnixStream,
    backing: Arc<dyn QemuRamBacking>,
    binding: RamPageBinding,
    cancellation: Arc<AtomicBool>,
    supervisor: HostOperationSupervisor,
) -> Result<(), QemuRamSourceError> {
    let mut sequence = 0_u64;
    loop {
        let (request, operation) = match read_request(&mut socket, &cancellation, &supervisor) {
            Ok(request) => request,
            Err(_) if cancellation.load(Ordering::Acquire) => return Ok(()),
            Err(error) => return Err(error),
        };
        let expected = sequence
            .checked_add(1)
            .ok_or(QemuRamSourceError::Ownership)?;
        if request.binding != binding || request.sequence != expected {
            send_response(
                &mut socket,
                &operation,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Rejected,
                    page: &[],
                    proof: &[],
                },
            )?;
            return Err(QemuRamSourceError::Ownership);
        }
        let region = backing
            .root_record()
            .topology()
            .regions()
            .get(request.region_ordinal as usize)
            .ok_or(QemuRamSourceError::Ownership)?;
        region
            .geometry()
            .valid_length(request.page_index)
            .map_err(|_| QemuRamSourceError::Ownership)?;
        let mut boundary = || {
            if cancellation.load(Ordering::Acquire) {
                return Err(QemuRamReadBoundaryError::Canceled);
            }
            operation.wait_slice()?;
            Ok(())
        };
        boundary()?;
        consume_backing_page(
            backing.as_ref(),
            region.id(),
            request.page_index,
            &mut boundary,
            &mut |read, boundary| {
                let page = read.bytes();
                let proof = read.proof();
                if proof.region_id() != region.id() || proof.page_index() != request.page_index {
                    return Err(QemuRamSourceError::Ownership);
                }
                proof
                    .verify(page, backing.root_record(), backing.root_record().digest())
                    .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
                boundary()?;
                let proof = read.encoded_proof();
                #[cfg(any(test, feature = "test-support"))]
                if let Some(fault) = backing.take_response_fault_for_test() {
                    send_faulted_response(
                        &mut socket,
                        &operation,
                        RamPageResponse {
                            binding,
                            sequence: request.sequence,
                            status: RamPageStatus::Page,
                            page,
                            proof,
                        },
                        fault,
                    )?;
                    return Err(io::Error::other(
                        "authored test-support response transport failure",
                    )
                    .into());
                }
                send_response(
                    &mut socket,
                    &operation,
                    RamPageResponse {
                        binding,
                        sequence: request.sequence,
                        status: RamPageStatus::Page,
                        page,
                        proof,
                    },
                )?;
                operation.progress(1)?;
                operation.complete()?;
                Ok(())
            },
        )?;
        sequence = request.sequence;
    }
}

fn consume_backing_page(
    backing: &dyn QemuRamBacking,
    region_id: &str,
    page_index: u64,
    boundary: &mut QemuRamReadBoundary<'_>,
    consume: &mut impl FnMut(
        crucible_ram::BorrowedPageResponse<'_>,
        &mut QemuRamReadBoundary<'_>,
    ) -> Result<(), QemuRamSourceError>,
) -> Result<(), QemuRamSourceError> {
    let mut consumed = None;
    let source =
        backing.with_page_response(region_id, page_index, boundary, &mut |page, boundary| {
            match &consumed {
                // A second delivery never reaches another boundary or publication.
                Some(Ok(())) => consumed = Some(Err(QemuRamSourceError::Ownership)),
                // The full first failure remains owned here, even if swallowed or
                // replaced by a later provider result.
                Some(Err(_)) => {}
                None => consumed = Some(consume(page, boundary)),
            }
        });

    match (consumed, source) {
        (Some(Err(first)), _) => Err(first),
        (None, Ok(())) => Err(QemuRamSourceError::Ownership),
        (_, Err(source)) => Err(source),
        (Some(Ok(())), Ok(())) => Ok(()),
    }
}

fn read_request(
    socket: &mut UnixStream,
    cancellation: &AtomicBool,
    supervisor: &HostOperationSupervisor,
) -> Result<(RamPageRequest, HostOperationGuard), QemuRamSourceError> {
    let mut bytes = [0; RAM_PAGE_REQUEST_BYTES];
    let mut offset = 0;
    let mut operation = None;
    while offset < bytes.len() {
        if cancellation.load(Ordering::Acquire) {
            return Err(QemuRamSourceError::Canceled);
        }
        let slice = match &operation {
            Some(guard) => HostOperationGuard::wait_slice(guard)?,
            None => Duration::from_millis(10),
        };
        socket.set_read_timeout(Some(slice))?;
        match socket.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(if cancellation.load(Ordering::Acquire) {
                    QemuRamSourceError::Canceled
                } else {
                    io::Error::from(io::ErrorKind::UnexpectedEof).into()
                });
            }
            Ok(count) => {
                if operation.is_none() {
                    operation = Some(supervisor.begin(HostOperationClass::PageIn)?);
                }
                offset += count;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let operation = operation.ok_or(QemuRamSourceError::Ownership)?;
    Ok((RamPageRequest::decode(&bytes)?, operation))
}

fn send_response(
    socket: &mut UnixStream,
    operation: &HostOperationGuard,
    response: RamPageResponse<'_>,
) -> Result<(), QemuRamSourceError> {
    let bytes = response.encode()?;
    write_response_bytes(socket, operation, &bytes)
}

#[cfg(any(test, feature = "test-support"))]
fn send_faulted_response(
    socket: &mut UnixStream,
    operation: &HostOperationGuard,
    mut response: RamPageResponse<'_>,
    fault: QemuRamResponseFault,
) -> Result<(), QemuRamSourceError> {
    operation.wait_slice()?;
    if fault == QemuRamResponseFault::DisconnectBeforeHeader {
        socket.shutdown(Shutdown::Write)?;
        return Ok(());
    }
    if fault == QemuRamResponseFault::StaleSourceGeneration {
        response.binding.source_generation = response
            .binding
            .source_generation
            .checked_add(1)
            .ok_or(QemuRamSourceError::Ownership)?;
    }
    let mut bytes = response.encode()?;
    let header = crucible_qemu_protocol::ram_page::RAM_PAGE_RESPONSE_HEADER_BYTES;
    match fault {
        QemuRamResponseFault::ChangedPageByte => {
            let first = bytes.get_mut(header).ok_or(QemuRamSourceError::Ownership)?;
            *first ^= 1;
        }
        QemuRamResponseFault::TruncatedBody => {
            // The original header still advertises the entire page and proof.
            // A successful prefix write supplies no complete response record.
            bytes.truncate(header + response.page.len() / 2);
        }
        QemuRamResponseFault::DisconnectBeforeHeader => return Err(QemuRamSourceError::Ownership),
        QemuRamResponseFault::StaleSourceGeneration => {}
    }
    write_response_bytes(socket, operation, &bytes)?;
    operation.wait_slice()?;
    socket.shutdown(Shutdown::Write)?;
    Ok(())
}

fn write_response_bytes(
    socket: &mut UnixStream,
    operation: &HostOperationGuard,
    bytes: &[u8],
) -> Result<(), QemuRamSourceError> {
    let mut offset = 0;
    while offset < bytes.len() {
        socket.set_write_timeout(Some(operation.wait_slice()?))?;
        match socket.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod scoped_response_tests;

mod stop;
pub use stop::QemuRamSourceStopHistory;
