//! Retains immutable backing authority for independently owned lazy RAM sources.
//!
//! The source thread serves only a separately authenticated root and namespace.
//! A child or restored process receives a fresh endpoint and binding. Immutable
//! backing may be shared, while mutable request cursors, cancellation, and
//! supervision guards belong to each source separately. Cancellation closes
//! admission and transport; it never supplies substitute page bytes.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_protocol::ram_page::{
    RAM_PAGE_REQUEST_BYTES, RamPageBinding, RamPageProtocolError, RamPageRequest, RamPageResponse,
    RamPageStatus,
};
use crucible_ram::{PageProof, RootRecord, Scope};
use thiserror::Error;

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

    /// Reads and authenticates one real logical page through its binary path.
    ///
    /// # Errors
    ///
    /// Returns an error for absent coordinates, unavailable or corrupt backing,
    /// cancellation, resource limits, or an operational deadline.
    fn read_page_with_proof(
        &self,
        region_id: &str,
        page_index: u64,
        boundary: &mut dyn FnMut() -> Result<(), QemuRamSourceError>,
    ) -> Result<(Vec<u8>, PageProof), QemuRamSourceError>;

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
        kind: crucible::BackendOperationalFailureKind,
        /// Original store error without diagnostic conversion or clone loss.
        #[source]
        source: crucible::BackendOperationalCause,
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
    WorkerFailed(#[source] Arc<QemuRamSourceError>),
    /// Explicit host service task or descriptor admission failed.
    #[error(transparent)]
    Services(#[from] crucible_linux_resource::host_services::HostServiceError),
}

/// Linear source service retained through process termination or quarantine.
#[must_use = "retain the source and its backing authority through process disposition"]
pub struct QemuRamSourceService {
    binding: RamPageBinding,
    backing: Arc<dyn QemuRamBacking>,
    cancellation: Arc<AtomicBool>,
    wake: UnixStream,
    worker: Option<JoinHandle<Result<(), Arc<QemuRamSourceError>>>>,
    supervisor: HostOperationSupervisor,
    failure: Arc<Mutex<Option<Arc<QemuRamSourceError>>>>,
    service_lease: crucible_linux_resource::host_services::HostServiceLease,
    launch_join: Option<crate::launch_cleanup::LaunchSourceJoin>,
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
    /// Starts an independently supervised source on an already owned socket.
    ///
    /// The caller binds the same complete root and namespace in QEMU before
    /// restoration or guest release. This method retains the lease before the
    /// worker can accept a request, including during thread creation failure.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or mismatched binding, an incomplete scope,
    /// transport setup failure, or worker creation failure.
    pub fn start(
        socket: UnixStream,
        backing: Arc<dyn QemuRamBacking>,
        binding: RamPageBinding,
        supervisor: HostOperationSupervisor,
        services: crucible_linux_resource::host_services::HostServiceAllocator,
    ) -> Result<Self, QemuRamSourceError> {
        Self::start_with_cleanup(socket, backing, binding, supervisor, services, None)
    }

    pub(crate) fn start_with_cleanup(
        socket: UnixStream,
        backing: Arc<dyn QemuRamBacking>,
        binding: RamPageBinding,
        supervisor: HostOperationSupervisor,
        services: crucible_linux_resource::host_services::HostServiceAllocator,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Result<Self, QemuRamSourceError> {
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
        let service_lease = services.reserve_resources(
            1,
            2,
            SOURCE_STACK_BYTES as u64
                + 3 * crucible_protocol::ram_page::RAM_PAGE_MAX_RESPONSE_BYTES as u64,
        )?;
        let worker_service_lease = service_lease.clone();
        let wake = socket.try_clone()?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_backing = Arc::clone(&backing);
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_supervisor = supervisor.clone();
        let failure = Arc::new(Mutex::new(None));
        let worker_failure = Arc::clone(&failure);
        let mut launch_join = cleanup
            .as_ref()
            .map(crate::launch_cleanup::LaunchCleanup::source_join)
            .transpose()
            .map_err(|_| QemuRamSourceError::Ownership)?;
        let worker = thread::Builder::new()
            .name("crucible-ram-source".to_owned())
            .stack_size(SOURCE_STACK_BYTES)
            .spawn(move || {
                // This last borrower closes after the socket, backing read,
                // and thread's service lease, even if the handle is detached.
                let _cleanup = cleanup;
                let _service_lease = worker_service_lease;
                let result = serve_pages(
                    socket,
                    worker_backing,
                    binding,
                    worker_cancellation,
                    worker_supervisor,
                )
                .map_err(Arc::new);
                if let Err(error) = &result
                    && let Ok(mut failure) = worker_failure.lock()
                {
                    *failure = Some(Arc::clone(error));
                }
                result
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                // No thread exists after a failed spawn; all closure captures
                // were destroyed before the builder returned this failure.
                if let Some(join) = &mut launch_join {
                    join.joined();
                }
                return Err(error.into());
            }
        };
        Ok(Self {
            binding,
            backing,
            cancellation,
            wake,
            worker: Some(worker),
            supervisor,
            failure,
            service_lease,
            launch_join,
        })
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
        let failure = self.failure.lock().map_err(|_| {
            QemuRamSourceError::Backing("source failure inventory unavailable".to_owned())
        })?;
        if let Some(error) = &*failure {
            return Err(QemuRamSourceError::WorkerFailed(Arc::clone(error)));
        }
        if self.cancellation.load(Ordering::Acquire) {
            return Err(QemuRamSourceError::Canceled);
        }
        if self
            .worker
            .as_ref()
            .is_none_or(|worker| worker.is_finished())
        {
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
        self.cancellation.store(true, Ordering::Release);
        let _ = self.wake.shutdown(Shutdown::Both);
    }

    /// Joins the canceled worker under the target execution's cleanup budget.
    ///
    /// # Errors
    ///
    /// Returns an owned error retaining this source and lease if cleanup cannot
    /// establish terminal worker disposition. Callers transfer it to quarantine.
    pub fn stop(mut self) -> Result<(), QemuRamSourceStopError> {
        self.cancel();
        let cleanup = match self.supervisor.begin(HostOperationClass::Cleanup) {
            Ok(guard) => guard,
            Err(error) => {
                return Err(QemuRamSourceStopError {
                    service: Box::new(self),
                    source: error.into(),
                });
            }
        };
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            match cleanup.wait_slice() {
                Ok(slice) => thread::sleep(slice.min(Duration::from_millis(20))),
                Err(error) => {
                    return Err(QemuRamSourceStopError {
                        service: Box::new(self),
                        source: error.into(),
                    });
                }
            }
        }
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if let Some(join) = &mut self.launch_join {
                join.joined();
            }
            match result {
                Ok(Ok(())) => {}
                Ok(Err(source)) => {
                    return Err(QemuRamSourceStopError {
                        service: Box::new(self),
                        source: QemuRamSourceError::WorkerFailed(source),
                    });
                }
                Err(_) => {
                    return Err(QemuRamSourceStopError {
                        service: Box::new(self),
                        source: QemuRamSourceError::WorkerPanicked,
                    });
                }
            }
        }
        match cleanup.complete() {
            Ok(_) => Ok(()),
            Err(error) => Err(QemuRamSourceStopError {
                service: Box::new(self),
                source: error.into(),
            }),
        }
    }
}

impl Drop for QemuRamSourceService {
    fn drop(&mut self) {
        self.cancel();
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
            if let Some(join) = &mut self.launch_join {
                join.joined();
            }
        }
        // A blocked storage operation still owns its independent backing Arc.
        // Detaching this handle cannot release that worker's descendant lease.
    }
}

/// Failed cleanup retaining its linear source and descendant storage authority.
#[derive(Debug, Error)]
#[error("RAM source cleanup failed: {source}")]
pub struct QemuRamSourceStopError {
    /// Source authority that must remain owned until cleanup succeeds.
    pub service: Box<QemuRamSourceService>,
    /// Exact operational cleanup failure.
    pub source: QemuRamSourceError,
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
                return Err(QemuRamSourceError::Canceled);
            }
            operation.wait_slice()?;
            Ok(())
        };
        boundary()?;
        let (page, proof) =
            backing.read_page_with_proof(region.id(), request.page_index, &mut boundary)?;
        if proof.region_id() != region.id() || proof.page_index() != request.page_index {
            return Err(QemuRamSourceError::Ownership);
        }
        proof
            .verify(&page, backing.root_record(), backing.root_record().digest())
            .map_err(|error| QemuRamSourceError::Proof(error.to_string()))?;
        boundary()?;
        let proof = proof.encode();
        #[cfg(any(test, feature = "test-support"))]
        if let Some(fault) = backing.take_response_fault_for_test() {
            send_faulted_response(
                &mut socket,
                &operation,
                RamPageResponse {
                    binding,
                    sequence: request.sequence,
                    status: RamPageStatus::Page,
                    page: &page,
                    proof: &proof,
                },
                fault,
            )?;
            return Err(
                io::Error::other("authored test-support response transport failure").into(),
            );
        }
        send_response(
            &mut socket,
            &operation,
            RamPageResponse {
                binding,
                sequence: request.sequence,
                status: RamPageStatus::Page,
                page: &page,
                proof: &proof,
            },
        )?;
        operation.progress(1)?;
        operation.complete()?;
        sequence = request.sequence;
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
    let header = crucible_protocol::ram_page::RAM_PAGE_RESPONSE_HEADER_BYTES;
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
