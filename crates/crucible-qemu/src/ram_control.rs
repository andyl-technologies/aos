//! Independent host-side pager controller over an authenticated Unix socket.
//!
//! This transport never enters QMP or waits for guest execution. Every exchange
//! has a finite host timeout and is bound to a fresh descriptor session, exact
//! operational owner, increasing request sequence, and canonical request digest.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationGuard,
    HostOperationSupervisor,
};
use crucible_linux_resource::ram_policy::{
    HostRamMode, HostRamPolicy, HostRamTarget, HostResourceVector,
};
use crucible_protocol::ram_control::*;

mod outer;
pub use outer::outer_cap_to_wire;

mod admission;
mod supervision;
pub use admission::{RamControlInventory, resources_to_wire};
use supervision::TransportDeadline;

/// Authenticated host-local context for a sealed pre-CPU inventory grant.
///
/// The topology is rebuilt from bounded portable descriptors. The declared
/// shape belongs to the host launch, preserving independent device-state
/// backing rather than accepting a guest-supplied resource declaration.
#[derive(Clone, Copy, Debug)]
pub struct RamInventoryAdmission<'a> {
    /// Exact live owner and arena incarnation.
    pub target: HostRamTarget,
    /// Already retained complete resource envelope.
    pub expected_initial: HostResourceVector,
    /// Host-authored main-RAM launch shape in bytes.
    pub declared_ram_bytes: u64,
    /// Canonical authenticated realized RAM topology, including device RAM.
    pub topology: &'a crucible_ram::Topology,
    /// Actual native metadata allocation floor.
    pub native_metadata_bytes: u64,
    /// Actual native observation scratch floor.
    pub native_scratch_bytes: u64,
    /// Observed actors/descriptors and explicitly planned future entitlements.
    pub owner_resources: RamControlOwnerInventory,
}

/// Retains final retirement authority for one exact published RAM owner.
///
/// This capability owns no controller or physical borrower. Implementations
/// require prior controller retirement and discharge capacity only when the
/// private launch record supplies its final process, join and close proofs.
pub trait RamControlRetirementAuthority: Send + Sync {
    /// Discharges the bound owner after its final physical borrower closes.
    ///
    /// # Errors
    /// Refuses absent preparation, stale ownership or uncertain accounting.
    fn retire_after_cleanup(&self) -> Result<(), RamControlError>;
}

/// Host-local registration of an admitted operational owner after native setup.
///
/// This interface lives entirely in the host process. Backend qualification is
/// independently supplied by the executor; an open socket proves transport
/// authority, never eviction safety or a lower execution peak.
pub trait RamControlRegistrar: Send + Sync {
    /// Controls one fixed diagnostic bank on the exact registered owner.
    ///
    /// # Errors
    /// Refuses unsupported diagnostics, stale ownership or original supervision.
    fn performance(
        &self,
        _target: HostRamTarget,
        _action: crucible_protocol::ram_control::RamControlPerformanceAction,
    ) -> Result<Option<crucible_protocol::ram_control::RamControlPerformance>, RamControlError>
    {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Observes native actor and physical-operation failures in one bounded RPC.
    ///
    /// # Errors
    /// Returns original controller transport, supervision or ownership failures.
    fn native_paging_health(
        &self,
        target: HostRamTarget,
    ) -> Result<
        (
            Option<RamControlFaultActorReport>,
            Option<RamControlOperationFailure>,
        ),
        RamControlError,
    > {
        self.fault_actor_status(target).map(|actor| (actor, None))
    }

    /// Observes the exact admitted native fault actor through independent control.
    ///
    /// Absence supplies no actor-lifetime evidence. The observation never
    /// renews a cap, changes policy, or releases any retained physical owner.
    ///
    /// # Errors
    /// Returns original controller transport or exact-ownership failures.
    fn fault_actor_status(
        &self,
        _target: HostRamTarget,
    ) -> Result<Option<RamControlFaultActorReport>, RamControlError> {
        Ok(None)
    }

    /// Issues independent final-close authority for an existing published owner.
    ///
    /// The returned capability must survive this registrar's destruction and
    /// must not retain a registry/controller back-reference cycle.
    ///
    /// # Errors
    /// Refuses unsupported final-close custody or an unknown exact target.
    fn retirement_authority(
        &self,
        _target: HostRamTarget,
    ) -> Result<Arc<dyn RamControlRetirementAuthority>, RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Reclassifies retained resources from authenticated pre-CPU RAM inventory.
    ///
    /// The controller has authenticated every descriptor and rebuilt the exact
    /// sealed topology before calling this method. The returned grant retains
    /// the complete resident/backing peaks and process slots; only RAM metadata
    /// and staging subsets can increase within that original entitlement. The
    /// native observer must receive this exact grant before sealing its limits
    /// or allocating its dense identity trees.
    /// The declared main-RAM shape comes from the authenticated host launch,
    /// and preserves its independent VMState backing reserve.
    ///
    /// # Errors
    /// Refuses stale ownership, insufficient retained entitlement, malformed
    /// inventory requirements, or unsupported prepublication admission.
    fn admit_inventory(
        &self,
        _admission: RamInventoryAdmission<'_>,
    ) -> Result<HostResourceVector, RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Registers the exact owner, retained resources, supervisor, and live client.
    ///
    /// A missing client can identify a fully resident owner whose backend lacks
    /// dynamic paging; it never authorizes pretending that a policy was applied.
    ///
    /// # Errors
    /// Returns errors for stale/duplicate ownership, insufficient admission,
    /// incompatible initial policy, uncertain setup, or failed durable authority.
    fn register(
        &self,
        target: HostRamTarget,
        initial_policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        client: Option<RamControlClient>,
    ) -> Result<(), RamControlError>;

    /// Retires an exact owner after complete process and source-service cleanup.
    ///
    /// The caller has proven process reap, source-worker join, and disposition
    /// of every outstanding physical borrower and retained paging lease. Kill
    /// requests, closed control sockets, or guest completion alone are insufficient.
    ///
    /// # Errors
    /// Refuses missing cleanup proof, stale ownership, or unsupported retirement.
    fn retire_after_cleanup(&self, _target: HostRamTarget) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Closes registered control custody before final physical borrower disposal.
    ///
    /// This callback releases no physical reservation. The final private cleanup
    /// record invokes [`Self::retire_after_cleanup`] after all handles close.
    ///
    /// # Errors
    /// Refuses stale ownership, active transactions or unsupported custody.
    fn prepare_retirement_after_cleanup(
        &self,
        _target: HostRamTarget,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Retires an exact unpublished admission after all physical borrowers close.
    ///
    /// The private launch cleanup record calls this only after actual child reap,
    /// source-worker joins, and final descriptor and service-lease destruction.
    /// The actor independently verifies the current exact retained reservation.
    ///
    /// # Errors
    /// Refuses stale ownership, mismatched resources, a published owner, or
    /// unsupported unpublished retirement. Refusal preserves retained capacity.
    fn retire_unpublished_after_cleanup(
        &self,
        _target: HostRamTarget,
        _resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }

    /// Quarantines the exact unpublished retained reservation after uncertain cleanup.
    ///
    /// This operation never frees or lowers capacity. The actor verifies the
    /// exact target and vector before retaining named quarantine ownership.
    ///
    /// # Errors
    /// Refuses stale targets, mismatched resources, or unsupported quarantine.
    fn quarantine_unpublished(
        &self,
        _target: HostRamTarget,
        _resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        Err(RamControlError::AuthorityMismatch)
    }
}

/// Cloneable launch registration bound to one admitted operational owner.
///
/// This host-local record is never serialized into process protocols. Clones
/// retain the same registrar authority while each replacement process receives
/// a newly generation-bound target and fresh socket session.
#[derive(Clone)]
pub struct RamControlRegistration {
    /// Exact executor-authenticated node or template target.
    pub target: HostRamTarget,
    /// Complete initial host placement and budget policy.
    pub initial_policy: HostRamPolicy,
    /// Independently retained peak/backing/metadata/staging reservations.
    pub resources: HostResourceVector,
    /// Independent private spill entitlement within the complete backing peak.
    pub spill_quota_bytes: u64,
    /// Clone-shared independent task/descriptor capacity for this node's host services.
    pub host_services: HostServiceAllocator,
    /// Host registry that takes ownership after successful native setup.
    pub registrar: Arc<dyn RamControlRegistrar>,
}

impl std::fmt::Debug for RamControlRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RamControlRegistration")
            .field("target", &self.target)
            .field("initial_policy", &self.initial_policy)
            .field("resources", &self.resources)
            .field("spill_quota_bytes", &self.spill_quota_bytes)
            .field("host_services", &self.host_services)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RamControlRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target
            && self.initial_policy == other.initial_policy
            && self.resources == other.resources
            && self.spill_quota_bytes == other.spill_quota_bytes
            && self.host_services == other.host_services
            && Arc::ptr_eq(&self.registrar, &other.registrar)
    }
}

impl Eq for RamControlRegistration {}

/// Host controller for one exact mapping incarnation.
#[derive(Debug)]
pub struct RamControlClient {
    stream: UnixStream,
    session: [u8; 32],
    target: RamControlTarget,
    sequence: u64,
    usable: bool,
    exchange_timeout: Duration,
    supervisor: Option<HostOperationSupervisor>,
    host_service_lease: Option<HostServiceLease>,
    pending_admission: Option<admission::PendingAdmission>,
    #[cfg(target_os = "linux")]
    launch_cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl RamControlClient {
    /// Authenticates a descriptor-bound controller with a finite exchange timeout.
    ///
    /// # Errors
    /// Rejects zero/overflowing timeouts, invalid setup binding, failed transport,
    /// mismatched response identity, and failed canonical request authentication.
    pub fn connect(
        stream: UnixStream,
        session: [u8; 32],
        target: HostRamTarget,
        timeout: Duration,
    ) -> Result<Self, RamControlError> {
        if TransportDeadline::after(timeout).is_err() {
            return Err(RamControlError::InvalidFrame);
        }
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let mut client = Self {
            stream,
            session,
            target: target_to_wire(target),
            sequence: 0,
            usable: true,
            exchange_timeout: timeout,
            supervisor: None,
            host_service_lease: None,
            pending_admission: None,
            #[cfg(target_os = "linux")]
            launch_cleanup: None,
        };
        client.exchange(RamControlRequest::Hello)?;
        Ok(client)
    }

    /// Authenticates setup under the owner's live class budgets and original cap.
    ///
    /// Every partial framed read recomputes the live polling/deadline slice.
    /// Socket traffic does not renew meaningful-progress or original-start time.
    ///
    /// # Errors
    /// Returns budget/cancellation, codec, transport, or authority failures.
    pub fn connect_supervised(
        stream: UnixStream,
        session: [u8; 32],
        target: HostRamTarget,
        supervisor: HostOperationSupervisor,
    ) -> Result<Self, RamControlError> {
        let mut client = Self {
            stream,
            session,
            target: target_to_wire(target),
            sequence: 0,
            usable: true,
            exchange_timeout: Duration::ZERO,
            supervisor: Some(supervisor),
            host_service_lease: None,
            pending_admission: None,
            #[cfg(target_os = "linux")]
            launch_cleanup: None,
        };
        client.exchange(RamControlRequest::Hello)?;
        Ok(client)
    }

    /// Retains the host descriptor permit for this live control endpoint.
    ///
    /// The lease comes from the node's independently admitted host-service
    /// allocator before socket creation. Clones share the original charge.
    ///
    /// # Errors
    /// Refuses absent descriptor entitlement or replacement of retained authority.
    pub fn retain_host_service_lease(
        &mut self,
        lease: HostServiceLease,
    ) -> Result<(), RamControlError> {
        if lease.file_descriptors() == 0 || self.host_service_lease.is_some() {
            return Err(RamControlError::AuthorityMismatch);
        }
        self.host_service_lease = Some(lease);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_launch_cleanup(&mut self, cleanup: crate::launch_cleanup::LaunchCleanup) {
        self.launch_cleanup = Some(cleanup);
    }

    /// Returns the exact operational target authenticated at setup.
    pub fn target(&self) -> HostRamTarget {
        target_from_wire(self.target)
    }

    /// Sends an already admitted revision to the independent paging owner.
    ///
    /// Acceptance does not imply application or convergence. Reservations must
    /// remain retained until an authenticated observation proves disposition.
    ///
    /// # Errors
    /// Returns policy normalization, stream, authentication, sequence, or revision
    /// errors. After ambiguous transport failure this client refuses reuse.
    pub fn apply(
        &mut self,
        expected_revision: u64,
        policy_revision: u64,
        reservation_revision: u64,
        policy: HostRamPolicy,
        resources: HostResourceVector,
    ) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::Apply {
            expected_revision,
            policy_revision,
            reservation_revision,
            resources: resources_to_wire(resources),
            policy: policy_to_wire(policy)?,
        })
    }

    /// Observes real pager state while the guest mainloop may be fault-blocked.
    ///
    /// # Errors
    /// Returns a bounded transport or authority failure; never infers convergence.
    pub fn status(&mut self) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::Status)
    }

    /// Starts, observes or stops one resource-admitted I/O diagnostic interval.
    ///
    /// # Errors
    /// Returns authentication, original supervision or transport failures.
    pub fn performance(
        &mut self,
        action: crucible_protocol::ram_control::RamControlPerformanceAction,
    ) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::Performance { action })
    }

    /// Controls diagnostics under the caller's existing lock-and-I/O guard.
    ///
    /// # Errors
    /// Refuses expired original ownership, invalid framing or transport failure.
    /// This exchange neither completes nor renews the encompassing guard.
    pub fn performance_under(
        &mut self,
        action: crucible_protocol::ram_control::RamControlPerformanceAction,
        guard: &HostOperationGuard,
    ) -> Result<RamControlReply, RamControlError> {
        let deadline = self.exchange_deadline(Some(guard))?;
        self.exchange_under(
            RamControlRequest::Performance { action },
            Some(guard),
            deadline,
        )
    }

    /// Observes the actual actor under the caller's original lock-and-I/O guard.
    ///
    /// # Errors
    /// Returns original deadline, transport or exact-ownership failures. It
    /// never completes or renews the caller's encompassing operation.
    pub fn status_under(
        &mut self,
        guard: &HostOperationGuard,
    ) -> Result<RamControlReply, RamControlError> {
        let deadline = self.exchange_deadline(Some(guard))?;
        self.exchange_under(RamControlRequest::Status, Some(guard), deadline)
    }

    /// Exercises an exact isolated actor only under a separate launch entitlement.
    ///
    /// # Errors
    /// Returns bounded transport or authentication errors; a returned acceptance
    /// never proves the actor returned or released its native membership.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_fault_actor(
        &mut self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: RamControlFaultActorAction,
    ) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::TestFaultActor {
            entitlement,
            worker_generation,
            action,
        })
    }

    /// Exercises the entitled actor under one original lock-and-I/O operation.
    ///
    /// # Errors
    /// Returns bounded transport or authentication failures. It does not complete
    /// the shared guard or infer native termination from request acceptance.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_fault_actor_under(
        &mut self,
        entitlement: [u8; 32],
        worker_generation: u64,
        action: RamControlFaultActorAction,
        guard: &HostOperationGuard,
    ) -> Result<RamControlReply, RamControlError> {
        let deadline = self.exchange_deadline(Some(guard))?;
        self.exchange_under(
            RamControlRequest::TestFaultActor {
                entitlement,
                worker_generation,
                action,
            },
            Some(guard),
            deadline,
        )
    }

    /// Requests cancellation of one exact nonzero operation generation.
    ///
    /// # Errors
    /// Rejects zero generations and returns bounded transport/authority failures.
    pub fn cancel(
        &mut self,
        operation_generation: u64,
    ) -> Result<RamControlReply, RamControlError> {
        self.exchange(RamControlRequest::Cancel {
            operation_generation,
        })
    }

    fn exchange(&mut self, request: RamControlRequest) -> Result<RamControlReply, RamControlError> {
        let class = if matches!(
            request,
            RamControlRequest::Cancel { .. }
                | RamControlRequest::SyncOuterCap { .. }
                | RamControlRequest::Status
                | RamControlRequest::Performance {
                    action: crucible_protocol::ram_control::RamControlPerformanceAction::Observe
                        | crucible_protocol::ram_control::RamControlPerformanceAction::Stop
                }
        ) {
            HostOperationClass::Cleanup
        } else {
            HostOperationClass::Setup
        };
        let guard = self
            .supervisor
            .as_ref()
            .map(|supervisor| supervisor.begin_control(class))
            .transpose()
            .map_err(supervision_error)?;
        let deadline = self.exchange_deadline(guard.as_ref())?;
        let state = self.exchange_under(request, guard.as_ref(), deadline)?;
        if let Some(guard) = guard {
            guard.complete().map_err(supervision_error)?;
        }
        Ok(state)
    }

    fn exchange_deadline(
        &self,
        guard: Option<&HostOperationGuard>,
    ) -> Result<Option<TransportDeadline>, RamControlError> {
        if guard.is_some() {
            Ok(None)
        } else {
            Ok(Some(TransportDeadline::after(self.exchange_timeout)?))
        }
    }

    fn exchange_under(
        &mut self,
        request: RamControlRequest,
        guard: Option<&HostOperationGuard>,
        deadline: Option<TransportDeadline>,
    ) -> Result<RamControlReply, RamControlError> {
        if !self.usable {
            return Err(RamControlError::AuthorityMismatch);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(RamControlError::AuthorityMismatch)?;
        let frame = RamControlFrame {
            session: self.session,
            sequence,
            target: self.target,
            message: RamControlMessage::Request(request),
        };
        let request_digest = ram_control_request_digest(&frame)?;
        // Any failure after the first byte may leave application ambiguous.
        // Only a new authenticated session/reconciliation can regain authority.
        self.usable = false;
        let mut stream = DeadlineStream {
            stream: &mut self.stream,
            deadline,
            guard,
        };
        write_ram_control(&mut stream, &frame)?;
        let reply = read_ram_control(&mut stream)?.ok_or(RamControlError::AuthorityMismatch)?;
        if reply.session != self.session
            || reply.sequence != sequence
            || reply.target != self.target
        {
            return Err(RamControlError::AuthorityMismatch);
        }
        let RamControlMessage::Reply {
            request_digest: observed,
            state,
        } = reply.message
        else {
            return Err(RamControlError::InvalidFrame);
        };
        if observed != request_digest {
            return Err(RamControlError::AuthorityMismatch);
        }
        self.sequence = sequence;
        self.usable = true;
        Ok(state)
    }
}

/// Converts the shared host operational identity to its portable socket record.
pub fn target_to_wire(target: HostRamTarget) -> RamControlTarget {
    RamControlTarget {
        daemon_epoch: target.daemon_epoch,
        owner_id: target.owner_id,
        node_id: target.node_id,
        owner_generation: target.owner_generation,
        arena_generation: target.arena_generation,
        retained_template: target.retained_template,
    }
}

/// Converts an authenticated portable identity into the host operational type.
pub fn target_from_wire(target: RamControlTarget) -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: target.daemon_epoch,
        owner_id: target.owner_id,
        node_id: target.node_id,
        owner_generation: target.owner_generation,
        arena_generation: target.arena_generation,
        retained_template: target.retained_template,
    }
}

fn milliseconds(duration: Duration) -> Result<u64, RamControlError> {
    let value = u64::try_from(duration.as_millis()).map_err(|_| RamControlError::InvalidFrame)?;
    if value == 0 || value > i64::MAX as u64 / 1_000_000 || Duration::from_millis(value) != duration
    {
        return Err(RamControlError::InvalidFrame);
    }
    Ok(value)
}

/// Converts a host policy into its exact, whole-millisecond portable form.
///
/// # Errors
/// Rejects fractional milliseconds, zero/overflowing durations, and invalid
/// scalar policy fields rather than silently rounding operational allowances.
pub fn policy_to_wire(policy: HostRamPolicy) -> Result<RamControlPolicy, RamControlError> {
    if policy.eviction_preference > 100
        || policy.writeback_bytes_per_second == 0
        || policy.maximum_paging_io_in_flight == 0
    {
        return Err(RamControlError::InvalidFrame);
    }
    let budgets = budgets_to_wire(policy.latency)?;
    let result = RamControlPolicy {
        mode: match policy.mode {
            HostRamMode::Managed => RamControlMode::Managed,
            HostRamMode::DiskOriented => RamControlMode::DiskOriented,
            HostRamMode::ResidentRequired => RamControlMode::ResidentRequired,
        },
        resident_target_bytes: policy.resident_target_bytes,
        eviction_preference: policy.eviction_preference,
        writeback_bytes_per_second: policy.writeback_bytes_per_second,
        maximum_paging_io_in_flight: policy.maximum_paging_io_in_flight,
        prefetch_on_increase: policy.prefetch_on_increase,
        budgets,
    };
    Ok(result)
}

/// Normalizes the actual host owner's initial live roster without placement acceptance.
///
/// # Errors
/// Rejects fractional, zero, or overflowing present durations rather than rounding.
pub fn budgets_to_wire(
    latency: HostOperationBudgets,
) -> Result<[RamControlBudget; RAM_CONTROL_BUDGET_COUNT], RamControlError> {
    let mut budgets = [RamControlBudget {
        poll_ms: 1,
        progress_ms: None,
        total_ms: None,
    }; RAM_CONTROL_BUDGET_COUNT];
    for (out, budget) in budgets.iter_mut().zip(latency.classes) {
        *out = RamControlBudget {
            poll_ms: milliseconds(budget.poll_interval)?,
            progress_ms: budget.progress_timeout.map(milliseconds).transpose()?,
            total_ms: budget.total_timeout.map(milliseconds).transpose()?,
        };
    }
    Ok(budgets)
}

/// Reconstructs host allowances from an already validated portable policy.
pub fn policy_from_wire(policy: RamControlPolicy) -> HostRamPolicy {
    HostRamPolicy {
        mode: match policy.mode {
            RamControlMode::Managed => HostRamMode::Managed,
            RamControlMode::DiskOriented => HostRamMode::DiskOriented,
            RamControlMode::ResidentRequired => HostRamMode::ResidentRequired,
        },
        resident_target_bytes: policy.resident_target_bytes,
        eviction_preference: policy.eviction_preference,
        writeback_bytes_per_second: policy.writeback_bytes_per_second,
        maximum_paging_io_in_flight: policy.maximum_paging_io_in_flight,
        prefetch_on_increase: policy.prefetch_on_increase,
        latency: HostOperationBudgets {
            classes: policy.budgets.map(|budget| HostOperationBudget {
                poll_interval: Duration::from_millis(budget.poll_ms),
                progress_timeout: budget.progress_ms.map(Duration::from_millis),
                total_timeout: budget.total_ms.map(Duration::from_millis),
            }),
        },
    }
}

struct DeadlineStream<'a> {
    stream: &'a mut UnixStream,
    deadline: Option<TransportDeadline>,
    guard: Option<&'a HostOperationGuard>,
}

fn supervision_error(
    error: crucible_linux_resource::host_supervision::HostSupervisionError,
) -> RamControlError {
    std::io::Error::new(std::io::ErrorKind::TimedOut, error).into()
}

impl DeadlineStream<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        if let Some(guard) = self.guard {
            return guard
                .wait_slice()
                .map(|slice| slice.min(Duration::from_millis(10)))
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::TimedOut, error));
        }
        self.deadline
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "RAM exchange has no supervision authority",
                )
            })?
            .remaining()
    }
}

impl std::io::Read for DeadlineStream<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            match std::io::Read::read(self.stream, output) {
                Err(error)
                    if self.guard.is_some()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                        ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl std::io::Write for DeadlineStream<'_> {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match std::io::Write::write(self.stream, input) {
                Err(error)
                    if self.guard.is_some()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                        ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining()?;
        std::io::Write::flush(self.stream)
    }
}

#[cfg(test)]
mod tests;
