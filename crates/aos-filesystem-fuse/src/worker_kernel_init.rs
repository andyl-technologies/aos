//! Retained kernel-only INIT preparation for the fixed original worker roles.
//!
//! The sole constructor consumes actual Linux startup custody, never received
//! FDs or a decoded plan alone. It retains one C session after genuine kernel
//! INIT while Mount applies the original namespace's required idmap. It does
//! not install metadata callbacks, acknowledge readiness, or issue read grants.

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::fuse_worker_startup::FixedFuseWorkerSessionV1;
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime};

use crate::worker_session::{WorkerPreparationPlanV1, WorkerPreparationWireError};
use crate::{RunError, TransportLimits, abi};

/// Reports fixed startup, original-plan, or actual kernel INIT refusal.
#[derive(Debug, thiserror::Error)]
pub enum FixedWorkerKernelInitError {
    /// The original inherited execution or kernel observations were rejected.
    #[error("fixed worker kernel observation failed: {0}")]
    Kernel(#[from] aos_sandbox_linux::Error),
    /// The original kernel BOOTTIME observation failed.
    #[error("fixed worker preparation clock failed: {0}")]
    Clock(#[from] BoundedRecordError),
    /// The sealed plan's closed structural profile was invalid.
    #[error("fixed worker preparation plan failed: {0}")]
    Plan(#[from] WorkerPreparationWireError),
    /// The original boot, ownership lease, or preparation deadline changed.
    #[error("fixed worker preparation scope is stale")]
    Stale,
    /// The limits or actual retained transport preparation were rejected.
    #[error("fixed worker kernel INIT failed: {0}")]
    Transport(#[from] RunError),
}

/// Retains the same C session and original fixed roles after kernel-only INIT.
///
/// No public constructor accepts arbitrary FDs and no safe continuation API
/// exists here. Completed INIT is not completed idmap, mount readiness, current
/// Controller/Mount authority, or either required ContentRead grant.
/// Dropping this owner closes only local transport custody; uncertain Mount
/// reservations and durable backing obligations require actual reconciliation.
///
/// Arbitrary received descriptors cannot construct this owner:
///
/// ```compile_fail
/// use std::os::fd::OwnedFd;
/// use aos_filesystem_fuse::TransportLimits;
/// use aos_filesystem_fuse::worker_kernel_init::PreparedFixedWorkerKernelSessionV1;
/// use aos_filesystem_fuse::worker_session::WorkerPreparationPlanV1;
///
/// fn cannot_adopt_received_connection(
///     connection: OwnedFd, plan: WorkerPreparationPlanV1, limits: TransportLimits,
/// ) {
///     let _ = PreparedFixedWorkerKernelSessionV1::prepare(connection, plan, limits);
/// }
/// ```
pub struct PreparedFixedWorkerKernelSessionV1 {
    // Rust drops fields in declaration order: C must release its retained
    // session before the original cancellation and connection owners close.
    _transport: abi::PreparedTransport,
    original: FixedFuseWorkerSessionV1,
    plan: WorkerPreparationPlanV1,
}

impl PreparedFixedWorkerKernelSessionV1 {
    /// Consumes the original fixed startup session for bounded kernel-only INIT.
    ///
    /// The plan is comparison data, not authority. Startup custody is retained
    /// throughout preparation and the same actual C session survives return.
    /// The producer must complete the original endpoint-copy closure and fresh
    /// Host/Mount challenge before using this preparation in a live flight.
    ///
    /// # Errors
    ///
    /// Rejects changed startup, malformed limits/plan, wrong boot, expired lease
    /// or deadline, cancellation, and an incompatible or incomplete kernel INIT.
    /// All errors consume local original roles without authorizing row deletion,
    /// reissue, mount teardown, metadata, or backing delivery.
    pub fn prepare(
        original: FixedFuseWorkerSessionV1,
        plan: WorkerPreparationPlanV1,
        limits: TransportLimits,
    ) -> Result<Self, FixedWorkerKernelInitError> {
        let limits = limits.encode()?;
        plan.encode()?;
        require_current_plan(&plan)?;
        original.recheck()?;

        let transport = abi::PreparedTransport::prepare(
            &original,
            plan.preparation_deadline_boottime_ns,
            limits,
        )
        .map_err(RunError::Transport)?;
        let prepared = Self {
            _transport: transport,
            original,
            plan,
        };
        prepared.recheck()?;
        Ok(prepared)
    }

    /// Rechecks the retained original execution, boot, lease and deadline.
    ///
    /// This does not observe Mount's idmap or prove remote held owner custody.
    ///
    /// # Errors
    ///
    /// Rejects a changed kernel observation, startup role, or original scope.
    pub fn recheck(&self) -> Result<(), FixedWorkerKernelInitError> {
        require_current_plan(&self.plan)?;
        self.original.recheck()?;
        require_current_plan(&self.plan)
    }
}

fn require_current_plan(plan: &WorkerPreparationPlanV1) -> Result<(), FixedWorkerKernelInitError> {
    if plan.kernel_boot != KernelBootId::current()?.into_bytes()
        || boottime()? >= plan.preparation_deadline_boottime_ns
        || boottime()? >= plan.ownership_lease_expires_boottime_ns
    {
        return Err(FixedWorkerKernelInitError::Stale);
    }
    Ok(())
}
