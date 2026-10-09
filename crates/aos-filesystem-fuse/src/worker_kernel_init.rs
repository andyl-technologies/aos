//! Retained kernel-only INIT preparation for the fixed original worker roles.
//!
//! Construction consumes actual Linux startup custody, never received FDs or
//! a decoded plan alone. It retains one C session after genuine kernel
//! INIT while Mount applies the original namespace's required idmap. It does
//! not install metadata callbacks, acknowledge readiness, or issue read grants.

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::fuse_worker_startup::FixedFuseWorkerSessionV1;
use aos_sandbox_linux::seqpacket::bounded::{BoundedRecordError, boottime};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketError};
use aos_sandbox_protocol::fuse_worker_preparation::{
    WORKER_KERNEL_PREPARATION_BYTES_V3, WorkerKernelPreparationPhaseV3 as Phase,
    WorkerRendezvousChallengeV2,
};

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
    /// The original preparation channel refused a record or subject.
    #[error("fixed worker preparation channel failed: {0}")]
    Channel(#[from] SeqpacketError),
}

/// Retains the same C session and original fixed roles after kernel-only INIT.
///
/// No public constructor accepts arbitrary FDs and no safe metadata/backing
/// continuation API exists here. Completed INIT is not completed idmap, mount readiness, current
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
    /// Drives kernel-only preparation in the actual original rendezvous flight.
    ///
    /// The fixed entry calls this only after replying to Mount's fresh challenge.
    /// It retains that actual Mount record subject and awaits the distinct INIT
    /// phase on the same original endpoint. The kernel-only C session stays
    /// alive while Mount performs its actual idmap syscall; neither record
    /// authorizes metadata, backing, publication or a Root read grant.
    ///
    /// # Errors
    ///
    /// Rejects wrong phases, stale original scope or subject, rights, startup
    /// drift, owner loss, failed kernel INIT, or incomplete idmap exchange.
    /// Errors consume local roles and leave remote durable obligations intact.
    #[doc(hidden)]
    pub fn prepare_original_flight(
        mut original: FixedFuseWorkerSessionV1,
        plan: WorkerPreparationPlanV1,
        challenge: &WorkerRendezvousChallengeV2,
        subject: &KernelAuthorizedRecordSubject,
    ) -> Result<Self, FixedWorkerKernelInitError> {
        receive_original_phase(&mut original, &plan, challenge, subject, Phase::StartInit)?;
        let mut prepared = Self::prepare(original, plan, fixed_preparation_limits())?;
        prepared.recheck()?;
        prepared
            .original
            .send_preparation_record(&Phase::InitComplete.encode(challenge), subject)?;
        receive_original_phase(
            &mut prepared.original,
            &prepared.plan,
            challenge,
            subject,
            Phase::IdmapComplete,
        )?;
        prepared.recheck()?;
        prepared
            .original
            .send_preparation_record(&Phase::SessionRetained.encode(challenge), subject)?;
        prepared.recheck()?;
        Ok(prepared)
    }

    /// Keeps the original C session idle until actual owner cancellation.
    ///
    /// This installs no callbacks and does not read another kernel request.
    ///
    /// # Errors
    ///
    /// Rejects changed startup or a failed cancellation observation.
    #[doc(hidden)]
    pub fn wait_for_owner_cancellation(&self) -> Result<(), FixedWorkerKernelInitError> {
        self.recheck()?;
        self.original.wait_for_owner_cancellation()?;
        Ok(())
    }

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

fn receive_original_phase(
    original: &mut FixedFuseWorkerSessionV1,
    plan: &WorkerPreparationPlanV1,
    challenge: &WorkerRendezvousChallengeV2,
    subject: &KernelAuthorizedRecordSubject,
    phase: Phase,
) -> Result<(), FixedWorkerKernelInitError> {
    // Bind the caller's comparison record to this actual sealed original plan;
    // this validates shape/scope only, never post-barrier or remote authority.
    WorkerRendezvousChallengeV2::decode(&challenge.encode(), plan, boottime()?)?;
    loop {
        require_current_plan(plan)?;
        original.recheck_preparation_subject(subject)?;
        let received = original.receive_preparation_record(WORKER_KERNEL_PREPARATION_BYTES_V3);
        original.recheck_preparation_subject(subject)?;
        match received {
            Ok((bytes, current_subject)) => {
                original.recheck_preparation_subject(&current_subject)?;
                phase.compare(&bytes, challenge, boottime()?)?;
                require_current_plan(plan)?;
                return Ok(());
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                original.wait_preparation_readiness(plan.preparation_deadline_boottime_ns)?;
                original.recheck_preparation_subject(subject)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

// Fixed bounded INIT limits, not manager environment, caller data or metadata
// authority. The same limits remain stored in the idle C session; eventual
// read dispatch needs its separately genuine owners and qualification.
fn fixed_preparation_limits() -> TransportLimits {
    TransportLimits {
        maximum_metadata_records: 1,
        maximum_name_bytes: 255,
        maximum_symlink_bytes: 4096,
        maximum_readdir_bytes: 65_536,
        maximum_readdir_entries: 256,
        maximum_write_bytes: 65_536,
        maximum_pages: 16,
        time_granularity_ns: 1,
        request_timeout_seconds: 30,
        entry_valid_ns: 0,
        attribute_valid_ns: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_kernel_only_limits_are_valid_and_disable_attribute_caching() {
        let limits = fixed_preparation_limits();
        assert!(limits.encode().is_ok());
        assert_eq!(limits.entry_valid_ns, 0);
        assert_eq!(limits.attribute_valid_ns, 0);
        assert_eq!(limits.maximum_write_bytes, 65_536);
        assert_eq!(limits.maximum_pages, 16);
    }
}
