//! Owned original native components without a whole-node execution issuer.
//!
//! Installation files, child wait authority, the original OS peer, and finite
//! Window/ACK journals share one pre-reserved common supervisory capsule.
//! Reconnection authenticates the same actual child generation before replacing
//! its poisoned channel. These component observations do not establish device,
//! input/output, exact capture, or simulation-node readiness.

mod custody;
mod journal;
mod peer;

use std::{
    fs::File,
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::Command,
    rc::Rc,
    time::Duration,
};

use crucible::node_contract::{
    ActivationRecord, EffectKnowledge, OperationFailure, RuntimeCustodySupervisor, RuntimeError,
    RuntimeLimits,
};

use crate::qmp::{
    QmpError, QmpKvmOriginalReturnState, QmpKvmOriginalWindowRequest, QmpKvmOriginalWindowState,
};

use super::{KvmArchitecture, KvmCandidateError, KvmInstalledCandidate};
use custody::KvmComponentCustody;

/// Borrows one retained original command without releasing its native obligation.
#[derive(Clone, Debug)]
pub struct KvmComponentToken {
    identity: Rc<()>,
    index: usize,
}

/// Separates bounded local admission from original native or transport failures.
#[derive(Debug, thiserror::Error)]
pub enum KvmComponentError {
    /// A finite journal, allocation or retry allowance was exhausted before effect.
    #[error("original native component resource credit unavailable")]
    ResourceLimit,
    /// A supplied token belongs to a different owning journal.
    #[error("foreign original native component token")]
    ForeignToken,
    /// An attempted transition conflicts with retained original custody.
    #[error("original native component transition refused: {0}")]
    Transition(&'static str),
    /// An original native exchange failed while its request remains retained.
    #[error("original native component exchange failed: {0}")]
    Exchange(#[from] QmpError),
    /// The actual installed files, host device or native prerequisites refused.
    #[error("original native component installation refused: {0}")]
    Candidate(#[from] KvmCandidateError),
    /// The common finite supervisor refused preparation before child allocation.
    #[error("original native component supervision refused: {0}")]
    Supervision(#[from] RuntimeError),
    /// An actual OS observation or native process operation failed.
    #[error("original native component custody failed: {0}")]
    Custody(String),
}

/// Retains one original submission even when its first native exchange fails.
#[derive(Debug)]
pub struct KvmComponentSubmission<T> {
    /// Refers to the exact owning ledger whose original request remains retained.
    pub token: KvmComponentToken,
    /// Reports the first native reply independently of the retained association.
    pub exchange: Result<T, QmpError>,
}

/// Retains a snapshot of original checked facts after one bounded attempt.
///
/// A failed exchange may leave the previous checked facts unchanged. This is
/// retained original history, never a fresh native observation after timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvmComponentObservation {
    /// Retains original Window facts, if a checked reply was received.
    Window {
        /// Stores the original checked reply without upgrading its qualification.
        state: Option<QmpKvmOriginalWindowState>,
        /// Preserves uncertainty at this original attempt, even after later recovery.
        uncertain: bool,
    },
    /// Retains original ACK facts, including a checked conflicting receipt.
    Ack {
        /// Stores the checked reply without consuming any pending response.
        state: Option<QmpKvmOriginalReturnState>,
        /// Preserves historical native or transport uncertainty.
        uncertain: bool,
    },
}

/// Owns one stopped native process and its original kernel/CPU component journals.
///
/// Preparation probes the real host KVM device and exact component capabilities
/// before creating any child. It never substitutes TCG. Successful preparation
/// is not an executable node profile: whole device/input/output closure and native
/// architectural preservation remain unsupported. The owner is actor-local.
/// Dropping it transfers its existing child and journals into its reserved common
/// supervisory slot without allocating another capsule or losing wait authority.
pub struct KvmOwnedComponents {
    custody: KvmComponentCustody,
    executable: File,
}

impl KvmOwnedComponents {
    /// Prepares a stopped native component process under mandatory supervision.
    ///
    /// The closed diagnostic machine has no guest image or external devices.
    /// Real clock, completion, original return and private response-byte kernel
    /// prerequisites are checked before the actual QEMU process can exist. This
    /// method supplies no `SimulationNode`, common grant, or preserved-state seal.
    ///
    /// # Errors
    /// Refuses finite credit or supervisor failure, changed installation files,
    /// unavailable native KVM, missing exact source components, child startup or
    /// OS peer authentication failure. Any allocated original child remains in
    /// the pre-reserved capsule and is transferred to supervised containment.
    pub fn prepare(
        candidate: KvmInstalledCandidate,
        supervisor: &dyn RuntimeCustodySupervisor,
        allocation: ActivationRecord,
        limits: RuntimeLimits,
        maximum_commands: usize,
        maximum_attempts: usize,
    ) -> Result<Self, KvmComponentError> {
        journal::validate_limits(maximum_commands, maximum_attempts)?;
        let mut custody = KvmComponentCustody::reserve(supervisor, allocation, limits)?;

        custody.reserve_control(maximum_commands, maximum_attempts)?;
        let preparation = candidate.prepare_stopped_component()?;
        let inventory = preparation.inventory();
        let (edition, coverage, machine) = match inventory.architecture {
            KvmArchitecture::X86_64 => (3, inventory.clock_v3_components, "microvm"),
            KvmArchitecture::Aarch64 => (2, inventory.clock_v2_components, "virt"),
        };
        if coverage != if edition == 3 { 159 } else { 228 } {
            return Err(KvmComponentError::Transition(
                "actual controller-clock component is incomplete",
            ));
        }
        for capability in [0xa028, 0xa029, 0xa02a] {
            if preparation.check_vm_extension(capability)? != 1 {
                return Err(KvmComponentError::Transition(
                    "actual completion/return/private-byte component is absent",
                ));
            }
        }
        let executable = candidate.original_qemu_descriptor()?;
        let directory = tempfile::Builder::new()
            .prefix("crucible-kvm-components-")
            .tempdir()
            .map_err(|error| KvmComponentError::Custody(error.to_string()))?;
        let endpoint = directory.path().join("control");
        // exec resolves the retained descriptor before CLOEXEC takes effect.
        // Rebinding an installation pathname cannot substitute another inode.
        let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        let accelerator = format!(
            concat!(
                "kvm,x-crucible-clock-experiment=on,",
                "x-crucible-clock-kernel-edition={},",
                "x-crucible-userspace-exit-ledger=on,",
                "x-crucible-completion-only=on,",
                "x-crucible-paused-response-service=on,",
                "x-crucible-original-window=on,",
                "x-crucible-response-bytes=on"
            ),
            edition,
        );
        command.env_clear().env("LC_ALL", "C");
        command.args([
            "-S",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-nodefaults",
            "-machine",
            machine,
            "-m",
            "64",
            "-smp",
            "1",
            "-accel",
        ]);
        command.arg(accelerator);
        command
            .arg("-qmp")
            .arg(format!("unix:{},server=on,wait=off", endpoint.display()));
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
        custody.retain_installation(candidate, directory);
        custody.spawn_child(&mut command).map_err(custody_error)?;
        let stream = connect_original_endpoint(&mut custody, &endpoint)?;
        custody
            .authenticate_control_peer(stream, &executable)
            .map_err(custody_error)?;
        custody
            .connect_control(maximum_commands, maximum_attempts)
            .map_err(custody_error)?;
        Ok(Self {
            custody,
            executable,
        })
    }

    /// Retains an original Window request before issuing its native mutation.
    ///
    /// Returned stopped/clock facts concern this partial component only. This
    /// interface cannot turn a caller's coordinates into a common-node grant.
    ///
    /// # Errors
    /// Refuses occupied/exhausted/foreign custody or invalid original geometry
    /// before effects. A failed exchange still returns its retained original token.
    pub fn submit_window(
        &mut self,
        request: QmpKvmOriginalWindowRequest,
    ) -> Result<KvmComponentSubmission<QmpKvmOriginalWindowState>, KvmComponentError> {
        self.custody.control(|native| {
            let (token, exchange) = native.submit_window(request)?;
            Ok(KvmComponentSubmission { token, exchange })
        })
    }

    /// Observes the same retained Window without repeating its original mutation.
    ///
    /// # Errors
    /// Refuses a foreign token, exhausted retry allowance, unavailable original
    /// child, poisoned channel or failed native observation; the original remains.
    pub fn reconcile_window(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmOriginalWindowState, KvmComponentError> {
        self.custody
            .control(|native| native.reconcile_window(token))
    }

    /// Reads and acknowledges one original receipt on this same authenticated peer.
    ///
    /// Caller-provided receipt bytes cannot authorize ACK. The owner observes its
    /// actual original inventory and full receipt before reserving the one-time
    /// acknowledgement. ACK never consumes pending device input or grants execution.
    ///
    /// # Errors
    /// Refuses missing/changed original receipt, duplicate ACK or exhausted credit
    /// before mutation. A failed ACK exchange still returns its retained token.
    pub fn submit_ack(
        &mut self,
        generation: u64,
        record_index: u32,
    ) -> Result<KvmComponentSubmission<QmpKvmOriginalReturnState>, KvmComponentError> {
        self.custody.control(|native| {
            let (token, exchange) = native.submit_ack(generation, record_index)?;
            Ok(KvmComponentSubmission { token, exchange })
        })
    }

    /// Queries the same retained ACK after an uncertain reply without reissuing it.
    ///
    /// # Errors
    /// Refuses foreign or exhausted custody and propagates original observation
    /// failure. Sticky uncertainty and the entire original receipt remain retained.
    pub fn reconcile_ack(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<QmpKvmOriginalReturnState, KvmComponentError> {
        self.custody.control(|native| native.reconcile_ack(token))
    }

    /// Copies the bounded original observation history without native effects.
    ///
    /// # Errors
    /// Refuses a foreign token, quarantined owner or unavailable host copy credit.
    /// Reading history cannot evict original records or release their custody.
    pub fn observations(
        &mut self,
        token: &KvmComponentToken,
    ) -> Result<Vec<KvmComponentObservation>, KvmComponentError> {
        self.custody.control(|native| native.history(token))
    }

    /// Authenticates a replacement stream to this same actual child generation.
    ///
    /// The original wait handle, pinned executable, PID/start ticks and actual OS
    /// credentials must agree before replacing the channel. Existing journals and
    /// uncertainty are unchanged. No serialized correlation label supplies authority.
    ///
    /// # Errors
    /// Refuses a different process/executable/credential generation, quarantined
    /// original custody, unavailable OS evidence or failed replacement handshake.
    pub fn reconnect(&mut self, stream: UnixStream) -> Result<(), KvmComponentError> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(2))))
            .map_err(|error| KvmComponentError::Custody(error.to_string()))?;
        self.custody
            .reconnect(stream, &self.executable)
            .map_err(custody_error)
    }

    /// Borrows the original prepared allocation record without granting activation.
    pub fn allocation(&self) -> &ActivationRecord {
        self.custody.activation_record()
    }

    /// Reports the actual authenticated original process ID, if connected.
    pub fn original_process_id(&self) -> Option<u32> {
        self.custody.original_peer().map(|peer| peer.process_id)
    }

    /// Observes authentic original process exit without clearing command custody.
    ///
    /// # Errors
    /// Returns native wait failure while retaining the original wait handle,
    /// journal and source files. Exit taints custody and never implies rollback.
    pub fn observe_process_exit(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, KvmComponentError> {
        self.custody.observe_original_exit().map_err(custody_error)
    }

    /// Borrows a previously observed exit status without resampling native state.
    pub fn original_exit_status(&self) -> Option<std::process::ExitStatus> {
        self.custody.original_exit_status()
    }

    /// Refuses preservation until genuine pending-exit and whole-device closure exists.
    ///
    /// # Errors
    /// Always returns unsupported with no modeled effects. Neither a stopped
    /// Window nor original ACK authenticates a backend-specific exact capture.
    pub fn capture_architectural_state(
        &mut self,
    ) -> Result<super::KvmArchitecturalCapture, OperationFailure> {
        Err(OperationFailure {
            effects: EffectKnowledge::None,
            reason: "native KVM exact whole-device and pending-exit preservation is unqualified"
                .into(),
        })
    }
}

// This deadline bounds host startup only; it never advances modeled node time.
fn connect_original_endpoint(
    custody: &mut KvmComponentCustody,
    endpoint: &std::path::Path,
) -> Result<UnixStream, KvmComponentError> {
    let deadline = crate::supervision::HostSupervisionDeadline::start(Duration::from_secs(5));
    loop {
        if custody
            .observe_original_exit()
            .map_err(custody_error)?
            .is_some()
        {
            return Err(KvmComponentError::Transition(
                "original native child exited during preparation",
            ));
        }
        match UnixStream::connect(endpoint) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(2))))
                    .map_err(|error| KvmComponentError::Custody(error.to_string()))?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) && deadline.has_time_remaining() =>
            {
                std::thread::yield_now()
            }
            Err(error) => return Err(KvmComponentError::Custody(error.to_string())),
        }
    }
}

fn custody_error(error: OperationFailure) -> KvmComponentError {
    KvmComponentError::Custody(error.reason)
}

#[cfg(test)]
mod tests;
