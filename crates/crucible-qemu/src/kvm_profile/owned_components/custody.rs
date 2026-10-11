//! Pre-reserved common supervisory custody for an original native KVM child.
//!
//! The capsule is installed before process allocation and retains the exact child
//! wait authority and original component journal. It has no readiness issuer or
//! execution interface. Process-group death is cleanup evidence only, never
//! rollback, device closure, output disposition or an exact preserved state.

use std::{
    cell::RefCell,
    fs::File,
    os::unix::{net::UnixStream, process::CommandExt},
    process::{Child, Command, ExitStatus},
    rc::Rc,
    task::{Context, Poll},
};

use crucible::node_contract::{
    ActivationRecord, EffectKnowledge, OperationFailure, PreparedNativeResources,
    PublicationStatus, RuntimeCustodySlot, RuntimeCustodySupervisor, RuntimeError, RuntimeLimits,
    WholeRuntimeCustody,
};
use rustix::process::{Pid, Signal, kill_process_group, test_kill_process_group};

use super::{
    journal::{Journal, JournalReservation},
    peer::{KvmAuthenticatedPeer, KvmNativePeerIdentity, authenticate_owned_peer},
};

struct Capsule {
    child: Option<Child>,
    group: Option<Pid>,
    original_status: Option<ExitStatus>,
    native: Option<Journal<UnixStream>>,
    reserved_journal: Option<JournalReservation>,
    source: Option<super::KvmInstalledCandidate>,
    endpoint: Option<tempfile::TempDir>,
    peer: Option<KvmAuthenticatedPeer>,
    original_peer: Option<KvmNativePeerIdentity>,
    quarantined: bool,
    kill_sent: bool,
    reaped: bool,
}

struct PreparedCapsule(Rc<RefCell<Capsule>>);

/// Retains an inactive original native owner in mandatory common supervision.
///
/// This initial capsule covers one original owner and supports no restored child
/// or mixed-owner construction. The complete-world factory must reserve one
/// aggregate resource capsule before extending this to multiple native owners.
/// Native source qualification, OS peer authentication and initial provenance
/// precede installation into an executable node; this guard cannot issue them.
pub(super) struct KvmComponentCustody {
    shared: Rc<RefCell<Capsule>>,
    activation: ActivationRecord,
    slot: Option<Box<dyn RuntimeCustodySlot>>,
    whole: Option<WholeRuntimeCustody>,
}

impl KvmComponentCustody {
    /// Reserves original resource retention before any autonomous child exists.
    ///
    /// # Errors
    /// Rejects an empty or mixed owner roster, unavailable finite supervisor
    /// capacity, or a reservation that does not authenticate the proposed world.
    pub(super) fn reserve(
        supervisor: &dyn RuntimeCustodySupervisor,
        activation: ActivationRecord,
        limits: RuntimeLimits,
    ) -> Result<Self, RuntimeError> {
        if activation.owners.len() != 1 {
            return Err(RuntimeError::InvalidRoute);
        }
        let slot = supervisor.reserve_world(&activation, limits)?;
        slot.validate_world(&activation, limits)?;
        let shared = Rc::new(RefCell::new(Capsule {
            child: None,
            group: None,
            original_status: None,
            native: None,
            reserved_journal: None,
            source: None,
            endpoint: None,
            peer: None,
            original_peer: None,
            quarantined: false,
            kill_sent: false,
            reaped: false,
        }));
        let whole = WholeRuntimeCustody::from_prepared_resources(
            Box::new(PreparedCapsule(Rc::clone(&shared))),
            activation.clone(),
            None,
            limits,
        );
        Ok(Self {
            shared,
            activation,
            slot: Some(slot),
            whole: Some(whole),
        })
    }

    pub(super) fn reserve_control(
        &mut self,
        maximum_commands: usize,
        maximum_attempts: usize,
    ) -> Result<(), super::KvmComponentError> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.child.is_some() || capsule.reserved_journal.is_some() || capsule.quarantined {
            return Err(super::KvmComponentError::Transition(
                "original journal must be reserved before child",
            ));
        }
        capsule.reserved_journal = Some(JournalReservation::reserve(
            maximum_commands,
            maximum_attempts,
        )?);
        Ok(())
    }

    /// Spawns one original child directly into the already reserved capsule.
    ///
    /// The private closed launcher supplies the measured executable and bounded
    /// startup configuration. A new original process group is mandatory. The
    /// actual child enters retained custody before any fallible post-spawn check;
    /// failed preparation cannot return an unowned child or substitute another.
    ///
    /// # Errors
    /// Refuses occupied or quarantined custody before spawn. A process allocation
    /// or post-spawn group failure returns explicit effect knowledge while the
    /// guard retains any actual child for mandatory supervised containment.
    pub(crate) fn spawn_child(&mut self, command: &mut Command) -> Result<(), OperationFailure> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.child.is_some()
            || capsule.quarantined
            || capsule.reaped
            || capsule.reserved_journal.is_none()
        {
            return Err(OperationFailure {
                effects: EffectKnowledge::None,
                reason: "original native child allocation is already reserved or quarantined"
                    .into(),
            });
        }
        command.process_group(0);
        let child = command
            .spawn()
            .map_err(|error| failure(&format!("original native child spawn failed: {error}")))?;
        let process_id = child.id();
        capsule.child = Some(child);

        let raw = i32::try_from(process_id)
            .map_err(|_| failure("original child PID is unrepresentable"))?;
        let pid = Pid::from_raw(raw).ok_or_else(|| failure("original child PID is invalid"))?;
        // The leader ID is retained even if the following query fails. Source
        // custody does not infer a fresh group or success from missing metadata.
        capsule.group = Some(pid);
        if rustix::process::getpgid(Some(pid)).ok() != Some(pid) {
            return Err(failure(
                "original native child does not head its reserved process group",
            ));
        }
        Ok(())
    }

    /// Authenticates the original owned child and retains that exact stream.
    ///
    /// This observation checks real socket peer credentials, process generation
    /// and executable inode. Source/build and native initial-state qualification
    /// remain independent. A failed authentication never replaces the original
    /// child or releases its mandatory prepared capsule.
    ///
    /// # Errors
    /// Refuses absent, quarantined or already connected custody, a foreign peer,
    /// changed executable or process generation, or unavailable OS evidence.
    pub(crate) fn authenticate_control_peer(
        &mut self,
        stream: UnixStream,
        expected_executable: &File,
    ) -> Result<(), OperationFailure> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.native.is_some()
            || capsule.peer.is_some()
            || capsule.original_peer.is_some()
            || capsule.quarantined
            || capsule.reaped
        {
            return Err(failure(
                "original native peer custody is occupied or quarantined",
            ));
        }
        let child = capsule
            .child
            .as_ref()
            .ok_or_else(|| failure("original native child custody is absent"))?;
        let peer = authenticate_owned_peer(child, stream, expected_executable)?;
        capsule.original_peer = Some(peer.identity.clone());
        capsule.peer = Some(peer);
        Ok(())
    }

    /// Installs the command journal on the same previously authenticated stream.
    ///
    /// A QMP handshake or allocation failure closes that one stream and retains
    /// the original peer evidence and child. A second peer cannot replace it.
    /// The greeting remains mechanical protocol evidence, never native readiness.
    ///
    /// # Errors
    /// Refuses absent or occupied original peer custody, invalid finite limits,
    /// failed native handshake or unavailable original-command allocation.
    pub(crate) fn connect_control(
        &mut self,
        maximum_commands: usize,
        maximum_attempts: usize,
    ) -> Result<(), OperationFailure> {
        super::journal::validate_limits(maximum_commands, maximum_attempts)
            .map_err(|error| failure(&format!("original native credit refused: {error}")))?;
        let mut capsule = self.shared.borrow_mut();
        if capsule.native.is_some() || capsule.quarantined || capsule.reaped {
            return Err(failure("original native channel custody is unavailable"));
        }
        let peer = capsule
            .peer
            .take()
            .ok_or_else(|| failure("original OS-authenticated peer custody is absent"))?;
        let qmp = crate::qmp::QmpClient::connect(peer.stream)
            .map_err(|error| failure(&format!("original native handshake failed: {error}")))?;
        let reservation = capsule
            .reserved_journal
            .take()
            .ok_or_else(|| failure("original preallocated journal custody is absent"))?;
        let native = reservation.connect(qmp);
        capsule.native = Some(native);
        Ok(())
    }

    pub(super) fn retain_installation(
        &mut self,
        source: super::KvmInstalledCandidate,
        endpoint: tempfile::TempDir,
    ) {
        let mut capsule = self.shared.borrow_mut();
        capsule.source = Some(source);
        capsule.endpoint = Some(endpoint);
    }

    pub(super) fn control<T>(
        &mut self,
        action: impl FnOnce(&mut Journal<UnixStream>) -> Result<T, super::KvmComponentError>,
    ) -> Result<T, super::KvmComponentError> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.quarantined || capsule.reaped {
            return Err(super::KvmComponentError::Transition(
                "original process is quarantined",
            ));
        }
        let native = capsule
            .native
            .as_mut()
            .ok_or(super::KvmComponentError::Transition(
                "original authenticated control is absent",
            ))?;
        action(native)
    }

    pub(super) fn reconnect(
        &mut self,
        stream: UnixStream,
        expected_executable: &File,
    ) -> Result<(), OperationFailure> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.quarantined || capsule.reaped || capsule.native.is_none() {
            return Err(failure("original authenticated controller is unavailable"));
        }
        let child = capsule
            .child
            .as_ref()
            .ok_or_else(|| failure("original child is absent"))?;
        let replacement = authenticate_owned_peer(child, stream, expected_executable)?;
        if capsule.original_peer.as_ref() != Some(&replacement.identity) {
            return Err(failure(
                "replacement is not the original OS process and executable",
            ));
        }
        let qmp = crate::qmp::QmpClient::connect(replacement.stream).map_err(|error| {
            failure(&format!("same-child replacement handshake failed: {error}"))
        })?;
        let native = capsule
            .native
            .as_mut()
            .ok_or_else(|| failure("original journal is absent"))?;
        native.qmp = qmp;
        Ok(())
    }

    pub(super) fn validate_admitted_installation(
        &self,
        artifacts: &[crucible_node_contract::ArtifactIdentity],
        executable: &File,
    ) -> Result<(), super::KvmComponentError> {
        use std::os::unix::fs::MetadataExt;

        let capsule = self.shared.borrow();
        if capsule.quarantined || capsule.reaped || capsule.native.is_none() {
            return Err(super::KvmComponentError::Transition(
                "original common mapping has no live retained controller",
            ));
        }
        let installed = capsule
            .source
            .as_ref()
            .ok_or(super::KvmComponentError::Transition(
                "original installed artifact custody is absent",
            ))?;
        installed.verify_original_artifacts()?;
        if !installed.artifact_identities().all(|reference| {
            artifacts
                .iter()
                .any(|artifact| &artifact.content == reference)
        }) {
            return Err(super::KvmComponentError::Transition(
                "admitted artifacts differ from original measured installation",
            ));
        }
        let peer = capsule
            .original_peer
            .as_ref()
            .ok_or(super::KvmComponentError::Transition(
                "original OS peer custody is absent",
            ))?;
        let metadata = executable
            .metadata()
            .map_err(|error| super::KvmComponentError::Custody(error.to_string()))?;
        let actual = File::open(format!("/proc/{}/exe", peer.process_id))
            .and_then(|file| file.metadata())
            .map_err(|error| super::KvmComponentError::Custody(error.to_string()))?;
        if super::peer::process_generation(peer.process_id).map_err(super::custody_error)?
            != peer.start_time_ticks
            || metadata.dev() != peer.executable_device
            || metadata.ino() != peer.executable_inode
            || actual.dev() != metadata.dev()
            || actual.ino() != metadata.ino()
            || actual.len() != metadata.len()
        {
            return Err(super::KvmComponentError::Transition(
                "original process generation or retained executable differs",
            ));
        }
        Ok(())
    }

    /// Borrows the actual original OS peer observation without granting readiness.
    pub(crate) fn original_peer(&self) -> Option<KvmNativePeerIdentity> {
        self.shared.borrow().original_peer.clone()
    }

    /// Borrows the exact original common allocation scope.
    pub(super) fn activation_record(&self) -> &ActivationRecord {
        &self.activation
    }

    /// Observes the actual original wait authority without inferring device closure.
    ///
    /// # Errors
    /// Returns a native wait failure while preserving the child and original group.
    pub(crate) fn observe_original_exit(&mut self) -> Result<Option<ExitStatus>, OperationFailure> {
        let mut capsule = self.shared.borrow_mut();
        if capsule.reaped {
            return Ok(capsule.original_status);
        }
        let child = capsule
            .child
            .as_mut()
            .ok_or_else(|| failure("original native child custody is absent"))?;
        let status = child
            .try_wait()
            .map_err(|error| failure(&format!("original child observation failed: {error}")))?;
        if let Some(status) = status {
            capsule.original_status = Some(status);
            capsule.reaped = true;
            capsule.quarantined = true;
        }
        Ok(status)
    }

    /// Reports the original wait result without resampling or granting rollback.
    pub(super) fn original_exit_status(&self) -> Option<ExitStatus> {
        self.shared.borrow().original_status
    }
}

impl Drop for KvmComponentCustody {
    fn drop(&mut self) {
        self.shared.borrow_mut().quarantined = true;
        if let (Some(slot), Some(whole)) = (self.slot.take(), self.whole.take()) {
            // Both the capsule and retention slot predate child allocation.
            // Transfer moves existing ownership and allocates no replacement.
            slot.retain(whole);
        }
    }
}

impl PreparedNativeResources for PreparedCapsule {
    fn quarantine_resources(&mut self, _: &ActivationRecord, _: Option<PublicationStatus>) {
        self.0.borrow_mut().quarantined = true;
    }

    fn poll_reclamation(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), OperationFailure>> {
        let mut capsule = self.0.borrow_mut();
        if !capsule.quarantined {
            return Poll::Ready(Err(failure("original native custody is not quarantined")));
        }
        if capsule.child.is_none() {
            return Poll::Ready(Ok(()));
        }
        let Some(group) = capsule.group else {
            return Poll::Ready(Err(failure(
                "original native process-group custody is missing",
            )));
        };
        if !capsule.kill_sent && !capsule.reaped {
            // The unreaped original Child still reserves the leader PID, so the
            // group ID cannot identify a newly reused unrelated leader. Never
            // send another signal after relinquishing that wait authority.
            match kill_process_group(group, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => capsule.kill_sent = true,
                Err(error) => {
                    return Poll::Ready(Err(failure(&format!(
                        "original native group containment failed: {error}"
                    ))));
                }
            }
        }
        if !capsule.reaped {
            let status = match capsule.child.as_mut() {
                Some(child) => child.try_wait(),
                None => return Poll::Ready(Err(failure("original wait authority disappeared"))),
            };
            match status {
                Ok(Some(status)) => {
                    capsule.original_status = Some(status);
                    capsule.reaped = true;
                }
                Ok(None) => {
                    context.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => {
                    return Poll::Ready(Err(failure(&format!(
                        "original child reap failed: {error}"
                    ))));
                }
            }
        }
        match test_kill_process_group(group) {
            Err(rustix::io::Errno::SRCH) => Poll::Ready(Ok(())),
            Ok(()) => {
                // A residual original member, or a reused group after leader
                // reap, is conservatively retained. Never signal a reused group.
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(failure(&format!(
                "original native group observation failed: {error}"
            )))),
        }
    }
}

fn failure(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::Unknown,
        reason: reason.into(),
    }
}
