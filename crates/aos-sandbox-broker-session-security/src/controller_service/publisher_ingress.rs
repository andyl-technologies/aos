//! Deployment-pinned registration of one publisher service execution.
//!
//! The systemd credential selects a principal, project, cache resource, and
//! service UID/GID. PID 1 supplies the active unit cgroup and main PID; a
//! retained pidfd and cgroup-v2 descriptor check that observation before the
//! controller accepts a publisher connection. Neither the socket path nor its
//! peer credentials select project authority.
//!
//! ```text
//! AOSPMS01 | principal:16 | project:16 | cache-resource:16 | uid:u32be | gid:u32be
//! ```

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::publisher_control::PublisherServiceRegistration;
use aos_sandbox::publisher_control::{PublisherControlError, PublisherControlPolicy};
use aos_sandbox::publisher_ingress::PublisherIngressLimits;
use aos_sandbox::publisher_policy::PublisherPolicyLimits;
use aos_sandbox::publisher_sessions::{
    PublisherSessionError, PublisherSessionLimits, PublisherSessionRegistry, PublisherSessionScope,
};
use aos_sandbox_core::{NodeId, PrincipalId, ProjectId, PublisherInstanceId, ResourceId};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{
    ListenerAdmissionFailureRefV1, RecordSubjectListener,
    RecordSubjectListenerAdmissionAttemptV1, SeqpacketError,
};
use aos_systemd::SystemdClient;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, open};

use super::ProductionController;
use super::publisher_credential::read_required_credential;
use crate::controller_ownership::{CLOCK_PROVENANCE, sample_ownership_clock};

const CREDENTIAL: &str = "publisher-service-scope-v1";
const MAGIC: &[u8; 8] = b"AOSPMS01";
const CREDENTIAL_BYTES: usize = 64;
const SOCKET: &str = "/run/aos/sandbox-publisher/control.sock";
const UNIT: &str = "aos-view-publisher.service";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Rejects absent or substituted publisher deployment authority.
#[derive(Debug, thiserror::Error)]
pub(super) enum PublisherIngressError {
    /// The fixed scope credential is absent, malformed, or unsafe.
    #[error("protected publisher service scope is invalid")]
    Scope,
    /// The sole systemd listener is missing, substituted, or lacks record identity.
    #[error("publisher listener activation is invalid")]
    Listener,
    /// PID 1 or the kernel could not prove the configured service execution.
    #[error("publisher service execution is not current")]
    Execution,
}

/// Retains the deployment-owned scope and expected service credentials.
#[derive(Clone, Copy)]
pub(super) struct PublisherServiceScopeV1 {
    scope: PublisherSessionScope,
    uid: u32,
    gid: u32,
}

impl PublisherServiceScopeV1 {
    pub(super) const fn session_scope(self) -> PublisherSessionScope {
        self.scope
    }

    pub(super) fn from_process_credential(node: NodeId) -> Result<Self, PublisherIngressError> {
        let bytes = read_required_credential(CREDENTIAL, CREDENTIAL_BYTES, CREDENTIAL_BYTES)
            .map_err(|_| PublisherIngressError::Scope)?;
        Self::parse(&bytes, node)
    }

    fn parse(bytes: &[u8], node: NodeId) -> Result<Self, PublisherIngressError> {
        let bytes: &[u8; CREDENTIAL_BYTES] =
            bytes.try_into().map_err(|_| PublisherIngressError::Scope)?;
        let principal: [u8; 16] = bytes[8..24]
            .try_into()
            .map_err(|_| PublisherIngressError::Scope)?;
        let project: [u8; 16] = bytes[24..40]
            .try_into()
            .map_err(|_| PublisherIngressError::Scope)?;
        let cache_resource: [u8; 16] = bytes[40..56]
            .try_into()
            .map_err(|_| PublisherIngressError::Scope)?;
        let uid = u32::from_be_bytes(
            bytes[56..60]
                .try_into()
                .map_err(|_| PublisherIngressError::Scope)?,
        );
        let gid = u32::from_be_bytes(
            bytes[60..64]
                .try_into()
                .map_err(|_| PublisherIngressError::Scope)?,
        );
        if &bytes[..8] != MAGIC
            || principal == [0; 16]
            || project == [0; 16]
            || cache_resource == [0; 16]
            || *node.as_bytes() == [0; 16]
            || uid == 0
            || gid == 0
        {
            return Err(PublisherIngressError::Scope);
        }
        Ok(Self {
            scope: PublisherSessionScope {
                principal: PrincipalId::from_bytes(principal),
                node,
                project: ProjectId::from_bytes(project),
                cache_resource: ResourceId::from_bytes(cache_resource),
            },
            uid,
            gid,
        })
    }

    pub(super) async fn observe_execution(
        self,
    ) -> Result<PublisherServiceRegistration, PublisherIngressError> {
        tokio::time::timeout(OBSERVATION_TIMEOUT, async {
            let systemd = SystemdClient::connect()
                .await
                .map_err(|_| PublisherIngressError::Execution)?;
            let first = systemd
                .observe_service_control_group(UNIT)
                .await
                .map_err(|_| PublisherIngressError::Execution)?;
            let root = CgroupV2Root::from_owned(
                open(
                    CGROUP_ROOT,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| PublisherIngressError::Execution)?,
            )
            .map_err(|_| PublisherIngressError::Execution)?;
            let relative = first
                .control_group
                .strip_prefix('/')
                .ok_or(PublisherIngressError::Execution)?;
            let anchor = root
                .resolve(Path::new(relative))
                .map_err(|_| PublisherIngressError::Execution)?;
            let process =
                PidFd::open(first.main_pid).map_err(|_| PublisherIngressError::Execution)?;
            let info = anchor
                .verify_exact_membership(&process)
                .map_err(|_| PublisherIngressError::Execution)?;
            let credentials = info.credentials().ok_or(PublisherIngressError::Execution)?;
            if info.pid() != first.main_pid.get()
                || info.thread_group_id() != first.main_pid.get()
                || credentials.real_user_id() != self.uid
                || credentials.effective_user_id() != self.uid
                || credentials.real_group_id() != self.gid
                || credentials.effective_group_id() != self.gid
            {
                return Err(PublisherIngressError::Execution);
            }
            let second = systemd
                .observe_service_control_group(UNIT)
                .await
                .map_err(|_| PublisherIngressError::Execution)?;
            if first != second
                || !process
                    .is_alive()
                    .map_err(|_| PublisherIngressError::Execution)?
            {
                return Err(PublisherIngressError::Execution);
            }
            anchor
                .verify_exact_membership(&process)
                .map_err(|_| PublisherIngressError::Execution)?;
            Ok(PublisherServiceRegistration {
                scope: self.scope,
                anchor,
                expected_process: process,
            })
        })
        .await
        .map_err(|_| PublisherIngressError::Execution)?
    }
}

/// Adopts only the fixed preconfigured record-subject listener from PID 1.
pub(super) fn adopt_observed_listener(
    descriptor: OwnedFd,
) -> Result<RecordSubjectListener, PublisherIngressError> {
    let listener = RecordSubjectListener::from_owned(descriptor)
        .map_err(|_| PublisherIngressError::Listener)?;
    listener
        .require_local_filesystem_path(Path::new(SOCKET))
        .map_err(|_| PublisherIngressError::Listener)?;
    Ok(listener)
}

/// Borrows a resident Publisher startup failure without releasing originals.
#[derive(Debug)]
pub(super) enum PublisherStartupFailureRefV1<'a> {
    /// The lower owner retains its original listener and typed first cause.
    Lower(ListenerAdmissionFailureRefV1<'a>),
    /// The existing fixed scope credential classification remains resident.
    Scope(&'a PublisherIngressError),
    /// The fixed registry constructor's actual error remains resident.
    Registry(&'a PublisherSessionError),
    /// The current-thread runtime constructor's actual error remains resident.
    Runtime(&'a std::io::Error),
    /// A crossing was reentered or its required ownership state is unavailable.
    Closed,
}

enum PublisherStartupFailureV1 {
    Lower,
    Scope(PublisherIngressError),
    Registry(PublisherSessionError),
    Runtime(std::io::Error),
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublisherStartupPhaseV1 {
    Fresh,
    CheckingListener,
    ListenerReady,
    CheckingRegistration,
    RegistrationReady,
    Ended,
    Taken,
}

/// Retains one original Publisher listener and its staged registration owners.
///
/// Listener admission and scope/registry/runtime construction remain separate
/// crossings at their existing caller positions. Failed or unwinding attempts
/// terminate with originals resident; they do not claim process or owner drain.
/// The installed Controller caller has not migrated to this dormant seam.
#[must_use]
pub(super) struct PublisherStartupAttemptV1 {
    lower: RecordSubjectListenerAdmissionAttemptV1,
    listener: Option<RecordSubjectListener>,
    sessions: Option<PublisherSessionRegistry>,
    scope: Option<PublisherServiceScopeV1>,
    runtime: Option<tokio::runtime::Runtime>,
    completed: Option<PublisherRegistrationOwnerV1>,
    phase: PublisherStartupPhaseV1,
    failure: Option<PublisherStartupFailureV1>,
    armed: bool,
}

impl PublisherStartupAttemptV1 {
    /// Parks the descriptor from the concrete original Publisher role handoff.
    pub(super) const fn from_original_listener(descriptor: OwnedFd) -> Self {
        Self {
            lower: RecordSubjectListenerAdmissionAttemptV1::new(descriptor),
            listener: None,
            sessions: None,
            scope: None,
            runtime: None,
            completed: None,
            phase: PublisherStartupPhaseV1::Fresh,
            failure: None,
            armed: true,
        }
    }

    /// Admits only the existing fixed listener, before node and recipe reads.
    ///
    /// # Errors
    /// Borrows the resident lower cause or permanent closed-state refusal.
    pub(super) fn admit_listener_once(
        &mut self,
    ) -> Result<(), PublisherStartupFailureRefV1<'_>> {
        if self.phase != PublisherStartupPhaseV1::Fresh || self.failure.is_some() {
            return Err(self.retain_failure(PublisherStartupFailureV1::Closed));
        }
        self.phase = PublisherStartupPhaseV1::CheckingListener;

        let result = {
            let _unwind = AbortPublisherStartupUnwind;
            self.admit_listener_body()
        };
        match result {
            Ok(()) => {
                self.phase = PublisherStartupPhaseV1::ListenerReady;
                Ok(())
            }
            Err(cause) => Err(self.retain_failure(cause)),
        }
    }

    /// Builds registration at the original fixed scope-credential position.
    ///
    /// # Errors
    /// Borrows the first scope, registry, runtime or closed-state cause while
    /// keeping every earlier returned listener/table/runtime original resident.
    pub(super) fn construct_registration_once(
        &mut self,
        node: NodeId,
    ) -> Result<(), PublisherStartupFailureRefV1<'_>> {
        if self.phase != PublisherStartupPhaseV1::ListenerReady || self.failure.is_some() {
            return Err(self.retain_failure(PublisherStartupFailureV1::Closed));
        }
        self.phase = PublisherStartupPhaseV1::CheckingRegistration;

        let result = {
            let _unwind = AbortPublisherStartupUnwind;
            self.construct_registration_body(node)
        };
        match result {
            Ok(()) => {
                self.phase = PublisherStartupPhaseV1::RegistrationReady;
                Ok(())
            }
            Err(cause) => Err(self.retain_failure(cause)),
        }
    }

    /// Borrows the actual first cause through the still-resident owning fields.
    pub(super) fn first_failure(&self) -> Option<PublisherStartupFailureRefV1<'_>> {
        self.failure.as_ref().map(|_| self.failure_view())
    }

    /// Transfers the same completed registration once, without fallible work.
    ///
    /// The caller must prepare its receiving destination before this move and
    /// retain that owner across every later fallible startup operation.
    pub(super) fn take_completed_registration(&mut self) -> Option<PublisherRegistrationOwnerV1> {
        if self.phase != PublisherStartupPhaseV1::RegistrationReady
            || self.failure.is_some()
            || self.listener.is_some()
            || self.sessions.is_some()
            || self.scope.is_some()
            || self.runtime.is_some()
            || self.completed.is_none()
        {
            return None;
        }

        let completed = self.completed.take();
        self.phase = PublisherStartupPhaseV1::Taken;
        self.armed = false;
        completed
    }

    fn admit_listener_body(&mut self) -> Result<(), PublisherStartupFailureV1> {
        if self.listener.is_some()
            || self.sessions.is_some()
            || self.scope.is_some()
            || self.runtime.is_some()
            || self.completed.is_some()
        {
            return Err(PublisherStartupFailureV1::Closed);
        }
        if self.lower.admit_once(Path::new(SOCKET)).is_err() {
            return Err(PublisherStartupFailureV1::Lower);
        }
        let Some(listener) = self.lower.take_completed_listener() else {
            return Err(PublisherStartupFailureV1::Closed);
        };
        self.listener = Some(listener);
        Ok(())
    }

    fn construct_registration_body(
        &mut self,
        node: NodeId,
    ) -> Result<(), PublisherStartupFailureV1> {
        if self.listener.is_none()
            || self.sessions.is_some()
            || self.scope.is_some()
            || self.runtime.is_some()
            || self.completed.is_some()
        {
            return Err(PublisherStartupFailureV1::Closed);
        }

        self.scope = Some(
            PublisherServiceScopeV1::from_process_credential(node)
                .map_err(PublisherStartupFailureV1::Scope)?,
        );
        self.sessions = Some(
            fixed_registration_sessions().map_err(PublisherStartupFailureV1::Registry)?,
        );
        self.runtime = Some(
            fixed_registration_runtime().map_err(PublisherStartupFailureV1::Runtime)?,
        );

        // Check every source/destination before moving any original. Final
        // assembly performs no observation, allocation or fallible continuation.
        if self.listener.is_none()
            || self.sessions.is_none()
            || self.scope.is_none()
            || self.runtime.is_none()
            || self.completed.is_some()
        {
            return Err(PublisherStartupFailureV1::Closed);
        }
        let originals = (
            self.listener.take(),
            self.sessions.take(),
            self.scope.take(),
            self.runtime.take(),
        );
        match originals {
            (Some(listener), Some(sessions), Some(scope), Some(runtime)) => {
                self.completed = Some(PublisherRegistrationOwnerV1 {
                    listener,
                    sessions,
                    scope,
                    runtime,
                    instance: None,
                });
                Ok(())
            }
            (listener, sessions, scope, runtime) => {
                self.listener = listener;
                self.sessions = sessions;
                self.scope = scope;
                self.runtime = runtime;
                Err(PublisherStartupFailureV1::Closed)
            }
        }
    }

    fn retain_failure(
        &mut self,
        cause: PublisherStartupFailureV1,
    ) -> PublisherStartupFailureRefV1<'_> {
        self.failure.get_or_insert(cause);
        self.phase = PublisherStartupPhaseV1::Ended;
        self.failure_view()
    }

    fn failure_view(&self) -> PublisherStartupFailureRefV1<'_> {
        match &self.failure {
            Some(PublisherStartupFailureV1::Lower) => match self.lower.first_failure() {
                Some(cause) => PublisherStartupFailureRefV1::Lower(cause),
                None => PublisherStartupFailureRefV1::Closed,
            },
            Some(PublisherStartupFailureV1::Scope(cause)) => {
                PublisherStartupFailureRefV1::Scope(cause)
            }
            Some(PublisherStartupFailureV1::Registry(cause)) => {
                PublisherStartupFailureRefV1::Registry(cause)
            }
            Some(PublisherStartupFailureV1::Runtime(cause)) => {
                PublisherStartupFailureRefV1::Runtime(cause)
            }
            Some(PublisherStartupFailureV1::Closed) | None => PublisherStartupFailureRefV1::Closed,
        }
    }
}

impl Drop for PublisherStartupAttemptV1 {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

struct AbortPublisherStartupUnwind;

impl Drop for AbortPublisherStartupUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

fn fixed_registration_sessions() -> Result<PublisherSessionRegistry, PublisherSessionError> {
    PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
}

fn fixed_registration_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Owns one live registration slot beside the controller's sole journal writer.
pub(super) struct PublisherRegistrationOwnerV1 {
    listener: RecordSubjectListener,
    sessions: PublisherSessionRegistry,
    scope: PublisherServiceScopeV1,
    runtime: tokio::runtime::Runtime,
    instance: Option<PublisherInstanceId>,
}

impl PublisherRegistrationOwnerV1 {
    pub(super) const fn service_scope(&self) -> PublisherSessionScope {
        self.scope.session_scope()
    }

    pub(super) fn new(
        listener: RecordSubjectListener,
        scope: PublisherServiceScopeV1,
    ) -> Result<Self, PublisherIngressError> {
        let sessions = fixed_registration_sessions()
            .map_err(|_| PublisherIngressError::Scope)?;
        let runtime = fixed_registration_runtime()
            .map_err(|_| PublisherIngressError::Execution)?;
        Ok(Self {
            listener,
            sessions,
            scope,
            runtime,
            instance: None,
        })
    }

    pub(super) const fn needs_registration(&self) -> bool {
        self.instance.is_none()
    }

    /// Registers one service execution or one queued challenge; neither grants publication.
    pub(super) fn try_register(
        &mut self,
        controller: &mut ProductionController,
    ) -> Result<(), String> {
        if let Some(instance) = self.instance {
            if self.sessions.recheck_registered(instance).is_ok() {
                return self.try_register_challenge(controller, instance);
            }
            self.sessions
                .retire(instance)
                .map_err(|error| format!("publisher retirement failed: {error}"))?;
            match controller.release_exited_publisher(&mut self.sessions, instance) {
                Ok(_) => self.instance = None,
                Err(PublisherControlError::Session(
                    aos_sandbox::publisher_sessions::PublisherSessionError::ExecutionAlive,
                )) => return Ok(()),
                Err(error) => return Err(format!("publisher exit custody failed: {error}")),
            }
        }
        let mut descriptors = [PollFd::from_borrowed_fd(
            self.listener.as_fd(),
            PollFlags::IN,
        )];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let ready = match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => false,
            Ok(_) => true,
            Err(error) => return Err(format!("publisher listener polling failed: {error}")),
        };
        if !ready {
            return Ok(());
        }
        let service = match self.runtime.block_on(self.scope.observe_execution()) {
            Ok(service) => service,
            Err(_) => return Ok(()),
        };
        let result = controller.register_publisher_execution(
            &mut self.sessions,
            &mut self.listener,
            service,
            control_policy(),
            &mut || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError),
        );
        match result {
            Ok(registration) => {
                self.instance = Some(registration.fields().instance);
                Ok(())
            }
            Err(PublisherControlError::Journal(error)) => {
                Err(format!("publisher journal registration failed: {error}"))
            }
            Err(PublisherControlError::Ingress(error)) => {
                Err(format!("publisher execution audit failed: {error}"))
            }
            Err(error) => {
                self.instance = self.sessions.reserved_instance(self.scope.scope);
                eprintln!("aos-sandboxd: publisher execution registration rejected: {error}");
                Ok(())
            }
        }
    }

    fn try_register_challenge(
        &mut self,
        controller: &mut ProductionController,
        instance: PublisherInstanceId,
    ) -> Result<(), String> {
        let result = controller.register_publisher_challenge(
            &mut self.sessions,
            instance,
            control_policy(),
            &mut || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError),
        );
        match result {
            Ok(_) => Ok(()),
            Err(PublisherControlError::Session(
                aos_sandbox::publisher_sessions::PublisherSessionError::Transport(
                    SeqpacketError::WouldBlock | SeqpacketError::Interrupted,
                ),
            )) => Ok(()),
            Err(PublisherControlError::Journal(error)) => {
                Err(format!("publisher challenge journal failed: {error}"))
            }
            Err(PublisherControlError::Ingress(
                aos_sandbox::publisher_ingress::PublisherIngressError::Journal(error),
            )) => Err(format!("publisher challenge audit failed: {error}")),
            Err(PublisherControlError::Policy(error)) => {
                Err(format!("publisher challenge policy state failed: {error}"))
            }
            Err(error) => {
                eprintln!("aos-sandboxd: publisher challenge rejected: {error}");
                Ok(())
            }
        }
    }
}

fn control_policy() -> PublisherControlPolicy {
    PublisherControlPolicy {
        clock_provenance: CLOCK_PROVENANCE,
        maximum_challenge_seconds: 60,
        policy_limits: PublisherPolicyLimits::default(),
        ingress_limits: PublisherIngressLimits::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_requires_exact_nonzero_deployment_binding() {
        let mut bytes = [0_u8; CREDENTIAL_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&[1; 16]);
        bytes[24..40].copy_from_slice(&[2; 16]);
        bytes[40..56].copy_from_slice(&[3; 16]);
        bytes[56..60].copy_from_slice(&993_u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&993_u32.to_be_bytes());
        let node = NodeId::from_bytes([4; 16]);
        let scope = PublisherServiceScopeV1::parse(&bytes, node).expect("valid scope");
        assert_eq!(scope.scope.project.as_bytes(), &[2; 16]);
        assert_eq!(scope.uid, 993);

        assert!(PublisherServiceScopeV1::parse(&bytes[..63], node).is_err());
        bytes[8] = 0;
        assert!(PublisherServiceScopeV1::parse(&bytes, node).is_ok());
        bytes[8..24].fill(0);
        assert!(PublisherServiceScopeV1::parse(&bytes, node).is_err());
        bytes[8..24].fill(1);
        bytes[56..60].fill(0);
        assert!(PublisherServiceScopeV1::parse(&bytes, node).is_err());
        bytes[56..60].copy_from_slice(&993_u32.to_be_bytes());
        bytes[..8].copy_from_slice(b"AOSPMS02");
        assert!(PublisherServiceScopeV1::parse(&bytes, node).is_err());
    }
}
