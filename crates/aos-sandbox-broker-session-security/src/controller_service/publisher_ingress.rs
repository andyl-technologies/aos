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

use std::fs::File;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Duration;

use aos_sandbox::ownership_authority::ProtectedOwnershipClockError;
use aos_sandbox::publisher_control::PublisherServiceRegistration;
use aos_sandbox::publisher_control::{PublisherControlError, PublisherControlPolicy};
use aos_sandbox::publisher_ingress::PublisherIngressLimits;
use aos_sandbox::publisher_policy::PublisherPolicyLimits;
use aos_sandbox::publisher_sessions::{
    PublisherSessionLimits, PublisherSessionRegistry, PublisherSessionScope,
};
use aos_sandbox_core::{NodeId, PrincipalId, ProjectId, PublisherInstanceId, ResourceId};
use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use aos_systemd::SystemdClient;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, open};

use super::ProductionController;
use crate::controller_ownership::{CLOCK_PROVENANCE, sample_ownership_clock};
use crate::production_activation::{activation_names, validate_activation_process};

const CREDENTIAL: &str = "publisher-service-scope-v1";
const MAGIC: &[u8; 8] = b"AOSPMS01";
const CREDENTIAL_BYTES: usize = 64;
const FD_NAME: &str = "aos-sandboxd-publisher";
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
    pub(super) fn from_process_credential(node: NodeId) -> Result<Self, PublisherIngressError> {
        let directory =
            std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(PublisherIngressError::Scope)?;
        let directory = Path::new(&directory);
        if !directory.is_absolute() {
            return Err(PublisherIngressError::Scope);
        }
        let descriptor = open(
            &directory.join(CREDENTIAL),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| PublisherIngressError::Scope)?;
        let mut file = File::from(descriptor);
        let metadata = file.metadata().map_err(|_| PublisherIngressError::Scope)?;
        let process_uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file()
            || metadata.len() != CREDENTIAL_BYTES as u64
            || metadata.nlink() != 1
            || (metadata.uid() != 0 && metadata.uid() != process_uid)
            || metadata.mode() & 0o077 != 0
        {
            return Err(PublisherIngressError::Scope);
        }
        let mut bytes = [0; CREDENTIAL_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| PublisherIngressError::Scope)?;
        if file
            .read(&mut [0])
            .map_err(|_| PublisherIngressError::Scope)?
            != 0
        {
            return Err(PublisherIngressError::Scope);
        }
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
pub(super) fn adopt_listener() -> Result<RecordSubjectListener, PublisherIngressError> {
    validate_activation_process(1).map_err(|_| PublisherIngressError::Listener)?;
    let names = activation_names(1).map_err(|_| PublisherIngressError::Listener)?;
    if names.as_slice() != [FD_NAME] {
        return Err(PublisherIngressError::Listener);
    }
    // SAFETY: process startup owns descriptor 3 before any thread or other
    // activation consumer exists; PID 1 supplied the exact checked table.
    let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1) }
        .map_err(|_| PublisherIngressError::Listener)?
        .into_descriptors();
    let [descriptor]: [OwnedFd; 1] = descriptors
        .try_into()
        .map_err(|_| PublisherIngressError::Listener)?;
    let listener = RecordSubjectListener::from_owned(descriptor)
        .map_err(|_| PublisherIngressError::Listener)?;
    listener
        .require_local_filesystem_path(Path::new(SOCKET))
        .map_err(|_| PublisherIngressError::Listener)?;
    Ok(listener)
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
    pub(super) fn new(
        listener: RecordSubjectListener,
        scope: PublisherServiceScopeV1,
    ) -> Result<Self, PublisherIngressError> {
        let sessions = PublisherSessionRegistry::new(PublisherSessionLimits {
            maximum_sessions: 1,
        })
        .map_err(|_| PublisherIngressError::Scope)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
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

    /// Registers one queued exact service execution; never grants publication.
    pub(super) fn try_register(
        &mut self,
        controller: &mut ProductionController,
    ) -> Result<(), String> {
        if let Some(instance) = self.instance {
            if self.sessions.recheck_registered(instance).is_ok() {
                return Ok(());
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
        let policy = PublisherControlPolicy {
            clock_provenance: CLOCK_PROVENANCE,
            maximum_challenge_seconds: 60,
            policy_limits: PublisherPolicyLimits::default(),
            ingress_limits: PublisherIngressLimits::default(),
        };
        let result = controller.register_publisher_execution(
            &mut self.sessions,
            &mut self.listener,
            service,
            policy,
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
