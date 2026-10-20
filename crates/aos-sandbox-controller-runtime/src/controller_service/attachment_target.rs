//! Acquires a fresh attachment namespace target from protected controller custody.
//!
//! The Host socket is a fixed locator, not a service identity. Trusted startup
//! must provide the exact retained Host cgroup and pinned verification policy;
//! this adapter never derives either from a public request or a socket reply.

pub(super) mod startup_identity;
mod retained_source;
pub(super) use retained_source::ControllerAttachmentSourceOriginalV1;

use std::path::Path;
use std::time::Duration;

use aos_proto::aos::sandbox::v1::{Attachment, AttachmentPhase};
use aos_sandbox::Journal;
use aos_sandbox::attachment_effect_owner::{
    ProtectedAttachmentEffectOwnerV1, ProtectedAttachmentTargetErrorV1,
};
use aos_sandbox_protocol::public_api::projection::{PublicProjectionResourceV1};
use aos_sandbox::controller_service::public_projection::{PublicProjectionStoreV1};
use aos_sandbox::mount_preparation::MountServiceIdentity;
use aos_sandbox_broker::paired_clock::ProtectedOwnershipClockError;
use aos_sandbox::runtime_authority::{
    RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStateV1, RuntimeAuthorityStore,
};
use aos_sandbox::runtime_scope::{
    CurrentRuntimeScope, CurrentRuntimeScopePolicy, HostServiceIdentity, NamespaceTargetOutcome,
    RuntimeScopeClient, RuntimeScopeError, RuntimeScopeHolder,
};
use aos_sandbox_core::{AttachmentSlotId, NodeId, OperationId, ProjectId, SandboxId};
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::pidfd::PidFd;
use aos_systemd::SystemdClient;
use rustix::fs::{Mode, OFlags, open};

use super::EffectFailure;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use crate::controller_service::ownership::{
    ControllerOwnershipConfigurationV1, ControllerOwnershipCredentialErrorV1,
};
use aos_sandbox_broker_session_security::controller_composition::{CLOCK_PROVENANCE, sample_ownership_clock};
use crate::controller_service::plan_signer::{
    ControllerBrokerPlanSignerError, ControllerBrokerPlanSignerV1,
};

const HOST_SOCKET: &str = "/run/aos/sandbox-host/control.sock";
const HOST_UNIT: &str = "aos-sandbox-hostd.service";
const MOUNT_UNIT: &str = "aos-sandbox-mountd.service";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SERVICE_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Selects the admitted consumer without treating the public projection as authority.
pub(super) fn admitted_attachment(
    journal: &Journal,
    operation: OperationId,
    project: ProjectId,
    request: &DormantSandboxRequestKindV1,
) -> Result<(SandboxId, AttachmentSlotId, Attachment), EffectFailure> {
    let projections = PublicProjectionStoreV1::new(journal)
        .list_operation(operation)
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
    let [projection] = projections.as_slice() else {
        return Err(EffectFailure::Retryable(
            "admitted attachment projection is unavailable".to_owned(),
        ));
    };
    if projection.project() != project {
        return Err(EffectFailure::Permanent(
            "admitted attachment belongs to another project".to_owned(),
        ));
    }
    let PublicProjectionResourceV1::Attachment(attachment) = projection.resource() else {
        return Err(EffectFailure::Permanent(
            "attachment operation has a different projection kind".to_owned(),
        ));
    };
    let exact_request = match request {
        DormantSandboxRequestKindV1::ViewAttach(value) => {
            value.sandbox_id == attachment.sandbox_id
                && value.destination_slot_id == attachment.destination_slot_id
                && value.view_id == attachment.source_view_id
                && value.view_revision == attachment.view_revision
                && value.mutation_mode == attachment.mutation
                && attachment.phase.as_known() == Some(AttachmentPhase::ATTACHMENT_PHASE_REQUESTED)
        }
        DormantSandboxRequestKindV1::ViewReplace(value) => {
            value.attachment_id == attachment.attachment_id
                && value.new_view_id == attachment.source_view_id
                && value.new_view_revision == attachment.view_revision
                && attachment.phase.as_known() == Some(AttachmentPhase::ATTACHMENT_PHASE_REPLACING)
        }
        DormantSandboxRequestKindV1::ViewDetach(value) => {
            value.attachment_id == attachment.attachment_id
                && attachment.phase.as_known() == Some(AttachmentPhase::ATTACHMENT_PHASE_DETACHING)
        }
        _ => false,
    };
    if !exact_request {
        return Err(EffectFailure::Permanent(
            "admitted attachment projection differs from its request".to_owned(),
        ));
    }
    let sandbox: [u8; 16] = attachment.sandbox_id.as_slice().try_into().map_err(|_| {
        EffectFailure::Permanent("admitted attachment sandbox identity is invalid".to_owned())
    })?;
    let slot: [u8; 16] = attachment
        .destination_slot_id
        .as_slice()
        .try_into()
        .map_err(|_| {
            EffectFailure::Permanent("admitted destination slot identity is invalid".to_owned())
        })?;
    Ok((
        SandboxId::from_bytes(sandbox),
        AttachmentSlotId::from_bytes(slot),
        attachment.clone(),
    ))
}

/// Reports failure to pin a named root service's exact kernel cgroup.
#[derive(Debug, thiserror::Error)]
pub(super) enum ControllerServiceIdentityErrorV1 {
    #[error("systemd service observation timed out")]
    Timeout,
    #[error("systemd service identity changed or is not root-owned")]
    Changed,
    #[error(transparent)]
    Systemd(#[from] aos_systemd::Error),
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Io(#[from] rustix::io::Errno),
}

/// Reports missing or invalid protected attachment observation configuration.
#[derive(Debug, thiserror::Error)]
pub(super) enum ControllerAttachmentProvisionErrorV1 {
    #[error("protected ownership verification policy is unavailable")]
    MissingOwnership,
    #[error(transparent)]
    Ownership(#[from] ControllerOwnershipCredentialErrorV1),
    #[error(transparent)]
    BrokerPlan(#[from] ControllerBrokerPlanSignerError),
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Io(#[from] rustix::io::Errno),
}

/// Pins the exact Host service cgroup reported by PID 1 and verified by pidfd.
///
/// Neither a socket peer nor an assumed systemd slice path selects this
/// identity. Runtime observation later requires the actual Host record subject
/// to belong to this same retained cgroup.
///
/// # Errors
///
/// Rejects unavailable or changing systemd service state, an invalid cgroup
/// locator, a non-root main process, failed exact membership, or a deadline.
pub(super) async fn observe_host_service_identity()
-> Result<HostServiceIdentity, ControllerServiceIdentityErrorV1> {
    Ok(HostServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: observe_root_service_cgroup(HOST_UNIT).await?,
    })
}

/// Pins Mount's exact PID 1-selected service cgroup independently of Host.
pub(super) async fn observe_mount_service_identity()
-> Result<MountServiceIdentity, ControllerServiceIdentityErrorV1> {
    Ok(MountServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: observe_root_service_cgroup(MOUNT_UNIT).await?,
    })
}

async fn observe_root_service_cgroup(
    unit: &str,
) -> Result<RetainedCgroupAnchor, ControllerServiceIdentityErrorV1> {
    tokio::time::timeout(SERVICE_OBSERVATION_TIMEOUT, async {
        let systemd = SystemdClient::connect().await?;
        let first = systemd.observe_service_control_group(unit).await?;
        let root = CgroupV2Root::from_owned(open(
            CGROUP_ROOT,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?)?;
        let relative = first
            .control_group
            .strip_prefix('/')
            .ok_or(ControllerServiceIdentityErrorV1::Changed)?;
        let cgroup = root.resolve(Path::new(relative))?;
        let process = PidFd::open(first.main_pid)?;
        let info = cgroup.verify_exact_membership(&process)?;
        let credentials = info
            .credentials()
            .ok_or(ControllerServiceIdentityErrorV1::Changed)?;
        if info.pid() != first.main_pid.get()
            || info.thread_group_id() != first.main_pid.get()
            || credentials.real_user_id() != 0
            || credentials.effective_user_id() != 0
            || credentials.real_group_id() != 0
            || credentials.effective_group_id() != 0
        {
            return Err(ControllerServiceIdentityErrorV1::Changed);
        }
        let second = systemd.observe_service_control_group(unit).await?;
        if first != second || !process.is_alive()? {
            return Err(ControllerServiceIdentityErrorV1::Changed);
        }
        cgroup.verify_exact_membership(&process)?;
        Ok(cgroup)
    })
    .await
    .map_err(|_| ControllerServiceIdentityErrorV1::Timeout)?
}

/// Reports why a production attachment target could not be freshly established.
#[derive(Debug, thiserror::Error)]
pub(super) enum ControllerAttachmentTargetErrorV1 {
    #[error("protected sandbox has no currently bound holder")]
    MissingHolder,
    #[error(transparent)]
    Authority(#[from] RuntimeAuthorityError),
    #[error(transparent)]
    Host(#[from] RuntimeScopeError),
    #[error(transparent)]
    Target(#[from] ProtectedAttachmentTargetErrorV1),
}

/// Consumes independently pinned deployment inputs for one Host observation.
pub(super) struct ControllerAttachmentTargetInputsV1 {
    pub(super) host: HostServiceIdentity,
    pub(super) policy: CurrentRuntimeScopePolicy,
}

impl ControllerAttachmentTargetInputsV1 {
    /// Constructs one-use inputs from credentials and an already pinned Host cgroup.
    ///
    /// Credential absence never falls back to an authority copied from a
    /// journal publication, Host reply, or public request.
    ///
    /// # Errors
    ///
    /// Rejects missing or inconsistent credentials and a stale Host cgroup.
    pub(super) fn from_protected_configuration(
        host: &HostServiceIdentity,
        node: NodeId,
    ) -> Result<Self, ControllerAttachmentProvisionErrorV1> {
        Self::from_configuration_with_disposition(host, node, None)
    }

    fn from_configuration_with_disposition(
        host: &HostServiceIdentity,
        node: NodeId,
        original: Option<&mut ControllerAttachmentSourceOriginalV1>,
    ) -> Result<Self, ControllerAttachmentProvisionErrorV1> {
        use retained_source::{HeldInputV1, InputDestinationsV1};
        let mut destinations = InputDestinationsV1::new(original);
        let duplicated = rustix::io::dup(host.cgroup.as_fd());
        let cgroup = if let Some(original) = destinations.cgroup_admission.take() {
            let duplicated = match duplicated {
                Ok(fd) => fd,
                Err(cause) => return Err(cause.into()),
            };
            original.capture_once(duplicated)?;
            let (root, anchor) = original.take_completed_once()
                .ok_or(ControllerAttachmentProvisionErrorV1::MissingOwnership)?;
            if let Some(destination) = destinations.cgroup_root.take() { *destination = Some(root); }
            anchor
        } else { CgroupV2Root::from_owned(duplicated?)?.resolve(Path::new("."))? };
        let cgroup = HeldInputV1::new(cgroup, destinations.cgroup.take());
        let ownership = if let Some(attempt) = destinations.ownership_credentials.take() {
            if !attempt.capture_once(ControllerOwnershipConfigurationV1::from_process_credentials_with_source) {
                return Err(ControllerAttachmentProvisionErrorV1::MissingOwnership);
            }
            attempt.take_completed().flatten().ok_or(ControllerAttachmentProvisionErrorV1::MissingOwnership)?
        } else { ControllerOwnershipConfigurationV1::from_process_credentials_optional()?
            .ok_or(ControllerAttachmentProvisionErrorV1::MissingOwnership)? };
        let ownership = HeldInputV1::new(ownership, destinations.ownership.take());
        let broker_anchor = if let Some(attempt) = destinations.broker_credentials.take() {
            if !attempt.capture_once(|source| ControllerBrokerPlanSignerV1::trust_anchor_from_process_credentials_with_source(source).map(Some)) {
                return Err(ControllerBrokerPlanSignerError::Credential.into());
            }
            attempt.take_completed().flatten().ok_or(ControllerBrokerPlanSignerError::Credential)?
        } else { ControllerBrokerPlanSignerV1::trust_anchor_from_process_credentials()? };
        let broker_anchor = HeldInputV1::new(broker_anchor, destinations.broker_anchor.take());
        let mount_broker_anchor = if let Some(attempt) = destinations.mount_credentials.take() {
            if !attempt.capture_once(|source| ControllerBrokerPlanSignerV1::mount_trust_anchor_from_process_credentials_with_source(source).map(Some)) {
                return Err(ControllerBrokerPlanSignerError::Credential.into());
            }
            attempt.take_completed().flatten().ok_or(ControllerBrokerPlanSignerError::Credential)?
        } else { ControllerBrokerPlanSignerV1::mount_trust_anchor_from_process_credentials()? };
        let mount_broker_anchor = HeldInputV1::new(mount_broker_anchor, destinations.mount_broker_anchor.take());
        Ok(Self {
            host: HostServiceIdentity {
                uid: host.uid,
                gid: host.gid,
                cgroup: cgroup.take().ok_or(ControllerAttachmentProvisionErrorV1::MissingOwnership)?,
            },
            policy: CurrentRuntimeScopePolicy {
                node,
                clock_provenance: CLOCK_PROVENANCE,
                maximum_validity_seconds: 10,
                runtime_limits: RuntimeAuthorityLimits::default(),
                ownership_verifier: ownership.take().ok_or(ControllerAttachmentProvisionErrorV1::MissingOwnership)?.into_verifier(),
                broker_anchor: broker_anchor.take().ok_or(ControllerBrokerPlanSignerError::Credential)?,
                mount_broker_anchor: mount_broker_anchor.take().ok_or(ControllerBrokerPlanSignerError::Credential)?,
            },
        })
    }

    /// Selects the protected holder and binds a fresh signed namespace target.
    ///
    /// A returned advancement proposal still needs a signed assignment
    /// successor and another observation before any attachment effect can run.
    ///
    /// # Errors
    ///
    /// Rejects unavailable or revoked holder state, Host socket/identity
    /// failure, invalid authority, clock failure, or a changed namespace target.
    pub(super) fn acquire(
        self,
        journal: &mut Journal,
        sandbox: SandboxId,
    ) -> Result<NamespaceTargetOutcome, ControllerAttachmentTargetErrorV1> {
        let binding = RuntimeAuthorityStore::load(journal, self.policy.runtime_limits)?
            .current(sandbox)?
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        if binding.state() != RuntimeAuthorityStateV1::Bound {
            return Err(ControllerAttachmentTargetErrorV1::MissingHolder);
        }
        let holder = binding
            .holder()
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;

        let client = RuntimeScopeClient::connect(Path::new(HOST_SOCKET), self.host)?;
        let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
            .map_err(ProtectedAttachmentTargetErrorV1::from)?;
        let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
        owner
            .observe_current_target(
                RuntimeScopeHolder { sandbox, holder },
                client,
                self.policy,
                &mut clock,
            )
            .map_err(Into::into)
    }

    /// Acquires an independently authenticated Host scope for a View source owner.
    ///
    /// # Errors
    ///
    /// Rejects an unbound source holder or stale Host and protected authority.
    pub(super) fn acquire_source(
        self,
        journal: &mut Journal,
        sandbox: SandboxId,
    ) -> Result<CurrentRuntimeScope, ControllerAttachmentTargetErrorV1> {
        self.acquire_source_with_disposition(journal, sandbox, None)
    }

    fn acquire_source_with_disposition(
        self,
        journal: &mut Journal,
        sandbox: SandboxId,
        original: Option<&mut ControllerAttachmentSourceOriginalV1>,
    ) -> Result<CurrentRuntimeScope, ControllerAttachmentTargetErrorV1> {
        use retained_source::HeldInputV1;
        let (input_destination, opening, client_destination, policy_destination, acquisition) = match original {
            Some(original) => (Some(&mut original.inputs), Some(&mut original.opening),
                Some(&mut original.client), Some(&mut original.policy), Some(&mut original.acquisition)),
            None => (None, None, None, None, None),
        };
        let inputs = HeldInputV1::new(self, input_destination);
        let input = inputs.get().ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        let binding = RuntimeAuthorityStore::load(journal, input.policy.runtime_limits)?
            .current(sandbox)?
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        if binding.state() != RuntimeAuthorityStateV1::Bound {
            return Err(ControllerAttachmentTargetErrorV1::MissingHolder);
        }
        let holder = binding
            .holder()
            .ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;

        let input = inputs.take().ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        let policy = HeldInputV1::new(input.policy, policy_destination);
        let client = match opening {
            Some(original) => RuntimeScopeClient::connect_retaining_v1(Path::new(HOST_SOCKET), input.host, original),
            None => RuntimeScopeClient::connect(Path::new(HOST_SOCKET), input.host),
        }?;
        let client = HeldInputV1::new(client, client_destination);
        let mut owner = ProtectedAttachmentEffectOwnerV1::claim(journal)
            .map_err(ProtectedAttachmentTargetErrorV1::from)?;
        let mut clock = || sample_ownership_clock().map_err(|_| ProtectedOwnershipClockError);
        let holder = RuntimeScopeHolder { sandbox, holder };
        let client = client.take().ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        let policy = policy.take().ok_or(ControllerAttachmentTargetErrorV1::MissingHolder)?;
        match acquisition {
            Some(original) => owner.observe_current_source_retaining_v1(holder, client, policy, &mut clock, original),
            None => owner.observe_current_source(holder, client, policy, &mut clock),
        }.map_err(Into::into)
    }
}
