//! Version-one durable execution evidence and pure transition decisions.
//!
//! The host-state envelope stores this module's tagged records beneath each
//! request. Launch persists the Guardian and bound payload transaction through
//! complete live proof. Stop persists exact payload-before-Guardian teardown,
//! while Freeze, Thaw, and Kill use the authenticated direct-lifecycle shape.
//!
//! ```text
//! { "kind": "guardian_launch", "state": { "evidence": ..., "phase": ... } }
//! { "kind": "composite_stop", "state": { "target": ..., "phase": ... } }
//! ```
//!
//! A decision that contains an effect also contains the state which must be
//! committed before that effect. Recovered active state is never promoted to a
//! readiness proof: a Guardian becomes ready only from the current fixed
//! `Type=notify` start job followed by an exact active/running observation.
//! Payload completion additionally requires fresh pidfd, cgroup, mount, and
//! namespace proofs. Stop completion requires manager and cgroup absence after
//! the exact unit reference is released.

use std::os::fd::BorrowedFd;

use aos_sandbox_broker::{
    ProtectedBrokerPublicCredentialRole, ProtectedBrokerPublicCredentialSnapshot,
};
use aos_systemd::GuardianExecutableSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const BINDING_DOMAIN: &[u8] = b"aos.host.guardian-launch-binding.v1\0";
const EXECUTION_AUTHENTICATION_DOMAIN: &[u8] = b"aos.host.execution-authentication.v1\0";
const EXECUTION_AUTHENTICATION_VERSION: u16 = 1;
const MAXIMUM_POLICY_BYTES: u64 = 64 * 1024;
const MAXIMUM_PLAN_BYTES: usize = 256 * 1024;
const MAXIMUM_LEASE_BYTES: usize = 64 * 1024;
const MAXIMUM_SIGNATURE_BYTES: usize = 64 * 1024;
const MAXIMUM_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// Closed host action retained in durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostAction {
    Launch,
    Stop,
    Freeze,
    Thaw,
    Kill,
    ApplyExecution,
    QueryExecution,
    ReserveExecutionOutput,
    QueryExecutionOutput,
    ObserveExecutionArgument,
    QueryExecutionArgument,
    InstallAttachGate,
}

impl HostAction {
    /// Whether this action uses the shared execution-handoff fence.
    pub(crate) const fn is_execution_handoff(self) -> bool {
        matches!(
            self,
            Self::ApplyExecution
                | Self::QueryExecution
                | Self::InstallAttachGate
                | Self::ReserveExecutionOutput
                | Self::QueryExecutionOutput
                | Self::ObserveExecutionArgument
                | Self::QueryExecutionArgument
        )
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Launch),
            2 => Some(Self::Stop),
            3 => Some(Self::Freeze),
            4 => Some(Self::Thaw),
            5 => Some(Self::Kill),
            6 => Some(Self::ApplyExecution),
            7 => Some(Self::QueryExecution),
            8 => Some(Self::InstallAttachGate),
            9 => Some(Self::ReserveExecutionOutput),
            10 => Some(Self::QueryExecutionOutput),
            11 => Some(Self::ObserveExecutionArgument),
            12 => Some(Self::QueryExecutionArgument),
            _ => None,
        }
    }

    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Launch => 1,
            Self::Stop => 2,
            Self::Freeze => 3,
            Self::Thaw => 4,
            Self::Kill => 5,
            Self::ApplyExecution => 6,
            Self::QueryExecution => 7,
            Self::InstallAttachGate => 8,
            Self::ReserveExecutionOutput => 9,
            Self::QueryExecutionOutput => 10,
            Self::ObserveExecutionArgument => 11,
            Self::QueryExecutionArgument => 12,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "state",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum DurableExecution {
    DirectLifecycle,
    GuardianLaunch(Box<GuardianLaunchRecord>),
    CompositeStop(CompositeStopRecord),
    HostExecutionHandoff(HostExecutionHandoffRecord),
}

/// Retains the protected runtime and stable operation bound to a Host grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostExecutionHandoffRecord {
    pub(crate) runtime_witness_request_id: [u8; 16],
    pub(crate) runtime_handle: [u8; 32],
    // Host pins the verified request identity; Controller owns full transcript replay.
    pub(crate) session_binding: [u8; 32],
    pub(crate) signed_request_digest: [u8; 32],
    pub(crate) operation_id: [u8; 16],
    pub(crate) execution_id: [u8; 16],
    pub(crate) source_commitment: [u8; 32],
    pub(crate) semantic_commitment: [u8; 32],
}

impl DurableExecution {
    /// Creates the execution kind for an authenticated direct lifecycle action.
    pub(crate) const fn direct_lifecycle(action: HostAction) -> Option<Self> {
        match action {
            HostAction::Freeze | HostAction::Thaw | HostAction::Kill => Some(Self::DirectLifecycle),
            HostAction::Launch
            | HostAction::Stop
            | HostAction::ApplyExecution
            | HostAction::QueryExecution
            | HostAction::InstallAttachGate => None,
            HostAction::ReserveExecutionOutput
            | HostAction::QueryExecutionOutput
            | HostAction::ObserveExecutionArgument
            | HostAction::QueryExecutionArgument => None,
        }
    }

    pub(crate) fn validate(&self, context: ExecutionContext) -> bool {
        match self {
            Self::DirectLifecycle => matches!(
                context.action,
                HostAction::Freeze | HostAction::Thaw | HostAction::Kill
            ),
            Self::GuardianLaunch(record) => {
                context.action == HostAction::Launch && record.validate(context)
            }
            Self::CompositeStop(record) => {
                context.action == HostAction::Stop && record.validate(context.receipt_present)
            }
            Self::HostExecutionHandoff(record) => {
                context.action.is_execution_handoff()
                    && record.runtime_witness_request_id != [0; 16]
                    && record.runtime_handle != [0; 32]
                    && record.session_binding != [0; 32]
                    && record.signed_request_digest != [0; 32]
                    && record.operation_id != [0; 16]
                    && record.execution_id != [0; 16]
                    && record.source_commitment != [0; 32]
                    && record.semantic_commitment != [0; 32]
            }
        }
    }

    /// Commits one execution record to its request and stable authority.
    ///
    /// The framed input excludes refreshed outer admission records, effect
    /// status, and receipt. A Guardian execution still binds its exact
    /// historical attempt lease evidence inside `self`; current outer lease
    /// records remain independently authenticated and cross-checked during
    /// state recovery.
    pub(crate) fn authentication_digest(
        &self,
        context: ExecutionContext,
        stable_authority_digest: [u8; 32],
    ) -> Option<[u8; 32]> {
        let execution = serde_json::to_vec(self).ok()?;
        let mut hash = Sha256::new();
        hash.update(EXECUTION_AUTHENTICATION_DOMAIN);
        update_authentication_field(
            &mut hash,
            1,
            &EXECUTION_AUTHENTICATION_VERSION.to_be_bytes(),
        )?;
        update_authentication_field(&mut hash, 2, &context.request_id)?;
        update_authentication_field(&mut hash, 3, &context.request_digest)?;
        update_authentication_field(&mut hash, 4, &[context.action.code()])?;
        update_authentication_field(&mut hash, 5, &context.sandbox_id)?;
        update_authentication_field(&mut hash, 6, &context.incarnation_id)?;
        update_authentication_field(&mut hash, 7, &context.assignment_epoch.to_be_bytes())?;
        update_authentication_field(&mut hash, 8, &context.desired_generation.to_be_bytes())?;
        update_authentication_field(&mut hash, 9, &context.assignment_digest)?;
        update_authentication_field(&mut hash, 10, &stable_authority_digest)?;
        update_authentication_field(&mut hash, 11, &execution)?;
        Some(hash.finalize().into())
    }

    pub(crate) fn guardian_binding(&self) -> Option<[u8; 32]> {
        match self {
            Self::GuardianLaunch(record) => Some(record.evidence.binding),
            Self::DirectLifecycle | Self::CompositeStop(_) | Self::HostExecutionHandoff(_) => None,
        }
    }

    pub(crate) fn stop_source(&self) -> Option<StopSourceReference> {
        match self {
            Self::CompositeStop(record) => record.target.source(),
            Self::DirectLifecycle | Self::GuardianLaunch(_) | Self::HostExecutionHandoff(_) => None,
        }
    }

    pub(crate) fn composite_stop(
        context: ExecutionContext,
        target: CompositeStopTarget,
    ) -> Option<Self> {
        let execution = Self::CompositeStop(CompositeStopRecord {
            target,
            phase: CompositeStopPhase::StopAuthorized,
        });
        execution.validate(context).then_some(execution)
    }

    pub(crate) fn composite_stop_record(&self) -> Option<&CompositeStopRecord> {
        let Self::CompositeStop(record) = self else {
            return None;
        };
        Some(record)
    }

    pub(crate) fn set_composite_stop_phase(&mut self, phase: CompositeStopPhase) -> bool {
        let Self::CompositeStop(record) = self else {
            return false;
        };
        if !phase.validate(&record.target) {
            return false;
        }
        record.phase = phase;
        true
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the durable evidence binds one complete closed Guardian attempt"
    )]
    pub(crate) fn guardian_launch(
        context: ExecutionContext,
        launch_body_digest: [u8; 32],
        node_id: [u8; 16],
        host_boot_id: [u8; 16],
        lease_generation: u64,
        lease_digest: [u8; 32],
        broker_plan: &[u8],
        broker_plan_signature: &[u8],
        ownership_lease: &[u8],
        ownership_lease_signature: &[u8],
        protected_inputs: [ProtectedInputSnapshot; 6],
        executable: GuardianExecutableSnapshot,
        payload: PayloadLaunchSnapshot,
    ) -> Option<Self> {
        let mut evidence = GuardianLaunchEvidence {
            attempt: 1,
            request_id: context.request_id,
            request_digest: context.request_digest,
            launch_body_digest,
            sandbox_id: context.sandbox_id,
            incarnation_id: context.incarnation_id,
            assignment_epoch: context.assignment_epoch,
            desired_generation: context.desired_generation,
            assignment_digest: context.assignment_digest,
            node_id,
            host_boot_id,
            lease_generation,
            lease_digest,
            broker_plan: broker_plan.to_vec(),
            broker_plan_signature: broker_plan_signature.to_vec(),
            ownership_lease: ownership_lease.to_vec(),
            ownership_lease_signature: ownership_lease_signature.to_vec(),
            protected_inputs,
            guardian_executable: PinnedExecutableIdentity::from(executable),
            payload,
            binding: [0; 32],
        };
        evidence.binding = evidence.recompute_binding();
        let execution = Self::GuardianLaunch(Box::new(GuardianLaunchRecord {
            evidence,
            phase: GuardianLaunchPhase::Authorized,
        }));
        execution.validate(context).then_some(execution)
    }

    pub(crate) fn guardian_attempt(&self) -> Option<GuardianAttempt<'_>> {
        let Self::GuardianLaunch(record) = self else {
            return None;
        };
        Some(GuardianAttempt {
            binding: record.evidence.binding,
            broker_plan: &record.evidence.broker_plan,
            broker_plan_signature: &record.evidence.broker_plan_signature,
            ownership_lease: &record.evidence.ownership_lease,
            ownership_lease_signature: &record.evidence.ownership_lease_signature,
            agent_required: record.evidence.payload.agent_required,
            phase: &record.phase,
        })
    }

    pub(crate) fn guardian_completed_invocations(&self) -> Option<([u8; 16], [u8; 16])> {
        let Self::GuardianLaunch(record) = self else {
            return None;
        };
        match record.phase {
            GuardianLaunchPhase::Complete {
                guardian_invocation,
                payload_invocation,
                ..
            } => Some((guardian_invocation, payload_invocation)),
            _ => None,
        }
    }

    pub(crate) fn guardian_runtime_inputs_match(
        &self,
        protected_inputs: &[ProtectedInputSnapshot; 6],
        executable: GuardianExecutableSnapshot,
        payload: &PayloadLaunchSnapshot,
    ) -> bool {
        let Self::GuardianLaunch(record) = self else {
            return false;
        };
        record.evidence.protected_inputs == *protected_inputs
            && record.evidence.guardian_executable == PinnedExecutableIdentity::from(executable)
            && record.evidence.payload == *payload
    }

    pub(crate) fn set_guardian_phase(&mut self, phase: GuardianLaunchPhase) -> bool {
        let Self::GuardianLaunch(record) = self else {
            return false;
        };
        if !phase.validate(record.evidence.binding) {
            return false;
        }
        record.phase = phase;
        true
    }

    #[cfg(test)]
    pub(crate) fn guardian_fixture(context: ExecutionContext) -> Self {
        let mut evidence = GuardianLaunchEvidence {
            attempt: 1,
            request_id: context.request_id,
            request_digest: context.request_digest,
            launch_body_digest: [8; 32],
            sandbox_id: context.sandbox_id,
            incarnation_id: context.incarnation_id,
            assignment_epoch: context.assignment_epoch,
            desired_generation: context.desired_generation,
            assignment_digest: context.assignment_digest,
            node_id: [9; 16],
            host_boot_id: [10; 16],
            lease_generation: 11,
            lease_digest: [12; 32],
            broker_plan: vec![13],
            broker_plan_signature: vec![14],
            ownership_lease: vec![15],
            ownership_lease_signature: vec![16],
            protected_inputs: std::array::from_fn(|role| ProtectedInputSnapshot {
                role: u8::try_from(role).unwrap_or(u8::MAX),
                device: 17,
                inode: 18 + u64::try_from(role).unwrap_or(u64::MAX),
                bytes: 1,
                sha256: [19 + u8::try_from(role).unwrap_or(0); 32],
            }),
            guardian_executable: PinnedExecutableIdentity {
                device: 25,
                inode: 26,
                bytes: 27,
                uid: 0,
                mode: 0o100555,
                modified_seconds: 28,
                modified_nanoseconds: 29,
                changed_seconds: 30,
                changed_nanoseconds: 31,
                sha256_content: [32; 32],
            },
            payload: PayloadLaunchSnapshot::fixture(),
            binding: [0; 32],
        };
        evidence.binding = evidence.recompute_binding();

        Self::GuardianLaunch(Box::new(GuardianLaunchRecord {
            evidence,
            phase: GuardianLaunchPhase::Authorized,
        }))
    }

    #[cfg(test)]
    pub(crate) fn composite_stop_fixture() -> Self {
        Self::CompositeStop(CompositeStopRecord {
            target: CompositeStopTarget::Absent,
            phase: CompositeStopPhase::StopAuthorized,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct GuardianAttempt<'a> {
    pub(crate) binding: [u8; 32],
    pub(crate) broker_plan: &'a [u8],
    pub(crate) broker_plan_signature: &'a [u8],
    pub(crate) ownership_lease: &'a [u8],
    pub(crate) ownership_lease_signature: &'a [u8],
    pub(crate) agent_required: bool,
    pub(crate) phase: &'a GuardianLaunchPhase,
}

fn update_authentication_field(hash: &mut Sha256, tag: u16, value: &[u8]) -> Option<()> {
    let length = u64::try_from(value.len()).ok()?;
    hash.update(tag.to_be_bytes());
    hash.update(length.to_be_bytes());
    hash.update(value);
    Some(())
}

#[derive(Clone, Copy)]
pub(crate) struct ExecutionContext {
    pub(crate) action: HostAction,
    pub(crate) request_id: [u8; 16],
    pub(crate) request_digest: [u8; 32],
    pub(crate) sandbox_id: [u8; 16],
    pub(crate) incarnation_id: [u8; 16],
    pub(crate) assignment_epoch: u64,
    pub(crate) desired_generation: u64,
    pub(crate) assignment_digest: [u8; 32],
    pub(crate) receipt_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardianLaunchRecord {
    pub(crate) evidence: GuardianLaunchEvidence,
    pub(crate) phase: GuardianLaunchPhase,
}

impl GuardianLaunchRecord {
    fn validate(&self, context: ExecutionContext) -> bool {
        self.evidence.validate(context)
            && self.phase.validate(self.evidence.binding)
            && matches!(
                self.phase,
                GuardianLaunchPhase::Compensated { .. } | GuardianLaunchPhase::Complete { .. }
            ) == context.receipt_present
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardianLaunchEvidence {
    attempt: u32,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    launch_body_digest: [u8; 32],
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    node_id: [u8; 16],
    host_boot_id: [u8; 16],
    lease_generation: u64,
    lease_digest: [u8; 32],
    broker_plan: Vec<u8>,
    broker_plan_signature: Vec<u8>,
    ownership_lease: Vec<u8>,
    ownership_lease_signature: Vec<u8>,
    protected_inputs: [ProtectedInputSnapshot; 6],
    guardian_executable: PinnedExecutableIdentity,
    payload: PayloadLaunchSnapshot,
    binding: [u8; 32],
}

impl GuardianLaunchEvidence {
    fn validate(&self, context: ExecutionContext) -> bool {
        self.attempt != 0
            && self.request_id == context.request_id
            && self.request_digest == context.request_digest
            && self.launch_body_digest != [0; 32]
            && self.sandbox_id == context.sandbox_id
            && self.incarnation_id == context.incarnation_id
            && self.assignment_epoch == context.assignment_epoch
            && self.desired_generation == context.desired_generation
            && self.assignment_digest == context.assignment_digest
            && self.node_id != [0; 16]
            && self.host_boot_id != [0; 16]
            && self.lease_generation != 0
            && self.lease_digest != [0; 32]
            && bounded(&self.broker_plan, MAXIMUM_PLAN_BYTES)
            && bounded(&self.broker_plan_signature, MAXIMUM_SIGNATURE_BYTES)
            && bounded(&self.ownership_lease, MAXIMUM_LEASE_BYTES)
            && bounded(&self.ownership_lease_signature, MAXIMUM_SIGNATURE_BYTES)
            && self
                .protected_inputs
                .iter()
                .enumerate()
                .all(|(role, input)| input.validate(role))
            && self.guardian_executable.validate()
            && self.payload.validate()
            && self.binding != [0; 32]
            && self.binding == self.recompute_binding()
    }

    fn recompute_binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(BINDING_DOMAIN);
        hash.update(self.attempt.to_be_bytes());
        hash.update(self.request_id);
        hash.update(self.request_digest);
        hash.update(self.launch_body_digest);
        hash.update(self.sandbox_id);
        hash.update(self.incarnation_id);
        hash.update(self.assignment_epoch.to_be_bytes());
        hash.update(self.desired_generation.to_be_bytes());
        hash.update(self.assignment_digest);
        hash.update(self.node_id);
        hash.update(self.host_boot_id);
        hash.update(self.lease_generation.to_be_bytes());
        hash.update(self.lease_digest);
        update_bounded_bytes(&mut hash, &self.broker_plan);
        update_bounded_bytes(&mut hash, &self.broker_plan_signature);
        update_bounded_bytes(&mut hash, &self.ownership_lease);
        update_bounded_bytes(&mut hash, &self.ownership_lease_signature);
        for input in &self.protected_inputs {
            input.update_binding(&mut hash);
        }
        self.guardian_executable.update_binding(&mut hash);
        self.payload.update_binding(&mut hash);
        hash.finalize().into()
    }
}

/// Captures the exact resolved payload resources and closed unit semantics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PayloadLaunchSnapshot {
    pub(crate) nspawn: PinnedObjectSnapshot,
    pub(crate) workspace: PinnedObjectSnapshot,
    pub(crate) network_device: u64,
    pub(crate) network_inode: u64,
    pub(crate) identity_range_start: u32,
    pub(crate) identity_range_size: u32,
    pub(crate) identity_catalog_generation: u64,
    pub(crate) attachment_anchor: PinnedObjectSnapshot,
    pub(crate) spec_semantic_digest: [u8; 32],
    #[serde(default)]
    pub(crate) agent_required: bool,
}

impl PayloadLaunchSnapshot {
    fn validate(&self) -> bool {
        self.nspawn.validate()
            && self.workspace.validate()
            && self.network_device != 0
            && self.network_inode != 0
            && self.identity_range_start != 0
            && self.identity_range_size >= 65_536
            && self
                .identity_range_start
                .checked_add(self.identity_range_size)
                .is_some()
            && self.identity_catalog_generation != 0
            && self.attachment_anchor.validate()
            && self.spec_semantic_digest != [0; 32]
    }

    fn update_binding(&self, hash: &mut Sha256) {
        self.nspawn.update_binding(hash);
        self.workspace.update_binding(hash);
        hash.update(self.network_device.to_be_bytes());
        hash.update(self.network_inode.to_be_bytes());
        hash.update(self.identity_range_start.to_be_bytes());
        hash.update(self.identity_range_size.to_be_bytes());
        hash.update(self.identity_catalog_generation.to_be_bytes());
        self.attachment_anchor.update_binding(hash);
        hash.update(self.spec_semantic_digest);
        // Legacy snapshots have no agent marker. Preserve their historical
        // binding while authenticating the stronger new launch contract.
        if self.agent_required {
            hash.update(b"aos.host.payload-agent-required.v1\0");
        }
    }

    #[cfg(test)]
    fn fixture() -> Self {
        Self {
            nspawn: PinnedObjectSnapshot {
                device: 33,
                inode: 34,
                mount_id: 35,
            },
            workspace: PinnedObjectSnapshot {
                device: 36,
                inode: 37,
                mount_id: 38,
            },
            network_device: 39,
            network_inode: 40,
            identity_range_start: 65_536,
            identity_range_size: 65_536,
            identity_catalog_generation: 41,
            attachment_anchor: PinnedObjectSnapshot {
                device: 42,
                inode: 43,
                mount_id: 44,
            },
            spec_semantic_digest: [45; 32],
            agent_required: false,
        }
    }
}

/// Names one descriptor-backed object and its kernel-unique mount instance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedObjectSnapshot {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mount_id: u64,
}

impl PinnedObjectSnapshot {
    fn validate(&self) -> bool {
        self.device != 0 && self.inode != 0 && self.mount_id != 0 && self.mount_id != u64::MAX
    }

    fn update_binding(&self, hash: &mut Sha256) {
        hash.update(self.device.to_be_bytes());
        hash.update(self.inode.to_be_bytes());
        hash.update(self.mount_id.to_be_bytes());
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedInputSnapshot {
    role: u8,
    device: u64,
    inode: u64,
    bytes: u64,
    sha256: [u8; 32],
}

impl ProtectedInputSnapshot {
    fn from_protected_credential(
        role: ProtectedBrokerPublicCredentialRole,
        snapshot: ProtectedBrokerPublicCredentialSnapshot,
    ) -> Option<Self> {
        let role = match role {
            ProtectedBrokerPublicCredentialRole::BrokerPlanPolicy => 0,
            ProtectedBrokerPublicCredentialRole::BrokerPlanPublicKey => 1,
            ProtectedBrokerPublicCredentialRole::BrokerPlanRevocationScope => 2,
            ProtectedBrokerPublicCredentialRole::OwnershipLeasePolicy => 3,
            ProtectedBrokerPublicCredentialRole::OwnershipLeasePublicKey => 4,
            ProtectedBrokerPublicCredentialRole::NodeId => 5,
        };
        Some(Self {
            role,
            device: snapshot.device(),
            inode: snapshot.inode(),
            bytes: u64::try_from(snapshot.bytes()).ok()?,
            sha256: snapshot.sha256(),
        })
    }

    fn validate(&self, role: usize) -> bool {
        let maximum = match role {
            0 | 3 => MAXIMUM_POLICY_BYTES,
            1 | 4 => 32,
            2 | 5 => 16,
            _ => return false,
        };
        self.role == u8::try_from(role).ok().unwrap_or(u8::MAX)
            && self.device != 0
            && self.inode != 0
            && (1..=maximum).contains(&self.bytes)
            && self.sha256 != [0; 32]
    }

    fn update_binding(&self, hash: &mut Sha256) {
        hash.update([self.role]);
        hash.update(self.device.to_be_bytes());
        hash.update(self.inode.to_be_bytes());
        hash.update(self.bytes.to_be_bytes());
        hash.update(self.sha256);
    }
}

/// Converts one all-at-once custody result into the durable Guardian order.
pub(crate) fn protected_input_snapshots(
    credentials: &[(
        ProtectedBrokerPublicCredentialRole,
        BorrowedFd<'_>,
        ProtectedBrokerPublicCredentialSnapshot,
    ); 6],
) -> Option<[ProtectedInputSnapshot; 6]> {
    let snapshots = credentials
        .iter()
        .enumerate()
        .map(|(index, (role, _, snapshot))| {
            (*role == ProtectedBrokerPublicCredentialRole::ALL[index])
                .then(|| ProtectedInputSnapshot::from_protected_credential(*role, *snapshot))
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    snapshots.try_into().ok()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedExecutableIdentity {
    device: u64,
    inode: u64,
    bytes: u64,
    uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    sha256_content: [u8; 32],
}

impl PinnedExecutableIdentity {
    fn validate(&self) -> bool {
        self.device != 0
            && self.inode != 0
            && (1..=MAXIMUM_EXECUTABLE_BYTES).contains(&self.bytes)
            && self.uid == 0
            && self.mode & 0o170000 == 0o100000
            && self.mode & 0o111 != 0
            && self.mode & 0o022 == 0
            && (0..NANOS_PER_SECOND).contains(&self.modified_nanoseconds)
            && (0..NANOS_PER_SECOND).contains(&self.changed_nanoseconds)
            && self.sha256_content != [0; 32]
    }

    fn update_binding(&self, hash: &mut Sha256) {
        hash.update(self.device.to_be_bytes());
        hash.update(self.inode.to_be_bytes());
        hash.update(self.bytes.to_be_bytes());
        hash.update(self.uid.to_be_bytes());
        hash.update(self.mode.to_be_bytes());
        hash.update(self.modified_seconds.to_be_bytes());
        hash.update(self.modified_nanoseconds.to_be_bytes());
        hash.update(self.changed_seconds.to_be_bytes());
        hash.update(self.changed_nanoseconds.to_be_bytes());
        hash.update(self.sha256_content);
    }
}

impl From<GuardianExecutableSnapshot> for PinnedExecutableIdentity {
    fn from(snapshot: GuardianExecutableSnapshot) -> Self {
        Self {
            device: snapshot.device,
            inode: snapshot.inode,
            bytes: snapshot.bytes,
            uid: snapshot.uid,
            mode: snapshot.mode,
            modified_seconds: snapshot.modified_seconds,
            modified_nanoseconds: snapshot.modified_nanoseconds,
            changed_seconds: snapshot.changed_seconds,
            changed_nanoseconds: snapshot.changed_nanoseconds,
            sha256_content: snapshot.sha256_content,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GuardianLaunchPhase {
    Authorized,
    GuardianStartIssued,
    GuardianReady {
        guardian_invocation: [u8; 16],
    },
    PayloadStartIssued {
        guardian_invocation: [u8; 16],
    },
    PayloadVerified {
        guardian_invocation: [u8; 16],
        payload_invocation: [u8; 16],
        observation_sequence: u64,
        worker_proof: RuntimeProofSnapshot,
    },
    CleanupIssued {
        payload: ExactUnitTarget,
        guardian: ExactUnitTarget,
        progress: CleanupProgress,
    },
    Compensated {
        observation_sequence: u64,
    },
    Complete {
        guardian_invocation: [u8; 16],
        payload_invocation: [u8; 16],
        observation_sequence: u64,
        worker_proof: RuntimeProofSnapshot,
    },
}

impl GuardianLaunchPhase {
    fn validate(&self, binding: [u8; 32]) -> bool {
        match self {
            Self::Authorized | Self::GuardianStartIssued => true,
            Self::Compensated {
                observation_sequence,
            } => *observation_sequence != 0,
            Self::GuardianReady {
                guardian_invocation,
            }
            | Self::PayloadStartIssued {
                guardian_invocation,
            } => *guardian_invocation != [0; 16],
            Self::PayloadVerified {
                guardian_invocation,
                payload_invocation,
                observation_sequence,
                worker_proof,
            }
            | Self::Complete {
                guardian_invocation,
                payload_invocation,
                observation_sequence,
                worker_proof,
            } => {
                *guardian_invocation != [0; 16]
                    && *payload_invocation != [0; 16]
                    && guardian_invocation != payload_invocation
                    && *observation_sequence != 0
                    && worker_proof.validate()
            }
            Self::CleanupIssued {
                payload,
                guardian,
                progress,
            } => {
                payload.validate(binding)
                    && guardian.validate(binding)
                    && match progress {
                        CleanupProgress::PayloadPending => payload.is_exact(),
                        CleanupProgress::GuardianPending => guardian.is_exact(),
                        CleanupProgress::PayloadAwaitingAbsence => payload.is_exact(),
                        CleanupProgress::GuardianAwaitingAbsence => guardian.is_exact(),
                    }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CleanupProgress {
    PayloadPending,
    GuardianPending,
    PayloadAwaitingAbsence,
    GuardianAwaitingAbsence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExactUnitTarget {
    Absent,
    Exact {
        binding: [u8; 32],
        invocation: [u8; 16],
    },
}

impl ExactUnitTarget {
    fn validate(&self, expected_binding: [u8; 32]) -> bool {
        match self {
            Self::Absent => true,
            Self::Exact {
                binding,
                invocation,
            } => *binding == expected_binding && *invocation != [0; 16],
        }
    }

    fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompositeStopRecord {
    pub(crate) target: CompositeStopTarget,
    pub(crate) phase: CompositeStopPhase,
}

impl CompositeStopRecord {
    fn validate(&self, receipt_present: bool) -> bool {
        self.target.validate()
            && self.phase.validate(&self.target)
            && matches!(self.phase, CompositeStopPhase::Complete { .. }) == receipt_present
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "shape", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CompositeStopTarget {
    Absent,
    GuardianComposite {
        source_launch_request_id: [u8; 16],
        incarnation_id: [u8; 16],
        launch_binding: [u8; 32],
        payload: StopUnitTarget,
        guardian: StopUnitTarget,
    },
}

impl CompositeStopTarget {
    fn validate(&self) -> bool {
        match self {
            Self::Absent => true,
            Self::GuardianComposite {
                source_launch_request_id,
                incarnation_id,
                launch_binding,
                payload,
                guardian,
            } => {
                *source_launch_request_id != [0; 16]
                    && *incarnation_id != [0; 16]
                    && *launch_binding != [0; 32]
                    && payload.validate(Some(*launch_binding))
                    && guardian.validate(Some(*launch_binding))
                    && (payload.is_exact() || guardian.is_exact())
            }
        }
    }

    fn source(&self) -> Option<StopSourceReference> {
        match self {
            Self::Absent => None,
            Self::GuardianComposite {
                source_launch_request_id,
                incarnation_id,
                launch_binding,
                ..
            } => Some(StopSourceReference {
                request_id: *source_launch_request_id,
                incarnation_id: *incarnation_id,
                guardian_binding: Some(*launch_binding),
            }),
        }
    }

    pub(crate) fn payload(&self) -> StopUnitTarget {
        match self {
            Self::Absent => StopUnitTarget::Absent,
            Self::GuardianComposite { payload, .. } => payload.clone(),
        }
    }

    pub(crate) fn guardian(&self) -> StopUnitTarget {
        match self {
            Self::GuardianComposite { guardian, .. } => guardian.clone(),
            Self::Absent => StopUnitTarget::Absent,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopSourceReference {
    pub(crate) request_id: [u8; 16],
    pub(crate) incarnation_id: [u8; 16],
    pub(crate) guardian_binding: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StopUnitTarget {
    Absent,
    Exact {
        binding: Option<[u8; 32]>,
        invocation: [u8; 16],
    },
}

impl StopUnitTarget {
    fn validate(&self, expected_binding: Option<[u8; 32]>) -> bool {
        match self {
            Self::Absent => true,
            Self::Exact {
                binding,
                invocation,
            } => *invocation != [0; 16] && *binding == expected_binding,
        }
    }

    pub(crate) fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }

    pub(crate) const fn exact_identity(&self) -> Option<(Option<[u8; 32]>, [u8; 16])> {
        match self {
            Self::Absent => None,
            Self::Exact {
                binding,
                invocation,
            } => Some((*binding, *invocation)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CompositeStopPhase {
    StopAuthorized,
    // This authenticated durable transition is the authority linearization
    // point. Retries may finish only the saved exact-target containment effect
    // after lease expiry; they cannot select a new binding or invocation.
    StopEffectIssued { progress: StopProgress },
    Complete { observation_sequence: u64 },
}

impl CompositeStopPhase {
    fn validate(&self, target: &CompositeStopTarget) -> bool {
        match self {
            Self::StopAuthorized => true,
            Self::StopEffectIssued { progress } => match progress {
                StopProgress::PayloadPending => target.payload().is_exact(),
                StopProgress::GuardianPending => target.guardian().is_exact(),
                StopProgress::PayloadAwaitingAbsence => target.payload().is_exact(),
                StopProgress::GuardianAwaitingAbsence => target.guardian().is_exact(),
            },
            Self::Complete {
                observation_sequence,
            } => *observation_sequence != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StopProgress {
    PayloadPending,
    GuardianPending,
    PayloadAwaitingAbsence,
    GuardianAwaitingAbsence,
}

fn bounded(bytes: &[u8], maximum: usize) -> bool {
    !bytes.is_empty() && bytes.len() <= maximum
}

fn update_bounded_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
}

/// Reports whether the current signed authority still permits a forward effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityFreshness {
    Fresh,
    Expired,
}

/// Records ephemeral completion evidence for the currently awaited start job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartJobEvidence {
    None,
    DoneForCurrentSubmission,
    RecoveredExactProof,
    FailedForCurrentSubmission,
}

/// Separates live, transitional, and terminal states without equating them to absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PresentUnitState {
    ActiveRunning,
    Activating,
    TerminalInactive,
    TerminalFailed,
    Other,
}

/// Carries one typed unit observation including its immutable local binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnitObservation {
    Absent,
    Present {
        binding: Option<[u8; 32]>,
        invocation: [u8; 16],
        state: PresentUnitState,
    },
    Indeterminate,
}

/// Stores the post-start worker proof needed before durable completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerProof {
    pub(crate) observation_sequence: u64,
    pub(crate) runtime: RuntimeProofSnapshot,
}

/// Persists the complete fresh kernel proof accepted for one payload start.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeProofSnapshot {
    pub(crate) host_boot_id: [u8; 16],
    pub(crate) supervisor: ProcessProofSnapshot,
    pub(crate) payload: ProcessProofSnapshot,
    pub(crate) supervisor_cgroup_id: u64,
    pub(crate) payload_cgroup_id: u64,
    pub(crate) workspace_mount_id: u64,
    pub(crate) payload_root_mount_id: u64,
    pub(crate) network_namespace: NamespaceProofSnapshot,
    pub(crate) mount_namespace: NamespaceProofSnapshot,
    pub(crate) user_namespace: NamespaceProofSnapshot,
}

impl RuntimeProofSnapshot {
    pub(crate) fn validate(&self) -> bool {
        self.host_boot_id != [0; 16]
            && self.supervisor.validate()
            && self.payload.validate()
            && self.supervisor.pid != self.payload.pid
            && self.payload.parent_pid == self.supervisor.pid
            && self.supervisor_cgroup_id != 0
            && self.payload_cgroup_id != 0
            && self.supervisor.cgroup_id == self.supervisor_cgroup_id
            && self.payload.cgroup_id == self.payload_cgroup_id
            && self.workspace_mount_id != 0
            && self.payload_root_mount_id != 0
            && self.network_namespace.validate()
            && self.mount_namespace.validate()
            && self.user_namespace.validate()
    }
}

/// Captures PIDFD_GET_INFO plus `/proc/PID/stat` field 22 for one live pidfd.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessProofSnapshot {
    pub(crate) pid: u32,
    pub(crate) thread_group_id: u32,
    pub(crate) parent_pid: u32,
    pub(crate) cgroup_id: u64,
    pub(crate) start_time_ticks: u64,
}

impl ProcessProofSnapshot {
    fn validate(&self) -> bool {
        self.pid != 0 && self.thread_group_id == self.pid && self.cgroup_id != 0
    }
}

/// Captures one type-checked namespace descriptor identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceProofSnapshot {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl NamespaceProofSnapshot {
    fn validate(&self) -> bool {
        self.device != 0 && self.inode != 0
    }
}

/// Names the only future side effects returned by the pure reducers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PlannedEffect {
    StartGuardian,
    StartPayload,
    StopPayload(StopUnitTarget),
    StopGuardian(StopUnitTarget),
}

/// Explains a fail-closed pure decision without authorizing an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecisionRejection {
    AuthorityExpired,
    InconsistentEvidence,
}

/// Requires every new effect to follow a durable state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GuardianDecision {
    Persist(GuardianLaunchPhase),
    PersistThen {
        phase: GuardianLaunchPhase,
        effect: PlannedEffect,
    },
    RetryIssued(PlannedEffect),
    ObserveAgain,
    HistoricalComplete,
    Compensated,
    Reject(DecisionRejection),
    Quarantine,
}

/// Supplies observation-only inputs to the Guardian launch reducer.
#[derive(Clone, Copy)]
pub(crate) struct GuardianDecisionInput<'a> {
    pub(crate) binding: [u8; 32],
    pub(crate) phase: &'a GuardianLaunchPhase,
    pub(crate) freshness: AuthorityFreshness,
    pub(crate) guardian_job: StartJobEvidence,
    pub(crate) payload_job: StartJobEvidence,
    pub(crate) guardian: UnitObservation,
    pub(crate) payload: UnitObservation,
    pub(crate) worker_proof: Option<WorkerProof>,
}

/// Applies the Guardian launch table without performing I/O or mutation.
pub(crate) fn decide_guardian_launch(input: GuardianDecisionInput<'_>) -> GuardianDecision {
    match input.phase {
        GuardianLaunchPhase::Authorized => decide_authorized_launch(input),
        GuardianLaunchPhase::GuardianStartIssued => decide_guardian_start_issued(input),
        GuardianLaunchPhase::GuardianReady {
            guardian_invocation,
        } => decide_guardian_ready(input, *guardian_invocation),
        GuardianLaunchPhase::PayloadStartIssued {
            guardian_invocation,
        } => decide_payload_start_issued(input, *guardian_invocation),
        GuardianLaunchPhase::PayloadVerified {
            guardian_invocation,
            payload_invocation,
            observation_sequence,
            worker_proof,
        } => decide_payload_verified(
            input,
            *guardian_invocation,
            *payload_invocation,
            *observation_sequence,
            *worker_proof,
        ),
        GuardianLaunchPhase::CleanupIssued {
            payload,
            guardian,
            progress,
        } => decide_launch_cleanup(input, payload, guardian, *progress),
        GuardianLaunchPhase::Compensated { .. } | GuardianLaunchPhase::Complete { .. } => {
            GuardianDecision::HistoricalComplete
        }
    }
}

fn decide_authorized_launch(input: GuardianDecisionInput<'_>) -> GuardianDecision {
    if input.guardian != UnitObservation::Absent || input.payload != UnitObservation::Absent {
        return GuardianDecision::Quarantine;
    }
    if input.freshness == AuthorityFreshness::Expired {
        return GuardianDecision::Reject(DecisionRejection::AuthorityExpired);
    }
    GuardianDecision::PersistThen {
        phase: GuardianLaunchPhase::GuardianStartIssued,
        effect: PlannedEffect::StartGuardian,
    }
}

fn decide_guardian_start_issued(input: GuardianDecisionInput<'_>) -> GuardianDecision {
    if input.payload != UnitObservation::Absent {
        return GuardianDecision::Quarantine;
    }
    match owned_observation(input.guardian, input.binding, None) {
        OwnedObservation::Absent => match (input.guardian_job, input.freshness) {
            (StartJobEvidence::None, AuthorityFreshness::Fresh) => {
                GuardianDecision::RetryIssued(PlannedEffect::StartGuardian)
            }
            (StartJobEvidence::DoneForCurrentSubmission, _)
            | (StartJobEvidence::RecoveredExactProof, _)
            | (StartJobEvidence::FailedForCurrentSubmission, _)
            | (StartJobEvidence::None, AuthorityFreshness::Expired) => {
                GuardianDecision::Compensated
            }
        },
        OwnedObservation::Present { invocation, state }
            if input.guardian_job == StartJobEvidence::DoneForCurrentSubmission
                && state == PresentUnitState::ActiveRunning =>
        {
            GuardianDecision::Persist(GuardianLaunchPhase::GuardianReady {
                guardian_invocation: invocation,
            })
        }
        OwnedObservation::Present { invocation, .. } => cleanup_decision(
            input.binding,
            StopUnitTarget::Absent,
            exact_stop_target(input.binding, invocation),
            CleanupProgress::GuardianPending,
            PlannedEffect::StopGuardian(exact_stop_target(input.binding, invocation)),
        ),
        OwnedObservation::Foreign | OwnedObservation::Indeterminate => GuardianDecision::Quarantine,
    }
}

fn decide_guardian_ready(
    input: GuardianDecisionInput<'_>,
    guardian_invocation: [u8; 16],
) -> GuardianDecision {
    if input.payload != UnitObservation::Absent {
        return GuardianDecision::Quarantine;
    }
    match owned_observation(input.guardian, input.binding, Some(guardian_invocation)) {
        OwnedObservation::Present {
            state: PresentUnitState::ActiveRunning,
            ..
        } if input.freshness == AuthorityFreshness::Fresh => GuardianDecision::PersistThen {
            phase: GuardianLaunchPhase::PayloadStartIssued {
                guardian_invocation,
            },
            effect: PlannedEffect::StartPayload,
        },
        OwnedObservation::Present { invocation, .. } => cleanup_decision(
            input.binding,
            StopUnitTarget::Absent,
            exact_stop_target(input.binding, invocation),
            CleanupProgress::GuardianPending,
            PlannedEffect::StopGuardian(exact_stop_target(input.binding, invocation)),
        ),
        OwnedObservation::Absent => GuardianDecision::Compensated,
        OwnedObservation::Foreign | OwnedObservation::Indeterminate => GuardianDecision::Quarantine,
    }
}

fn decide_payload_start_issued(
    input: GuardianDecisionInput<'_>,
    guardian_invocation: [u8; 16],
) -> GuardianDecision {
    let guardian = owned_observation(input.guardian, input.binding, Some(guardian_invocation));
    let guardian_live = matches!(
        guardian,
        OwnedObservation::Present {
            state: PresentUnitState::ActiveRunning,
            ..
        }
    );
    let payload = owned_observation(input.payload, input.binding, None);
    if matches!(
        guardian,
        OwnedObservation::Foreign | OwnedObservation::Indeterminate
    ) || matches!(
        payload,
        OwnedObservation::Foreign | OwnedObservation::Indeterminate
    ) {
        return GuardianDecision::Quarantine;
    }

    match payload {
        OwnedObservation::Present {
            invocation: payload_invocation,
            state: PresentUnitState::ActiveRunning,
        } if guardian_live
            && input.freshness == AuthorityFreshness::Fresh
            && matches!(
                input.payload_job,
                StartJobEvidence::DoneForCurrentSubmission | StartJobEvidence::RecoveredExactProof
            )
            && input.worker_proof.is_some_and(|proof| {
                proof.observation_sequence != 0 && proof.runtime.validate()
            }) =>
        {
            let Some(proof) = input.worker_proof else {
                return GuardianDecision::Reject(DecisionRejection::InconsistentEvidence);
            };
            GuardianDecision::Persist(GuardianLaunchPhase::PayloadVerified {
                guardian_invocation,
                payload_invocation,
                observation_sequence: proof.observation_sequence,
                worker_proof: proof.runtime,
            })
        }
        OwnedObservation::Present {
            invocation: payload_invocation,
            ..
        } => {
            let payload_target = exact_stop_target(input.binding, payload_invocation);
            let guardian_target = if let OwnedObservation::Present { invocation, .. } = guardian {
                exact_stop_target(input.binding, invocation)
            } else {
                StopUnitTarget::Absent
            };
            cleanup_decision(
                input.binding,
                payload_target.clone(),
                guardian_target,
                CleanupProgress::PayloadPending,
                PlannedEffect::StopPayload(payload_target),
            )
        }
        OwnedObservation::Absent => match guardian {
            OwnedObservation::Present { invocation, .. } => cleanup_decision(
                input.binding,
                StopUnitTarget::Absent,
                exact_stop_target(input.binding, invocation),
                CleanupProgress::GuardianPending,
                PlannedEffect::StopGuardian(exact_stop_target(input.binding, invocation)),
            ),
            OwnedObservation::Absent => GuardianDecision::Compensated,
            OwnedObservation::Foreign | OwnedObservation::Indeterminate => {
                GuardianDecision::Quarantine
            }
        },
        OwnedObservation::Foreign | OwnedObservation::Indeterminate => GuardianDecision::Quarantine,
    }
}

fn decide_payload_verified(
    input: GuardianDecisionInput<'_>,
    guardian_invocation: [u8; 16],
    payload_invocation: [u8; 16],
    observation_sequence: u64,
    worker_proof: RuntimeProofSnapshot,
) -> GuardianDecision {
    let guardian = owned_observation(input.guardian, input.binding, Some(guardian_invocation));
    let payload = owned_observation(input.payload, input.binding, Some(payload_invocation));
    if matches!(
        guardian,
        OwnedObservation::Foreign | OwnedObservation::Indeterminate
    ) || matches!(
        payload,
        OwnedObservation::Foreign | OwnedObservation::Indeterminate
    ) {
        return GuardianDecision::Quarantine;
    }

    let guardian_live = matches!(
        guardian,
        OwnedObservation::Present {
            state: PresentUnitState::ActiveRunning,
            ..
        }
    );
    let payload_live = matches!(
        payload,
        OwnedObservation::Present {
            state: PresentUnitState::ActiveRunning,
            ..
        }
    );
    let proof_matches = input.worker_proof
        == Some(WorkerProof {
            observation_sequence,
            runtime: worker_proof,
        });
    if guardian_live
        && payload_live
        && proof_matches
        && input.freshness == AuthorityFreshness::Fresh
    {
        return GuardianDecision::Persist(GuardianLaunchPhase::Complete {
            guardian_invocation,
            payload_invocation,
            observation_sequence,
            worker_proof,
        });
    }

    match payload {
        OwnedObservation::Present { invocation, .. } => {
            let payload_target = exact_stop_target(input.binding, invocation);
            let guardian_target = match guardian {
                OwnedObservation::Present { invocation, .. } => {
                    exact_stop_target(input.binding, invocation)
                }
                OwnedObservation::Absent => StopUnitTarget::Absent,
                OwnedObservation::Foreign | OwnedObservation::Indeterminate => {
                    return GuardianDecision::Quarantine;
                }
            };
            cleanup_decision(
                input.binding,
                payload_target.clone(),
                guardian_target,
                CleanupProgress::PayloadPending,
                PlannedEffect::StopPayload(payload_target),
            )
        }
        OwnedObservation::Absent => match guardian {
            OwnedObservation::Present { invocation, .. } => cleanup_decision(
                input.binding,
                StopUnitTarget::Absent,
                exact_stop_target(input.binding, invocation),
                CleanupProgress::GuardianPending,
                PlannedEffect::StopGuardian(exact_stop_target(input.binding, invocation)),
            ),
            OwnedObservation::Absent => GuardianDecision::Compensated,
            OwnedObservation::Foreign | OwnedObservation::Indeterminate => {
                GuardianDecision::Quarantine
            }
        },
        OwnedObservation::Foreign | OwnedObservation::Indeterminate => GuardianDecision::Quarantine,
    }
}

fn cleanup_decision(
    binding: [u8; 32],
    payload: StopUnitTarget,
    guardian: StopUnitTarget,
    progress: CleanupProgress,
    effect: PlannedEffect,
) -> GuardianDecision {
    GuardianDecision::PersistThen {
        phase: GuardianLaunchPhase::CleanupIssued {
            payload: launch_target(binding, payload),
            guardian: launch_target(binding, guardian),
            progress,
        },
        effect,
    }
}

fn decide_launch_cleanup(
    input: GuardianDecisionInput<'_>,
    payload: &ExactUnitTarget,
    guardian: &ExactUnitTarget,
    progress: CleanupProgress,
) -> GuardianDecision {
    let payload_observation = cleanup_observation(input.payload, payload);
    let guardian_observation = cleanup_observation(input.guardian, guardian);

    match progress {
        CleanupProgress::PayloadPending => match (payload_observation, guardian_observation) {
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                GuardianDecision::Quarantine
            }
            (CleanupObservation::Present(target), _) => {
                GuardianDecision::RetryIssued(PlannedEffect::StopPayload(target))
            }
            (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                GuardianDecision::PersistThen {
                    phase: GuardianLaunchPhase::CleanupIssued {
                        payload: payload.clone(),
                        guardian: guardian.clone(),
                        progress: CleanupProgress::GuardianPending,
                    },
                    effect: PlannedEffect::StopGuardian(target),
                }
            }
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                GuardianDecision::Compensated
            }
        },
        CleanupProgress::GuardianPending => match (payload_observation, guardian_observation) {
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                GuardianDecision::Quarantine
            }
            (CleanupObservation::Present(_), _) => GuardianDecision::Quarantine,
            (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                GuardianDecision::RetryIssued(PlannedEffect::StopGuardian(target))
            }
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                GuardianDecision::Compensated
            }
        },
        CleanupProgress::PayloadAwaitingAbsence => {
            match (payload_observation, guardian_observation) {
                (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                    GuardianDecision::PersistThen {
                        phase: GuardianLaunchPhase::CleanupIssued {
                            payload: payload.clone(),
                            guardian: guardian.clone(),
                            progress: CleanupProgress::GuardianPending,
                        },
                        effect: PlannedEffect::StopGuardian(target),
                    }
                }
                (CleanupObservation::Absent, CleanupObservation::Absent) => {
                    GuardianDecision::Compensated
                }
                (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                    GuardianDecision::Quarantine
                }
                _ => GuardianDecision::ObserveAgain,
            }
        }
        CleanupProgress::GuardianAwaitingAbsence => {
            match (payload_observation, guardian_observation) {
                (CleanupObservation::Absent, CleanupObservation::Absent) => {
                    GuardianDecision::Compensated
                }
                (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                    GuardianDecision::Quarantine
                }
                _ => GuardianDecision::ObserveAgain,
            }
        }
    }
}

/// Represents a pure composite-Stop decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StopDecision {
    Persist(CompositeStopPhase),
    PersistThen {
        phase: CompositeStopPhase,
        effect: PlannedEffect,
    },
    RetryIssued(PlannedEffect),
    ObserveAgain,
    HistoricalComplete,
    Reject(DecisionRejection),
    Quarantine,
}

/// Supplies observation-only inputs to the composite-Stop reducer.
#[derive(Clone, Copy)]
pub(crate) struct StopDecisionInput<'a> {
    pub(crate) target: &'a CompositeStopTarget,
    pub(crate) phase: &'a CompositeStopPhase,
    pub(crate) freshness: AuthorityFreshness,
    pub(crate) payload: UnitObservation,
    pub(crate) guardian: UnitObservation,
    pub(crate) observation_sequence: u64,
}

/// Applies the planned-versus-issued Stop table without performing I/O.
pub(crate) fn decide_composite_stop(input: StopDecisionInput<'_>) -> StopDecision {
    match input.phase {
        CompositeStopPhase::StopAuthorized => decide_stop_authorized(input),
        CompositeStopPhase::StopEffectIssued { progress } => {
            decide_stop_effect_issued(input, *progress)
        }
        CompositeStopPhase::Complete { .. } => StopDecision::HistoricalComplete,
    }
}

fn decide_stop_authorized(input: StopDecisionInput<'_>) -> StopDecision {
    if input.freshness == AuthorityFreshness::Expired {
        return StopDecision::Reject(DecisionRejection::AuthorityExpired);
    }
    let payload = input.target.payload();
    let guardian = input.target.guardian();
    let payload_observation = target_observation(input.payload, &payload);
    let guardian_observation = target_observation(input.guardian, &guardian);

    match (payload_observation, guardian_observation) {
        (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
            StopDecision::Quarantine
        }
        (CleanupObservation::Present(target), _) => StopDecision::PersistThen {
            phase: CompositeStopPhase::StopEffectIssued {
                progress: StopProgress::PayloadPending,
            },
            effect: PlannedEffect::StopPayload(target),
        },
        (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
            StopDecision::PersistThen {
                phase: CompositeStopPhase::StopEffectIssued {
                    progress: StopProgress::GuardianPending,
                },
                effect: PlannedEffect::StopGuardian(target),
            }
        }
        (CleanupObservation::Absent, CleanupObservation::Absent)
            if input.observation_sequence != 0 =>
        {
            StopDecision::Persist(CompositeStopPhase::Complete {
                observation_sequence: input.observation_sequence,
            })
        }
        (CleanupObservation::Absent, CleanupObservation::Absent) => StopDecision::ObserveAgain,
    }
}

fn decide_stop_effect_issued(input: StopDecisionInput<'_>, progress: StopProgress) -> StopDecision {
    let payload = input.target.payload();
    let guardian = input.target.guardian();
    let payload_observation = target_observation(input.payload, &payload);
    let guardian_observation = target_observation(input.guardian, &guardian);

    match progress {
        StopProgress::PayloadPending => match (payload_observation, guardian_observation) {
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                StopDecision::Quarantine
            }
            (CleanupObservation::Present(target), _) => {
                StopDecision::RetryIssued(PlannedEffect::StopPayload(target))
            }
            (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                StopDecision::PersistThen {
                    phase: CompositeStopPhase::StopEffectIssued {
                        progress: StopProgress::GuardianPending,
                    },
                    effect: PlannedEffect::StopGuardian(target),
                }
            }
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                complete_or_observe_stop(input)
            }
        },
        StopProgress::GuardianPending => match (payload_observation, guardian_observation) {
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                StopDecision::Quarantine
            }
            (CleanupObservation::Present(_), _) => StopDecision::Quarantine,
            (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                StopDecision::RetryIssued(PlannedEffect::StopGuardian(target))
            }
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                complete_or_observe_stop(input)
            }
        },
        StopProgress::PayloadAwaitingAbsence => match (payload_observation, guardian_observation) {
            (CleanupObservation::Absent, CleanupObservation::Present(target)) => {
                StopDecision::PersistThen {
                    phase: CompositeStopPhase::StopEffectIssued {
                        progress: StopProgress::GuardianPending,
                    },
                    effect: PlannedEffect::StopGuardian(target),
                }
            }
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                complete_or_observe_stop(input)
            }
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                StopDecision::Quarantine
            }
            _ => StopDecision::ObserveAgain,
        },
        StopProgress::GuardianAwaitingAbsence => complete_or_observe_stop(input),
    }
}

fn complete_or_observe_stop(input: StopDecisionInput<'_>) -> StopDecision {
    let payload = input.target.payload();
    let guardian = input.target.guardian();
    match (
        target_observation(input.payload, &payload),
        target_observation(input.guardian, &guardian),
    ) {
        (CleanupObservation::Absent, CleanupObservation::Absent)
            if input.observation_sequence != 0 =>
        {
            StopDecision::Persist(CompositeStopPhase::Complete {
                observation_sequence: input.observation_sequence,
            })
        }
        (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
            StopDecision::Quarantine
        }
        _ => StopDecision::ObserveAgain,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OwnedObservation {
    Absent,
    Present {
        invocation: [u8; 16],
        state: PresentUnitState,
    },
    Foreign,
    Indeterminate,
}

fn owned_observation(
    observed: UnitObservation,
    expected_binding: [u8; 32],
    expected_invocation: Option<[u8; 16]>,
) -> OwnedObservation {
    match observed {
        UnitObservation::Absent => OwnedObservation::Absent,
        UnitObservation::Present {
            binding: Some(binding),
            invocation,
            state,
        } if binding == expected_binding
            && invocation != [0; 16]
            && expected_invocation.is_none_or(|expected| expected == invocation) =>
        {
            OwnedObservation::Present { invocation, state }
        }
        UnitObservation::Present { .. } => OwnedObservation::Foreign,
        UnitObservation::Indeterminate => OwnedObservation::Indeterminate,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CleanupObservation {
    Absent,
    Present(StopUnitTarget),
    Foreign,
}

fn cleanup_observation(observed: UnitObservation, target: &ExactUnitTarget) -> CleanupObservation {
    target_observation(observed, &stop_target(target))
}

fn target_observation(observed: UnitObservation, target: &StopUnitTarget) -> CleanupObservation {
    match (observed, target) {
        (UnitObservation::Absent, _) => CleanupObservation::Absent,
        (UnitObservation::Present { .. }, StopUnitTarget::Absent)
        | (UnitObservation::Indeterminate, _) => CleanupObservation::Foreign,
        (
            UnitObservation::Present {
                binding,
                invocation,
                ..
            },
            StopUnitTarget::Exact {
                binding: expected_binding,
                invocation: expected_invocation,
            },
        ) if binding == *expected_binding && invocation == *expected_invocation => {
            CleanupObservation::Present(target.clone())
        }
        (UnitObservation::Present { .. }, StopUnitTarget::Exact { .. }) => {
            CleanupObservation::Foreign
        }
    }
}

fn exact_stop_target(binding: [u8; 32], invocation: [u8; 16]) -> StopUnitTarget {
    StopUnitTarget::Exact {
        binding: Some(binding),
        invocation,
    }
}

fn launch_target(binding: [u8; 32], target: StopUnitTarget) -> ExactUnitTarget {
    match target {
        StopUnitTarget::Absent => ExactUnitTarget::Absent,
        StopUnitTarget::Exact { invocation, .. } => ExactUnitTarget::Exact {
            binding,
            invocation,
        },
    }
}

fn stop_target(target: &ExactUnitTarget) -> StopUnitTarget {
    match target {
        ExactUnitTarget::Absent => StopUnitTarget::Absent,
        ExactUnitTarget::Exact {
            binding,
            invocation,
        } => StopUnitTarget::Exact {
            binding: Some(*binding),
            invocation: *invocation,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_handoff_actions_use_the_shared_execution_fence() {
        for action in [
            HostAction::ApplyExecution,
            HostAction::QueryExecution,
            HostAction::InstallAttachGate,
            HostAction::ReserveExecutionOutput,
            HostAction::QueryExecutionOutput,
            HostAction::ObserveExecutionArgument,
            HostAction::QueryExecutionArgument,
        ] {
            assert!(action.is_execution_handoff(), "action {action:?}");
            assert_eq!(HostAction::from_code(action.code()), Some(action));
        }

        for action in [
            HostAction::Launch,
            HostAction::Stop,
            HostAction::Freeze,
            HostAction::Thaw,
            HostAction::Kill,
        ] {
            assert!(!action.is_execution_handoff(), "action {action:?}");
        }
    }

    #[test]
    fn original_host_session_is_part_of_authenticated_handoff() {
        let context = context(HostAction::ObserveExecutionArgument, false);
        let handoff = HostExecutionHandoffRecord {
            runtime_witness_request_id: [8; 16],
            runtime_handle: [9; 32],
            session_binding: [10; 32],
            signed_request_digest: [11; 32],
            operation_id: [12; 16],
            execution_id: [13; 16],
            source_commitment: [14; 32],
            semantic_commitment: [15; 32],
        };
        let stable_authority = [16; 32];
        let original = DurableExecution::HostExecutionHandoff(handoff.clone());
        assert!(original.validate(context));
        let original_digest = original
            .authentication_digest(context, stable_authority)
            .expect("valid original handoff");

        let changed_session = DurableExecution::HostExecutionHandoff(HostExecutionHandoffRecord {
            session_binding: [17; 32],
            ..handoff.clone()
        });
        let changed_record = DurableExecution::HostExecutionHandoff(HostExecutionHandoffRecord {
            signed_request_digest: [18; 32],
            ..handoff.clone()
        });
        assert_ne!(
            changed_session.authentication_digest(context, stable_authority),
            Some(original_digest)
        );
        assert_ne!(
            changed_record.authentication_digest(context, stable_authority),
            Some(original_digest)
        );

        let missing_session = DurableExecution::HostExecutionHandoff(HostExecutionHandoffRecord {
            session_binding: [0; 32],
            ..handoff
        });
        assert!(!missing_session.validate(context));
    }

    fn context(action: HostAction, receipt_present: bool) -> ExecutionContext {
        ExecutionContext {
            action,
            request_id: [1; 16],
            request_digest: [2; 32],
            sandbox_id: [3; 16],
            incarnation_id: [4; 16],
            assignment_epoch: 5,
            desired_generation: 6,
            assignment_digest: [7; 32],
            receipt_present,
        }
    }

    fn evidence() -> GuardianLaunchEvidence {
        let DurableExecution::GuardianLaunch(record) =
            DurableExecution::guardian_fixture(context(HostAction::Launch, false))
        else {
            panic!("Guardian fixture has the wrong execution kind");
        };
        record.evidence
    }

    fn guardian_record(phase: GuardianLaunchPhase) -> DurableExecution {
        DurableExecution::GuardianLaunch(Box::new(GuardianLaunchRecord {
            evidence: evidence(),
            phase,
        }))
    }

    fn present(
        binding: Option<[u8; 32]>,
        invocation: u8,
        state: PresentUnitState,
    ) -> UnitObservation {
        UnitObservation::Present {
            binding,
            invocation: [invocation; 16],
            state,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ObservationKind {
        Exact,
        ForeignInvocation,
        ForeignBinding,
        Indeterminate,
        Absent,
    }

    impl ObservationKind {
        fn observe(self, binding: [u8; 32], invocation: u8) -> UnitObservation {
            match self {
                Self::Exact => present(
                    Some(binding),
                    invocation,
                    PresentUnitState::TerminalInactive,
                ),
                Self::ForeignInvocation => present(
                    Some(binding),
                    invocation.wrapping_add(1),
                    PresentUnitState::ActiveRunning,
                ),
                Self::ForeignBinding => {
                    let mut foreign_binding = binding;
                    foreign_binding[0] ^= 1;
                    present(
                        Some(foreign_binding),
                        invocation,
                        PresentUnitState::ActiveRunning,
                    )
                }
                Self::Indeterminate => UnitObservation::Indeterminate,
                Self::Absent => UnitObservation::Absent,
            }
        }

        fn is_untrusted(self) -> bool {
            matches!(
                self,
                Self::ForeignInvocation | Self::ForeignBinding | Self::Indeterminate
            )
        }
    }

    const OBSERVATION_KINDS: [ObservationKind; 5] = [
        ObservationKind::Exact,
        ObservationKind::ForeignInvocation,
        ObservationKind::ForeignBinding,
        ObservationKind::Indeterminate,
        ObservationKind::Absent,
    ];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DecisionShape {
        PersistPayloadStop,
        RetryPayloadStop,
        PersistGuardianStop,
        RetryGuardianStop,
        ObserveAgain,
        Complete,
        Quarantine,
    }

    fn expected_cleanup_shape(
        progress: CleanupProgress,
        payload: ObservationKind,
        guardian: ObservationKind,
    ) -> DecisionShape {
        if payload.is_untrusted() || guardian.is_untrusted() {
            return DecisionShape::Quarantine;
        }

        match (progress, payload, guardian) {
            (CleanupProgress::PayloadPending, ObservationKind::Exact, _) => {
                DecisionShape::RetryPayloadStop
            }
            (CleanupProgress::PayloadPending, ObservationKind::Absent, ObservationKind::Exact) => {
                DecisionShape::PersistGuardianStop
            }
            (CleanupProgress::PayloadPending, ObservationKind::Absent, ObservationKind::Absent) => {
                DecisionShape::Complete
            }
            (CleanupProgress::GuardianPending, ObservationKind::Exact, _) => {
                DecisionShape::Quarantine
            }
            (CleanupProgress::GuardianPending, ObservationKind::Absent, ObservationKind::Exact) => {
                DecisionShape::RetryGuardianStop
            }
            (
                CleanupProgress::GuardianPending,
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (
                CleanupProgress::GuardianAwaitingAbsence,
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (CleanupProgress::GuardianAwaitingAbsence, _, _) => DecisionShape::ObserveAgain,
            (
                CleanupProgress::PayloadAwaitingAbsence,
                ObservationKind::Absent,
                ObservationKind::Exact,
            ) => DecisionShape::PersistGuardianStop,
            (
                CleanupProgress::PayloadAwaitingAbsence,
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (CleanupProgress::PayloadAwaitingAbsence, _, _) => DecisionShape::ObserveAgain,
            _ => DecisionShape::Quarantine,
        }
    }

    fn exact_effect_target(
        target: &StopUnitTarget,
        binding: [u8; 32],
        invocation: [u8; 16],
    ) -> bool {
        matches!(
            target,
            StopUnitTarget::Exact {
                binding: Some(observed_binding),
                invocation: observed_invocation,
            } if *observed_binding == binding && *observed_invocation == invocation
        )
    }

    fn guardian_decision_shape(
        decision: GuardianDecision,
        binding: [u8; 32],
        payload_invocation: [u8; 16],
        guardian_invocation: [u8; 16],
    ) -> Option<DecisionShape> {
        match decision {
            GuardianDecision::PersistThen {
                phase:
                    GuardianLaunchPhase::CleanupIssued {
                        progress: CleanupProgress::GuardianPending,
                        ..
                    },
                effect: PlannedEffect::StopGuardian(target),
            } if exact_effect_target(&target, binding, guardian_invocation) => {
                Some(DecisionShape::PersistGuardianStop)
            }
            GuardianDecision::RetryIssued(PlannedEffect::StopPayload(target))
                if exact_effect_target(&target, binding, payload_invocation) =>
            {
                Some(DecisionShape::RetryPayloadStop)
            }
            GuardianDecision::RetryIssued(PlannedEffect::StopGuardian(target))
                if exact_effect_target(&target, binding, guardian_invocation) =>
            {
                Some(DecisionShape::RetryGuardianStop)
            }
            GuardianDecision::ObserveAgain => Some(DecisionShape::ObserveAgain),
            GuardianDecision::Compensated => Some(DecisionShape::Complete),
            GuardianDecision::Quarantine => Some(DecisionShape::Quarantine),
            _ => None,
        }
    }

    fn expected_stop_shape(
        progress: Option<StopProgress>,
        payload: ObservationKind,
        guardian: ObservationKind,
    ) -> DecisionShape {
        if payload.is_untrusted() || guardian.is_untrusted() {
            return DecisionShape::Quarantine;
        }

        match (progress, payload, guardian) {
            (None, ObservationKind::Exact, _) => DecisionShape::PersistPayloadStop,
            (None, ObservationKind::Absent, ObservationKind::Exact) => {
                DecisionShape::PersistGuardianStop
            }
            (None, ObservationKind::Absent, ObservationKind::Absent) => DecisionShape::Complete,
            (Some(StopProgress::PayloadPending), ObservationKind::Exact, _) => {
                DecisionShape::RetryPayloadStop
            }
            (
                Some(StopProgress::PayloadPending),
                ObservationKind::Absent,
                ObservationKind::Exact,
            ) => DecisionShape::PersistGuardianStop,
            (
                Some(StopProgress::PayloadPending),
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (Some(StopProgress::GuardianPending), ObservationKind::Exact, _) => {
                DecisionShape::Quarantine
            }
            (
                Some(StopProgress::GuardianPending),
                ObservationKind::Absent,
                ObservationKind::Exact,
            ) => DecisionShape::RetryGuardianStop,
            (
                Some(StopProgress::GuardianPending),
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (
                Some(StopProgress::GuardianAwaitingAbsence),
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (Some(StopProgress::GuardianAwaitingAbsence), _, _) => DecisionShape::ObserveAgain,
            (
                Some(StopProgress::PayloadAwaitingAbsence),
                ObservationKind::Absent,
                ObservationKind::Exact,
            ) => DecisionShape::PersistGuardianStop,
            (
                Some(StopProgress::PayloadAwaitingAbsence),
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (Some(StopProgress::PayloadAwaitingAbsence), _, _) => DecisionShape::ObserveAgain,
            _ => DecisionShape::Quarantine,
        }
    }

    fn stop_decision_shape(
        decision: StopDecision,
        binding: [u8; 32],
        payload_invocation: [u8; 16],
        guardian_invocation: [u8; 16],
    ) -> Option<DecisionShape> {
        match decision {
            StopDecision::PersistThen {
                phase:
                    CompositeStopPhase::StopEffectIssued {
                        progress: StopProgress::PayloadPending,
                    },
                effect: PlannedEffect::StopPayload(target),
            } if exact_effect_target(&target, binding, payload_invocation) => {
                Some(DecisionShape::PersistPayloadStop)
            }
            StopDecision::PersistThen {
                phase:
                    CompositeStopPhase::StopEffectIssued {
                        progress: StopProgress::GuardianPending,
                    },
                effect: PlannedEffect::StopGuardian(target),
            } if exact_effect_target(&target, binding, guardian_invocation) => {
                Some(DecisionShape::PersistGuardianStop)
            }
            StopDecision::RetryIssued(PlannedEffect::StopPayload(target))
                if exact_effect_target(&target, binding, payload_invocation) =>
            {
                Some(DecisionShape::RetryPayloadStop)
            }
            StopDecision::RetryIssued(PlannedEffect::StopGuardian(target))
                if exact_effect_target(&target, binding, guardian_invocation) =>
            {
                Some(DecisionShape::RetryGuardianStop)
            }
            StopDecision::ObserveAgain => Some(DecisionShape::ObserveAgain),
            StopDecision::Persist(CompositeStopPhase::Complete { .. }) => {
                Some(DecisionShape::Complete)
            }
            StopDecision::Quarantine => Some(DecisionShape::Quarantine),
            _ => None,
        }
    }

    fn guardian_input<'a>(
        phase: &'a GuardianLaunchPhase,
        guardian: UnitObservation,
    ) -> GuardianDecisionInput<'a> {
        GuardianDecisionInput {
            binding: evidence().binding,
            phase,
            freshness: AuthorityFreshness::Fresh,
            guardian_job: StartJobEvidence::None,
            payload_job: StartJobEvidence::None,
            guardian,
            payload: UnitObservation::Absent,
            worker_proof: None,
        }
    }

    fn runtime_proof() -> RuntimeProofSnapshot {
        RuntimeProofSnapshot {
            host_boot_id: [51; 16],
            supervisor: ProcessProofSnapshot {
                pid: 52,
                thread_group_id: 52,
                parent_pid: 1,
                cgroup_id: 53,
                start_time_ticks: 54,
            },
            payload: ProcessProofSnapshot {
                pid: 55,
                thread_group_id: 55,
                parent_pid: 52,
                cgroup_id: 56,
                start_time_ticks: 57,
            },
            supervisor_cgroup_id: 53,
            payload_cgroup_id: 56,
            workspace_mount_id: 58,
            payload_root_mount_id: 59,
            network_namespace: NamespaceProofSnapshot {
                device: 60,
                inode: 61,
            },
            mount_namespace: NamespaceProofSnapshot {
                device: 62,
                inode: 63,
            },
            user_namespace: NamespaceProofSnapshot {
                device: 64,
                inode: 65,
            },
        }
    }

    #[test]
    fn execution_authentication_binds_context_stable_authority_and_attempt_evidence() {
        let execution = DurableExecution::guardian_fixture(context(HostAction::Launch, false));
        let baseline_context = context(HostAction::Launch, false);
        let stable_authority = [40; 32];
        let baseline = execution
            .authentication_digest(baseline_context, stable_authority)
            .unwrap_or_else(|| panic!("cannot authenticate valid execution"));

        let mut contexts = Vec::new();
        let mut changed = baseline_context;
        changed.request_id[0] ^= 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.request_digest[0] ^= 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.action = HostAction::Stop;
        contexts.push(changed);
        changed = baseline_context;
        changed.sandbox_id[0] ^= 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.incarnation_id[0] ^= 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.assignment_epoch += 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.desired_generation += 1;
        contexts.push(changed);
        changed = baseline_context;
        changed.assignment_digest[0] ^= 1;
        contexts.push(changed);

        assert!(contexts.into_iter().all(|changed| {
            execution.authentication_digest(changed, stable_authority) != Some(baseline)
        }));
        assert_ne!(
            execution.authentication_digest(baseline_context, [41; 32]),
            Some(baseline)
        );

        let mut changed_phase = execution.clone();
        let DurableExecution::GuardianLaunch(record) = &mut changed_phase else {
            panic!("Guardian fixture has the wrong kind");
        };
        record.phase = GuardianLaunchPhase::GuardianStartIssued;
        assert_ne!(
            changed_phase.authentication_digest(baseline_context, stable_authority),
            Some(baseline)
        );

        let mut changed_attempt_lease = execution.clone();
        let DurableExecution::GuardianLaunch(record) = &mut changed_attempt_lease else {
            panic!("Guardian fixture has the wrong kind");
        };
        record.evidence.ownership_lease[0] ^= 1;
        assert_ne!(
            changed_attempt_lease.authentication_digest(baseline_context, stable_authority),
            Some(baseline)
        );

        // A renewed outer admission that preserves the stable commitment does
        // not rewrite the historical attempt evidence or its authentication.
        assert_eq!(
            execution.authentication_digest(baseline_context, stable_authority),
            Some(baseline)
        );

        let direct = DurableExecution::DirectLifecycle;
        let direct_context = context(HostAction::Freeze, false);
        let direct_digest = direct
            .authentication_digest(direct_context, stable_authority)
            .unwrap_or_else(|| panic!("cannot authenticate direct lifecycle execution"));
        let mut changed_direct_context = direct_context;
        changed_direct_context.action = HostAction::Thaw;
        assert_ne!(
            direct.authentication_digest(changed_direct_context, stable_authority),
            Some(direct_digest)
        );
    }

    #[test]
    fn execution_kind_matrix_rejects_impossible_action_pairs() {
        for action in [HostAction::Freeze, HostAction::Thaw, HostAction::Kill] {
            let direct = DurableExecution::direct_lifecycle(action)
                .unwrap_or_else(|| panic!("direct lifecycle action was rejected"));
            assert!(direct.validate(context(action, false)));
        }
        assert!(DurableExecution::direct_lifecycle(HostAction::Launch).is_none());
        assert!(DurableExecution::direct_lifecycle(HostAction::Stop).is_none());
        assert!(!DurableExecution::DirectLifecycle.validate(context(HostAction::Launch, false)));
        assert!(!DurableExecution::DirectLifecycle.validate(context(HostAction::Stop, false)));
        assert!(
            guardian_record(GuardianLaunchPhase::Authorized)
                .validate(context(HostAction::Launch, false))
        );
        assert!(
            !guardian_record(GuardianLaunchPhase::Authorized)
                .validate(context(HostAction::Stop, false))
        );
        let composite = DurableExecution::composite_stop_fixture();
        assert!(composite.validate(context(HostAction::Stop, false)));
        assert!(!composite.validate(context(HostAction::Launch, false)));
    }

    #[test]
    fn binding_is_recomputed_from_artifact_executable_and_attachment_evidence() {
        let original = evidence();
        assert!(original.validate(context(HostAction::Launch, false)));

        let mut changed_artifact = original.clone();
        changed_artifact.broker_plan[0] ^= 1;
        assert!(!changed_artifact.validate(context(HostAction::Launch, false)));

        let mut changed_executable = original.clone();
        changed_executable.guardian_executable.sha256_content[0] ^= 1;
        assert!(!changed_executable.validate(context(HostAction::Launch, false)));

        let mut changed_attachment = original;
        changed_attachment.payload.attachment_anchor.mount_id ^= 1;
        assert!(!changed_attachment.validate(context(HostAction::Launch, false)));
    }

    #[test]
    fn payload_snapshot_rejects_invalid_attachment_anchor_with_matching_binding() {
        let mut changed = evidence();
        changed.payload.attachment_anchor.mount_id = 0;
        changed.binding = changed.recompute_binding();

        assert!(!changed.validate(context(HostAction::Launch, false)));
    }

    #[test]
    fn agent_required_marker_changes_the_authenticated_launch_binding() {
        let legacy = PayloadLaunchSnapshot::fixture();
        let mut protected = legacy.clone();
        protected.agent_required = true;

        let mut legacy_hash = Sha256::new();
        legacy.update_binding(&mut legacy_hash);
        let mut protected_hash = Sha256::new();
        protected.update_binding(&mut protected_hash);
        assert_ne!(legacy_hash.finalize(), protected_hash.finalize());

        let mut old_wire = serde_json::to_value(legacy).unwrap();
        old_wire.as_object_mut().unwrap().remove("agent_required");
        let decoded: PayloadLaunchSnapshot = serde_json::from_value(old_wire).unwrap();
        assert!(!decoded.agent_required);
    }

    #[test]
    fn arbitrary_active_state_never_creates_guardian_readiness() {
        let phase = GuardianLaunchPhase::GuardianStartIssued;
        let active = present(
            Some(evidence().binding),
            40,
            PresentUnitState::ActiveRunning,
        );
        let recovered = decide_guardian_launch(guardian_input(&phase, active));
        assert!(matches!(
            recovered,
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopGuardian(_),
            }
        ));

        let mut current = guardian_input(&phase, active);
        current.guardian_job = StartJobEvidence::DoneForCurrentSubmission;
        assert_eq!(
            decide_guardian_launch(current),
            GuardianDecision::Persist(GuardianLaunchPhase::GuardianReady {
                guardian_invocation: [40; 16],
            })
        );
    }

    #[test]
    fn replay_runtime_inputs_must_match_the_authenticated_attempt() {
        let execution = guardian_record(GuardianLaunchPhase::GuardianStartIssued);
        let original = evidence();
        let executable = GuardianExecutableSnapshot {
            device: original.guardian_executable.device,
            inode: original.guardian_executable.inode,
            bytes: original.guardian_executable.bytes,
            uid: original.guardian_executable.uid,
            mode: original.guardian_executable.mode,
            modified_seconds: original.guardian_executable.modified_seconds,
            modified_nanoseconds: original.guardian_executable.modified_nanoseconds,
            changed_seconds: original.guardian_executable.changed_seconds,
            changed_nanoseconds: original.guardian_executable.changed_nanoseconds,
            sha256_content: original.guardian_executable.sha256_content,
        };
        assert!(execution.guardian_runtime_inputs_match(
            &original.protected_inputs,
            executable,
            &original.payload,
        ));

        let mut changed_protected = original.protected_inputs.clone();
        changed_protected[0].sha256[0] ^= 1;
        assert!(!execution.guardian_runtime_inputs_match(
            &changed_protected,
            executable,
            &original.payload,
        ));
        let mut replaced_protected = original.protected_inputs.clone();
        replaced_protected[0].inode += 1;
        assert!(!execution.guardian_runtime_inputs_match(
            &replaced_protected,
            executable,
            &original.payload,
        ));

        let mut changed_executable = executable;
        changed_executable.sha256_content[0] ^= 1;
        assert!(!execution.guardian_runtime_inputs_match(
            &original.protected_inputs,
            changed_executable,
            &original.payload,
        ));
        let mut replaced_executable = executable;
        replaced_executable.inode += 1;
        assert!(!execution.guardian_runtime_inputs_match(
            &original.protected_inputs,
            replaced_executable,
            &original.payload,
        ));
    }

    #[test]
    fn expiry_after_done_records_ready_but_cannot_authorize_payload_start() {
        let binding = evidence().binding;
        let active = present(Some(binding), 40, PresentUnitState::ActiveRunning);
        let issued = GuardianLaunchPhase::GuardianStartIssued;
        let mut completed_start = guardian_input(&issued, active);
        completed_start.freshness = AuthorityFreshness::Expired;
        completed_start.guardian_job = StartJobEvidence::DoneForCurrentSubmission;
        let ready = decide_guardian_launch(completed_start);
        assert_eq!(
            ready,
            GuardianDecision::Persist(GuardianLaunchPhase::GuardianReady {
                guardian_invocation: [40; 16],
            })
        );

        let GuardianDecision::Persist(ready_phase) = ready else {
            panic!("exact completed start did not produce durable readiness");
        };
        let mut expired_ready = guardian_input(&ready_phase, active);
        expired_ready.freshness = AuthorityFreshness::Expired;
        assert!(matches!(
            decide_guardian_launch(expired_ready),
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopGuardian(_),
            }
        ));
    }

    #[test]
    fn inactive_and_failed_units_remain_present_cleanup_targets() {
        for state in [
            PresentUnitState::TerminalInactive,
            PresentUnitState::TerminalFailed,
        ] {
            let phase = GuardianLaunchPhase::GuardianStartIssued;
            let terminal = present(Some(evidence().binding), 41, state);
            assert!(matches!(
                decide_guardian_launch(guardian_input(&phase, terminal)),
                GuardianDecision::PersistThen {
                    phase: GuardianLaunchPhase::CleanupIssued { .. },
                    effect: PlannedEffect::StopGuardian(StopUnitTarget::Exact {
                        invocation,
                        ..
                    }),
                } if invocation == [41; 16]
            ));
        }
    }

    #[test]
    fn payload_verification_requires_nonzero_worker_proof() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::PayloadStartIssued {
            guardian_invocation: [42; 16],
        };

        for worker_proof in [
            WorkerProof {
                observation_sequence: 0,
                runtime: runtime_proof(),
            },
            WorkerProof {
                observation_sequence: 44,
                runtime: RuntimeProofSnapshot {
                    host_boot_id: [0; 16],
                    ..runtime_proof()
                },
            },
        ] {
            let mut input = guardian_input(
                &phase,
                present(Some(binding), 42, PresentUnitState::ActiveRunning),
            );
            input.payload = present(Some(binding), 45, PresentUnitState::ActiveRunning);
            input.payload_job = StartJobEvidence::DoneForCurrentSubmission;
            input.worker_proof = Some(worker_proof);

            assert!(matches!(
                decide_guardian_launch(input),
                GuardianDecision::PersistThen {
                    phase: GuardianLaunchPhase::CleanupIssued { .. },
                    effect: PlannedEffect::StopPayload(StopUnitTarget::Exact {
                        invocation,
                        ..
                    }),
                } if invocation == [45; 16]
            ));
        }
    }

    #[test]
    fn recovered_payload_requires_explicit_complete_exact_proof() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::PayloadStartIssued {
            guardian_invocation: [42; 16],
        };
        let mut input = guardian_input(
            &phase,
            present(Some(binding), 42, PresentUnitState::ActiveRunning),
        );
        input.payload = present(Some(binding), 45, PresentUnitState::ActiveRunning);
        input.worker_proof = Some(WorkerProof {
            observation_sequence: 44,
            runtime: runtime_proof(),
        });

        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopPayload(_),
            }
        ));

        input.payload_job = StartJobEvidence::RecoveredExactProof;
        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::Persist(GuardianLaunchPhase::PayloadVerified {
                guardian_invocation,
                payload_invocation,
                observation_sequence: 44,
                ..
            }) if guardian_invocation == [42; 16] && payload_invocation == [45; 16]
        ));

        input.freshness = AuthorityFreshness::Expired;
        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopPayload(_),
            }
        ));
    }

    #[test]
    fn payload_verified_recovery_requires_a_live_guardian_and_fresh_authority() {
        let binding = evidence().binding;
        let runtime = runtime_proof();
        let phase = GuardianLaunchPhase::PayloadVerified {
            guardian_invocation: [42; 16],
            payload_invocation: [45; 16],
            observation_sequence: 44,
            worker_proof: runtime,
        };
        let payload = present(Some(binding), 45, PresentUnitState::ActiveRunning);
        let mut input = guardian_input(
            &phase,
            present(Some(binding), 42, PresentUnitState::ActiveRunning),
        );
        input.payload = payload;
        input.worker_proof = Some(WorkerProof {
            observation_sequence: 44,
            runtime,
        });
        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::Persist(GuardianLaunchPhase::Complete { .. })
        ));

        input.guardian = UnitObservation::Absent;
        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopPayload(_),
            }
        ));

        input.guardian = present(Some(binding), 42, PresentUnitState::ActiveRunning);
        input.freshness = AuthorityFreshness::Expired;
        assert!(matches!(
            decide_guardian_launch(input),
            GuardianDecision::PersistThen {
                phase: GuardianLaunchPhase::CleanupIssued { .. },
                effect: PlannedEffect::StopPayload(_),
            }
        ));
    }

    #[test]
    fn cleanup_awaiting_absence_quarantines_foreign_units() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::CleanupIssued {
            payload: ExactUnitTarget::Exact {
                binding,
                invocation: [46; 16],
            },
            guardian: ExactUnitTarget::Absent,
            progress: CleanupProgress::GuardianAwaitingAbsence,
        };
        let mut input = guardian_input(&phase, UnitObservation::Absent);
        input.payload = present(Some(binding), 47, PresentUnitState::ActiveRunning);

        assert_eq!(decide_guardian_launch(input), GuardianDecision::Quarantine);
    }

    #[test]
    fn launch_cleanup_never_stops_a_saved_guardian_target_without_an_exact_observation() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::CleanupIssued {
            payload: ExactUnitTarget::Exact {
                binding,
                invocation: [48; 16],
            },
            guardian: ExactUnitTarget::Exact {
                binding,
                invocation: [49; 16],
            },
            progress: CleanupProgress::PayloadPending,
        };
        let foreign_guardian = present(Some(binding), 50, PresentUnitState::ActiveRunning);
        let mut input = guardian_input(&phase, foreign_guardian);
        input.payload = UnitObservation::Absent;

        assert_eq!(decide_guardian_launch(input), GuardianDecision::Quarantine);
    }

    #[test]
    fn launch_cleanup_quarantines_payload_reappearance_after_ordered_progress() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::CleanupIssued {
            payload: ExactUnitTarget::Exact {
                binding,
                invocation: [51; 16],
            },
            guardian: ExactUnitTarget::Exact {
                binding,
                invocation: [52; 16],
            },
            progress: CleanupProgress::GuardianPending,
        };
        let guardian = present(Some(binding), 52, PresentUnitState::TerminalInactive);
        let mut input = guardian_input(&phase, guardian);
        input.payload = present(Some(binding), 51, PresentUnitState::TerminalInactive);

        assert_eq!(decide_guardian_launch(input), GuardianDecision::Quarantine);
    }

    #[test]
    fn launch_cleanup_exhaustively_checks_each_observation_pair() {
        let binding = evidence().binding;
        let payload = ExactUnitTarget::Exact {
            binding,
            invocation: [53; 16],
        };
        let guardian = ExactUnitTarget::Exact {
            binding,
            invocation: [54; 16],
        };

        for progress in [
            CleanupProgress::PayloadPending,
            CleanupProgress::GuardianPending,
            CleanupProgress::GuardianAwaitingAbsence,
        ] {
            let phase = GuardianLaunchPhase::CleanupIssued {
                payload: payload.clone(),
                guardian: guardian.clone(),
                progress,
            };
            for payload_kind in OBSERVATION_KINDS {
                for guardian_kind in OBSERVATION_KINDS {
                    let input = GuardianDecisionInput {
                        binding,
                        phase: &phase,
                        freshness: AuthorityFreshness::Expired,
                        guardian_job: StartJobEvidence::None,
                        payload_job: StartJobEvidence::None,
                        guardian: guardian_kind.observe(binding, 54),
                        payload: payload_kind.observe(binding, 53),
                        worker_proof: None,
                    };
                    assert_eq!(
                        guardian_decision_shape(
                            decide_guardian_launch(input),
                            binding,
                            [53; 16],
                            [54; 16]
                        ),
                        Some(expected_cleanup_shape(
                            progress,
                            payload_kind,
                            guardian_kind
                        )),
                        "progress={progress:?}, payload={payload_kind:?}, guardian={guardian_kind:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn planned_stop_expires_but_issued_exact_stop_can_continue() {
        let binding = [60; 32];
        let target = CompositeStopTarget::GuardianComposite {
            source_launch_request_id: [61; 16],
            incarnation_id: [62; 16],
            launch_binding: binding,
            payload: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [63; 16],
            },
            guardian: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [64; 16],
            },
        };
        let payload = present(Some(binding), 63, PresentUnitState::TerminalInactive);
        let guardian = present(Some(binding), 64, PresentUnitState::ActiveRunning);
        let authorized = CompositeStopPhase::StopAuthorized;
        let expired = StopDecisionInput {
            target: &target,
            phase: &authorized,
            freshness: AuthorityFreshness::Expired,
            payload,
            guardian,
            observation_sequence: 65,
        };
        assert_eq!(
            decide_composite_stop(expired),
            StopDecision::Reject(DecisionRejection::AuthorityExpired)
        );

        let issued = CompositeStopPhase::StopEffectIssued {
            progress: StopProgress::PayloadPending,
        };
        let expired_issued = StopDecisionInput {
            phase: &issued,
            ..expired
        };
        assert!(matches!(
            decide_composite_stop(expired_issued),
            StopDecision::RetryIssued(PlannedEffect::StopPayload(StopUnitTarget::Exact {
                invocation,
                ..
            })) if invocation == [63; 16]
        ));
    }

    #[test]
    fn issued_stop_never_stops_a_saved_guardian_target_without_an_exact_observation() {
        let binding = [70; 32];
        let target = CompositeStopTarget::GuardianComposite {
            source_launch_request_id: [71; 16],
            incarnation_id: [72; 16],
            launch_binding: binding,
            payload: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [73; 16],
            },
            guardian: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [74; 16],
            },
        };
        let phase = CompositeStopPhase::StopEffectIssued {
            progress: StopProgress::PayloadPending,
        };
        let decision = decide_composite_stop(StopDecisionInput {
            target: &target,
            phase: &phase,
            freshness: AuthorityFreshness::Expired,
            payload: UnitObservation::Absent,
            guardian: present(Some(binding), 75, PresentUnitState::ActiveRunning),
            observation_sequence: 76,
        });

        assert_eq!(decision, StopDecision::Quarantine);
    }

    #[test]
    fn issued_stop_quarantines_payload_reappearance_after_ordered_progress() {
        let binding = [80; 32];
        let target = CompositeStopTarget::GuardianComposite {
            source_launch_request_id: [81; 16],
            incarnation_id: [82; 16],
            launch_binding: binding,
            payload: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [83; 16],
            },
            guardian: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [84; 16],
            },
        };
        let phase = CompositeStopPhase::StopEffectIssued {
            progress: StopProgress::GuardianPending,
        };
        let decision = decide_composite_stop(StopDecisionInput {
            target: &target,
            phase: &phase,
            freshness: AuthorityFreshness::Expired,
            payload: present(Some(binding), 83, PresentUnitState::TerminalInactive),
            guardian: present(Some(binding), 84, PresentUnitState::TerminalInactive),
            observation_sequence: 85,
        });

        assert_eq!(decision, StopDecision::Quarantine);
    }

    #[test]
    fn composite_stop_exhaustively_checks_each_observation_pair() {
        let binding = [90; 32];
        let target = CompositeStopTarget::GuardianComposite {
            source_launch_request_id: [91; 16],
            incarnation_id: [92; 16],
            launch_binding: binding,
            payload: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [93; 16],
            },
            guardian: StopUnitTarget::Exact {
                binding: Some(binding),
                invocation: [94; 16],
            },
        };

        for progress in [
            None,
            Some(StopProgress::PayloadPending),
            Some(StopProgress::GuardianPending),
            Some(StopProgress::GuardianAwaitingAbsence),
        ] {
            let phase = progress.map_or(CompositeStopPhase::StopAuthorized, |progress| {
                CompositeStopPhase::StopEffectIssued { progress }
            });
            for payload_kind in OBSERVATION_KINDS {
                for guardian_kind in OBSERVATION_KINDS {
                    let input = StopDecisionInput {
                        target: &target,
                        phase: &phase,
                        freshness: AuthorityFreshness::Fresh,
                        payload: payload_kind.observe(binding, 93),
                        guardian: guardian_kind.observe(binding, 94),
                        observation_sequence: 95,
                    };
                    assert_eq!(
                        stop_decision_shape(
                            decide_composite_stop(input),
                            binding,
                            [93; 16],
                            [94; 16]
                        ),
                        Some(expected_stop_shape(progress, payload_kind, guardian_kind)),
                        "progress={progress:?}, payload={payload_kind:?}, guardian={guardian_kind:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn frozen_absence_never_authorizes_a_later_same_name_unit() {
        let target = CompositeStopTarget::Absent;
        let phase = CompositeStopPhase::StopAuthorized;
        let decision = decide_composite_stop(StopDecisionInput {
            target: &target,
            phase: &phase,
            freshness: AuthorityFreshness::Fresh,
            payload: present(None, 60, PresentUnitState::ActiveRunning),
            guardian: UnitObservation::Absent,
            observation_sequence: 61,
        });
        assert_eq!(decision, StopDecision::Quarantine);
    }

    #[test]
    fn complete_is_historical_and_does_not_claim_current_liveness() {
        let phase = GuardianLaunchPhase::Complete {
            guardian_invocation: [70; 16],
            payload_invocation: [71; 16],
            observation_sequence: 72,
            worker_proof: runtime_proof(),
        };
        let mut input = guardian_input(&phase, UnitObservation::Absent);
        input.freshness = AuthorityFreshness::Expired;
        assert_eq!(
            decide_guardian_launch(input),
            GuardianDecision::HistoricalComplete
        );
    }

    #[test]
    fn guardian_record_codec_rejects_unknown_fields_and_bad_binding() {
        let execution = guardian_record(GuardianLaunchPhase::Authorized);
        let bytes = serde_json::to_vec(&execution)
            .unwrap_or_else(|error| panic!("cannot encode execution fixture: {error}"));
        let decoded: DurableExecution = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("cannot decode execution fixture: {error}"));
        assert_eq!(decoded, execution);

        let mut value: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("cannot decode execution JSON: {error}"));
        value
            .pointer_mut("/state/evidence/payload")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|payload| payload.remove("attachment_anchor"))
            .unwrap_or_else(|| panic!("execution JSON omitted the attachment-anchor fixture"));
        let missing_attachment = serde_json::to_vec(&value)
            .unwrap_or_else(|error| panic!("cannot encode incomplete execution: {error}"));
        assert!(serde_json::from_slice::<DurableExecution>(&missing_attachment).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("cannot decode execution JSON: {error}"));
        value
            .as_object_mut()
            .unwrap_or_else(|| panic!("execution JSON is not an object"))
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let unknown = serde_json::to_vec(&value)
            .unwrap_or_else(|error| panic!("cannot encode mutated execution: {error}"));
        assert!(serde_json::from_slice::<DurableExecution>(&unknown).is_err());
    }
}
