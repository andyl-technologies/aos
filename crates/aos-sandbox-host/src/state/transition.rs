//! Version-4 durable execution evidence and pure transition decisions.
//!
//! The host-state envelope stores this module's tagged records beneath each
//! request. Current carrier versions continue to use the `legacy` kind. The
//! future Guardian launch and composite Stop kinds are deliberately codec- and
//! decision-only until the broker's live effect integration is qualified.
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

use std::os::fd::BorrowedFd;

use aos_sandbox_broker::{
    ProtectedBrokerPublicCredentialRole, ProtectedBrokerPublicCredentialSnapshot,
};
use aos_sandbox_core::ProtocolVersion;
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
}

impl HostAction {
    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Launch),
            2 => Some(Self::Stop),
            3 => Some(Self::Freeze),
            4 => Some(Self::Thaw),
            5 => Some(Self::Kill),
            _ => None,
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Launch => 1,
            Self::Stop => 2,
            Self::Freeze => 3,
            Self::Thaw => 4,
            Self::Kill => 5,
        }
    }
}

/// Selects the signed Host authority version independently of the carrier.
///
/// Carriers 1.1 through 1.4 retain the established Host 1.1 semantics. The
/// future 1.5 carrier upgrades only Launch; lifecycle operations remain signed
/// under Host 1.1. Callers must still keep the live carrier-1.5 guard closed
/// until Guardian effects are integrated.
pub(crate) const fn signed_authority_version(
    carrier: ProtocolVersion,
    action: HostAction,
) -> Option<ProtocolVersion> {
    if carrier.major() != 1 {
        return None;
    }
    match (carrier.minor(), action) {
        (1..=4, _) => Some(ProtocolVersion::new(1, 1)),
        (5, HostAction::Launch) => Some(ProtocolVersion::new(1, 5)),
        (5, HostAction::Stop | HostAction::Freeze | HostAction::Thaw | HostAction::Kill) => {
            Some(ProtocolVersion::new(1, 1))
        }
        _ => None,
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
    Legacy,
    GuardianLaunch(Box<GuardianLaunchRecord>),
    CompositeStop(CompositeStopRecord),
}

impl DurableExecution {
    /// Creates the only execution kind emitted by the current closed carrier.
    pub(crate) fn current_legacy(carrier: ProtocolVersion, action: HostAction) -> Option<Self> {
        matches!(carrier.major(), 1)
            .then_some(carrier.minor())
            .filter(|minor| (1..=4).contains(minor))?;
        signed_authority_version(carrier, action)?;
        Some(Self::Legacy)
    }

    pub(crate) fn validate(&self, context: ExecutionContext) -> bool {
        match self {
            Self::Legacy => {
                (1..=4).contains(&context.carrier.minor())
                    && context.carrier.major() == 1
                    && signed_authority_version(context.carrier, context.action)
                        == Some(ProtocolVersion::new(1, 1))
            }
            Self::GuardianLaunch(record) => {
                context.action == HostAction::Launch
                    && context.carrier == ProtocolVersion::new(1, 5)
                    && signed_authority_version(context.carrier, context.action)
                        == Some(ProtocolVersion::new(1, 5))
                    && record.validate(context)
            }
            Self::CompositeStop(record) => {
                context.action == HostAction::Stop
                    && context.carrier.major() == 1
                    && (1..=5).contains(&context.carrier.minor())
                    && signed_authority_version(context.carrier, context.action)
                        == Some(ProtocolVersion::new(1, 1))
                    && record.validate(context.receipt_present)
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
        update_authentication_field(&mut hash, 4, &context.carrier.major().to_be_bytes())?;
        update_authentication_field(&mut hash, 5, &context.carrier.minor().to_be_bytes())?;
        update_authentication_field(&mut hash, 6, &[context.action.code()])?;
        update_authentication_field(&mut hash, 7, &context.sandbox_id)?;
        update_authentication_field(&mut hash, 8, &context.incarnation_id)?;
        update_authentication_field(&mut hash, 9, &context.assignment_epoch.to_be_bytes())?;
        update_authentication_field(&mut hash, 10, &context.desired_generation.to_be_bytes())?;
        update_authentication_field(&mut hash, 11, &context.assignment_digest)?;
        update_authentication_field(&mut hash, 12, &stable_authority_digest)?;
        update_authentication_field(&mut hash, 13, &execution)?;
        Some(hash.finalize().into())
    }

    pub(crate) fn guardian_binding(&self) -> Option<[u8; 32]> {
        match self {
            Self::GuardianLaunch(record) => Some(record.evidence.binding),
            Self::Legacy | Self::CompositeStop(_) => None,
        }
    }

    pub(crate) fn stop_source(&self) -> Option<StopSourceReference> {
        match self {
            Self::CompositeStop(record) => record.target.source(),
            Self::Legacy | Self::GuardianLaunch(_) => None,
        }
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

fn update_authentication_field(hash: &mut Sha256, tag: u16, value: &[u8]) -> Option<()> {
    let length = u64::try_from(value.len()).ok()?;
    hash.update(tag.to_be_bytes());
    hash.update(length.to_be_bytes());
    hash.update(value);
    Some(())
}

#[derive(Clone, Copy)]
pub(crate) struct ExecutionContext {
    pub(crate) carrier: ProtocolVersion,
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
            && matches!(self.phase, GuardianLaunchPhase::Complete { .. }) == context.receipt_present
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
        hash.finalize().into()
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
        worker_proof_digest: [u8; 32],
    },
    CleanupIssued {
        payload: ExactUnitTarget,
        guardian: ExactUnitTarget,
        progress: CleanupProgress,
    },
    Complete {
        guardian_invocation: [u8; 16],
        payload_invocation: [u8; 16],
        observation_sequence: u64,
        worker_proof_digest: [u8; 32],
    },
}

impl GuardianLaunchPhase {
    fn validate(&self, binding: [u8; 32]) -> bool {
        match self {
            Self::Authorized | Self::GuardianStartIssued => true,
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
                worker_proof_digest,
            }
            | Self::Complete {
                guardian_invocation,
                payload_invocation,
                observation_sequence,
                worker_proof_digest,
            } => {
                *guardian_invocation != [0; 16]
                    && *payload_invocation != [0; 16]
                    && guardian_invocation != payload_invocation
                    && *observation_sequence != 0
                    && *worker_proof_digest != [0; 32]
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
                        CleanupProgress::AwaitingAbsence => {
                            payload.is_exact() || guardian.is_exact()
                        }
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
    AwaitingAbsence,
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
    LegacyPayload {
        source_launch_request_id: [u8; 16],
        incarnation_id: [u8; 16],
        payload: StopUnitTarget,
    },
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
            Self::LegacyPayload {
                source_launch_request_id,
                incarnation_id,
                payload,
            } => {
                *source_launch_request_id != [0; 16]
                    && *incarnation_id != [0; 16]
                    && payload.validate(None)
            }
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
            Self::LegacyPayload {
                source_launch_request_id,
                incarnation_id,
                ..
            } => Some(StopSourceReference {
                request_id: *source_launch_request_id,
                incarnation_id: *incarnation_id,
                guardian_binding: None,
            }),
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

    fn payload(&self) -> StopUnitTarget {
        match self {
            Self::Absent => StopUnitTarget::Absent,
            Self::LegacyPayload { payload, .. } | Self::GuardianComposite { payload, .. } => {
                payload.clone()
            }
        }
    }

    fn guardian(&self) -> StopUnitTarget {
        match self {
            Self::GuardianComposite { guardian, .. } => guardian.clone(),
            Self::Absent | Self::LegacyPayload { .. } => StopUnitTarget::Absent,
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

    fn is_exact(&self) -> bool {
        matches!(self, Self::Exact { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CompositeStopPhase {
    StopAuthorized,
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
                StopProgress::AwaitingAbsence => {
                    target.payload().is_exact() || target.guardian().is_exact()
                }
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
    AwaitingAbsence,
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
    pub(crate) digest: [u8; 32],
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
    StartFailed,
    RuntimeDisappeared,
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
            worker_proof_digest,
        } => GuardianDecision::Persist(GuardianLaunchPhase::Complete {
            guardian_invocation: *guardian_invocation,
            payload_invocation: *payload_invocation,
            observation_sequence: *observation_sequence,
            worker_proof_digest: *worker_proof_digest,
        }),
        GuardianLaunchPhase::CleanupIssued {
            payload,
            guardian,
            progress,
        } => decide_launch_cleanup(input, payload, guardian, *progress),
        GuardianLaunchPhase::Complete { .. } => GuardianDecision::HistoricalComplete,
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
            (StartJobEvidence::DoneForCurrentSubmission, _) => {
                GuardianDecision::Reject(DecisionRejection::InconsistentEvidence)
            }
            (StartJobEvidence::FailedForCurrentSubmission, _) => {
                GuardianDecision::Reject(DecisionRejection::StartFailed)
            }
            (StartJobEvidence::None, AuthorityFreshness::Fresh) => {
                GuardianDecision::RetryIssued(PlannedEffect::StartGuardian)
            }
            (StartJobEvidence::None, AuthorityFreshness::Expired) => {
                GuardianDecision::Reject(DecisionRejection::AuthorityExpired)
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
        OwnedObservation::Absent => GuardianDecision::Reject(DecisionRejection::RuntimeDisappeared),
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
        OwnedObservation::Absent
            if guardian_live
                && input.freshness == AuthorityFreshness::Fresh
                && input.payload_job == StartJobEvidence::None =>
        {
            GuardianDecision::RetryIssued(PlannedEffect::StartPayload)
        }
        OwnedObservation::Present {
            invocation: payload_invocation,
            state: PresentUnitState::ActiveRunning,
        } if guardian_live
            && input.payload_job == StartJobEvidence::DoneForCurrentSubmission
            && input.worker_proof.is_some_and(|proof| {
                proof.observation_sequence != 0 && proof.digest != [0; 32]
            }) =>
        {
            let Some(proof) = input.worker_proof else {
                return GuardianDecision::Reject(DecisionRejection::InconsistentEvidence);
            };
            GuardianDecision::Persist(GuardianLaunchPhase::PayloadVerified {
                guardian_invocation,
                payload_invocation,
                observation_sequence: proof.observation_sequence,
                worker_proof_digest: proof.digest,
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
            OwnedObservation::Absent => {
                GuardianDecision::Reject(DecisionRejection::RuntimeDisappeared)
            }
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
        CleanupProgress::AwaitingAbsence => match (payload_observation, guardian_observation) {
            (CleanupObservation::Absent, CleanupObservation::Absent) => {
                GuardianDecision::Compensated
            }
            (CleanupObservation::Foreign, _) | (_, CleanupObservation::Foreign) => {
                GuardianDecision::Quarantine
            }
            _ => GuardianDecision::ObserveAgain,
        },
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
        StopProgress::AwaitingAbsence => complete_or_observe_stop(input),
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

    fn context(carrier_minor: u16, action: HostAction, receipt_present: bool) -> ExecutionContext {
        ExecutionContext {
            carrier: ProtocolVersion::new(1, carrier_minor),
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
            DurableExecution::guardian_fixture(context(5, HostAction::Launch, false))
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
                CleanupProgress::AwaitingAbsence,
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (CleanupProgress::AwaitingAbsence, _, _) => DecisionShape::ObserveAgain,
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
                Some(StopProgress::AwaitingAbsence),
                ObservationKind::Absent,
                ObservationKind::Absent,
            ) => DecisionShape::Complete,
            (Some(StopProgress::AwaitingAbsence), _, _) => DecisionShape::ObserveAgain,
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

    #[test]
    fn carrier_and_signed_authority_versions_are_independent() {
        let actions = [
            HostAction::Launch,
            HostAction::Stop,
            HostAction::Freeze,
            HostAction::Thaw,
            HostAction::Kill,
        ];
        for minor in 1..=4 {
            for action in actions {
                assert_eq!(
                    signed_authority_version(ProtocolVersion::new(1, minor), action),
                    Some(ProtocolVersion::new(1, 1))
                );
            }
        }
        assert_eq!(
            signed_authority_version(ProtocolVersion::new(1, 5), HostAction::Launch),
            Some(ProtocolVersion::new(1, 5))
        );
        for action in [
            HostAction::Stop,
            HostAction::Freeze,
            HostAction::Thaw,
            HostAction::Kill,
        ] {
            assert_eq!(
                signed_authority_version(ProtocolVersion::new(1, 5), action),
                Some(ProtocolVersion::new(1, 1))
            );
        }
        assert_eq!(
            signed_authority_version(ProtocolVersion::new(2, 1), HostAction::Launch),
            None
        );
        assert_eq!(
            signed_authority_version(ProtocolVersion::new(1, 6), HostAction::Launch),
            None
        );
    }

    #[test]
    fn execution_authentication_binds_context_stable_authority_and_attempt_evidence() {
        let execution = DurableExecution::guardian_fixture(context(5, HostAction::Launch, false));
        let baseline_context = context(5, HostAction::Launch, false);
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
        changed.carrier = ProtocolVersion::new(1, 4);
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
    }

    #[test]
    fn execution_kind_matrix_rejects_impossible_action_pairs() {
        assert!(
            DurableExecution::current_legacy(ProtocolVersion::new(1, 4), HostAction::Launch)
                .is_some()
        );
        assert!(
            DurableExecution::current_legacy(ProtocolVersion::new(1, 5), HostAction::Launch)
                .is_none()
        );
        assert!(
            guardian_record(GuardianLaunchPhase::Authorized).validate(context(
                5,
                HostAction::Launch,
                false
            ))
        );
        assert!(
            !guardian_record(GuardianLaunchPhase::Authorized).validate(context(
                5,
                HostAction::Stop,
                false
            ))
        );
    }

    #[test]
    fn binding_is_recomputed_from_artifact_and_executable_content_evidence() {
        let original = evidence();
        assert!(original.validate(context(5, HostAction::Launch, false)));

        let mut changed_artifact = original.clone();
        changed_artifact.broker_plan[0] ^= 1;
        assert!(!changed_artifact.validate(context(5, HostAction::Launch, false)));

        let mut changed_executable = original;
        changed_executable.guardian_executable.sha256_content[0] ^= 1;
        assert!(!changed_executable.validate(context(5, HostAction::Launch, false)));
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
                digest: [43; 32],
            },
            WorkerProof {
                observation_sequence: 44,
                digest: [0; 32],
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
    fn cleanup_awaiting_absence_quarantines_foreign_units() {
        let binding = evidence().binding;
        let phase = GuardianLaunchPhase::CleanupIssued {
            payload: ExactUnitTarget::Exact {
                binding,
                invocation: [46; 16],
            },
            guardian: ExactUnitTarget::Absent,
            progress: CleanupProgress::AwaitingAbsence,
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
            CleanupProgress::AwaitingAbsence,
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
            Some(StopProgress::AwaitingAbsence),
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
            worker_proof_digest: [73; 32],
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
            .as_object_mut()
            .unwrap_or_else(|| panic!("execution JSON is not an object"))
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let unknown = serde_json::to_vec(&value)
            .unwrap_or_else(|error| panic!("cannot encode mutated execution: {error}"));
        assert!(serde_json::from_slice::<DurableExecution>(&unknown).is_err());
    }
}
