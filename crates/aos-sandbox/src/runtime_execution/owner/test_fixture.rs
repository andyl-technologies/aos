//! Test-only protected Host owner provisioning through the normal peer writer.
//!
//! The fixed identities support cross-crate Host admission fixtures. They are
//! never production bootstrap authority, and this module is absent from
//! release builds.

use std::path::Path;

use aos_sandbox_core::runtime_backend::{
    BackendCapabilitiesV1, BackendProbeCurrentnessV1, RequiredBackendCapabilitiesV1,
    ResolvedRuntimePlanV1, RuntimeCurrentnessV1, RuntimeHandleCommitmentV1,
};
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, NodeId, ObjectDigest,
    ObservationSequence, PayloadBootId, Revision, SandboxId,
};
use aos_sandbox_linux::boot::KernelBootId;
use ed25519_dalek::SigningKey;

use super::{
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionOwnerV1,
    DormantRuntimeExecutionProvisionerV1, DormantRuntimeExecutionProvisioningTransitionV1,
    DormantRuntimeExecutionProvisioningV1, Journal, JournalLimits, PEER_JOURNAL_NAME,
};

impl DormantRuntimeExecutionOwnerV1 {
    /// Provisions and opens a fixed test owner through the normal atomic peer writer.
    ///
    /// The generated identities are test-only and cannot establish production
    /// bootstrap authority. Unlike direct journal seeding, this path retains
    /// the provisioner's preflight, transaction, and commit-ambiguity rules.
    ///
    /// # Errors
    ///
    /// Rejects unsafe protected journals, invalid fixture currentness, or an
    /// ambiguous or conflicting provisioning append.
    #[doc(hidden)]
    pub fn provisioned_protected_at_uid_for_test(
        directory: &Path,
        expected_uid: u32,
    ) -> Result<Self, DormantRuntimeExecutionOwnerErrorV1> {
        let currentness = RuntimeCurrentnessV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            NodeId::from_bytes([3; 16]),
            AssignmentEpoch::new(4),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(6),
            NamespaceGeneration::new(7),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let plan = ResolvedRuntimePlanV1::new(
            currentness,
            RequiredBackendCapabilitiesV1::new(Vec::new())
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            ObjectDigest::from_bytes([20; 32]),
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let runtime = RuntimeHandleCommitmentV1::new(
            currentness,
            plan.plan_commitment(),
            ObjectDigest::from_bytes([24; 32]),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let probe = BackendProbeCurrentnessV1::new(
            NodeId::from_bytes([3; 16]),
            ObjectDigest::from_bytes([10; 32]),
            Revision::new(11),
            ObjectDigest::from_bytes([12; 32]),
        )
        .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?;
        let boot = KernelBootId::current()
            .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?
            .into_bytes();
        let provisioning = DormantRuntimeExecutionProvisioningV1::new(
            SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
            ObjectDigest::from_bytes([13; 32]),
            ObservationSequence::new(14),
            runtime,
            PayloadBootId::new([15; 16])
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            probe,
            BackendCapabilitiesV1::new(Vec::new())
                .map_err(|_| DormantRuntimeExecutionOwnerErrorV1::MalformedCurrentness)?,
            ObjectDigest::from_bytes([16; 32]),
            ObjectDigest::from_bytes([17; 32]),
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            ObjectDigest::from_bytes([18; 32]),
            ObjectDigest::from_bytes([19; 32]),
            boot,
            plan,
        )?;
        let (journal, _) = Journal::open_protected_at_uid(
            directory,
            PEER_JOURNAL_NAME,
            JournalLimits::default(),
            expected_uid,
        )?;
        match (DormantRuntimeExecutionProvisionerV1 { journal }).provision(provisioning)? {
            DormantRuntimeExecutionProvisioningTransitionV1::Committed(_) => {}
            DormantRuntimeExecutionProvisioningTransitionV1::RecoveryRequired(_) => {
                return Err(DormantRuntimeExecutionOwnerErrorV1::BootstrapOutcomeUnknown);
            }
        }
        Self::open_protected_at_uid_for_test(directory, expected_uid)
    }
}
