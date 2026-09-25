//! Closed production handoff from a retained lifecycle READY to inspection.
//!
//! This precursor binds a new attempt to the SCM-nominated worker pidfd, its
//! exact cgroup, the broker's challenge and namespace descriptors, and the
//! signed V2/V3 deployment. It cannot authorize dispatch: no production owner
//! yet proves the Accept=yes activation and protected publication custody.

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::NamespaceIdentity;
use aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject;
use thiserror::Error;

pub(crate) use super::production::KernelInspectorClock;
use super::{
    BrokerLifecycleWorkerInspectionContextV1, InspectorProcessIdentityV1, InspectorTrustedClockV1,
    MAXIMUM_INSPECTOR_EXCHANGE_NS, NetworkNamespaceInspectorError,
    PendingLifecycleWorkerInspectionV1, ValidatedLifecycleWorkerLeaderV1, validate_fresh_time,
};
use crate::inspector_deployment::{InspectorDeploymentErrorV2, ProtectedInspectorDeploymentV2};
use crate::lifecycle_worker_process::NetworkLifecycleWorkerChallengeV1;

/// Reports an unavailable or inconsistent production inspector handoff.
#[derive(Debug, Error)]
pub enum BrokerInspectorHandoffErrorV1 {
    /// The broker has no signed deployment to bind this attempt.
    #[error("Network inspector signed deployment is unavailable")]
    DeploymentUnavailable,
    /// The signed deployment or selected service load graph changed.
    #[error(transparent)]
    Deployment(#[from] InspectorDeploymentErrorV2),
    /// The retained worker pidfd or exact cgroup failed revalidation.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The READY subject was not the same live worker leader.
    #[error("Network inspector worker custody changed after READY")]
    WorkerMismatch,
    /// The boot clock or canonical expected record was invalid.
    #[error(transparent)]
    Attempt(#[from] NetworkNamespaceInspectorError),
    /// No production proof binds protected publication to this activation.
    #[error("Network inspector activation and publication custody is unproved")]
    ActivationProofUnavailable,
}

/// Retains the exact pending record while the original pidfd and cgroup stay held.
#[derive(Debug)]
pub(crate) struct PreparedBrokerInspectorHandoffV1 {
    pending: PendingLifecycleWorkerInspectionV1,
}

impl PreparedBrokerInspectorHandoffV1 {
    /// Derives one fresh attempt from a previously validated READY subject.
    ///
    /// The caller retains the subject and cgroup until this handoff is consumed.
    /// The worker is rechecked before and after construction; neither snapshot
    /// alone grants a currentness decision at a later dispatch boundary.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed signed policy, an expired or invalid clock,
    /// invalid nonce, altered pidfd/cgroup membership, or a mismatched leader.
    pub(crate) fn prepare(
        subject: &KernelAuthorizedRecordSubject,
        worker_cgroup: &RetainedCgroupAnchor,
        cgroup_name: &str,
        challenge: NetworkLifecycleWorkerChallengeV1,
        host_namespace: NamespaceIdentity,
        target_namespace: NamespaceIdentity,
        deployment: Option<&ProtectedInspectorDeploymentV2>,
        nonce: [u8; 32],
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<Self, BrokerInspectorHandoffErrorV1> {
        let deployment = deployment.ok_or(BrokerInspectorHandoffErrorV1::DeploymentUnavailable)?;
        deployment.service_launch(false)?;
        deployment.service_launch(true)?;

        let process = validate_retained_worker(subject, worker_cgroup)?;
        let now = clock.observe()?;
        let deadline = now
            .boottime_ns
            .checked_add(MAXIMUM_INSPECTOR_EXCHANGE_NS)
            .ok_or(NetworkNamespaceInspectorError::Stale)?;
        let pending = PendingLifecycleWorkerInspectionV1::from_validated_ready_with_digest(
            ValidatedLifecycleWorkerLeaderV1 {
                process,
                cgroup: cgroup_name.to_owned(),
                request_id: challenge.request_id(),
                effect_digest: challenge.effect_digest(),
                dispatch_digest: challenge.dispatch_digest(),
            },
            BrokerLifecycleWorkerInspectionContextV1 {
                forbidden_host: host_namespace,
                forbidden_target: target_namespace,
            },
            ObjectDigest::from_bytes(deployment.inspector_v1_contract_digest()),
            nonce,
            now.boot_id,
            now.boottime_ns,
            deadline,
        )?;

        validate_retained_worker(subject, worker_cgroup)?;
        deployment.revalidate()?;
        validate_fresh_time(&pending.expected, clock.observe()?)?;
        Ok(Self { pending })
    }

    /// Closes production dispatch until activation and publication have proof.
    ///
    /// The source-level publisher and response receiver cannot supply that
    /// proof without a broker-owned protected root and an enforcing MAC policy.
    ///
    /// # Errors
    ///
    /// Always rejects; this type has no positive production completion path.
    pub(crate) fn require_authenticated_activation(
        self,
    ) -> Result<(), BrokerInspectorHandoffErrorV1> {
        let _pending = self.pending;
        Err(BrokerInspectorHandoffErrorV1::ActivationProofUnavailable)
    }
}

fn validate_retained_worker(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<InspectorProcessIdentityV1, BrokerInspectorHandoffErrorV1> {
    let credentials = subject.credentials();
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info != subject.initial_info()
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != info.pid()
        || !subject.is_alive()?
    {
        return Err(BrokerInspectorHandoffErrorV1::WorkerMismatch);
    }
    worker_cgroup.validate_current()?;
    Ok(InspectorProcessIdentityV1 {
        pid: info.pid(),
        thread_group_id: info.thread_group_id(),
        parent_pid: info.parent_pid(),
        cgroup_id: info
            .cgroup_id()
            .ok_or(BrokerInspectorHandoffErrorV1::WorkerMismatch)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_attempt_cannot_authorize_unproved_activation() {
        let handoff = PreparedBrokerInspectorHandoffV1 {
            pending: super::super::tests::pending(4),
        };
        assert!(matches!(
            handoff.require_authenticated_activation(),
            Err(BrokerInspectorHandoffErrorV1::ActivationProofUnavailable)
        ));
    }

    #[test]
    fn ready_attempt_rejects_substituted_contract_and_namespace_context() {
        let expected = super::super::tests::pending(5).expected;
        let leader = || ValidatedLifecycleWorkerLeaderV1 {
            process: expected.process,
            cgroup: expected.cgroup.clone(),
            request_id: expected.request_id,
            effect_digest: expected.effect_digest,
            dispatch_digest: expected.dispatch_digest,
        };
        let context = || BrokerLifecycleWorkerInspectionContextV1 {
            forbidden_host: expected.forbidden_host,
            forbidden_target: expected.forbidden_target,
        };

        assert!(matches!(
            PendingLifecycleWorkerInspectionV1::from_validated_ready_with_digest(
                leader(),
                context(),
                ObjectDigest::from_bytes([0; 32]),
                expected.nonce,
                expected.boot_id,
                expected.not_before_boottime_ns,
                expected.deadline_boottime_ns,
            ),
            Err(NetworkNamespaceInspectorError::Protocol(_))
        ));
        assert!(matches!(
            PendingLifecycleWorkerInspectionV1::from_validated_ready_with_digest(
                leader(),
                BrokerLifecycleWorkerInspectionContextV1 {
                    forbidden_host: expected.forbidden_host,
                    forbidden_target: expected.forbidden_host,
                },
                expected.launch_contract_digest,
                expected.nonce,
                expected.boot_id,
                expected.not_before_boottime_ns,
                expected.deadline_boottime_ns,
            ),
            Err(NetworkNamespaceInspectorError::Protocol(_))
        ));
    }
}
