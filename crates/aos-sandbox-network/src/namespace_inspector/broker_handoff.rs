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
use super::store::{BrokerExpectedAttemptPublisher, InspectorProtectedStorePublishError};
use super::{
    BrokerLifecycleWorkerInspectionContextV1, ExpectedInspectorAttemptV1,
    InspectorProcessIdentityV1, InspectorTrustedClockV1, MAXIMUM_INSPECTOR_EXCHANGE_NS,
    NetworkNamespaceInspectorError, PendingLifecycleWorkerInspectionV1,
    ValidatedLifecycleWorkerLeaderV1, validate_fresh_time,
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

/// Preserves publication recovery evidence while the broker retains READY custody.
#[derive(Debug, Error)]
pub(crate) enum BrokerInspectorPublicationErrorV1<'root> {
    /// The retained READY worker, signed deployment, or clock changed.
    #[error(transparent)]
    Handoff(#[from] BrokerInspectorHandoffErrorV1),
    /// The protected store retains exact private/final inode recovery evidence.
    #[error("protected expected publication failed: {0}")]
    Publication(InspectorProtectedStorePublishError<'root>),
    /// Durable readback did not match the precise pending record.
    #[error("Network inspector published attempt changed during readback")]
    ReadbackMismatch,
}

/// Borrows the exact READY pidfd and cgroup with its one-use pending record.
#[derive(Debug)]
pub(crate) struct PreparedBrokerInspectorHandoffV1<'ready> {
    pending: PendingLifecycleWorkerInspectionV1,
    subject: &'ready KernelAuthorizedRecordSubject,
    worker_cgroup: &'ready RetainedCgroupAnchor,
}

/// Keeps the published record tied to the same READY pidfd and cgroup.
#[derive(Debug)]
pub(crate) struct PublishedBrokerInspectorHandoffV1<'ready> {
    pending: PendingLifecycleWorkerInspectionV1,
    subject: &'ready KernelAuthorizedRecordSubject,
    worker_cgroup: &'ready RetainedCgroupAnchor,
}

impl<'ready> PreparedBrokerInspectorHandoffV1<'ready> {
    /// Derives one fresh attempt from a previously validated READY subject.
    ///
    /// The handoff borrows the subject and cgroup until it is consumed.
    /// The worker is rechecked before and after construction; neither snapshot
    /// alone grants a currentness decision at a later dispatch boundary.
    ///
    /// # Errors
    ///
    /// Rejects absent or changed signed policy, an expired or invalid clock,
    /// invalid nonce, altered pidfd/cgroup membership, or a mismatched leader.
    pub(crate) fn prepare(
        subject: &'ready KernelAuthorizedRecordSubject,
        worker_cgroup: &'ready RetainedCgroupAnchor,
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
            ObjectDigest::from_bytes(deployment.lifecycle_worker_launch_digest()?),
            nonce,
            now.boot_id,
            now.boottime_ns,
            deadline,
        )?;

        validate_retained_worker(subject, worker_cgroup)?;
        deployment.revalidate()?;
        validate_fresh_time(&pending.expected, clock.observe()?)?;
        Ok(Self {
            pending,
            subject,
            worker_cgroup,
        })
    }

    /// Publishes one exact expected record after fresh READY and policy checks.
    ///
    /// This source-level transition is not an activation permit. Production
    /// cannot invoke it until the protected broker/inspector MAC and socket
    /// activation proof is available; a failed publication must not be retried
    /// or have its retained recovery evidence silently discarded.
    ///
    /// # Errors
    ///
    /// Rejects a stale or substituted worker, changed deployment credential,
    /// elapsed deadline, no-replace replay, or inexact durable readback.
    pub(crate) fn publish<'root>(
        self,
        publisher: &'root BrokerExpectedAttemptPublisher,
        deployment: &ProtectedInspectorDeploymentV2,
        clock: &mut impl InspectorTrustedClockV1,
    ) -> Result<PublishedBrokerInspectorHandoffV1<'ready>, BrokerInspectorPublicationErrorV1<'root>>
    {
        publish_exact_after_rechecks(
            &self.pending.expected,
            || {
                revalidate_pending(
                    &self.pending,
                    self.subject,
                    self.worker_cgroup,
                    deployment,
                    clock,
                )
                .map_err(Into::into)
            },
            |expected| {
                publisher
                    .publish(expected)
                    .map_err(BrokerInspectorPublicationErrorV1::Publication)
            },
        )?;

        Ok(PublishedBrokerInspectorHandoffV1 {
            pending: self.pending,
            subject: self.subject,
            worker_cgroup: self.worker_cgroup,
        })
    }

    /// Permanently rejects activation from an unpublished pending attempt.
    ///
    /// The source-level publisher and response receiver cannot supply that
    /// proof without a broker-owned protected root and an enforcing MAC policy.
    ///
    /// # Errors
    ///
    /// Always rejects. Only a published handoff may gain a future activation
    /// witness; this prepared-state gate must not be relaxed to accept one.
    pub(crate) fn reject_unpublished_activation(self) -> Result<(), BrokerInspectorHandoffErrorV1> {
        let _ = (self.pending, self.subject, self.worker_cgroup);
        Err(BrokerInspectorHandoffErrorV1::ActivationProofUnavailable)
    }
}

impl<'ready> PublishedBrokerInspectorHandoffV1<'ready> {
    /// Rejects response dispatch until authenticated activation is proved.
    ///
    /// # Errors
    ///
    /// Always rejects; no production activation witness can currently be made.
    pub(crate) fn require_authenticated_activation(
        self,
    ) -> Result<(), BrokerInspectorHandoffErrorV1> {
        let _ = (self.pending, self.subject, self.worker_cgroup);
        Err(BrokerInspectorHandoffErrorV1::ActivationProofUnavailable)
    }
}

fn revalidate_pending(
    pending: &PendingLifecycleWorkerInspectionV1,
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    deployment: &ProtectedInspectorDeploymentV2,
    clock: &mut impl InspectorTrustedClockV1,
) -> Result<(), BrokerInspectorHandoffErrorV1> {
    if validate_retained_worker(subject, worker_cgroup)? != pending.expected.process
        || ObjectDigest::from_bytes(deployment.lifecycle_worker_launch_digest()?)
            != pending.expected.launch_contract_digest
    {
        return Err(BrokerInspectorHandoffErrorV1::WorkerMismatch);
    }
    deployment.service_launch(false)?;
    deployment.service_launch(true)?;
    deployment.revalidate()?;
    validate_fresh_time(&pending.expected, clock.observe()?)?;
    Ok(())
}

fn publish_exact_after_rechecks<'root>(
    expected: &ExpectedInspectorAttemptV1,
    mut recheck: impl FnMut() -> Result<(), BrokerInspectorPublicationErrorV1<'root>>,
    mut publish: impl FnMut(
        &ExpectedInspectorAttemptV1,
    ) -> Result<
        ExpectedInspectorAttemptV1,
        BrokerInspectorPublicationErrorV1<'root>,
    >,
) -> Result<(), BrokerInspectorPublicationErrorV1<'root>> {
    recheck()?;
    if publish(expected)? != *expected {
        return Err(BrokerInspectorPublicationErrorV1::ReadbackMismatch);
    }
    recheck()
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
    fn only_published_handoff_has_the_activation_method() {
        fn assert_separate_gate_types<'ready>() {
            let _reject_unpublished: fn(
                PreparedBrokerInspectorHandoffV1<'ready>,
            ) -> Result<(), BrokerInspectorHandoffErrorV1> =
                PreparedBrokerInspectorHandoffV1::reject_unpublished_activation;
            let _activate_published: fn(
                PublishedBrokerInspectorHandoffV1<'ready>,
            ) -> Result<(), BrokerInspectorHandoffErrorV1> =
                PublishedBrokerInspectorHandoffV1::require_authenticated_activation;
        }

        assert_separate_gate_types();
    }

    #[test]
    fn publisher_rechecks_foreign_worker_before_writing() {
        let expected = super::super::tests::pending(4).expected;
        let mut published = false;

        let result = publish_exact_after_rechecks(
            &expected,
            || Err(BrokerInspectorHandoffErrorV1::WorkerMismatch.into()),
            |_| {
                published = true;
                Ok(expected.clone())
            },
        );

        assert!(matches!(
            result,
            Err(BrokerInspectorPublicationErrorV1::Handoff(
                BrokerInspectorHandoffErrorV1::WorkerMismatch
            ))
        ));
        assert!(!published);
    }

    #[test]
    fn publisher_rechecks_deadline_after_exact_readback() {
        let expected = super::super::tests::pending(5).expected;
        let mut checks = 0;
        let mut publications = 0;

        let result = publish_exact_after_rechecks(
            &expected,
            || {
                checks += 1;
                if checks == 2 {
                    Err(BrokerInspectorHandoffErrorV1::Attempt(
                        NetworkNamespaceInspectorError::Stale,
                    )
                    .into())
                } else {
                    Ok(())
                }
            },
            |record| {
                publications += 1;
                Ok(record.clone())
            },
        );

        assert!(matches!(
            result,
            Err(BrokerInspectorPublicationErrorV1::Handoff(
                BrokerInspectorHandoffErrorV1::Attempt(NetworkNamespaceInspectorError::Stale)
            ))
        ));
        assert_eq!((checks, publications), (2, 1));
    }

    #[test]
    fn publisher_rejects_foreign_readback_without_second_action() {
        let expected = super::super::tests::pending(6).expected;
        let mut checks = 0;

        let result = publish_exact_after_rechecks(
            &expected,
            || {
                checks += 1;
                Ok(())
            },
            |record| {
                let mut foreign = record.clone();
                foreign.nonce[0] ^= 1;
                Ok(foreign)
            },
        );

        assert!(matches!(
            result,
            Err(BrokerInspectorPublicationErrorV1::ReadbackMismatch)
        ));
        assert_eq!(checks, 1);
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
