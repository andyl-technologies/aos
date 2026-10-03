//! Purpose-56 artifacts derived inside the original held Controller owner.
//!
//! The remote sealed-plan coordinates remain comparison data. The security
//! signer must additionally receive them on the original retained Mount flight;
//! these methods alone neither sign nor establish live Mount or read authority.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerAuthorizationArtifactsV1, BrokerDescriptorEntry, BrokerDescriptorRole,
    BrokerMethod, BrokerRequestEnvelope,
};
use aos_sandbox_core::{HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, encode_object_descriptor};
use aos_sandbox_protocol::fuse_worker_preparation::WorkerPreparationPlanV1;
use aos_sandbox_protocol::host_fuse_worker_session::{
    ValidatedHostFuseWorkerSessionRequestV1, decode_host_fuse_worker_session_request_v1,
};
use aos_sandbox_protocol::semantics::host_fuse_worker_session::canonical_host_fuse_worker_session_semantics_v1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use sha2::{Digest as _, Sha256};

use super::*;

impl CurrentControllerFuseIntentDispatchV1<'_> {
    /// Derives the exact Host worker plan from this still-held current owner.
    ///
    /// The complete worker plan is compared to actual accepted desired/View,
    /// assignment, Policy and signed ownership. Its physical slot/reservation
    /// and original signed-request join remain the retained Mount flight's job.
    /// No ordinary Attach capability is promoted into content-read authority.
    ///
    /// # Errors
    ///
    /// Rejects stale custody, substituted scope or plan, extended deadlines,
    /// changed ownership and malformed canonical method-49 bytes.
    pub fn host_worker_plan_at<T>(
        &mut self,
        body: &[u8],
        worker: &WorkerPreparationPlanV1,
        clock: &mut T,
    ) -> Result<BrokerAuthorizationPlan, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        self.recheck(clock)?;
        let scope = self.prepared.target.runtime_generation().scope();
        let (lease, fresh) = scope.verified_plan_lease(self.journal, clock)?;
        let request = compare_worker_request(body, worker, fresh.boottime_nanoseconds())?;
        let accepted = aos_sandbox_core::format::decode_ownership_lease(
            lease.canonical_lease(),
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        let (_, ownership_limit) = scope.attachment_lease_bounds(self.journal, clock)?;
        let wall_limit =
            ownership_limit.min(self.prepared.desired.intent().lease().expires_seconds());
        let remaining = wall_limit
            .checked_sub(fresh.wall_seconds())
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .and_then(|duration| fresh.boottime_nanoseconds().checked_add(duration))
            .ok_or(ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        let descriptor_digest = |descriptor: &aos_sandbox_core::ObjectDescriptor| -> [u8; 32] {
            Sha256::digest(encode_object_descriptor(descriptor)).into()
        };
        if request.fence() != self.request.fence()
            || worker.kernel_boot != fresh.host_boot_id()
            || worker.assignment != *self.request.fence().assignment_digest()
            || worker.attachment != *self.request.desired_record_digest()
            || worker.original_view_descriptor != descriptor_digest(self.request.intent().view())
            || worker.resolved_policy_descriptor
                != descriptor_digest(self.request.accepted_policy())
            || worker.ownership_lease != *accepted.renewal_nonce()
            || worker.ownership_lease_expires_boottime_ns > remaining
            || worker.preparation_deadline_boottime_ns
                != self.request.header().deadline_boottime_nanoseconds()
        {
            return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
        }
        let semantics = canonical_host_fuse_worker_session_semantics_v1(&request)
            .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        let grant = BrokerGrant::new(
            semantics.verb(),
            semantics.target(),
            semantics.commitment(),
            body.len() as u32,
            4,
        )?;
        let manifest = scope.binding().manifest().manifest();
        let plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Host,
            ProtocolId::HostBroker,
            ProtocolVersion::new(1, 0),
            scope
                .binding()
                .manifest()
                .broker_assignment()
                .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
            manifest.node(),
            lease.signer().clone(),
            vec![grant],
            manifest.policy().digest(),
            scope.host_worker_plan_revocation_scope(),
            fresh.wall_seconds(),
            scope.expires_wall_seconds().min(wall_limit),
            vec![
                FeatureRef::new(HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE, 1, 0)
                    .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?,
            ],
        )?;
        self.recheck(clock)?;
        Ok(plan)
    }

    /// Rebinds a signed Host worker plan and carries the exact original quartet.
    ///
    /// This dedicated four-role carrier leaves the generic outbound one-FD
    /// allowlist unchanged. An envelope is still DATA until the real Mount
    /// owner and authenticated Host session retain and deliver its original FDs.
    ///
    /// # Errors
    ///
    /// Rejects changed current resources, another grant or signer, an extended
    /// lease/plan or a substituted exact body/sealed-plan comparison.
    pub fn host_worker_envelope_at<T>(
        &mut self,
        body: &[u8],
        worker: &WorkerPreparationPlanV1,
        signed: &SignedBrokerPlan,
        clock: &mut T,
    ) -> Result<BrokerRequestEnvelope, ControllerFuseIntentDispatchErrorV1>
    where
        T: FnMut() -> Result<RawPairedClockSample, ProtectedOwnershipClockError>,
    {
        let expected = self.host_worker_plan_at(body, worker, clock)?;
        let retained = aos_sandbox_core::format::decode_broker_authorization_plan(
            signed.canonical_plan(),
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        if retained.expires_seconds() > expected.expires_seconds() {
            return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
        }
        let scope = self.prepared.target.runtime_generation().scope();
        let (lease, fresh) = scope.verified_plan_lease(self.journal, clock)?;
        let request = compare_worker_request(body, worker, fresh.boottime_nanoseconds())?;
        let semantics = canonical_host_fuse_worker_session_semantics_v1(&request)
            .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
        scope.verify_host_worker_plan(
            self.journal,
            signed,
            BrokerPlanRequest {
                verb: semantics.verb(),
                target: semantics.target(),
                argument_commitment: semantics.commitment(),
                request_bytes: body.len() as u32,
                descriptor_count: 4,
            },
            clock,
        )?;
        let roles = [
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_PLAN_V1,
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_CONNECTION_V1,
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_RECORDS_V1,
            BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_FUSE_WORKER_CANCELLATION_V1,
        ];
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1.into(),
            body: body.to_vec(),
            descriptors: roles
                .into_iter()
                .enumerate()
                .map(|(index, role)| BrokerDescriptorEntry {
                    index: index as u32,
                    role: role.into(),
                    ..Default::default()
                })
                .collect(),
            authorization: Some(BrokerAuthorizationArtifactsV1 {
                broker_plan: signed.canonical_plan().to_vec(),
                broker_plan_signature: signed.canonical_signature().to_vec(),
                ownership_lease: lease.canonical_lease().to_vec(),
                ownership_lease_signature: lease.canonical_signature().to_vec(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        self.recheck(clock)?;
        Ok(envelope)
    }
}

pub(super) fn compare_worker_request(
    body: &[u8],
    worker: &WorkerPreparationPlanV1,
    now: u64,
) -> Result<ValidatedHostFuseWorkerSessionRequestV1, ControllerFuseIntentDispatchErrorV1> {
    // RootMount values select a structural grammar only. This is not a peer
    // identity observation; actual record/service proof stays in the flight.
    let request = decode_host_fuse_worker_session_request_v1(
        body,
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        },
        now,
    )
    .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?;
    if request.worker_instance() != worker.worker_instance
        || request.reservation_commitment() != worker.mount_reservation
        || request.plan_digest()
            != worker
                .digest()
                .map_err(|_| ControllerFuseIntentDispatchErrorV1::CurrentMismatch)?
        || request.header().deadline_boottime_nanoseconds()
            > worker.preparation_deadline_boottime_ns
    {
        return Err(ControllerFuseIntentDispatchErrorV1::CurrentMismatch);
    }
    Ok(request)
}
