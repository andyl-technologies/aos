//! Permanent, location-authenticated escrow before an original worker launch.
//!
//! The optional Host snapshot table carries version-one bindings and their
//! request-location MAC. A row means reconciliation is required, not that a
//! process launched or that a received FD reconstructs original custody.
//! Nothing retires a row, rearms a locator or adopts a process from this table.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker::VerifiedBrokerAdmission;
use aos_sandbox_core::{BrokerGrantTarget, BrokerResourceHandle, BrokerVerb};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerRequestDirectionV1;
use aos_sandbox_protocol::host_fuse_worker_session::ValidatedHostFuseWorkerSessionRequestV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{HostState, MAXIMUM_REQUESTS};
use crate::authorization::HostAuthorityV1;
use crate::{HostError, Result};

const DOMAIN: &[u8] = b"aos.host.original-fuse-worker-launch.v1\0";
const MAXIMUM_ESCROW_FIELD_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableFuseWorkerLaunchV1 {
    binding: Binding,
    authentication: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u16,
    request_id: [u8; 16],
    sandbox: [u8; 16],
    worker: [u8; 16],
    boot: [u8; 16],
    plan: [u8; 32],
    reservation: [u8; 32],
    body_digest: [u8; 32],
    signed_request: [u8; 32],
    session: [u8; 32],
    base_fence: Vec<u8>,
    phase_fence: Vec<u8>,
    effect: Vec<u8>,
}

impl DurableFuseWorkerLaunchV1 {
    pub(super) const fn request_id(&self) -> [u8; 16] {
        self.binding.request_id
    }

    fn payload(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(
            &serde_json::to_vec(&self.binding)
                .map_err(|error| HostError::State(error.to_string()))?,
        );
        Ok(bytes)
    }

    pub(super) fn validate_shape(&self) -> Result<()> {
        let b = &self.binding;
        if b.version != 1
            || [b.request_id, b.sandbox, b.worker, b.boot].contains(&[0; 16])
            || [
                b.plan,
                b.reservation,
                b.body_digest,
                b.signed_request,
                b.session,
            ]
            .contains(&[0; 32])
            || [
                &b.base_fence,
                &b.phase_fence,
                &b.effect,
                &self.authentication,
            ]
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > MAXIMUM_ESCROW_FIELD_BYTES)
        {
            return Err(HostError::Fence(
                "original worker launch escrow is malformed",
            ));
        }
        Ok(())
    }

    fn validate_authenticated(&self, authority: &HostAuthorityV1) -> Result<()> {
        self.validate_shape()?;
        let b = &self.binding;
        if authority.open_execution_record(&b.request_id, &self.authentication)?
            != self.payload()?
        {
            return Err(HostError::Fence(
                "original worker launch escrow MAC changed",
            ));
        }
        let effect = authority.open_effect(&b.request_id, &b.effect)?;
        let base = authority.open_fence(&b.sandbox, &b.base_fence)?;
        let phase = authority.open_fence(&b.sandbox, &b.phase_fence)?;
        if effect.verb() != BrokerVerb::HostPrepareFuseWorkerSession
            || effect.transport_request_digest().as_bytes() != &b.body_digest
            || phase.assignment() != base.assignment()
            || phase.local_lease_record() != base.local_lease_record()
            || phase.assignment().sandbox().as_bytes() != &b.sandbox
            || phase.local_lease_record() != effect.local_lease_record()
            || phase.plan_digest() != effect.plan_digest()
            || effect.host_boot_id() != &b.boot
            || effect.target()
                != BrokerGrantTarget::Resource(
                    BrokerResourceHandle::from_bytes(b.reservation)
                        .map_err(|_| HostError::Fence("worker reservation target is malformed"))?,
                )
        {
            return Err(HostError::Fence(
                "original worker launch escrow join changed",
            ));
        }
        Ok(())
    }
}

impl HostState {
    pub(super) fn validate_fuse_worker_launches(&self, authority: &HostAuthorityV1) -> Result<()> {
        let mut workers = std::collections::BTreeSet::new();
        for (request, record) in &self.fuse_worker_launches {
            if request != &record.request_id()
                || self.requests.contains_key(request)
                || !workers.insert(record.binding.worker)
            {
                return Err(HostError::Fence(
                    "worker escrow aliases another Host request",
                ));
            }
            record.validate_authenticated(authority)?;
        }
        Ok(())
    }

    pub(crate) fn require_request_not_worker_escrow(&self, request: &[u8; 16]) -> Result<()> {
        if self.fuse_worker_launches.contains_key(request) {
            return Err(HostError::Fence(
                "original worker request requires reconciliation",
            ));
        }
        Ok(())
    }

    pub(crate) fn retain_original_fuse_worker_launch(
        &mut self,
        original: &AuthenticatedBrokerMethodRequestV1,
        request: &ValidatedHostFuseWorkerSessionRequestV1,
        admitted: &VerifiedBrokerAdmission,
        base_fence: Vec<u8>,
        boot: [u8; 16],
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        let id = *request.header().request_id();
        if self.requests.contains_key(&id)
            || self.fuse_worker_launches.contains_key(&id)
            || self
                .fuse_worker_launches
                .values()
                .any(|row| row.binding.worker == request.worker_instance())
        {
            return Err(HostError::Fence(
                "worker request/locator requires reconciliation",
            ));
        }
        if self.fuse_worker_launches.len() + self.requests.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::ResourceExhausted);
        }
        if original.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || original.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_FUSE_WORKER_SESSION_V1
            || original.request_id() != id
            || original.exact_body().is_empty()
            || <[u8; 32]>::from(Sha256::digest(original.exact_body()))
                != *admitted.effect.transport_request_digest().as_bytes()
            || original.semantic_commitment() != *admitted.effect.request_digest().as_bytes()
            || original.deadline_boottime_nanoseconds()
                != request.header().deadline_boottime_nanoseconds()
            || admitted.effect.request_id() != &id
            || admitted.fence.assignment()
                != request
                    .fence()
                    .broker_assignment()
                    .map_err(|_| HostError::Fence("worker assignment is malformed"))?
        {
            return Err(HostError::Fence("original worker request differs"));
        }
        let mut row = DurableFuseWorkerLaunchV1 {
            binding: Binding {
                version: 1,
                request_id: id,
                sandbox: *request.fence().sandbox_id(),
                worker: request.worker_instance(),
                boot,
                plan: request.plan_digest(),
                reservation: request.reservation_commitment(),
                body_digest: *admitted.effect.transport_request_digest().as_bytes(),
                signed_request: original.signed_request_digest(),
                session: original.session_binding(),
                base_fence,
                phase_fence: authority.seal_fence(request.fence().sandbox_id(), &admitted.fence)?,
                effect: authority.seal_effect(&id, &admitted.effect)?,
            },
            authentication: Vec::new(),
        };
        row.authentication = authority.seal_execution_record(&id, &row.payload()?)?;
        row.validate_authenticated(authority)?;
        self.fuse_worker_launches.insert(id, row);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn assert_signed_escrow_currentness_regressions(
    authority: &HostAuthorityV1,
    request: &ValidatedHostFuseWorkerSessionRequestV1,
    admitted: &VerifiedBrokerAdmission,
    base_fence: Vec<u8>,
) {
    // The phase and effect come from real signed purpose-56 admission. These
    // fixed transcript commitments test storage authentication only; they do
    // not replace the production constructor's genuine received-request join.
    let id = *request.header().request_id();
    let mut row = DurableFuseWorkerLaunchV1 {
        binding: Binding {
            version: 1,
            request_id: id,
            sandbox: *request.fence().sandbox_id(),
            worker: request.worker_instance(),
            boot: *admitted.effect.host_boot_id(),
            plan: request.plan_digest(),
            reservation: request.reservation_commitment(),
            body_digest: *admitted.effect.transport_request_digest().as_bytes(),
            signed_request: [121; 32],
            session: [122; 32],
            base_fence,
            phase_fence: authority
                .seal_fence(request.fence().sandbox_id(), &admitted.fence)
                .unwrap(),
            effect: authority.seal_effect(&id, &admitted.effect).unwrap(),
        },
        authentication: Vec::new(),
    };
    row.authentication = authority
        .seal_execution_record(&id, &row.payload().unwrap())
        .unwrap();
    row.validate_authenticated(authority).unwrap();

    for case in 0..8 {
        let mut changed = row.clone();
        match case {
            0 => changed.binding.request_id[0] ^= 1,
            1 => changed.binding.worker[0] ^= 1,
            2 => changed.binding.plan[0] ^= 1,
            3 => changed.binding.session[0] ^= 1,
            4 => changed.binding.signed_request[0] ^= 1,
            5 => changed.binding.body_digest[0] ^= 1,
            6 => changed.binding.reservation[0] ^= 1,
            7 => changed.authentication[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            changed.validate_authenticated(authority).is_err(),
            "MAC substitution {case}"
        );
    }
    assert!(
        authority
            .open_execution_record(&[123; 16], &row.authentication)
            .is_err()
    );

    let mut expected = HostState::default();
    expected.fuse_worker_launches.insert(id, row);
    expected.validate_authenticated(authority).unwrap();
    let recovered = HostState::decode(&expected.encode().unwrap()).unwrap();
    recovered.validate_authenticated(authority).unwrap();
    assert_eq!(recovered, expected);
    assert!(recovered.require_request_not_worker_escrow(&id).is_err());
    assert!(recovered.query_effect(&id, request.plan_digest()).is_err());
    assert!(recovered.query_effect(&id, [124; 32]).is_err());

    let mut relocated = recovered.clone();
    let retained = relocated.fuse_worker_launches.remove(&id).unwrap();
    relocated.fuse_worker_launches.insert([123; 16], retained);
    assert!(relocated.validate_authenticated(authority).is_err());

    use super::{FileHostStateStore, HostStateStore, require_current_worker_snapshot};
    use std::os::unix::fs::PermissionsExt as _;

    let parent = tempfile::tempdir().unwrap();
    let named = parent.path().join("state");
    let displaced = parent.path().join("old-state");
    std::fs::create_dir(&named).unwrap();
    std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o700)).unwrap();
    let writer = FileHostStateStore::open_exclusive(&named).unwrap();
    writer.commit(&expected).unwrap();
    require_current_worker_snapshot(&writer, &expected, authority).unwrap();

    // Every check uses the same actual protected store, as a resumed async
    // launch does. Neither missing state nor another valid snapshot is absence.
    std::fs::remove_file(named.join("state.bin")).unwrap();
    assert!(require_current_worker_snapshot(&writer, &expected, authority).is_err());
    writer.commit(&HostState::default()).unwrap();
    assert!(require_current_worker_snapshot(&writer, &expected, authority).is_err());
    writer.commit(&expected).unwrap();
    require_current_worker_snapshot(&writer, &expected, authority).unwrap();

    std::fs::rename(&named, &displaced).unwrap();
    std::fs::create_dir(&named).unwrap();
    std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o700)).unwrap();
    let replacement = FileHostStateStore::open_exclusive(&named).unwrap();
    replacement.commit(&expected).unwrap();
    assert!(require_current_worker_snapshot(&writer, &expected, authority).is_err());
    assert!(displaced.join("state.bin").exists());
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately unauthenticated structural rows cannot mint launch custody.
    // These tests cover only snapshot retention and conservative ID exclusion.
    fn structural_row() -> DurableFuseWorkerLaunchV1 {
        DurableFuseWorkerLaunchV1 {
            binding: Binding {
                version: 1,
                request_id: [1; 16],
                sandbox: [2; 16],
                worker: [3; 16],
                boot: [4; 16],
                plan: [5; 32],
                reservation: [6; 32],
                body_digest: [7; 32],
                signed_request: [8; 32],
                session: [9; 32],
                base_fence: vec![10],
                phase_fence: vec![11],
                effect: vec![12],
            },
            authentication: vec![13],
        }
    }

    #[test]
    fn historical_escrow_refuses_native_id_reuse_and_absence_queries() {
        let row = structural_row();
        let mut state = HostState::default();
        state.fuse_worker_launches.insert(row.request_id(), row);
        let encoded = state.encode().unwrap();
        let recovered = HostState::decode(&encoded).unwrap();

        assert!(
            recovered
                .require_request_not_worker_escrow(&[1; 16])
                .is_err()
        );
        assert!(recovered.query_effect(&[1; 16], [7; 32]).is_err());
        assert!(
            recovered
                .require_request_not_worker_escrow(&[14; 16])
                .is_ok()
        );
        assert_eq!(recovered.encode().unwrap(), encoded);
    }

    #[test]
    fn escrow_inner_version_and_bounds_are_closed() {
        let row = structural_row();
        row.validate_shape().unwrap();
        for case in 0..4 {
            let mut changed = row.clone();
            match case {
                0 => changed.binding.version = 2,
                1 => changed.binding.worker = [0; 16],
                2 => changed.binding.session = [0; 32],
                3 => changed.authentication = vec![1; MAXIMUM_ESCROW_FIELD_BYTES + 1],
                _ => unreachable!(),
            }
            assert!(changed.validate_shape().is_err(), "substitution {case}");
        }
    }
}
