//! Crash-safe ordering for fixed mount effects.

use aos_proto::aos::sandbox::local::v1::{MountAction, MountResult};
use aos_sandbox::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::OperationId;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedMountRequest, decode_mount_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::state::{EffectStatus, decode_effect, encode_effect, encode_fence, validate_fence};
use crate::worker::{EffectHandles, MountWorker, WorkerObservation, expected_handles};
use crate::{MountError, Result};

/// Applies validated mount requests through durable, idempotent effects.
pub struct MountBroker<W> {
    journal: Journal,
    worker: W,
}

impl<W: MountWorker> MountBroker<W> {
    /// Constructs a broker around an exclusively owned journal and worker.
    #[must_use]
    pub const fn new(journal: Journal, worker: W) -> Self {
        Self { journal, worker }
    }

    /// Validates, fences, applies, and durably completes one mount request.
    ///
    /// # Errors
    ///
    /// Returns an error before effects for hostile input, stale/equivocating
    /// assignment state, request-ID reuse, or malformed replay state. Worker
    /// and completion failures leave a durable pending intent for exact retry.
    pub fn apply_mount(
        &mut self,
        request_bytes: &[u8],
        peer: PeerCredentials,
        policy: PeerPolicy,
        now_boottime_nanoseconds: u64,
    ) -> Result<Vec<u8>> {
        let request = decode_mount_request(request_bytes, peer, policy, now_boottime_nanoseconds)?;
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let idempotency = IdempotencyKey::new(request.header().request_id().to_vec())?;
        let operation_id = OperationId::from_bytes(*request.header().request_id());
        let action = action_code(request.action());

        validate_fence(&self.journal, request.fence())?;
        match self.journal.check_idempotency(&idempotency, request_digest) {
            IdempotencyOutcome::Conflict => {
                return Err(MountError::Fence(
                    "request ID was reused with different bytes",
                ));
            }
            IdempotencyOutcome::Replay(existing) => {
                if existing != operation_id {
                    return Err(MountError::State(
                        "mount idempotency operation identity changed".to_owned(),
                    ));
                }
            }
            IdempotencyOutcome::Vacant => {
                self.persist_intent(&request, &idempotency, operation_id, request_digest, action)?;
            }
        }

        let effect = self.effect(request.header().request_id())?;
        if effect.request_digest != request_digest || effect.action != action {
            return Err(MountError::Fence(
                "durable effect contradicts exact request",
            ));
        }
        if effect.status == EffectStatus::Complete {
            return Ok(effect.receipt);
        }

        let supplied = request.detached_mount_handle().copied();
        let handles = expected_handles(request.action(), request_digest, supplied)?;
        let observation = self.worker.execute(&request, request_digest, handles)?;
        validate_observation(request.action(), handles, &observation)?;
        let response = encode_result(&request, &observation)?;
        let response_limit = usize::try_from(request.header().maximum_response_bytes())
            .map_err(|_| MountError::State("response limit does not fit usize".to_owned()))?;
        if response.len() > response_limit {
            return Err(MountError::State(
                "mount result exceeds the admitted response bound".to_owned(),
            ));
        }
        self.persist_completion(&request, request_digest, action, &response)?;
        Ok(response)
    }

    fn persist_intent(
        &mut self,
        request: &ValidatedMountRequest,
        idempotency: &IdempotencyKey,
        operation_id: OperationId,
        request_digest: [u8; 32],
        action: u8,
    ) -> Result<()> {
        let records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                request.fence().sandbox_id().to_vec(),
                encode_fence(request.fence()),
            ),
            JournalRecord::idempotency(idempotency, request_digest, operation_id),
            JournalRecord::put(
                RecordNamespace::Effect,
                request.header().request_id().to_vec(),
                encode_effect(EffectStatus::Pending, action, request_digest, &[])?,
            ),
        ];
        let transaction = JournalTransaction::new(*request.header().request_id(), records)?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    fn persist_completion(
        &mut self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        action: u8,
        response: &[u8],
    ) -> Result<()> {
        let transaction = JournalTransaction::new(
            completion_transaction(request_digest),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                request.header().request_id().to_vec(),
                encode_effect(EffectStatus::Complete, action, request_digest, response)?,
            )],
        )?;
        self.journal.commit(&transaction)?;
        Ok(())
    }

    fn effect(&self, request_id: &[u8; 16]) -> Result<crate::state::EffectRecord> {
        let bytes = self
            .journal
            .get(RecordNamespace::Effect, request_id)
            .ok_or_else(|| MountError::State("durable mount effect is absent".to_owned()))?;
        decode_effect(bytes)
    }
}

fn validate_observation(
    action: MountAction,
    expected: EffectHandles,
    observed: &WorkerObservation,
) -> Result<()> {
    let state_valid = match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => {
            observed.state == aos_proto::aos::sandbox::local::v1::MountState::MOUNT_STATE_DETACHED
        }
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
            observed.state == aos_proto::aos::sandbox::local::v1::MountState::MOUNT_STATE_INSTALLED
        }
        MountAction::MOUNT_ACTION_DETACH => {
            observed.state == aos_proto::aos::sandbox::local::v1::MountState::MOUNT_STATE_REVOKED
        }
        MountAction::MOUNT_ACTION_RELEASE => {
            observed.state == aos_proto::aos::sandbox::local::v1::MountState::MOUNT_STATE_ABSENT
        }
        MountAction::MOUNT_ACTION_UNSPECIFIED => false,
    };
    if !state_valid || observed.handles != expected {
        return Err(MountError::Worker(
            "worker returned a contradictory mount observation".to_owned(),
        ));
    }
    Ok(())
}

fn encode_result(
    request: &ValidatedMountRequest,
    observation: &WorkerObservation,
) -> Result<Vec<u8>> {
    let result = MountResult {
        attachment_id: request.attachment_id().to_vec(),
        detached_mount_handle: observation
            .handles
            .detached
            .map_or_else(Vec::new, |handle| handle.to_vec()),
        installed_mount_handle: observation
            .handles
            .installed
            .map_or_else(Vec::new, |handle| handle.to_vec()),
        view_revision: request
            .view_revision()
            .map(
                |descriptor| aos_proto::aos::sandbox::local::v1::Descriptor {
                    media_type: descriptor.media_type().as_str().to_owned(),
                    sha256: descriptor.digest().as_bytes().to_vec(),
                    encoded_size: descriptor.encoded_size(),
                    ..Default::default()
                },
            )
            .into(),
        source_generation: request.source_generation(),
        state: observation.state.into(),
        ..Default::default()
    };
    let bytes = result.encode_to_vec();
    if bytes.is_empty() {
        return Err(MountError::State(
            "mount result encoded to an empty receipt".to_owned(),
        ));
    }
    Ok(bytes)
}

fn completion_transaction(request_digest: [u8; 32]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.completion.v1\0");
    digest.update(request_digest);
    let output = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&output[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

const fn action_code(action: MountAction) -> u8 {
    match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => 1,
        MountAction::MOUNT_ACTION_INSTALL => 2,
        MountAction::MOUNT_ACTION_REPLACE => 3,
        MountAction::MOUNT_ACTION_DETACH => 4,
        MountAction::MOUNT_ACTION_RELEASE => 5,
        MountAction::MOUNT_ACTION_UNSPECIFIED => 0,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAttributes, MountState,
        RequestHeader,
    };
    use aos_sandbox::journal::JournalLimits;

    use super::*;

    #[derive(Default)]
    struct ScriptedWorker {
        calls: usize,
        fail_next: bool,
    }

    impl MountWorker for ScriptedWorker {
        fn execute(
            &mut self,
            request: &ValidatedMountRequest,
            _request_digest: [u8; 32],
            handles: EffectHandles,
        ) -> Result<WorkerObservation> {
            self.calls += 1;
            if self.fail_next {
                self.fail_next = false;
                return Err(MountError::Worker("injected failure".to_owned()));
            }
            let state = match request.action() {
                MountAction::MOUNT_ACTION_CREATE_DETACHED => MountState::MOUNT_STATE_DETACHED,
                MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
                    MountState::MOUNT_STATE_INSTALLED
                }
                MountAction::MOUNT_ACTION_DETACH => MountState::MOUNT_STATE_REVOKED,
                MountAction::MOUNT_ACTION_RELEASE => MountState::MOUNT_STATE_ABSENT,
                MountAction::MOUNT_ACTION_UNSPECIFIED => MountState::MOUNT_STATE_FAILED,
            };
            Ok(WorkerObservation {
                state,
                handles,
                detached_mount_id: None,
                installed: None,
            })
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            uid: 811,
            gid: 811,
            pid: Some(42),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 811,
            gid: Some(811),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn request(request_id: u8, desired_generation: u64) -> Vec<u8> {
        ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![request_id; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 1_000,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![1; 16],
                incarnation_id: vec![2; 16],
                assignment_epoch: 1,
                desired_generation,
                assignment_digest: vec![u8::try_from(desired_generation).unwrap(); 32],
                ..Default::default()
            })
            .into(),
            action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
            attachment_id: vec![3; 16],
            destination_slot_id: vec![4; 16],
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![5; 32],
                encoded_size: 64,
                ..Default::default()
            })
            .into(),
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                mutation_mode: 0,
                ..Default::default()
            })
            .into(),
            source_generation: 1,
            namespace_generation: 1,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn broker(worker: ScriptedWorker) -> (tempfile::TempDir, MountBroker<ScriptedWorker>) {
        let directory = tempfile::tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("mount.journal"),
            JournalLimits::default(),
        )
        .unwrap();
        (directory, MountBroker::new(journal, worker))
    }

    #[test]
    fn exact_replay_returns_durable_receipt_without_repeating_effect() {
        let (_directory, mut broker) = broker(ScriptedWorker::default());
        let bytes = request(9, 1);
        let first = broker.apply_mount(&bytes, peer(), policy(), 100).unwrap();
        let second = broker.apply_mount(&bytes, peer(), policy(), 100).unwrap();
        assert_eq!(first, second);
        assert_eq!(broker.worker.calls, 1);

        let result = MountResult::decode_from_slice(&first).unwrap();
        assert_eq!(
            result.state.as_known(),
            Some(MountState::MOUNT_STATE_DETACHED)
        );
        assert_eq!(result.detached_mount_handle.len(), 32);
    }

    #[test]
    fn pending_effect_reconciles_after_worker_failure() {
        let (_directory, mut broker) = broker(ScriptedWorker {
            fail_next: true,
            ..Default::default()
        });
        let bytes = request(10, 1);
        assert!(broker.apply_mount(&bytes, peer(), policy(), 100).is_err());
        assert!(broker.apply_mount(&bytes, peer(), policy(), 100).is_ok());
        assert_eq!(broker.worker.calls, 2);
    }

    #[test]
    fn request_id_conflicts_and_stale_fences_fail_before_effects() {
        let (_directory, mut broker) = broker(ScriptedWorker::default());
        let bytes = request(11, 2);
        broker.apply_mount(&bytes, peer(), policy(), 100).unwrap();

        let mut conflict = ApplyMountRequest::decode_from_slice(&bytes).unwrap();
        conflict.source_generation = 2;
        assert!(
            matches!(
                broker.apply_mount(&conflict.encode_to_vec(), peer(), policy(), 100),
                Err(MountError::Fence(
                    "request ID was reused with different bytes"
                ))
            ),
            "request identity must bind exact bytes"
        );
        assert!(
            matches!(
                broker.apply_mount(&request(12, 1), peer(), policy(), 100),
                Err(MountError::Fence("assignment generation is stale"))
            ),
            "older desired generation must fail closed"
        );
        assert_eq!(broker.worker.calls, 1);
    }
}
