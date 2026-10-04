//! Installed exclusive-cohort enrollment under the original worker profile.
//!
//! This local child owns the actual two inventory Sessions while their first
//! Prepare/Read pairs are current. Core owns the Root carrier and account CAS;
//! the existing Cache initializer owns its private clock guard. Failed work
//! aborts before these originals drop. Success restores only the same inventory
//! owners, not reconstructed transports or a detached currentness permit.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::cache_residency::CacheResidentUnavailableV1;
use aos_sandbox::lifecycle::LifecyclePhase6ErrorV1;
use aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1;
use aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1;
use aos_sandbox_core::format::git_upload_enrollment::{
    GitCoverageBirthV1, GitCoverageBrokerRoleV1, GitCoverageCatalogV1,
    GitCoverageDataErrorV1, GitCoverageEnrollmentV1, GitCoverageFenceFieldsV1,
    GitCoverageFenceV1, GitCoverageFlightV1, GitCoverageJournalProfileV1,
    GitCoverageRequestCoordinatesV1,
};

use crate::lifecycle_host_inventory::DormantGitCoverageQueryOwnerV1;
use crate::{
    BrokerSessionSecurityError, DormantBrokerSessionHandshakeErrorV1,
    DormantMountLifecycleInventoryOwnerV1, DormantStorageLifecycleInventoryOwnerV1,
    ProtectedBrokerSessionFixedCustodyV1, ProtectedBrokerSessionFixedEndpointV1,
};

use super::publisher_policy_source::PublisherPolicyBootstrapAttemptV1;
use super::{ControllerBrokerSessions, ProductionController};

#[derive(Debug, thiserror::Error)]
enum CoverageFailureV1 {
    #[error("exclusive Git cohort continuation is closed")]
    Closed,
    #[error(transparent)]
    Data(#[from] GitCoverageDataErrorV1),
    #[error(transparent)]
    Protected(#[from] BrokerSessionSecurityError),
    #[error(transparent)]
    Handshake(#[from] DormantBrokerSessionHandshakeErrorV1),
    #[error(transparent)]
    Query(#[from] LifecyclePhase6ErrorV1),
}

type CacheCoordinatesV1 = (
    aos_sandbox_core::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
    GitCoverageFenceFieldsV1,
    [u8; 32],
    u64,
);

/// Keeps the real profile loan local to the selected diverging worker.
pub(super) struct GitCoverageWorkerV1<'profile> {
    inputs: GitCoverageCredentialCustodyV1,
    account: GitCoverageAccountAttemptV1<'profile>,
    fixed: [Option<ProtectedBrokerSessionFixedCustodyV1>; 2],
    queries: [Option<DormantGitCoverageQueryOwnerV1>; 2],
    requests: [[Option<Result<Vec<u8>, GitCoverageDataErrorV1>>; 2]; 2],
    cache: [Option<Result<CacheCoordinatesV1, CacheResidentUnavailableV1>>; 2],
    restored_mount: Option<Result<DormantMountLifecycleInventoryOwnerV1, DormantGitCoverageQueryOwnerV1>>,
    restored_storage: Option<Result<DormantStorageLifecycleInventoryOwnerV1, DormantGitCoverageQueryOwnerV1>>,
    nonce: Option<[u8; 16]>,
    existing_birth_nonce: Option<Result<[u8; 16], aos_sandbox::journal::GitCoverageNativeHistoryErrorV1>>,
    first_failure: Option<CoverageFailureV1>,
    postcheck: Option<CoverageFailureV1>,
    attempted: bool,
    completed: bool,
    read_metadata: Option<Result<(), CacheResidentUnavailableV1>>,
    initial_issuance: Option<aos_sandbox::public_capability_issuance::RetainedGitInitialIssuanceV1>,
    initial_reply: Option<tokio::sync::oneshot::Sender<super::ControllerCommandResponse<(aos_sandbox_core::CapabilityId, [u8; 32])>>>,
    initial_sent: Option<Result<(), super::ControllerCommandResponse<(aos_sandbox_core::CapabilityId, [u8; 32])>>>,
}

impl<'profile> GitCoverageWorkerV1<'profile> {
    pub(super) fn new(
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Self {
        Self {
            inputs: GitCoverageCredentialCustodyV1::controller(),
            account: GitCoverageAccountAttemptV1::new(profile),
            fixed: [None, None],
            queries: [None, None],
            requests: std::array::from_fn(|_| [None, None]),
            cache: [None, None],
            restored_mount: None,
            restored_storage: None,
            nonce: None,
            existing_birth_nonce: None,
            first_failure: None,
            postcheck: None,
            attempted: false,
            completed: false,
            read_metadata: None,
            initial_issuance: None,
            initial_reply: None,
            initial_sent: None,
        }
    }

    pub(super) fn install_once(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
        sessions: &mut ControllerBrokerSessions,
        node: [u8; 16],
    ) -> Result<(), ()> {
        if self.attempted {
            self.first_failure.get_or_insert(CoverageFailureV1::Closed);
            return Err(());
        }
        self.attempted = true;
        let returned = self.install(controller, bootstrap, sessions, node);
        if let Err(cause) = returned {
            self.first_failure.get_or_insert(cause);
        }

        // The actual first error and all returned owners are resident before
        // the independent postcheck. A marker never replaces their cause.
        if self.inputs.ready().is_some() && self.inputs.recheck().is_err() {
            self.postcheck.get_or_insert(CoverageFailureV1::Closed);
        }
        if self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(());
        }
        self.completed = true;
        Ok(())
    }

    fn install(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
        sessions: &mut ControllerBrokerSessions,
        node: [u8; 16],
    ) -> Result<(), CoverageFailureV1> {
        self.inputs.capture().map_err(|_| CoverageFailureV1::Closed)?;
        if bootstrap.existing_enrollment_selected() {
            // The stored nonce comes from this actual complete native prefix,
            // not catalog DATA or a guessed earlier flight coordinate.
            let inputs = self.inputs.ready().ok_or(CoverageFailureV1::Closed)?;
            let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
            self.existing_birth_nonce = Some(controller.existing_git_coverage_birth_nonce_v1(&catalog));
            if !matches!(self.existing_birth_nonce, Some(Ok(_))) {
                return Err(CoverageFailureV1::Closed);
            }
            self.account.select_existing_replay_before_root_v1()
                .map_err(|_| CoverageFailureV1::Closed)?;
        }
        self.account.begin_root_once().map_err(|_| CoverageFailureV1::Closed)?;
        let (nonce, _boot, cutoff) = self.account.root_challenge()
            .map_err(|_| CoverageFailureV1::Closed)?;
        self.nonce = Some(nonce);

        // No previously queried Session can become a fresh coverage Session.
        // Occupied destinations remain untouched on refusal.
        if sessions.mount.is_some() || sessions.storage.is_some()
            || sessions.storage_cold.is_some()
        {
            return Err(CoverageFailureV1::Closed);
        }
        self.open_mount(cutoff, node)?;
        self.open_storage(cutoff, node, sessions)?;

        let cache_flight = if self.existing_birth_nonce.is_some() {
            GitCoverageFlightV1::Read
        } else {
            GitCoverageFlightV1::Prepare
        };
        self.cache[0] = Some(controller.compare_existing_cache_git_coverage_v1(
            &mut self.inputs, cache_flight, nonce, None,
        ));
        self.inputs.recheck().map_err(|_| CoverageFailureV1::Closed)?;
        if !matches!(&self.cache[0], Some(Ok(_))) {
            return Err(CoverageFailureV1::Closed);
        }
        for index in 0..2 {
            self.exchange_pair(index, nonce)?;
        }
        self.cache[1] = Some(controller.compare_existing_cache_git_coverage_v1(
            &mut self.inputs, GitCoverageFlightV1::Read, nonce, None,
        ));
        self.check_latest()?;
        if !matches!(&self.cache[1], Some(Ok(_)))
            || self.cache[0].as_ref().and_then(|result| result.as_ref().ok())
                != self.cache[1].as_ref().and_then(|result| result.as_ref().ok())
        {
            return Err(CoverageFailureV1::Closed);
        }

        let captured = bootstrap.capture_coverage_account_once(
            controller, &mut self.inputs, &mut self.account,
        );
        let postchecked = self.check_latest();
        captured.map_err(|_| CoverageFailureV1::Closed)?;
        postchecked?;
        let submitted = {
            let mount = self.queries[0].as_ref().ok_or(CoverageFailureV1::Closed)?;
            let storage = self.queries[1].as_ref().ok_or(CoverageFailureV1::Closed)?;
            let mount_proof = mount.proof().ok_or(CoverageFailureV1::Closed)?;
            let storage_proof = storage.proof().ok_or(CoverageFailureV1::Closed)?;
            let outcomes = [
                &mount.reply(0).ok_or(CoverageFailureV1::Closed)?.0,
                &mount.reply(1).ok_or(CoverageFailureV1::Closed)?.0,
                &storage.reply(0).ok_or(CoverageFailureV1::Closed)?.0,
                &storage.reply(1).ok_or(CoverageFailureV1::Closed)?.0,
            ];
            self.account.submit_root_once(&self.inputs, [mount_proof, storage_proof], outcomes)
        };
        let postchecked = self.check_latest();
        submitted.map_err(|_| CoverageFailureV1::Closed)?;
        postchecked?;
        let observed = self.account.observe_root_once();
        let postchecked = self.check_latest();
        observed.map_err(|_| CoverageFailureV1::Closed)?;
        postchecked?;

        self.check_latest()?;
        if self.existing_birth_nonce.is_none() {
            let committed = bootstrap.commit_coverage_account_once(
                controller, &mut self.inputs, &mut self.account,
            );
            let postchecked = self.check_latest();
            committed.map_err(|_| CoverageFailureV1::Closed)?;
            postchecked?;
        }
        let finished = if self.existing_birth_nonce.is_some() {
            self.account.finish_existing_root_once()
        } else {
            self.account.finish_local_root_once()
        };
        let postchecked = self.check_latest();
        finished.map_err(|_| CoverageFailureV1::Closed)?;
        postchecked?;

        // Both target slots are checked before either original moves. No
        // fallible operation follows either successful ownership restoration.
        if sessions.mount.is_some() || sessions.storage.is_some() {
            return Err(CoverageFailureV1::Closed);
        }
        let mount = self.queries[0].take().ok_or(CoverageFailureV1::Closed)?;
        self.restored_mount = Some(mount.restore_original_mount());
        let storage = self.queries[1].take().ok_or(CoverageFailureV1::Closed)?;
        self.restored_storage = Some(storage.restore_original_storage());
        if !matches!(&self.restored_mount, Some(Ok(_)))
            || !matches!(&self.restored_storage, Some(Ok(_)))
        {
            return Err(CoverageFailureV1::Closed);
        }
        if let Some(Ok(original)) = self.restored_mount.take() {
            sessions.mount = Some(original);
        }
        if let Some(Ok(original)) = self.restored_storage.take() {
            sessions.storage = Some(original);
        }
        Ok(())
    }

    pub(super) fn inspect_current(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
        original: &mut aos_sandbox::git::delegated_read::GitReadRequestOwnerV1,
        acceptor: &aos_sandbox::public_api_session::PublicApiSessionAcceptor,
    ) -> Result<(), ()> {
        if !self.completed || self.first_failure.is_some() || self.postcheck.is_some()
            || self.read_metadata.as_ref().is_some_and(Result::is_err)
        {
            return Err(());
        }
        self.bookend(controller, bootstrap)?;
        self.read_metadata = Some(controller.inspect_enrolled_gateway_git_read_v1(
            original, acceptor, &mut self.inputs, &mut self.account,
        ));
        let postchecked = self.bookend(controller, bootstrap);
        if !matches!(self.read_metadata, Some(Ok(()))) {
            self.first_failure.get_or_insert(CoverageFailureV1::Closed);
            return Err(());
        }
        postchecked
    }

    pub(super) fn bootstrap_public_capability(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        idempotency_key: Vec<u8>,
        expires_at: std::time::Instant,
        reply: tokio::sync::oneshot::Sender<super::ControllerCommandResponse<(aos_sandbox_core::CapabilityId, [u8; 32])>>,
    ) -> Result<(), ()> {
        if self.initial_issuance.is_some() || self.initial_reply.is_some() {
            // Incoming original arguments still belong to this frame.
            std::process::abort();
        }
        self.initial_issuance = Some(aos_sandbox::public_capability_issuance::RetainedGitInitialIssuanceV1::new(
            peer, idempotency_key, expires_at,
        ));
        self.initial_reply = Some(reply);
        self.bookend(controller, bootstrap)?;
        let original = self.initial_issuance.as_mut().ok_or(())?;
        self.read_metadata = Some(controller.bootstrap_enrolled_git_public_capability_v1(
            original, &mut self.inputs, &mut self.account,
        ));
        let postchecked = self.bookend(controller, bootstrap);
        if !matches!(self.read_metadata, Some(Ok(()))) {
            let original = self.initial_issuance.as_ref().ok_or(())?;
            let failure = if original.deadline_exceeded() {
                super::ControllerCommandFailure::DeadlineExceeded
            } else if original.rejected() {
                super::ControllerCommandFailure::Rejected
            } else {
                super::ControllerCommandFailure::ControllerUnavailable
            };
            let reply = self.initial_reply.take().ok_or(())?;
            self.initial_sent = Some(reply.send(Err(failure)));
            // A negative response is not permission to destroy the original
            // failed capsule. The caller ends with every remaining owner here.
            return Err(());
        }
        postchecked?;

        let original = self.initial_issuance.as_mut().ok_or(())?;
        let issued = original.issued().ok_or(())?;
        let response = Ok((issued.id(), *issued.holder_handle()));
        let reply = self.initial_reply.take().ok_or(())?;
        self.initial_sent = Some(reply.send(response));
        if !matches!(self.initial_sent, Some(Ok(()))) { return Err(()); }
        original.retire_local().map_err(|_| ())?;
        drop(self.initial_issuance.take());
        Ok(())
    }

    fn open_mount(&mut self, cutoff: u64, node: [u8; 16])
        -> Result<(), CoverageFailureV1>
    {
        self.fixed[0] = Some(ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
        )?);
        let deadline = crate::handshake::OriginalBrokerColdDeadlineV1::git_coverage(cutoff)?;
        let fixed = self.fixed[0].take().ok_or(CoverageFailureV1::Closed)?;
        let returned = fixed.connect_git_coverage_mount_session_v1(deadline.value());
        match returned {
            Ok(session) => {
                let original = DormantMountLifecycleInventoryOwnerV1::from_protected_session(session);
                self.queries[0] = Some(DormantGitCoverageQueryOwnerV1::from_original_mount(original, cutoff));
            }
            Err(cause) => return Err(cause.into()),
        }
        self.queries[0].as_mut().ok_or(CoverageFailureV1::Closed)?
            .require_original_node(node)?;
        Ok(())
    }

    fn open_storage(&mut self, cutoff: u64, node: [u8; 16], sessions: &mut ControllerBrokerSessions)
        -> Result<(), CoverageFailureV1>
    {
        self.fixed[1] = Some(ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        )?);
        let deadline = crate::handshake::OriginalBrokerColdDeadlineV1::git_coverage(cutoff)?;
        let fixed = self.fixed[1].take().ok_or(CoverageFailureV1::Closed)?;
        let returned = fixed.retain_launch_image(sessions.launch_image.clone())?
            .connect_retained_git_coverage_storage_session_v1(
                deadline, &mut sessions.storage_cold, node,
            );
        match returned {
            Ok(session) => {
                let original = DormantStorageLifecycleInventoryOwnerV1::from_protected_session(session);
                self.queries[1] = Some(DormantGitCoverageQueryOwnerV1::from_original_storage(original, cutoff));
            }
            Err(cause) => return Err(cause.into()),
        }
        self.queries[1].as_mut().ok_or(CoverageFailureV1::Closed)?
            .require_original_node(node)?;
        Ok(())
    }

    fn exchange_pair(&mut self, index: usize, nonce: [u8; 16])
        -> Result<(), CoverageFailureV1>
    {
        let inputs = self.inputs.ready().ok_or(CoverageFailureV1::Closed)?;
        let enrollment = GitCoverageEnrollmentV1::decode(inputs.enrollment())?;
        let catalog = GitCoverageCatalogV1::decode(inputs.catalog())?;
        let (role, profile, methods) = if index == 0 {
            (GitCoverageBrokerRoleV1::Mount, GitCoverageJournalProfileV1::Mount, [
                BrokerMethod::BROKER_METHOD_MOUNT_PREPARE_GIT_PROJECT_COVERAGE_V1,
                BrokerMethod::BROKER_METHOD_MOUNT_READ_GIT_PROJECT_COVERAGE_V1,
            ])
        } else {
            (GitCoverageBrokerRoleV1::Storage, GitCoverageJournalProfileV1::StorageCatalog, [
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_GIT_PROJECT_COVERAGE_V1,
                BrokerMethod::BROKER_METHOD_STORAGE_READ_GIT_PROJECT_COVERAGE_V1,
            ])
        };
        let birth_nonce = match self.existing_birth_nonce.as_ref() {
            Some(Ok(original)) => *original,
            Some(Err(_)) => return Err(CoverageFailureV1::Closed),
            None => nonce,
        };
        let birth = enrollment.fixed_owner_birth_recipe_v1(&catalog, profile, birth_nonce)?;
        let birth_bytes = birth.encode()?;
        let birth_digest = GitCoverageBirthV1::decode(&birth_bytes)?.digest();
        let fence_bytes = GitCoverageFenceFieldsV1 {
            owner: birth.owner,
            project: birth.project,
            node: birth.node,
            epoch: birth.epoch,
            generation: enrollment.generation_interval().0,
            enrollment: birth.enrollment,
            birth: birth_digest,
            catalog: birth.catalog,
            transaction: birth.transaction,
            predecessor_prefix: birth.predecessor_prefix,
            prepare_nonce: birth_nonce,
        }.encode()?;
        let fence_digest = GitCoverageFenceV1::decode(&fence_bytes)?.digest();
        for slot in 0..2 {
            let coordinates = GitCoverageRequestCoordinatesV1 {
                role,
                project: birth.project,
                node: birth.node,
                epoch: birth.epoch,
                generation: enrollment.generation_interval().0,
                nonce,
                enrollment: birth.enrollment,
                birth: birth_digest,
                expected: if slot == 0 && self.existing_birth_nonce.is_none() {
                    birth.predecessor_prefix
                } else {
                    fence_digest
                },
                catalog: birth.catalog,
            };
            self.requests[index][slot] = Some(if slot == 0 && self.existing_birth_nonce.is_some() {
                coordinates.encode_existing_pair(inputs.enrollment())
            } else {
                coordinates.encode(if slot == 0 { Some(inputs.enrollment()) } else { None })
            });
            let body = self.requests[index][slot].as_ref()
                .and_then(|result| result.as_ref().ok()).ok_or(CoverageFailureV1::Closed)?;
            self.queries[index].as_mut().ok_or(CoverageFailureV1::Closed)?
                .exchange(methods[slot], body)?;
        }
        self.queries[index].as_mut().ok_or(CoverageFailureV1::Closed)?.assemble_proof()?;
        Ok(())
    }

    fn check_latest(&mut self) -> Result<(), CoverageFailureV1> {
        if self.inputs.recheck().is_err() {
            self.postcheck.get_or_insert(CoverageFailureV1::Closed);
        }
        for query in &mut self.queries {
            let checked = match query.as_mut() {
                Some(query) => query.recheck(1).map_err(CoverageFailureV1::from),
                None => Err(CoverageFailureV1::Closed),
            };
            if let Err(cause) = checked {
                // All originals receive their independent bookend even when
                // another owner or the primary action has already failed.
                self.postcheck.get_or_insert(cause);
            }
        }
        if self.postcheck.is_some() {
            return Err(CoverageFailureV1::Closed);
        }
        Ok(())
    }

    pub(super) fn bookend(
        &mut self,
        controller: &mut ProductionController,
        bootstrap: &mut PublisherPolicyBootstrapAttemptV1,
    ) -> Result<(), ()> {
        if !self.completed || self.first_failure.is_some() || self.postcheck.is_some() {
            return Err(());
        }
        let nonce = self.nonce.ok_or(())?;
        self.cache[1] = Some(controller.compare_existing_cache_git_coverage_v1(
            &mut self.inputs, GitCoverageFlightV1::Read, nonce, Some(&mut self.account),
        ));
        let policy = bootstrap.current_enrolled_cache_project(controller, &self.account);
        let credentials = self.inputs.recheck();
        if !matches!(&self.cache[1], Some(Ok(_))) || policy.is_err() || credentials.is_err() {
            self.first_failure.get_or_insert(CoverageFailureV1::Closed);
            return Err(());
        }
        Ok(())
    }
}

impl Drop for GitCoverageWorkerV1<'_> {
    fn drop(&mut self) {
        // The selected worker is a resident, diverging lifetime. Cancellation
        // or unwind cannot release its originals or masquerade as Drain.
        std::process::abort();
    }
}
