//! Retains method31 admission and its creation/current publication relation.
//!
//! Only the real signed request reaches this owner. The ordinary Storage
//! authority remains the sole plan/lease verifier. The physical creation is
//! authenticated separately and stays unchanged when the current assignment
//! advances; neither a descriptor nor a response DATA model grants a rebind.

use super::*;
use aos_sandbox_broker::VerifiedBrokerAdmission;
use crate::authorization::SealedStorageAdmission;
use crate::state::GuestRootStateRecordOriginalV2;
use crate::ZfsWorkerError;
use aos_sandbox_protocol::semantics::storage_guest_root::{
    CanonicalStorageGuestRootArgumentsV1 as Arguments,
    StorageGuestRootCurrentPublicationDataV2,
};

#[derive(Clone, Copy)]
enum Failure { Current, Payment, PriorFence, Admission, Creation, CreationFenceSource, CreationFence, Relation, Seal, Pending, Request }

pub(crate) struct GuestRootAdmissionOriginalV2 {
    prior_fence: Option<Result<Option<Vec<u8>>, crate::StorageStateError>>,
    admission: Option<Result<VerifiedBrokerAdmission, crate::StorageAdmissionError>>,
    creation: Option<Result<crate::CommittedStorageResultV1, crate::StorageStateError>>,
    creation_fence_source: Option<Result<Option<Vec<u8>>, crate::StorageStateError>>,
    creation_fence: Option<Result<BrokerAuthorizationFenceV1, crate::StorageAdmissionError>>,
    sealed: Option<Result<SealedStorageAdmission, crate::StorageAdmissionError>>,
    current: Option<Result<(), StorageBrokerError>>,
    relation: Option<Result<GuestRootPublicationAttemptV2, StorageBrokerError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    pending: GuestRootStateRecordOriginalV2,
    pending_status: Option<Result<(), crate::StorageStateError>>,
    request: Option<Result<Vec<u8>, ZfsWorkerError>>,
    first: Option<Failure>,
    entered: bool,
    completed: bool,
}

impl GuestRootAdmissionOriginalV2 {
    pub(crate) fn new() -> Self {
        Self { prior_fence: None, admission: None, creation: None, creation_fence_source: None, creation_fence: None,
            sealed: None, current: None, relation: None, payment: None,
            pending: GuestRootStateRecordOriginalV2::new(), pending_status: None,
            request: None, first: None, entered: false, completed: false }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(slot: &Option<Result<T, E>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { slot.as_ref()?.as_ref().err().map(|cause| cause as _) }
        match self.first? {
            Failure::Current => error(&self.current),
            Failure::Payment => error(&self.payment),
            Failure::PriorFence => error(&self.prior_fence),
            Failure::Admission => error(&self.admission),
            Failure::Creation => error(&self.creation),
            Failure::CreationFenceSource => error(&self.creation_fence_source),
            Failure::CreationFence => error(&self.creation_fence),
            Failure::Relation => error(&self.relation),
            Failure::Seal => error(&self.sealed),
            Failure::Pending => self.pending.failure().or_else(|| error(&self.pending_status)),
            Failure::Request => error(&self.request),
        }
    }

    fn refuse<T>(&mut self, first: Failure) -> Result<T, StorageBrokerError> {
        self.first.get_or_insert(first);
        Err(crate::StorageStateError::Receiving.into())
    }

    pub(crate) fn pending_v2(&self) -> Option<&GuestRootStateRecordOriginalV2> {
        self.completed.then_some(&self.pending)
    }

    pub(crate) fn request_v2(&self) -> Option<&[u8]> {
        if !self.completed || self.first.is_some() { return None; }
        self.request.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_once_v2(
        &mut self, coordinator: &mut StorageAdmissionCoordinator,
        semantics: &CanonicalStorageGuestRootSemanticsV1, request_body: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion, peer: PeerCredentials, policy: PeerPolicy,
        clock: &RawPairedClockSample, workspace: &ValidatedStorageWorkspace,
        expected_proof: GuestRootPublicationProofV1,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), StorageBrokerError> {
        if self.entered {
            self.completed = false;
            if !self.current.as_ref().is_some_and(Result::is_err) {
                self.current = Some(Err(StorageBrokerError::Request));
            }
            return self.refuse(Failure::Current);
        }
        self.entered = true;
        let sandbox = *semantics.fence().sandbox_id();
        let operation = semantics.operation_id();
        let request_id = *semantics.header().request_id();
        self.current = Some((|| {
            coordinator.transactions.ensure_authority_readable()?;
            if workspace.workspace_handle() != &semantics.workspace_handle()
                || workspace.creation_operation_id() != &semantics.creation_operation_id()
                || expected_proof.sandbox != sandbox
                || expected_proof.incarnation != *workspace.fence().incarnation_id()
                || expected_proof.assignment_epoch != workspace.fence().assignment_epoch()
                || expected_proof.assignment_digest != *workspace.fence().assignment_digest()
                || expected_proof.creation_operation != semantics.creation_operation_id()
                || expected_proof.workspace_handle != semantics.workspace_handle()
                || expected_proof.dataset_guid != workspace.dataset_guid()
                || expected_proof.root_image_digest != *workspace.root_image().digest().as_bytes()
                || workspace.resource_kernel_boot_id() != &clock.host_boot_id()
            { return Err(StorageBrokerError::Request); }
            let pin = coordinator.transactions.satisfied_workspace_ensure_pin_for_active_creation(
                semantics.creation_operation_id(), semantics.workspace_handle(),
            )?;
            if pin.dataset_guid() != workspace.dataset_guid()
                || pin.root_device() != workspace.root_device() || pin.root_inode() != workspace.root_inode()
            { return Err(StorageBrokerError::Request); }
            Ok(())
        })());
        if !matches!(self.current, Some(Ok(()))) { return self.refuse(Failure::Current); }
        // The actual outer owner prepays this decoder/authority family before
        // entry. This additional bound pays the three reached seal buffers and
        // their precise current fence/effect representation before materializing.
        self.prior_fence = Some(coordinator.transactions.authority_record(RecordNamespace::DesiredState, &sandbox)
            .map(|row| row.map(<[u8]>::to_vec)));
        let Some(Ok(prior)) = self.prior_fence.as_ref() else { return self.refuse(Failure::PriorFence); };
        self.admission = Some(coordinator.authority.admit_guest_root_publication(
            artifacts, semantics, request_body, protocol_version, peer, policy, clock, prior.as_deref(),
        ));
        let Some(Ok(admission)) = self.admission.as_ref() else { return self.refuse(Failure::Admission); };
        let sealing = aos_sandbox_broker::storage_admission_sealing_bytes_v1(&admission.fence, &admission.effect)
            .ok_or(crate::StorageStateError::InvalidValue)?;
        self.payment = Some(receiving.reserve_encoded_capacity_v1(sealing, 0));
        if !matches!(self.payment, Some(Ok(()))) { return self.refuse(Failure::Payment); }
        self.creation = Some(coordinator.transactions.workspace_creation_for_pin_repair(semantics.workspace_handle()));
        let Some(Ok(creation)) = self.creation.as_ref() else { return self.refuse(Failure::Creation); };
        self.creation_fence_source = Some(coordinator.transactions.authority_record(
            RecordNamespace::AuthorityPublication, &semantics.creation_operation_id())
            .map(|row| row.map(<[u8]>::to_vec)));
        let Some(Ok(bytes)) = self.creation_fence_source.as_ref() else { return self.refuse(Failure::CreationFenceSource); };
        self.creation_fence = Some(match bytes {
            Some(bytes) => coordinator.authority.open_operation_fence(&semantics.creation_operation_id(), bytes),
            None => Err(crate::StorageAdmissionError::FenceRejected),
        });
        let Some(Ok(creation_fence)) = self.creation_fence.as_ref() else { return self.refuse(Failure::CreationFence); };
        self.sealed = Some(coordinator.authority.seal(&sandbox, &request_id, &operation, admission));
        let Some(Ok(sealed)) = self.sealed.as_ref() else { return self.refuse(Failure::Seal); };
        self.relation = Some((|| {
            coordinator.authority.check_current_fence(creation_fence)
                .map_err(StorageBrokerError::GuestRootCreationAuthority)?;
            let publication = coordinator.transactions.workspace_publication_intent(semantics.creation_operation_id())?
                .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
            let creation_assignment = publication.portable_metadata().assignment();
            if creation.operation_id() != semantics.creation_operation_id()
                || creation.storage_handle() != Some(semantics.workspace_handle())
                || creation.object_guid() != Some(workspace.dataset_guid())
                || creation_assignment != workspace.fence().broker_assignment().map_err(|_| StorageBrokerError::Request)?
                || creation_fence.assignment() != creation_assignment
                || creation_fence.node() != admission.fence.node()
                || creation_fence.ownership_authority() != admission.fence.ownership_authority()
                || publication.portable_metadata().node() != admission.fence.node()
                || publication.root_image() != workspace.root_image()
                || publication.identity_range_start() != workspace.uid_range_start()
                || publication.identity_range_size() != workspace.uid_range_size()
            { return Err(StorageBrokerError::Request); }
            let creation_arguments = Arguments::from_protected_assignment(creation_assignment, operation,
                semantics.workspace_handle(), semantics.creation_operation_id()).map_err(|_| StorageBrokerError::Request)?;
            let current_arguments = Arguments::from_protected_assignment(admission.fence.assignment(), operation,
                semantics.workspace_handle(), semantics.creation_operation_id()).map_err(|_| StorageBrokerError::Request)?;
            let current_publication = StorageGuestRootCurrentPublicationDataV2::from_data_v2(
                current_arguments, *workspace.resource_digest(), Sha256::digest(&sealed.effect).into(),
                Sha256::digest(&sealed.operation_fence).into(), *admission.effect.lease_digest().as_bytes(), request_id,
            ).map_err(|_| StorageBrokerError::Request)?;
            current_publication.require_creation_data_v2(creation_assignment, expected_proof, workspace.resource_digest())
                .map_err(|_| StorageBrokerError::Request)?;
            Ok(GuestRootPublicationAttemptV2 {
                effect_operation: operation, request_id,
                sealed_effect_digest: Sha256::digest(&sealed.effect).into(),
                operation_fence_digest: Sha256::digest(&sealed.operation_fence).into(),
                expected_proof, root_device: workspace.root_device(), root_inode: workspace.root_inode(),
                kernel_boot: clock.host_boot_id(), effect_deadline_boottime_nanoseconds: admission.effect.effect_deadline_boottime_nanoseconds(),
                phase: GuestRootAttemptPhaseV2::Ambiguous, creation_arguments, current_publication,
            })
        })());
        let Some(Ok(attempt)) = self.relation.as_ref() else { return self.refuse(Failure::Relation); };
        self.pending_status = Some(self.pending.begin_pending_once_v2(&mut coordinator.transactions,
            *attempt, sealed, clock.boottime_nanoseconds(), receiving));
        if !matches!(self.pending_status, Some(Ok(()))) { return self.refuse(Failure::Pending); }
        let encoded = self.pending.encoded_pending_v2().ok_or(crate::StorageStateError::InvalidTransition)?;
        self.request = Some(encode_guest_root_worker_request(operation, encoded, &sealed.effect, &sealed.operation_fence));
        if !matches!(self.request, Some(Ok(_))) { return self.refuse(Failure::Request); }
        self.completed = true;
        Ok(())
    }
}

impl StorageAdmissionCoordinator {
    /// Lends only the durably completed current binding for this physical root.
    ///
    /// This passive projection independently opens the actual current fence
    /// and the exact method31 effect/fence records. The caller must still own
    /// the paid native catalog/readback interval and attach the unchanged
    /// physical creation proof before publishing a signed Inventory body.
    pub(crate) fn completed_guest_root_publication_v2(
        &self,
        workspace: &ValidatedStorageWorkspace,
        physical: GuestRootPublicationProofV1,
    ) -> Result<Option<StorageGuestRootCurrentPublicationDataV2>, StorageBrokerError> {
        self.transactions.ensure_authority_readable()?;
        let sandbox = workspace.fence().sandbox_id();
        let Some(bytes) = self.transactions.authority_record(RecordNamespace::DesiredState, sandbox)? else {
            return Ok(None);
        };
        let current = self.authority.open_fence(sandbox, bytes)
            .map_err(StorageBrokerError::GuestRootCurrentAuthority)?;
        self.authority.check_current_fence(&current)
            .map_err(StorageBrokerError::GuestRootCurrentAuthority)?;
        let Some(attempt) = self.transactions.current_guest_root_attempt_v2(
            workspace.workspace_handle(), current.assignment(),
        )? else {
            return Ok(None);
        };
        let effect = self.transactions.authority_record(RecordNamespace::Effect, &attempt.request_id)?
            .ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        let operation_fence = self.transactions.authority_record(
            RecordNamespace::AuthorityPublication, &attempt.effect_operation,
        )?.ok_or(crate::StorageStateError::MissingAuthorityLink)?;
        attempt.require_authority_v2(&self.authority, effect, operation_fence)
            .map_err(StorageBrokerError::GuestRootCurrentAuthority)?;
        if attempt.expected_proof != physical
            || attempt.root_device != workspace.root_device()
            || attempt.root_inode != workspace.root_inode()
        {
            return Err(StorageBrokerError::Request);
        }
        attempt.current_publication.require_creation_data_v2(
            workspace.fence().broker_assignment().map_err(|_| StorageBrokerError::Request)?,
            physical,
            workspace.resource_digest(),
        ).map_err(|_| StorageBrokerError::Request)?;
        Ok(Some(attempt.current_publication))
    }
}

impl StorageAdmissionCoordinator {
    /// Commits completion only from the actual pending and posted readback owners.
    pub(crate) fn complete_guest_root_publication_v2(
        &mut self,
        completion: &mut GuestRootStateRecordOriginalV2,
        pending: &GuestRootStateRecordOriginalV2,
        readback: &crate::guest_root_inventory::GuestRootTargetReadbackOriginalV2,
        receiving: &mut crate::state::encoding::StateEncodingLoanV1<'_, '_>,
    ) -> Result<(), crate::StorageStateError> {
        completion.complete_once_v2(&mut self.transactions, pending, readback, receiving)
    }
}
