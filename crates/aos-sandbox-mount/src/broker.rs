//! Crash-safe ordering for mount effects and broker-owned resources.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt as _;

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Descriptor, InventoryMountResourcesResponse, MountAction,
    MountAssignmentBinding, MountAttributes, MountFaultCorrelation, MountFaultPhase,
    MountInventoryRecord, MountKernelObservation, MountLifecycle, MountOperationCorrelation,
    MountPublicationCorrelation, MountRecipe, MountResult, MountState,
};
use aos_sandbox::journal::{
    IdempotencyKey, IdempotencyOutcome, Journal, JournalRecord, JournalTransaction, RecordNamespace,
};
use aos_sandbox_core::{ObjectDigest, OperationId, ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_protocol::session::ValidatedUntrustedAuthorizationArtifacts;
use aos_sandbox_protocol::{
    PeerCredentials, PeerPolicy, ValidatedMountAttributes, ValidatedMountRequest,
    decode_mount_request,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::authorization::semantics_v1::MountCatalogCommitmentV1;
use crate::authorization::{MountAuthorityV1, VerifiedMountAdmissionV1};
use crate::state::authorization_v1::{MountEffectIntentV2, MountEffectStatusV2};
use crate::state::mount_resource_v1::{
    AssignmentBindingV1, DetachedMountIdentityV1, InstalledMountObservationV1, MountFaultPhaseV1,
    MountHandleV1, MountPolicyV1, MountRecipeV1, MountResourceLimitsV1, MountResourceStateV1,
    MountResourceTableV1, MountResourceV1, NativeMutationV1, ObjectDescriptorV1,
    OperationCorrelationV1, OwnedMountAttributeV1, PublicationCorrelationV1,
    canonical_fd_store_key,
};
use crate::worker::{
    EffectDeadlineV1, EffectHandles, MountTargetObservation, MountWorker, RetainedMountObservation,
    WorkerObservation, expected_handles,
};
use crate::{MountError, Result};

/// Applies validated mount requests through durable, idempotent effects.
pub struct MountBroker<W> {
    journal: Journal,
    worker: W,
    resources: MountResourceTableV1,
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    authority: MountAuthorityV1,
}

impl<W: MountWorker> MountBroker<W> {
    /// Constructs a broker after bounded recovery and exact custody validation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed state, unavailable boot identity,
    /// stale-boot fault persistence failure, or contradictory retained FDs.
    pub fn new(mut journal: Journal, mut worker: W, authority: MountAuthorityV1) -> Result<Self> {
        let kernel_boot_id = KernelBootId::current()
            .map_err(|error| MountError::State(error.to_string()))?
            .into_bytes();
        let broker_instance_id = broker_instance_id()?;
        let mut resources = MountResourceTableV1::recover(
            &journal,
            MountResourceLimitsV1::default(),
            kernel_boot_id,
        )?;
        fault_stale_boot_resources(&mut journal, &mut resources, kernel_boot_id)?;
        fault_unverifiable_allocated_custody(
            &mut journal,
            &mut resources,
            kernel_boot_id,
            &mut worker,
        )?;
        validate_custody(&resources, kernel_boot_id, &worker.custody_inventory()?)?;
        Ok(Self {
            journal,
            worker,
            resources,
            kernel_boot_id,
            broker_instance_id,
            authority,
        })
    }

    /// Encodes one complete authoritative durable resource-table snapshot.
    ///
    #[must_use]
    pub fn inventory_resources(&self) -> Vec<u8> {
        let response = InventoryMountResourcesResponse {
            kernel_boot_id: self.kernel_boot_id.to_vec(),
            journal_sequence: self.journal.snapshot_sequence(),
            mounts: self.resources.resources().map(inventory_record).collect(),
            broker_instance_id: self.broker_instance_id.to_vec(),
            ..Default::default()
        };
        response.encode_to_vec()
    }

    /// Validates, fences, applies, and durably completes one mount request.
    ///
    /// # Errors
    ///
    /// Returns an error before effects for hostile input, stale/equivocating
    /// assignment state, request-ID reuse, contradictory resource state, or
    /// malformed replay state. Effects remain represented by durable intent.
    pub fn apply_mount<F>(
        &mut self,
        request_bytes: &[u8],
        artifacts: &ValidatedUntrustedAuthorizationArtifacts,
        protocol_version: ProtocolVersion,
        peer: PeerCredentials,
        policy: PeerPolicy,
        mut trusted_clock: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut() -> Result<RawPairedClockSample>,
    {
        let verification_clock = trusted_clock()?;
        let request = decode_mount_request(
            request_bytes,
            peer,
            policy,
            verification_clock.boottime_nanoseconds(),
        )?;
        let catalog_commitment = self.worker.catalog_commitment(&request)?;
        let catalog_semantics = catalog_commitment
            .map(MountCatalogCommitmentV1::from_verified_digest)
            .transpose()
            .map_err(|error| MountError::State(error.to_string()))?;
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let prior_fence = self
            .journal
            .get(RecordNamespace::DesiredState, request.fence().sandbox_id());
        let admission = self
            .authority
            .admit(
                artifacts,
                &request,
                request_bytes,
                catalog_semantics,
                &[],
                protocol_version,
                &verification_clock,
                prior_fence,
            )
            .map_err(|_| MountError::Fence("signed mount authority was rejected"))?;
        let idempotency = IdempotencyKey::new(request.header().request_id().to_vec())?;
        let operation_id = OperationId::from_bytes(*request.header().request_id());
        match self.journal.check_idempotency(&idempotency, request_digest) {
            IdempotencyOutcome::Conflict => {
                return Err(MountError::Fence(
                    "request ID was reused with different bytes",
                ));
            }
            IdempotencyOutcome::Replay(existing) if existing != operation_id => {
                return Err(MountError::State(
                    "mount idempotency operation identity changed".to_owned(),
                ));
            }
            IdempotencyOutcome::Replay(_) => {
                let effect = self.effect(request.header().request_id())?;
                validate_effect_matches(&effect, &admission, request_digest)?;
                if effect.status() == MountEffectStatusV2::Complete {
                    return Ok(effect.receipt().to_vec());
                }
                if effect.plan_digest() != admission.effect.plan_digest()
                    || effect.lease_digest() != admission.effect.lease_digest()
                {
                    self.persist_authority_refresh(&request, &admission)?;
                }
            }
            IdempotencyOutcome::Vacant => {
                self.persist_intent(
                    &request,
                    &idempotency,
                    operation_id,
                    request_digest,
                    catalog_commitment,
                    &admission,
                )?;
            }
        }

        let effect = self.effect(request.header().request_id())?;
        validate_effect_matches(&effect, &admission, request_digest)?;
        if effect.status() == MountEffectStatusV2::Complete {
            return Ok(effect.receipt().to_vec());
        }
        self.authority
            .validate_effect_clock(&effect, &trusted_clock()?)
            .map_err(|_| MountError::Fence("mount authority expired before the effect"))?;

        let handle = operation_handle(&request, request_digest)?;
        let current = self
            .resources
            .get(&handle)
            .cloned()
            .ok_or_else(|| MountError::State("durable mount resource is absent".to_owned()))?;
        validate_request_resource(&request, &current, self.kernel_boot_id)?;
        validate_pending_action_state(request.action(), &current.state)?;
        let handles = expected_handles(
            request.action(),
            request_digest,
            request.detached_mount_handle().copied(),
        )?;
        let authority = &self.authority;
        let mut before_effect = || {
            let clock = trusted_clock()?;
            authority
                .validate_effect_clock(&effect, &clock)
                .map_err(|_| MountError::Fence("mount authority expired before the effect"))?;
            Ok(EffectDeadlineV1 {
                clock_provenance: *effect.clock_provenance(),
                host_boot_id: *effect.host_boot_id(),
                boottime_nanoseconds: effect.effect_deadline_boottime_nanoseconds(),
            })
        };
        let observation = if request.action() == MountAction::MOUNT_ACTION_DETACH {
            execute_durable_detach(
                &mut self.worker,
                &request,
                request_digest,
                &current,
                handles,
                catalog_commitment.ok_or(MountError::Fence(
                    "detach lost its admitted catalog commitment",
                ))?,
                &mut before_effect,
            )?
        } else {
            self.worker.execute(
                &request,
                request_digest,
                handles,
                catalog_commitment,
                &mut before_effect,
            )?
        };
        validate_observation(request.action(), handles, &observation)?;
        let response = encode_result(&request, &observation)?;
        let response_limit = usize::try_from(request.header().maximum_response_bytes())
            .map_err(|_| MountError::State("response limit does not fit usize".to_owned()))?;
        if response.len() > response_limit {
            return Err(MountError::State(
                "mount result exceeds the admitted response bound".to_owned(),
            ));
        }
        self.persist_completion(&request, &current, &observation, &response, effect)?;
        Ok(response)
    }

    fn persist_authority_refresh(
        &mut self,
        request: &ValidatedMountRequest,
        admission: &VerifiedMountAdmissionV1,
    ) -> Result<()> {
        let records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                request.fence().sandbox_id().to_vec(),
                self.authority
                    .seal_fence(request.fence().sandbox_id(), &admission.fence)
                    .map_err(|_| MountError::Fence("mount authority fence could not be sealed"))?,
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                request.header().request_id().to_vec(),
                self.authority
                    .seal_effect(request.header().request_id(), &admission.effect)
                    .map_err(|_| MountError::Fence("mount effect intent could not be sealed"))?,
            ),
        ];
        self.journal.commit(&JournalTransaction::new(
            authority_refresh_transaction(
                *request.header().request_id(),
                admission.effect.plan_digest(),
                admission.effect.lease_digest(),
            ),
            records,
        )?)?;
        Ok(())
    }

    fn persist_intent(
        &mut self,
        request: &ValidatedMountRequest,
        idempotency: &IdempotencyKey,
        operation_id: OperationId,
        request_digest: [u8; 32],
        catalog_commitment: Option<ObjectDigest>,
        admission: &VerifiedMountAdmissionV1,
    ) -> Result<()> {
        let correlation = operation_correlation(request, request_digest);
        let mut resource_records = match request.action() {
            MountAction::MOUNT_ACTION_CREATE_DETACHED => self.resources.plan_allocate(
                &allocated_resource(request, request_digest, self.kernel_boot_id, correlation)?,
            )?,
            MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => self
                .plan_publication_intent(
                    request,
                    request_digest,
                    correlation,
                    catalog_commitment.ok_or(MountError::Fence(
                        "publication lost its admitted catalog commitment",
                    ))?,
                )?,
            MountAction::MOUNT_ACTION_DETACH => self.plan_detach_intent(request, correlation)?,
            MountAction::MOUNT_ACTION_RELEASE => {
                let current = resource_for_supplied_handle(&self.resources, request)?;
                validate_request_resource(request, current, self.kernel_boot_id)?;
                if !matches!(
                    current.state,
                    MountResourceStateV1::Prepared { .. } | MountResourceStateV1::Draining { .. }
                ) {
                    return Err(MountError::State(
                        "release requires a prepared or draining mount resource".to_owned(),
                    ));
                }
                self.plan_release_intent(current, correlation)?
            }
            MountAction::MOUNT_ACTION_UNSPECIFIED => return Err(invalid_pending_state()),
        };
        let applied_records = resource_records.clone();
        let mut records = vec![
            JournalRecord::put(
                RecordNamespace::DesiredState,
                request.fence().sandbox_id().to_vec(),
                self.authority
                    .seal_fence(request.fence().sandbox_id(), &admission.fence)
                    .map_err(|_| MountError::Fence("mount authority fence could not be sealed"))?,
            ),
            JournalRecord::idempotency(idempotency, request_digest, operation_id),
            JournalRecord::put(
                RecordNamespace::Effect,
                request.header().request_id().to_vec(),
                self.authority
                    .seal_effect(request.header().request_id(), &admission.effect)
                    .map_err(|_| MountError::Fence("mount effect intent could not be sealed"))?,
            ),
        ];
        records.append(&mut resource_records);
        self.journal.commit(&JournalTransaction::new(
            intent_transaction(*request.header().request_id()),
            records,
        )?)?;
        if !applied_records.is_empty() {
            self.resources.apply_committed(&applied_records)?;
        }
        Ok(())
    }

    fn plan_publication_intent(
        &self,
        request: &ValidatedMountRequest,
        request_digest: [u8; 32],
        operation: OperationCorrelationV1,
        catalog_commitment: aos_sandbox_core::ObjectDigest,
    ) -> Result<Vec<JournalRecord>> {
        let current = resource_for_supplied_handle(&self.resources, request)?;
        validate_request_resource(request, current, self.kernel_boot_id)?;
        let MountResourceStateV1::Prepared { detached, .. } = &current.state else {
            return Err(MountError::State(
                "publication requires a prepared mount resource".to_owned(),
            ));
        };
        let expected_mount_id = mount_id(detached.unique_mount_id)?;
        let predecessor = request
            .replacement_mount_handle()
            .map(|handle| replacement_predecessor(&self.resources, request, *handle))
            .transpose()?;
        let predecessor_identity = predecessor
            .map(|resource| -> Result<_> {
                Ok((resource.handle, mount_id(installed_mount_id(resource)?)?))
            })
            .transpose()?;
        let preflight = self.worker.preflight_publication(
            request,
            request_digest,
            current.handle,
            expected_mount_id,
            predecessor_identity,
            catalog_commitment,
        )?;
        let valid = match request.action() {
            MountAction::MOUNT_ACTION_INSTALL => {
                matches!(preflight.disposition, MountTargetObservation::Absent)
            }
            MountAction::MOUNT_ACTION_REPLACE => matches!(
                preflight.disposition,
                MountTargetObservation::PredecessorInstalled
            ),
            _ => false,
        };
        if !valid {
            return Err(MountError::Worker(
                "publication preflight found a conflicting target".to_owned(),
            ));
        }
        let mut next = current.clone();
        next.revision = checked_revision(current.revision)?;
        next.state = MountResourceStateV1::Publishing {
            detached: detached.clone(),
            publication: PublicationCorrelationV1 {
                operation,
                target_mount_namespace_id: preflight.target_mount_namespace_id,
                target_namespace_generation: request.namespace_generation(),
                replaces: predecessor.map(|resource| resource.handle),
            },
        };
        self.resources.plan_transition(current.revision, &next)
    }

    fn plan_detach_intent(
        &self,
        request: &ValidatedMountRequest,
        detachment: OperationCorrelationV1,
    ) -> Result<Vec<JournalRecord>> {
        let current = resource_for_supplied_handle(&self.resources, request)?;
        validate_request_resource(request, current, self.kernel_boot_id)?;
        let MountResourceStateV1::Installed {
            detached,
            installed,
            ..
        } = &current.state
        else {
            return Err(MountError::State(
                "detach requires an installed mount resource".to_owned(),
            ));
        };
        let mut next = current.clone();
        next.revision = checked_revision(current.revision)?;
        next.state = MountResourceStateV1::Detaching {
            detached: detached.clone(),
            installed: installed.clone(),
            detachment,
        };
        self.resources.plan_transition(current.revision, &next)
    }

    fn plan_release_intent(
        &self,
        current: &MountResourceV1,
        release: OperationCorrelationV1,
    ) -> Result<Vec<JournalRecord>> {
        let (detached, installed, replaced_by) = match &current.state {
            MountResourceStateV1::Prepared { detached, .. } => (detached.clone(), None, None),
            MountResourceStateV1::Draining {
                detached,
                installed,
                replaced_by,
            } => (
                detached.clone(),
                Some(installed.clone()),
                Some(*replaced_by),
            ),
            _ => return Err(invalid_pending_state()),
        };
        let mut next = current.clone();
        next.revision = checked_revision(current.revision)?;
        next.state = MountResourceStateV1::Releasing {
            detached,
            installed,
            release,
            replaced_by,
        };
        self.resources.plan_transition(current.revision, &next)
    }

    fn persist_completion(
        &mut self,
        request: &ValidatedMountRequest,
        current: &MountResourceV1,
        observation: &WorkerObservation,
        response: &[u8],
        effect: MountEffectIntentV2,
    ) -> Result<()> {
        let resource_records = self.plan_completion(request, current, observation)?;
        let mut records = resource_records.clone();
        let request_digest = *effect.transport_request_digest().as_bytes();
        let completed = effect
            .complete(response.to_vec())
            .map_err(|_| MountError::State("completed mount effect is invalid".to_owned()))?;
        records.push(JournalRecord::put(
            RecordNamespace::Effect,
            request.header().request_id().to_vec(),
            self.authority
                .seal_effect(request.header().request_id(), &completed)
                .map_err(|_| MountError::Fence("completed mount effect could not be sealed"))?,
        ));
        self.journal.commit(&JournalTransaction::new(
            completion_transaction(request_digest),
            records,
        )?)?;
        self.resources.apply_committed(&resource_records)?;
        Ok(())
    }

    fn plan_completion(
        &self,
        request: &ValidatedMountRequest,
        current: &MountResourceV1,
        observation: &WorkerObservation,
    ) -> Result<Vec<JournalRecord>> {
        match request.action() {
            MountAction::MOUNT_ACTION_CREATE_DETACHED => {
                let MountResourceStateV1::Allocated { creation } = &current.state else {
                    return Err(invalid_pending_state());
                };
                let observed = observation.detached_mount_id.ok_or_else(|| {
                    MountError::Worker("create omitted detached mount identity".to_owned())
                })?;
                let mut next = current.clone();
                next.revision = checked_revision(current.revision)?;
                next.state = MountResourceStateV1::Prepared {
                    detached: DetachedMountIdentityV1 {
                        unique_mount_id: observed.get(),
                    },
                    creation: creation.clone(),
                };
                self.resources.plan_transition(current.revision, &next)
            }
            MountAction::MOUNT_ACTION_INSTALL => self.resources.plan_transition(
                current.revision,
                &installed_successor(current, observation)?,
            ),
            MountAction::MOUNT_ACTION_REPLACE => {
                let successor = installed_successor(current, observation)?;
                let predecessor = self
                    .resources
                    .get(request.replacement_mount_handle().ok_or_else(|| {
                        MountError::State("replacement predecessor is absent".to_owned())
                    })?)
                    .ok_or_else(|| {
                        MountError::State("replacement predecessor is unknown".to_owned())
                    })?;
                let MountResourceStateV1::Installed {
                    detached,
                    installed,
                    ..
                } = &predecessor.state
                else {
                    return Err(MountError::State(
                        "replacement predecessor is not installed".to_owned(),
                    ));
                };
                let mut draining = predecessor.clone();
                draining.revision = checked_revision(predecessor.revision)?;
                draining.state = MountResourceStateV1::Draining {
                    detached: detached.clone(),
                    installed: installed.clone(),
                    replaced_by: successor.handle,
                };
                self.resources.plan_confirm_replacement(
                    current.revision,
                    &successor,
                    predecessor.revision,
                    &draining,
                )
            }
            MountAction::MOUNT_ACTION_DETACH => {
                let (last_detached_mount_id, last_installed_mount_id) = release_ids(&current.state);
                let mut next = current.clone();
                next.revision = checked_revision(current.revision)?;
                next.state = MountResourceStateV1::Released {
                    last_detached_mount_id,
                    last_installed_mount_id,
                };
                self.resources.plan_transition(current.revision, &next)
            }
            MountAction::MOUNT_ACTION_RELEASE => self.plan_release_completion(current),
            MountAction::MOUNT_ACTION_UNSPECIFIED => Err(invalid_pending_state()),
        }
    }

    fn plan_release_completion(&self, current: &MountResourceV1) -> Result<Vec<JournalRecord>> {
        let (last_detached_mount_id, last_installed_mount_id) = release_ids(&current.state);
        let mut released = current.clone();
        released.revision = checked_revision(current.revision)?;
        released.state = MountResourceStateV1::Released {
            last_detached_mount_id,
            last_installed_mount_id,
        };
        let MountResourceStateV1::Releasing { replaced_by, .. } = &current.state else {
            return self.resources.plan_transition(current.revision, &released);
        };
        let Some(replaced_by) = replaced_by else {
            return self.resources.plan_transition(current.revision, &released);
        };
        let successor = self.resources.get(replaced_by).ok_or_else(|| {
            MountError::State("draining resource successor is unknown".to_owned())
        })?;
        let MountResourceStateV1::Installed {
            detached,
            installed,
            publication,
        } = &successor.state
        else {
            return Err(MountError::State(
                "draining resource successor is not installed".to_owned(),
            ));
        };
        let mut retired_successor = successor.clone();
        retired_successor.revision = checked_revision(successor.revision)?;
        let mut retired_publication = publication.clone();
        retired_publication.replaces = None;
        retired_successor.state = MountResourceStateV1::Installed {
            detached: detached.clone(),
            installed: installed.clone(),
            publication: retired_publication,
        };
        self.resources.plan_finish_replacement(
            successor.revision,
            &retired_successor,
            current.revision,
            &released,
        )
    }

    fn effect(&self, request_id: &[u8; 16]) -> Result<MountEffectIntentV2> {
        self.authority
            .open_effect(
                request_id,
                self.journal
                    .get(RecordNamespace::Effect, request_id)
                    .ok_or_else(|| {
                        MountError::State("durable mount effect is absent".to_owned())
                    })?,
            )
            .map_err(|_| MountError::Fence("durable mount effect authentication failed"))
    }
}

fn execute_durable_detach<W: MountWorker>(
    worker: &mut W,
    request: &ValidatedMountRequest,
    request_digest: [u8; 32],
    current: &MountResourceV1,
    handles: EffectHandles,
    catalog_commitment: aos_sandbox_core::ObjectDigest,
    before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
) -> Result<WorkerObservation> {
    let expected = mount_id(installed_mount_id(current)?)?;
    worker.reconcile_detach(
        request,
        request_digest,
        current.handle,
        expected,
        catalog_commitment,
        before_effect,
    )?;
    Ok(WorkerObservation {
        state: MountState::MOUNT_STATE_REVOKED,
        handles,
        detached_mount_id: None,
        installed: None,
    })
}

fn installed_successor(
    current: &MountResourceV1,
    observation: &WorkerObservation,
) -> Result<MountResourceV1> {
    let MountResourceStateV1::Publishing {
        detached,
        publication,
    } = &current.state
    else {
        return Err(invalid_pending_state());
    };
    let observed = observation.installed.as_ref().ok_or_else(|| {
        MountError::Worker("publication omitted installed mount evidence".to_owned())
    })?;
    if observed.mount.mount_namespace_id != publication.target_mount_namespace_id {
        return Err(MountError::Worker(
            "publication changed target mount namespace identity".to_owned(),
        ));
    }
    let mut next = current.clone();
    next.revision = checked_revision(current.revision)?;
    next.state = MountResourceStateV1::Installed {
        detached: detached.clone(),
        installed: InstalledMountObservationV1 {
            unique_mount_id: observed.mount.mount_id.get(),
            parent_mount_id: observed.mount.parent_mount_id.get(),
            target_mount_namespace_id: observed.mount.mount_namespace_id,
            device_major: observed.mount.device_major,
            device_minor: observed.mount.device_minor,
            superblock_magic: observed.mount.superblock_magic,
            superblock_flags: observed.mount.superblock_flags,
            mount_attributes: observed.mount.mount_attributes,
            propagation: observed.mount.propagation,
            root: observed.mount.root.as_os_str().as_bytes().to_vec(),
            mount_point: observed.mount.mount_point.as_os_str().as_bytes().to_vec(),
            identity_map_digest: observed.idmap_digest,
        },
        publication: publication.clone(),
    };
    Ok(next)
}

fn allocated_resource(
    request: &ValidatedMountRequest,
    request_digest: [u8; 32],
    kernel_boot_id: [u8; 16],
    creation: OperationCorrelationV1,
) -> Result<MountResourceV1> {
    let attributes = request.attributes().ok_or_else(|| {
        MountError::State("create request lost validated mount attributes".to_owned())
    })?;
    let descriptor = request.view_revision().ok_or_else(|| {
        MountError::State("create request lost validated view descriptor".to_owned())
    })?;
    let handle = derive_handle(b"detached", request_digest);
    Ok(MountResourceV1 {
        handle,
        fd_store_key: canonical_fd_store_key(handle),
        kernel_boot_id,
        revision: 1,
        binding: binding(request),
        recipe: MountRecipeV1 {
            attachment_id: *request.attachment_id(),
            destination_slot_id: *request.destination_slot_id(),
            view_revision: ObjectDescriptorV1::from_runtime(descriptor)?,
            source_generation: request.source_generation(),
            policy: mount_policy(attributes),
        },
        state: MountResourceStateV1::Allocated { creation },
    })
}

fn binding(request: &ValidatedMountRequest) -> AssignmentBindingV1 {
    AssignmentBindingV1 {
        sandbox_id: *request.fence().sandbox_id(),
        incarnation_id: *request.fence().incarnation_id(),
        assignment_epoch: request.fence().assignment_epoch(),
        desired_generation: request.fence().desired_generation(),
        assignment_digest: *request.fence().assignment_digest(),
        namespace_generation: request.namespace_generation(),
    }
}

fn mount_policy(attributes: ValidatedMountAttributes) -> MountPolicyV1 {
    let mut owned = Vec::new();
    for (enabled, attribute) in [
        (attributes.read_only(), OwnedMountAttributeV1::ReadOnly),
        (attributes.no_exec(), OwnedMountAttributeV1::NoExec),
        (attributes.no_suid(), OwnedMountAttributeV1::NoSuid),
        (attributes.no_device(), OwnedMountAttributeV1::NoDevice),
        (attributes.no_atime(), OwnedMountAttributeV1::NoAtime),
    ] {
        if enabled {
            owned.push(attribute);
        }
    }
    let mutation = match attributes.mutation_mode() {
        0 => NativeMutationV1::ReadOnly,
        1 => NativeMutationV1::ReadWrite,
        2 => NativeMutationV1::PrivateCow,
        3 => NativeMutationV1::AppendOnly,
        4 => NativeMutationV1::Service,
        _ => unreachable!("validated mutation mode is closed"),
    };
    MountPolicyV1 {
        attributes: owned,
        mutation,
    }
}

fn validate_request_resource(
    request: &ValidatedMountRequest,
    resource: &MountResourceV1,
    kernel_boot_id: [u8; 16],
) -> Result<()> {
    let request_binding = binding(request);
    let teardown_binding_matches = matches!(
        request.action(),
        MountAction::MOUNT_ACTION_DETACH | MountAction::MOUNT_ACTION_RELEASE
    ) && request_binding.sandbox_id == resource.binding.sandbox_id
        && request_binding.incarnation_id == resource.binding.incarnation_id
        && request_binding.namespace_generation == resource.binding.namespace_generation
        && (
            request_binding.assignment_epoch,
            request_binding.desired_generation,
        ) >= (
            resource.binding.assignment_epoch,
            resource.binding.desired_generation,
        );
    let attributes_match = request
        .attributes()
        .is_none_or(|attributes| resource.recipe.policy == mount_policy(attributes));
    let view_matches = request.view_revision().is_none_or(|descriptor| {
        ObjectDescriptorV1::from_runtime(descriptor)
            .is_ok_and(|value| value == resource.recipe.view_revision)
    });
    if resource.kernel_boot_id != kernel_boot_id
        || (resource.binding != request_binding && !teardown_binding_matches)
        || resource.recipe.attachment_id != *request.attachment_id()
        || resource.recipe.destination_slot_id != *request.destination_slot_id()
        || resource.recipe.source_generation != request.source_generation()
        || !attributes_match
        || !view_matches
    {
        return Err(MountError::Fence(
            "mount request contradicts immutable resource recipe",
        ));
    }
    Ok(())
}

fn resource_for_supplied_handle<'a>(
    resources: &'a MountResourceTableV1,
    request: &ValidatedMountRequest,
) -> Result<&'a MountResourceV1> {
    resources
        .get(request.detached_mount_handle().ok_or_else(|| {
            MountError::State("mount action omitted its resource handle".to_owned())
        })?)
        .ok_or_else(|| MountError::State("mount resource handle is unknown".to_owned()))
}

fn replacement_predecessor<'a>(
    resources: &'a MountResourceTableV1,
    request: &ValidatedMountRequest,
    handle: [u8; 32],
) -> Result<&'a MountResourceV1> {
    let predecessor = resources
        .get(&handle)
        .ok_or_else(|| MountError::State("replacement predecessor is unknown".to_owned()))?;
    let successor_generation = (
        request.fence().assignment_epoch(),
        request.fence().desired_generation(),
    );
    let predecessor_generation = (
        predecessor.binding.assignment_epoch,
        predecessor.binding.desired_generation,
    );
    if !matches!(predecessor.state, MountResourceStateV1::Installed { .. })
        || predecessor.recipe.attachment_id != *request.attachment_id()
        || predecessor.recipe.destination_slot_id != *request.destination_slot_id()
        || predecessor.binding.sandbox_id != *request.fence().sandbox_id()
        || predecessor.binding.incarnation_id != *request.fence().incarnation_id()
        || successor_generation <= predecessor_generation
    {
        return Err(MountError::Fence(
            "replacement predecessor is not the prior generation of this slot",
        ));
    }
    Ok(predecessor)
}

fn operation_handle(request: &ValidatedMountRequest, request_digest: [u8; 32]) -> Result<[u8; 32]> {
    if request.action() == MountAction::MOUNT_ACTION_CREATE_DETACHED {
        Ok(derive_handle(b"detached", request_digest))
    } else {
        request
            .detached_mount_handle()
            .copied()
            .ok_or_else(|| MountError::State("mount action omitted its durable handle".to_owned()))
    }
}

fn operation_correlation(
    request: &ValidatedMountRequest,
    request_digest: [u8; 32],
) -> OperationCorrelationV1 {
    OperationCorrelationV1 {
        operation_id: *request.header().request_id(),
        request_digest,
    }
}

fn derive_handle(label: &[u8], request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.handle.v1\0");
    digest.update(label);
    digest.update(request_digest);
    digest.finalize().into()
}

fn installed_mount_id(resource: &MountResourceV1) -> Result<u64> {
    match &resource.state {
        MountResourceStateV1::Installed { installed, .. }
        | MountResourceStateV1::Detaching { installed, .. }
        | MountResourceStateV1::Draining { installed, .. } => Ok(installed.unique_mount_id),
        _ => Err(invalid_pending_state()),
    }
}

fn release_ids(state: &MountResourceStateV1) -> (Option<u64>, Option<u64>) {
    match state {
        MountResourceStateV1::Prepared { detached, .. }
        | MountResourceStateV1::Publishing { detached, .. } => {
            (Some(detached.unique_mount_id), None)
        }
        MountResourceStateV1::Installed {
            detached,
            installed,
            ..
        }
        | MountResourceStateV1::Detaching {
            detached,
            installed,
            ..
        }
        | MountResourceStateV1::Draining {
            detached,
            installed,
            ..
        } => (
            Some(detached.unique_mount_id),
            Some(installed.unique_mount_id),
        ),
        MountResourceStateV1::Releasing {
            detached,
            installed,
            ..
        } => (
            Some(detached.unique_mount_id),
            installed.as_ref().map(|value| value.unique_mount_id),
        ),
        _ => (None, None),
    }
}

fn fault_unverifiable_allocated_custody<W: MountWorker>(
    journal: &mut Journal,
    resources: &mut MountResourceTableV1,
    current_boot_id: [u8; 16],
    worker: &mut W,
) -> Result<()> {
    let retained: std::collections::BTreeSet<_> = worker
        .custody_inventory()?
        .into_iter()
        .map(|observation| observation.handle)
        .collect();
    let uncertain: Vec<_> = resources
        .resources()
        .filter(|resource| {
            resource.kernel_boot_id == current_boot_id
                && retained.contains(&resource.handle)
                && matches!(resource.state, MountResourceStateV1::Allocated { .. })
        })
        .cloned()
        .collect();
    for current in uncertain {
        worker.discard_retained(current.handle)?;
        let MountResourceStateV1::Allocated { creation } = &current.state else {
            return Err(invalid_pending_state());
        };
        let failure_digest: [u8; 32] =
            Sha256::digest(b"aos.mount.fault.unverifiable-allocated-custody.v1").into();
        let mut next = current.clone();
        next.revision = checked_revision(current.revision)?;
        next.state = fault(
            MountFaultPhaseV1::Allocated,
            Some(creation.clone()),
            None,
            None,
            None,
            None,
            None,
            failure_digest,
        );
        let records = resources.plan_transition(current.revision, &next)?;
        journal.commit(&JournalTransaction::new(
            custody_fault_transaction(current.handle, next.revision),
            records.clone(),
        )?)?;
        resources.apply_committed(&records)?;
    }
    Ok(())
}

fn fault_stale_boot_resources(
    journal: &mut Journal,
    resources: &mut MountResourceTableV1,
    current_boot_id: [u8; 16],
) -> Result<()> {
    let stale: Vec<_> = resources
        .resources()
        .filter(|resource| {
            resource.kernel_boot_id != current_boot_id
                && !matches!(
                    resource.state,
                    MountResourceStateV1::Released { .. } | MountResourceStateV1::Faulted { .. }
                )
        })
        .cloned()
        .collect();
    for current in stale {
        let mut next = current.clone();
        next.revision = checked_revision(current.revision)?;
        next.state = stale_boot_fault(&current.state);
        let records = resources.plan_transition(current.revision, &next)?;
        let transaction = JournalTransaction::new(
            boot_fault_transaction(current.handle, next.revision),
            records.clone(),
        )?;
        journal.commit(&transaction)?;
        resources.apply_committed(&records)?;
    }
    Ok(())
}

fn stale_boot_fault(state: &MountResourceStateV1) -> MountResourceStateV1 {
    let failure_digest: [u8; 32] = Sha256::digest(b"aos.mount.fault.kernel-boot-changed.v1").into();
    match state {
        MountResourceStateV1::Allocated { creation } => fault(
            MountFaultPhaseV1::Allocated,
            Some(creation.clone()),
            None,
            None,
            None,
            None,
            None,
            failure_digest,
        ),
        MountResourceStateV1::Prepared { detached, creation } => fault(
            MountFaultPhaseV1::Prepared,
            Some(creation.clone()),
            None,
            None,
            None,
            Some(detached.clone()),
            None,
            failure_digest,
        ),
        MountResourceStateV1::Publishing {
            detached,
            publication,
        } => fault(
            MountFaultPhaseV1::Publishing,
            None,
            Some(publication.clone()),
            None,
            None,
            Some(detached.clone()),
            None,
            failure_digest,
        ),
        MountResourceStateV1::Installed {
            detached,
            installed,
            publication,
        } => fault(
            MountFaultPhaseV1::Installed,
            None,
            Some(publication.clone()),
            None,
            None,
            Some(detached.clone()),
            Some(installed.clone()),
            failure_digest,
        ),
        MountResourceStateV1::Detaching {
            detached,
            installed,
            detachment,
        } => fault(
            MountFaultPhaseV1::Detaching,
            None,
            None,
            Some(detachment.clone()),
            None,
            Some(detached.clone()),
            Some(installed.clone()),
            failure_digest,
        ),
        MountResourceStateV1::Draining {
            detached,
            installed,
            replaced_by,
        } => fault(
            MountFaultPhaseV1::Draining,
            None,
            None,
            None,
            Some(*replaced_by),
            Some(detached.clone()),
            Some(installed.clone()),
            failure_digest,
        ),
        MountResourceStateV1::Releasing {
            detached,
            installed,
            release,
            replaced_by,
        } => MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Releasing,
            creation: None,
            publication: None,
            detachment: None,
            release: Some(release.clone()),
            replaced_by: *replaced_by,
            detached: Some(detached.clone()),
            installed: installed.clone(),
            failure_digest,
        },
        MountResourceStateV1::Released { .. } | MountResourceStateV1::Faulted { .. } => {
            state.clone()
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fault(
    from: MountFaultPhaseV1,
    creation: Option<OperationCorrelationV1>,
    publication: Option<PublicationCorrelationV1>,
    detachment: Option<OperationCorrelationV1>,
    replaced_by: Option<[u8; 32]>,
    detached: Option<DetachedMountIdentityV1>,
    installed: Option<InstalledMountObservationV1>,
    failure_digest: [u8; 32],
) -> MountResourceStateV1 {
    MountResourceStateV1::Faulted {
        from,
        creation,
        publication,
        detachment,
        release: None,
        replaced_by,
        detached,
        installed,
        failure_digest,
    }
}

fn validate_custody(
    resources: &MountResourceTableV1,
    current_boot_id: [u8; 16],
    custody: &[RetainedMountObservation],
) -> Result<()> {
    let mut retained = BTreeMap::new();
    let mut mount_ids = std::collections::BTreeSet::new();
    for observation in custody {
        if retained
            .insert(observation.handle, observation.mount_id.get())
            .is_some()
            || !mount_ids.insert(observation.mount_id)
        {
            return Err(MountError::State(
                "retained mount custody contains a handle or mount-ID alias".to_owned(),
            ));
        }
    }
    for resource in resources.resources() {
        let retained_id = retained.remove(&resource.handle);
        if resource.kernel_boot_id != current_boot_id {
            if retained_id.is_some() {
                return Err(MountError::State(
                    "retained mount belongs to a stale kernel boot".to_owned(),
                ));
            }
            continue;
        }
        let expected = match &resource.state {
            MountResourceStateV1::Allocated { .. } => continue,
            MountResourceStateV1::Prepared { detached, .. }
            | MountResourceStateV1::Publishing { detached, .. }
            | MountResourceStateV1::Installed { detached, .. }
            | MountResourceStateV1::Draining { detached, .. } => Some(detached.unique_mount_id),
            MountResourceStateV1::Detaching { detached, .. }
            | MountResourceStateV1::Releasing { detached, .. } => {
                if retained_id.is_some_and(|value| value != detached.unique_mount_id) {
                    return Err(MountError::State(
                        "releasing custody has the wrong mount identity".to_owned(),
                    ));
                }
                continue;
            }
            MountResourceStateV1::Faulted { detached, .. } => {
                detached.as_ref().map(|value| value.unique_mount_id)
            }
            MountResourceStateV1::Released { .. } => None,
        };
        if retained_id != expected {
            return Err(MountError::State(
                "retained mount custody contradicts durable resource state".to_owned(),
            ));
        }
    }
    if !retained.is_empty() {
        return Err(MountError::State(
            "retained mount custody contains an unknown handle".to_owned(),
        ));
    }
    Ok(())
}

fn validate_observation(
    action: MountAction,
    expected: EffectHandles,
    observed: &WorkerObservation,
) -> Result<()> {
    let shape = match action {
        MountAction::MOUNT_ACTION_CREATE_DETACHED => {
            observed.state == MountState::MOUNT_STATE_DETACHED
                && observed.detached_mount_id.is_some()
                && observed.installed.is_none()
        }
        MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
            observed.state == MountState::MOUNT_STATE_INSTALLED
                && observed.detached_mount_id.is_none()
                && observed.installed.is_some()
        }
        MountAction::MOUNT_ACTION_DETACH => {
            observed.state == MountState::MOUNT_STATE_REVOKED
                && observed.detached_mount_id.is_none()
                && observed.installed.is_none()
        }
        MountAction::MOUNT_ACTION_RELEASE => {
            observed.state == MountState::MOUNT_STATE_ABSENT
                && observed.detached_mount_id.is_none()
                && observed.installed.is_none()
        }
        MountAction::MOUNT_ACTION_UNSPECIFIED => false,
    };
    if !shape || observed.handles != expected {
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

fn mount_id(value: u64) -> Result<MountId> {
    MountId::new(value).map_err(|error| MountError::State(error.to_string()))
}

fn checked_revision(revision: u64) -> Result<u64> {
    revision
        .checked_add(1)
        .ok_or_else(|| MountError::State("mount resource revision overflow".to_owned()))
}

fn broker_instance_id() -> Result<[u8; 16]> {
    const RANDOM_UUID_PATH: &str = "/proc/sys/kernel/random/uuid";
    let bytes = std::fs::read(RANDOM_UUID_PATH)
        .map_err(|error| MountError::State(format!("cannot read broker instance UUID: {error}")))?;
    KernelBootId::parse(&bytes)
        .map(KernelBootId::into_bytes)
        .map_err(|error| MountError::State(format!("invalid broker instance UUID: {error}")))
}

fn inventory_record(resource: &MountResourceV1) -> MountInventoryRecord {
    let (
        lifecycle,
        creation,
        publication,
        detachment,
        release,
        replaced_by,
        detached,
        installed,
        fault,
        last_installed,
    ) = inventory_state(&resource.state);
    MountInventoryRecord {
        mount_handle: resource.handle.to_vec(),
        resource_revision: resource.revision,
        binding: Some(MountAssignmentBinding {
            fence: Some(AssignmentFence {
                sandbox_id: resource.binding.sandbox_id.to_vec(),
                incarnation_id: resource.binding.incarnation_id.to_vec(),
                assignment_epoch: resource.binding.assignment_epoch,
                desired_generation: resource.binding.desired_generation,
                assignment_digest: resource.binding.assignment_digest.to_vec(),
                ..Default::default()
            })
            .into(),
            namespace_generation: resource.binding.namespace_generation,
            ..Default::default()
        })
        .into(),
        recipe: Some(inventory_recipe(&resource.recipe)).into(),
        lifecycle: lifecycle.into(),
        resource_kernel_boot_id: resource.kernel_boot_id.to_vec(),
        detached_unique_mount_id: detached,
        installed_observation: installed.map(inventory_observation).into(),
        publication: publication.map(inventory_publication).into(),
        replaced_by_mount_handle: replaced_by.map_or_else(Vec::new, |value| value.to_vec()),
        fault: fault
            .map(|(from, failure_digest)| MountFaultCorrelation {
                from: from.into(),
                failure_digest: failure_digest.to_vec(),
                ..Default::default()
            })
            .into(),
        last_installed_unique_mount_id: last_installed,
        creation: creation.map(inventory_operation).into(),
        detachment: detachment.map(inventory_operation).into(),
        release: release.map(inventory_operation).into(),
        ..Default::default()
    }
}

type InventoryState<'a> = (
    MountLifecycle,
    Option<&'a OperationCorrelationV1>,
    Option<&'a PublicationCorrelationV1>,
    Option<&'a OperationCorrelationV1>,
    Option<&'a OperationCorrelationV1>,
    Option<MountHandleV1>,
    Option<u64>,
    Option<&'a InstalledMountObservationV1>,
    Option<(MountFaultPhase, &'a [u8; 32])>,
    Option<u64>,
);

#[allow(clippy::too_many_lines)]
fn inventory_state(state: &MountResourceStateV1) -> InventoryState<'_> {
    match state {
        MountResourceStateV1::Allocated { creation } => (
            MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED,
            Some(creation),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        MountResourceStateV1::Prepared { detached, creation } => (
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED,
            Some(creation),
            None,
            None,
            None,
            None,
            Some(detached.unique_mount_id),
            None,
            None,
            None,
        ),
        MountResourceStateV1::Publishing {
            detached,
            publication,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING,
            None,
            Some(publication),
            None,
            None,
            None,
            Some(detached.unique_mount_id),
            None,
            None,
            None,
        ),
        MountResourceStateV1::Installed {
            detached,
            installed,
            publication,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
            None,
            Some(publication),
            None,
            None,
            None,
            Some(detached.unique_mount_id),
            Some(installed),
            None,
            None,
        ),
        MountResourceStateV1::Detaching {
            detached,
            installed,
            detachment,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_DETACHING,
            None,
            None,
            Some(detachment),
            None,
            None,
            Some(detached.unique_mount_id),
            Some(installed),
            None,
            None,
        ),
        MountResourceStateV1::Draining {
            detached,
            installed,
            replaced_by,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_DRAINING,
            None,
            None,
            None,
            None,
            Some(*replaced_by),
            Some(detached.unique_mount_id),
            Some(installed),
            None,
            None,
        ),
        MountResourceStateV1::Releasing {
            detached,
            installed,
            release,
            replaced_by,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_RELEASING,
            None,
            None,
            None,
            Some(release),
            *replaced_by,
            Some(detached.unique_mount_id),
            installed.as_ref(),
            None,
            None,
        ),
        MountResourceStateV1::Released {
            last_detached_mount_id,
            last_installed_mount_id,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_RELEASED,
            None,
            None,
            None,
            None,
            None,
            *last_detached_mount_id,
            None,
            None,
            *last_installed_mount_id,
        ),
        MountResourceStateV1::Faulted {
            from,
            creation,
            publication,
            detachment,
            release,
            replaced_by,
            detached,
            installed,
            failure_digest,
        } => (
            MountLifecycle::MOUNT_LIFECYCLE_FAULTED,
            creation.as_ref(),
            publication.as_ref(),
            detachment.as_ref(),
            release.as_ref(),
            *replaced_by,
            detached.as_ref().map(|value| value.unique_mount_id),
            installed.as_ref(),
            Some((inventory_fault_phase(*from), failure_digest)),
            None,
        ),
    }
}

fn inventory_fault_phase(phase: MountFaultPhaseV1) -> MountFaultPhase {
    match phase {
        MountFaultPhaseV1::Allocated => MountFaultPhase::MOUNT_FAULT_PHASE_ALLOCATED,
        MountFaultPhaseV1::Prepared => MountFaultPhase::MOUNT_FAULT_PHASE_PREPARED,
        MountFaultPhaseV1::Publishing => MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING,
        MountFaultPhaseV1::Installed => MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED,
        MountFaultPhaseV1::Detaching => MountFaultPhase::MOUNT_FAULT_PHASE_DETACHING,
        MountFaultPhaseV1::Draining => MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING,
        MountFaultPhaseV1::Releasing => MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING,
    }
}

fn inventory_operation(value: &OperationCorrelationV1) -> MountOperationCorrelation {
    MountOperationCorrelation {
        operation_id: value.operation_id.to_vec(),
        request_digest: value.request_digest.to_vec(),
        ..Default::default()
    }
}

fn inventory_publication(value: &PublicationCorrelationV1) -> MountPublicationCorrelation {
    MountPublicationCorrelation {
        operation: Some(inventory_operation(&value.operation)).into(),
        target_mount_namespace_id: value.target_mount_namespace_id,
        target_namespace_generation: value.target_namespace_generation,
        replaces_mount_handle: value
            .replaces
            .map_or_else(Vec::new, |handle| handle.to_vec()),
        ..Default::default()
    }
}

fn inventory_recipe(value: &MountRecipeV1) -> MountRecipe {
    MountRecipe {
        attachment_id: value.attachment_id.to_vec(),
        destination_slot_id: value.destination_slot_id.to_vec(),
        view_revision: Some(Descriptor {
            media_type: value.view_revision.media_type.clone(),
            sha256: value.view_revision.sha256_digest.to_vec(),
            encoded_size: value.view_revision.encoded_size,
            ..Default::default()
        })
        .into(),
        source_generation: value.source_generation,
        attributes: Some(MountAttributes {
            read_only: value
                .policy
                .attributes
                .contains(&OwnedMountAttributeV1::ReadOnly),
            no_exec: value
                .policy
                .attributes
                .contains(&OwnedMountAttributeV1::NoExec),
            no_suid: value
                .policy
                .attributes
                .contains(&OwnedMountAttributeV1::NoSuid),
            no_device: value
                .policy
                .attributes
                .contains(&OwnedMountAttributeV1::NoDevice),
            no_atime: value
                .policy
                .attributes
                .contains(&OwnedMountAttributeV1::NoAtime),
            mutation_mode: match value.policy.mutation {
                NativeMutationV1::ReadOnly => 0,
                NativeMutationV1::ReadWrite => 1,
                NativeMutationV1::PrivateCow => 2,
                NativeMutationV1::AppendOnly => 3,
                NativeMutationV1::Service => 4,
            },
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

fn inventory_observation(value: &InstalledMountObservationV1) -> MountKernelObservation {
    MountKernelObservation {
        unique_mount_id: value.unique_mount_id,
        parent_mount_id: value.parent_mount_id,
        mount_namespace_id: value.target_mount_namespace_id,
        device_major: value.device_major,
        device_minor: value.device_minor,
        superblock_magic: value.superblock_magic,
        superblock_flags: value.superblock_flags,
        mount_attributes: value.mount_attributes,
        propagation: value.propagation,
        root: value.root.clone(),
        mount_point: value.mount_point.clone(),
        identity_map_digest: value.identity_map_digest.to_vec(),
        ..Default::default()
    }
}

fn boot_fault_transaction(handle: [u8; 32], revision: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.mount.boot-fault.v1\0");
    digest.update(handle);
    digest.update(revision.to_le_bytes());
    let output = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&output[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn custody_fault_transaction(handle: [u8; 32], revision: u64) -> [u8; 16] {
    derived_transaction_id(b"aos.mount.custody-fault.v1\0", handle, revision)
}

fn derived_transaction_id(label: &[u8], handle: [u8; 32], revision: u64) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(label);
    digest.update(handle);
    digest.update(revision.to_le_bytes());
    let output = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&output[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn invalid_pending_state() -> MountError {
    MountError::State("pending effect contradicts durable resource lifecycle".to_owned())
}

fn validate_pending_action_state(action: MountAction, state: &MountResourceStateV1) -> Result<()> {
    let valid = matches!(
        (action, state),
        (
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            MountResourceStateV1::Allocated { .. }
        ) | (
            MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE,
            MountResourceStateV1::Publishing { .. }
        ) | (
            MountAction::MOUNT_ACTION_DETACH,
            MountResourceStateV1::Detaching { .. }
        ) | (
            MountAction::MOUNT_ACTION_RELEASE,
            MountResourceStateV1::Releasing { .. }
        )
    );
    if valid {
        Ok(())
    } else {
        Err(invalid_pending_state())
    }
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

fn intent_transaction(request_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.intent.v1\0");
    digest.update(request_id);
    let output = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&output[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn authority_refresh_transaction(
    request_id: [u8; 16],
    plan_digest: ObjectDigest,
    lease_digest: ObjectDigest,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.authority-refresh.v1\0");
    digest.update(request_id);
    digest.update(plan_digest.as_bytes());
    digest.update(lease_digest.as_bytes());
    let output = digest.finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&output[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn validate_effect_matches(
    effect: &MountEffectIntentV2,
    admission: &VerifiedMountAdmissionV1,
    transport_request_digest: [u8; 32],
) -> Result<()> {
    if effect.transport_request_digest().as_bytes() != &transport_request_digest
        || effect.request_digest() != admission.effect.request_digest()
        || effect.verb() != admission.effect.verb()
        || effect.target() != admission.effect.target()
    {
        return Err(MountError::Fence(
            "durable effect contradicts exact request",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, BrokerAuthorizationArtifactsV1, BrokerMethod,
        BrokerRequestEnvelope, Descriptor, MountAttributes, RequestHeader,
    };
    use aos_sandbox::journal::JournalLimits;
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, KeyUsage, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
        DecodeLimits, DesiredGeneration, IncarnationId, LeaseAssignment, MediaType, NodeId,
        ObjectDigest, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId,
        RawClockProvenance, RevocationScopeId, SandboxId, TrustScopeId, descriptor_for_bytes,
        sign_statement,
    };
    use aos_sandbox_linux::inventory::MountObservation;
    use aos_sandbox_linux::pidfd::NamespaceIdentity;
    use aos_sandbox_protocol::session::decode_request_envelope;
    use ed25519_dalek::SigningKey;
    use std::os::unix::ffi::OsStringExt as _;

    use super::*;
    use crate::worker::{
        InstalledMountObservation, PublicationPreflight, ReleasedMountObservation,
    };

    const TEST_WALL_SECONDS: i64 = 150;
    const TEST_BOOTTIME_NANOSECONDS: u64 = 100;
    const TEST_NODE: NodeId = NodeId::from_bytes([31; 16]);

    struct AuthorityFixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_policy: Vec<u8>,
        lease_policy_descriptor: aos_sandbox_core::ObjectDescriptor,
        lease_scope: TrustScopeId,
        revocation_scope: RevocationScopeId,
    }

    impl AuthorityFixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let plan_signer = key_reference(
                "mount-plan-controller",
                3,
                KeyUsage::BrokerAuthorization,
                &plan_key,
            );
            let lease_signer = key_reference(
                "mount-ownership-authority",
                7,
                KeyUsage::OwnershipLease,
                &lease_key,
            );
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_policy_descriptor) = trust_policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_policy_descriptor) = trust_policy(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                lease_signer.clone(),
            );
            Self {
                plan_key,
                lease_key,
                plan_signer,
                lease_signer,
                plan_policy,
                plan_policy_descriptor,
                plan_scope,
                lease_policy,
                lease_policy_descriptor,
                lease_scope,
                revocation_scope: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> MountAuthorityV1 {
            let plan_anchor = aos_sandbox_core::BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_policy_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation_scope,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_policy_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            MountAuthorityV1::new(plan_anchor, lease_anchor, TEST_NODE, [46; 16], [47; 32]).unwrap()
        }

        fn artifacts(
            &self,
            request_bytes: &[u8],
            catalog_digest: Option<ObjectDigest>,
            lease_generation: u64,
            authorized_requests: &[&[u8]],
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            self.artifacts_with_plan_key(
                request_bytes,
                catalog_digest,
                lease_generation,
                authorized_requests,
                &self.plan_key,
            )
        }

        fn artifacts_with_plan_key(
            &self,
            request_bytes: &[u8],
            catalog_digest: Option<ObjectDigest>,
            lease_generation: u64,
            authorized_requests: &[&[u8]],
            plan_key: &SigningKey,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let validated =
                decode_mount_request(request_bytes, peer(), policy(), TEST_BOOTTIME_NANOSECONDS)
                    .unwrap();
            let catalog = catalog_digest
                .map(MountCatalogCommitmentV1::from_verified_digest)
                .transpose()
                .unwrap();
            let semantics = crate::authorization::semantics_v1::canonical_mount_semantics_v1(
                &validated,
                catalog,
                &[],
            )
            .unwrap();
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes(*validated.fence().sandbox_id()),
                IncarnationId::from_bytes(*validated.fence().incarnation_id()),
                AssignmentEpoch::new(validated.fence().assignment_epoch()),
                DesiredGeneration::new(validated.fence().desired_generation()),
                ObjectDigest::from_bytes(*validated.fence().assignment_digest()),
            )
            .unwrap();
            let mut grants = Vec::new();
            for candidate_bytes in authorized_requests {
                let candidate = decode_mount_request(
                    candidate_bytes,
                    peer(),
                    policy(),
                    TEST_BOOTTIME_NANOSECONDS,
                )
                .unwrap();
                if candidate.fence() != validated.fence() {
                    continue;
                }
                let candidate_catalog = (candidate.action() != MountAction::MOUNT_ACTION_RELEASE)
                    .then(|| {
                        MountCatalogCommitmentV1::from_verified_digest(ObjectDigest::from_bytes(
                            [77; 32],
                        ))
                        .unwrap()
                    });
                let candidate_semantics =
                    crate::authorization::semantics_v1::canonical_mount_semantics_v1(
                        &candidate,
                        candidate_catalog,
                        &[],
                    )
                    .unwrap();
                grants.push(
                    BrokerGrant::new(
                        candidate_semantics.verb(),
                        candidate_semantics.target(),
                        candidate_semantics.commitment(),
                        u32::try_from(candidate_bytes.len()).unwrap(),
                        0,
                    )
                    .unwrap(),
                );
            }
            assert!(grants.iter().any(|grant| {
                grant.verb() == semantics.verb()
                    && grant.target() == semantics.target()
                    && grant.argument_commitment() == semantics.commitment()
            }));
            grants.sort_by_key(|grant| (grant.verb(), grant.target()));
            grants.dedup_by(|right, left| {
                right.verb() == left.verb()
                    && right.target() == left.target()
                    && right.argument_commitment() == left.argument_commitment()
            });
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Mount,
                ProtocolId::MountBroker,
                ProtocolVersion::new(1, 1),
                assignment,
                TEST_NODE,
                self.lease_signer.clone(),
                grants,
                ObjectDigest::from_bytes([48; 32]),
                self.revocation_scope,
                100,
                300,
                Vec::new(),
            )
            .unwrap();
            let broker_plan = encode_broker_authorization_plan(&plan);
            let plan_signer = if plan_key.verifying_key() == self.plan_key.verifying_key() {
                self.plan_signer.clone()
            } else {
                key_reference(
                    "untrusted-mount-plan-controller",
                    3,
                    KeyUsage::BrokerAuthorization,
                    plan_key,
                )
            };
            let broker_plan_signature = signed_object(
                &broker_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                plan_signer,
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                plan_key,
            );
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                TEST_NODE,
                lease_generation,
                100,
                300,
                10,
                [u8::try_from(lease_generation).unwrap_or(255); 16],
            )
            .unwrap();
            let ownership_lease = encode_ownership_lease(&lease);
            let ownership_lease_signature = signed_object(
                &ownership_lease,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                self.lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_policy_descriptor,
                &self.lease_key,
            );
            validated_artifacts(BrokerAuthorizationArtifactsV1 {
                broker_plan,
                broker_plan_signature,
                ownership_lease,
                ownership_lease_signature,
                ..Default::default()
            })
        }
    }

    fn key_reference(id: &str, generation: u64, usage: KeyUsage, key: &SigningKey) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(id.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn trust_policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        signer: KeyReference,
    ) -> (Vec<u8>, aos_sandbox_core::ObjectDescriptor) {
        let bytes = encode_trust_policy(
            &TrustPolicy::new(scope, purpose, vec![signer], Vec::new()).unwrap(),
        );
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_object(
        bytes: &[u8],
        media_type: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &aos_sandbox_core::ObjectDescriptor,
        key: &SigningKey,
    ) -> Vec<u8> {
        let subject = descriptor_for_bytes(
            MediaType::new(media_type.as_str().to_owned()).unwrap(),
            bytes,
        );
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            100,
            Some(300),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }

    fn validated_artifacts(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_MOUNT_APPLY.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::MountBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    fn clock() -> RawPairedClockSample {
        clock_at(TEST_WALL_SECONDS)
    }

    fn clock_at(wall_seconds: i64) -> RawPairedClockSample {
        clock_sample(wall_seconds, TEST_BOOTTIME_NANOSECONDS)
    }

    fn clock_sample(wall_seconds: i64, boottime_nanoseconds: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([49; 16]).unwrap(),
            [50; 16],
            wall_seconds,
            boottime_nanoseconds,
        )
        .unwrap()
    }

    fn apply<W: MountWorker>(
        broker: &mut MountBroker<W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        apply_authorized(broker, fixture, request_bytes, &[request_bytes])
    }

    fn apply_authorized<W: MountWorker>(
        broker: &mut MountBroker<W>,
        fixture: &AuthorityFixture,
        request_bytes: &[u8],
        authorized_requests: &[&[u8]],
    ) -> Result<Vec<u8>> {
        let catalog = broker.worker.catalog_commitment(&decode_mount_request(
            request_bytes,
            peer(),
            policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )?)?;
        let artifacts = fixture.artifacts(request_bytes, catalog, 1, authorized_requests);
        broker.apply_mount(
            request_bytes,
            &artifacts,
            ProtocolVersion::new(1, 1),
            peer(),
            policy(),
            || Ok(clock()),
        )
    }

    fn test_broker<W: MountWorker>(
        journal: Journal,
        worker: W,
    ) -> (MountBroker<W>, AuthorityFixture) {
        let fixture = AuthorityFixture::new();
        let broker = MountBroker::new(journal, worker, fixture.authority()).unwrap();
        (broker, fixture)
    }

    struct ScriptedWorker {
        calls: usize,
        fail_after_custody_once: bool,
        fail_release_after_custody_once: bool,
        custody: Vec<RetainedMountObservation>,
        catalog_byte: u8,
    }

    impl Default for ScriptedWorker {
        fn default() -> Self {
            Self {
                calls: 0,
                fail_after_custody_once: false,
                fail_release_after_custody_once: false,
                custody: Vec::new(),
                catalog_byte: 77,
            }
        }
    }

    impl MountWorker for ScriptedWorker {
        fn catalog_commitment(
            &self,
            request: &ValidatedMountRequest,
        ) -> Result<Option<aos_sandbox_core::ObjectDigest>> {
            Ok((request.action() != MountAction::MOUNT_ACTION_RELEASE)
                .then(|| aos_sandbox_core::ObjectDigest::from_bytes([self.catalog_byte; 32])))
        }

        fn custody_inventory(&self) -> Result<Vec<RetainedMountObservation>> {
            Ok(self.custody.clone())
        }

        fn discard_retained(&mut self, handle: [u8; 32]) -> Result<()> {
            self.custody.retain(|value| value.handle != handle);
            Ok(())
        }

        fn preflight_publication(
            &self,
            _request: &ValidatedMountRequest,
            _request_digest: [u8; 32],
            _handle: [u8; 32],
            _expected_mount_id: MountId,
            predecessor: Option<([u8; 32], MountId)>,
            _expected_catalog_commitment: aos_sandbox_core::ObjectDigest,
        ) -> Result<PublicationPreflight> {
            Ok(PublicationPreflight {
                target_mount_namespace_id: 500,
                disposition: if predecessor.is_some() {
                    MountTargetObservation::PredecessorInstalled
                } else {
                    MountTargetObservation::Absent
                },
            })
        }

        fn reconcile_detach(
            &mut self,
            _request: &ValidatedMountRequest,
            _request_digest: [u8; 32],
            handle: [u8; 32],
            expected_mount_id: MountId,
            _expected_catalog_commitment: aos_sandbox_core::ObjectDigest,
            before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
        ) -> Result<ReleasedMountObservation> {
            before_effect()?;
            self.custody.retain(|value| value.handle != handle);
            Ok(ReleasedMountObservation {
                mount_id: expected_mount_id,
            })
        }

        fn execute(
            &mut self,
            request: &ValidatedMountRequest,
            _request_digest: [u8; 32],
            handles: EffectHandles,
            _expected_catalog_commitment: Option<aos_sandbox_core::ObjectDigest>,
            before_effect: &mut dyn FnMut() -> Result<EffectDeadlineV1>,
        ) -> Result<WorkerObservation> {
            before_effect()?;
            self.calls += 1;
            match request.action() {
                MountAction::MOUNT_ACTION_CREATE_DETACHED => {
                    let handle = handles.detached.unwrap();
                    if !self.custody.iter().any(|value| value.handle == handle) {
                        let mount_id = MountId::new(700 + self.custody.len() as u64).unwrap();
                        self.custody
                            .push(RetainedMountObservation { handle, mount_id });
                    }
                    if self.fail_after_custody_once {
                        self.fail_after_custody_once = false;
                        return Err(MountError::Worker(
                            "injected crash after custody barrier".to_owned(),
                        ));
                    }
                    let mount_id = self
                        .custody
                        .iter()
                        .find(|value| value.handle == handle)
                        .unwrap()
                        .mount_id;
                    Ok(WorkerObservation {
                        state: MountState::MOUNT_STATE_DETACHED,
                        handles,
                        detached_mount_id: Some(mount_id),
                        installed: None,
                    })
                }
                MountAction::MOUNT_ACTION_INSTALL | MountAction::MOUNT_ACTION_REPLACE => {
                    let handle = handles.installed.unwrap();
                    let mount_id = self
                        .custody
                        .iter()
                        .find(|value| value.handle == handle)
                        .unwrap()
                        .mount_id;
                    Ok(WorkerObservation {
                        state: MountState::MOUNT_STATE_INSTALLED,
                        handles,
                        detached_mount_id: None,
                        installed: Some(installed(mount_id)),
                    })
                }
                MountAction::MOUNT_ACTION_RELEASE => {
                    let handle = request.detached_mount_handle().copied().unwrap();
                    self.custody.retain(|value| value.handle != handle);
                    if self.fail_release_after_custody_once {
                        self.fail_release_after_custody_once = false;
                        return Err(MountError::Worker(
                            "injected crash after descriptor removal".to_owned(),
                        ));
                    }
                    Ok(WorkerObservation {
                        state: MountState::MOUNT_STATE_ABSENT,
                        handles,
                        detached_mount_id: None,
                        installed: None,
                    })
                }
                _ => Err(MountError::Worker("unexpected action".to_owned())),
            }
        }
    }

    fn installed(mount_id: MountId) -> InstalledMountObservation {
        InstalledMountObservation {
            mount: MountObservation {
                mount_id,
                parent_mount_id: MountId::new(600).unwrap(),
                mount_namespace_id: 500,
                device_major: 8,
                device_minor: 1,
                superblock_magic: 0xef53,
                superblock_flags: 1,
                mount_attributes: 2,
                propagation: 4,
                supported_mask: Some(7),
                root: std::ffi::OsString::from_vec(b"/".to_vec()),
                mount_point: std::ffi::OsString::from_vec(b"/run/aos/slot".to_vec()),
                filesystem_type: std::ffi::OsString::from_vec(b"ext4".to_vec()),
                superblock_source: std::ffi::OsString::from_vec(b"none".to_vec()),
                uid_map: None,
                gid_map: None,
            },
            mount_namespace: NamespaceIdentity {
                device: 10,
                inode: 11,
            },
            idmap_digest: [12; 32],
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

    fn request(request_id: u8) -> Vec<u8> {
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
                desired_generation: 1,
                assignment_digest: vec![6; 32],
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

    fn action_request(
        request_id: u8,
        generation: u64,
        source_generation: u64,
        action: MountAction,
        handle: Option<[u8; 32]>,
        replacement: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let mut request = ApplyMountRequest::decode_from_slice(&request(request_id)).unwrap();
        request.fence = Some(AssignmentFence {
            sandbox_id: vec![1; 16],
            incarnation_id: vec![2; 16],
            assignment_epoch: 1,
            desired_generation: generation,
            assignment_digest: vec![u8::try_from(generation).unwrap() + 5; 32],
            ..Default::default()
        })
        .into();
        request.action = action.into();
        request.source_generation = source_generation;
        request.detached_mount_handle = handle.map_or_else(Vec::new, |value| value.to_vec());
        request.replacement_mount_handle =
            replacement.map_or_else(Vec::new, |value| value.to_vec());
        if matches!(
            action,
            MountAction::MOUNT_ACTION_DETACH | MountAction::MOUNT_ACTION_RELEASE
        ) {
            request.view_revision = None.into();
            request.attributes = None.into();
        }
        request.encode_to_vec()
    }

    fn open(path: &std::path::Path) -> Journal {
        Journal::open(path, JournalLimits::default()).unwrap().0
    }

    #[test]
    fn create_completion_atomically_materializes_prepared_resource() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
        let bytes = request(9);
        let first = apply(&mut broker, &fixture, &bytes).unwrap();
        let second = apply(&mut broker, &fixture, &bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(broker.worker.calls, 1);
        let resource = broker.resources.resources().next().unwrap();
        assert!(matches!(
            resource.state,
            MountResourceStateV1::Prepared { .. }
        ));
        assert_eq!(resource.revision, 2);

        let inventory = broker.inventory_resources();
        let decoded =
            aos_sandbox_protocol::decode_mount_inventory_response(&inventory, 4096).unwrap();
        assert_eq!(decoded.mounts().len(), 1);
        assert_eq!(
            decoded.mounts()[0].lifecycle(),
            MountLifecycle::MOUNT_LIFECYCLE_PREPARED
        );
        assert_eq!(decoded.kernel_boot_id(), &broker.kernel_boot_id);
        assert_ne!(decoded.broker_instance_id(), &[0; 16]);
        assert!(decoded.journal_sequence() > 1);
    }

    #[test]
    fn signed_authority_rejects_wrong_signature_body_and_catalog_substitution() {
        for attack in ["signature", "body", "catalog"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(format!("{attack}.journal"));
            let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
            let original = request(60);
            let catalog = Some(ObjectDigest::from_bytes([77; 32]));
            let wrong_key = SigningKey::from_bytes(&[99; 32]);
            let artifacts = if attack == "signature" {
                fixture.artifacts_with_plan_key(&original, catalog, 1, &[&original], &wrong_key)
            } else {
                fixture.artifacts(&original, catalog, 1, &[&original])
            };
            let presented = if attack == "body" {
                let mut substituted = ApplyMountRequest::decode_from_slice(&original).unwrap();
                substituted.source_generation += 1;
                substituted.encode_to_vec()
            } else {
                original
            };
            if attack == "catalog" {
                broker.worker.catalog_byte = 78;
            }

            assert!(
                broker
                    .apply_mount(
                        &presented,
                        &artifacts,
                        ProtocolVersion::new(1, 1),
                        peer(),
                        policy(),
                        || Ok(clock()),
                    )
                    .is_err()
            );
            assert_eq!(broker.worker.calls, 0, "attack {attack} reached worker");
        }
    }

    #[test]
    fn expired_authority_fails_before_effect_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
        let bytes = request(61);
        let artifacts = fixture.artifacts(
            &bytes,
            Some(ObjectDigest::from_bytes([77; 32])),
            1,
            &[&bytes],
        );

        assert!(
            broker
                .apply_mount(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock_at(301)),
                )
                .is_err()
        );
        assert_eq!(broker.worker.calls, 0);
        assert!(
            broker
                .journal
                .get(RecordNamespace::Effect, &[61; 16])
                .is_none()
        );
    }

    #[test]
    fn request_deadline_crossing_after_intent_prevents_the_worker_effect() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
        let bytes = request(63);
        let artifacts = fixture.artifacts(
            &bytes,
            Some(ObjectDigest::from_bytes([77; 32])),
            1,
            &[&bytes],
        );
        let mut reads = 0;

        assert!(
            broker
                .apply_mount(
                    &bytes,
                    &artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || {
                        reads += 1;
                        Ok(if reads == 1 {
                            clock()
                        } else {
                            clock_sample(TEST_WALL_SECONDS, 1_000)
                        })
                    },
                )
                .is_err()
        );
        assert_eq!(broker.worker.calls, 0);
        assert!(
            broker
                .journal
                .get(RecordNamespace::Effect, &[63; 16])
                .is_some()
        );
    }

    #[test]
    fn pending_replay_accepts_a_fresher_lease_without_reallocating() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(
            open(&path),
            ScriptedWorker {
                fail_after_custody_once: true,
                ..Default::default()
            },
        );
        let bytes = request(62);
        let catalog = Some(ObjectDigest::from_bytes([77; 32]));
        let first = fixture.artifacts(&bytes, catalog, 1, &[&bytes]);
        assert!(
            broker
                .apply_mount(
                    &bytes,
                    &first,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .is_err()
        );
        assert_eq!(broker.worker.calls, 1);
        assert_eq!(broker.worker.custody.len(), 1);

        let renewed = fixture.artifacts(&bytes, catalog, 2, &[&bytes]);
        broker
            .apply_mount(
                &bytes,
                &renewed,
                ProtocolVersion::new(1, 1),
                peer(),
                policy(),
                || Ok(clock()),
            )
            .unwrap();
        assert_eq!(broker.worker.calls, 2);
        assert_eq!(broker.worker.custody.len(), 1);
    }

    #[test]
    fn restart_faults_unverifiable_allocated_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let bytes = request(10);
        let (mut broker, fixture) = test_broker(
            open(&path),
            ScriptedWorker {
                fail_after_custody_once: true,
                ..Default::default()
            },
        );
        assert!(apply(&mut broker, &fixture, &bytes).is_err());
        let custody = broker.worker.custody.clone();
        assert!(matches!(
            broker.resources.resources().next().unwrap().state,
            MountResourceStateV1::Allocated { .. }
        ));
        drop(broker);

        let (mut recovered, recovered_fixture) = test_broker(
            open(&path),
            ScriptedWorker {
                custody,
                ..Default::default()
            },
        );
        assert!(recovered.worker.custody.is_empty());
        assert!(apply(&mut recovered, &recovered_fixture, &bytes).is_err());
        assert!(matches!(
            recovered.resources.resources().next().unwrap().state,
            MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Allocated,
                ..
            }
        ));
    }

    #[test]
    fn constructor_rejects_unexplained_retained_mount() {
        let directory = tempfile::tempdir().unwrap();
        let worker = ScriptedWorker {
            custody: vec![RetainedMountObservation {
                handle: [8; 32],
                mount_id: MountId::new(900).unwrap(),
            }],
            ..Default::default()
        };
        let fixture = AuthorityFixture::new();
        assert!(
            MountBroker::new(
                open(&directory.path().join("mount.journal")),
                worker,
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[test]
    fn constructor_rejects_wrong_retained_mount_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
        apply(&mut broker, &fixture, &request(39)).unwrap();
        let mut custody = broker.worker.custody.clone();
        custody[0].mount_id = MountId::new(999).unwrap();
        drop(broker);

        assert!(
            MountBroker::new(
                open(&path),
                ScriptedWorker {
                    custody,
                    ..Default::default()
                },
                fixture.authority(),
            )
            .is_err()
        );
    }

    #[test]
    fn restart_admits_missing_custody_for_precommitted_release() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());
        let create = request(40);
        let handle = derive_handle(b"detached", Sha256::digest(&create).into());
        let release = action_request(
            41,
            1,
            1,
            MountAction::MOUNT_ACTION_RELEASE,
            Some(handle),
            None,
        );
        let competing_release = action_request(
            42,
            1,
            1,
            MountAction::MOUNT_ACTION_RELEASE,
            Some(handle),
            None,
        );
        let authorized = [&create[..], &release[..]];
        let receipt = apply_authorized(&mut broker, &fixture, &create, &authorized).unwrap();
        assert_eq!(
            MountResult::decode_from_slice(&receipt)
                .unwrap()
                .detached_mount_handle,
            handle
        );
        broker.worker.fail_release_after_custody_once = true;
        assert!(apply_authorized(&mut broker, &fixture, &release, &authorized).is_err());
        assert!(broker.worker.custody.is_empty());
        assert!(matches!(
            broker.resources.get(&handle).unwrap().state,
            MountResourceStateV1::Releasing { .. }
        ));
        let release_artifacts = fixture.artifacts(&release, None, 1, &authorized);
        assert!(
            broker
                .apply_mount(
                    &competing_release,
                    &release_artifacts,
                    ProtocolVersion::new(1, 1),
                    peer(),
                    policy(),
                    || Ok(clock()),
                )
                .is_err()
        );
        let custody = broker.worker.custody.clone();
        drop(broker);

        let (mut recovered, recovered_fixture) = test_broker(
            open(&path),
            ScriptedWorker {
                custody,
                ..Default::default()
            },
        );
        apply_authorized(&mut recovered, &recovered_fixture, &release, &authorized).unwrap();
        assert!(matches!(
            recovered.resources.get(&handle).unwrap().state,
            MountResourceStateV1::Released { .. }
        ));
    }

    #[test]
    fn replacement_draining_release_atomically_retires_both_edges() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());

        let create_predecessor = action_request(
            20,
            1,
            1,
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            None,
            None,
        );
        let predecessor = derive_handle(b"detached", Sha256::digest(&create_predecessor).into());
        let install_predecessor = action_request(
            21,
            1,
            1,
            MountAction::MOUNT_ACTION_INSTALL,
            Some(predecessor),
            None,
        );
        let create_successor = action_request(
            22,
            2,
            2,
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            None,
            None,
        );
        let successor = derive_handle(b"detached", Sha256::digest(&create_successor).into());
        let replace = action_request(
            23,
            2,
            2,
            MountAction::MOUNT_ACTION_REPLACE,
            Some(successor),
            Some(predecessor),
        );
        let release = action_request(
            24,
            2,
            1,
            MountAction::MOUNT_ACTION_RELEASE,
            Some(predecessor),
            None,
        );
        let generation_one = [&create_predecessor[..], &install_predecessor[..]];
        let generation_two = [&create_successor[..], &replace[..], &release[..]];

        apply_authorized(&mut broker, &fixture, &create_predecessor, &generation_one).unwrap();
        apply_authorized(&mut broker, &fixture, &install_predecessor, &generation_one).unwrap();
        apply_authorized(&mut broker, &fixture, &create_successor, &generation_two).unwrap();
        apply_authorized(&mut broker, &fixture, &replace, &generation_two).unwrap();
        assert!(matches!(
            broker.resources.get(&predecessor).unwrap().state,
            MountResourceStateV1::Draining { .. }
        ));

        apply_authorized(&mut broker, &fixture, &release, &generation_two).unwrap();
        assert!(matches!(
            broker.resources.get(&predecessor).unwrap().state,
            MountResourceStateV1::Released { .. }
        ));
        let successor_state = &broker.resources.get(&successor).unwrap().state;
        assert!(matches!(
            successor_state,
            MountResourceStateV1::Installed { publication, .. }
                if publication.replaces.is_none()
        ));
    }

    #[test]
    fn authoritative_inventory_decodes_reciprocal_faulted_replacement_pair() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mount.journal");
        let (mut broker, fixture) = test_broker(open(&path), ScriptedWorker::default());

        let create_predecessor = action_request(
            50,
            1,
            1,
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            None,
            None,
        );
        let predecessor = derive_handle(b"detached", Sha256::digest(&create_predecessor).into());
        let install_predecessor = action_request(
            51,
            1,
            1,
            MountAction::MOUNT_ACTION_INSTALL,
            Some(predecessor),
            None,
        );
        let create_successor = action_request(
            52,
            2,
            2,
            MountAction::MOUNT_ACTION_CREATE_DETACHED,
            None,
            None,
        );
        let successor = derive_handle(b"detached", Sha256::digest(&create_successor).into());
        let replace = action_request(
            53,
            2,
            2,
            MountAction::MOUNT_ACTION_REPLACE,
            Some(successor),
            Some(predecessor),
        );
        let generation_one = [&create_predecessor[..], &install_predecessor[..]];
        let generation_two = [&create_successor[..], &replace[..]];
        apply_authorized(&mut broker, &fixture, &create_predecessor, &generation_one).unwrap();
        apply_authorized(&mut broker, &fixture, &install_predecessor, &generation_one).unwrap();
        apply_authorized(&mut broker, &fixture, &create_successor, &generation_two).unwrap();
        apply_authorized(&mut broker, &fixture, &replace, &generation_two).unwrap();

        for (handle, transaction_id) in [(successor, [54; 16]), (predecessor, [55; 16])] {
            let current = broker.resources.get(&handle).unwrap().clone();
            let mut faulted = current.clone();
            faulted.revision = checked_revision(current.revision).unwrap();
            faulted.state = stale_boot_fault(&current.state);
            let records = broker
                .resources
                .plan_transition(current.revision, &faulted)
                .unwrap();
            broker
                .journal
                .commit(&JournalTransaction::new(transaction_id, records.clone()).unwrap())
                .unwrap();
            broker.resources.apply_committed(&records).unwrap();
        }

        let bytes = broker.inventory_resources();
        let inventory =
            aos_sandbox_protocol::decode_mount_inventory_response(&bytes, 16 * 1024).unwrap();
        assert_eq!(inventory.mounts().len(), 2);
        assert!(
            inventory.mounts().iter().all(|resource| {
                resource.lifecycle() == MountLifecycle::MOUNT_LIFECYCLE_FAULTED
            })
        );
    }
}
