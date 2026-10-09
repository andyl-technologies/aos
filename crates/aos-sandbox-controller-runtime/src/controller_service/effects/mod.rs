//! Complete private Controller effect owner and unchanged custody graph.
//!
//! Admission, lifecycle progress, snapshot coordination and concrete execution
//! are implementations on one retained executor. Its fields and constructor
//! moves keep their original order; the parent still owns shared broker sessions.
//! These private leaves add no authority factory or alternate effect engine.

use super::*;

mod admission;
mod execution;
mod lifecycle;
mod snapshot_coordination;

use admission::is_lifecycle_mutation;
use lifecycle::{lifecycle_plan_transaction_id, lifecycle_progress_resource_id};
use snapshot_coordination::auxiliary_publication_disposition;

pub(super) use execution::{
    current_boot_and_boottime, current_lifecycle_time, missing_broker_session,
    production_authority_effect_timing,
};
pub(super) use lifecycle::{lifecycle_plan_resource_id, lifecycle_progress_transaction_id};

/// Retains the original concrete effect owner and its ordered custody slots.
///
/// The child implementations borrow this same owner; no leaf creates a second
/// state graph or changes the original field and native-result drop order.
pub(super) struct ProductionEffectExecutor {
    pub(in crate::controller_service) resource_bank:
        Option<Arc<Mutex<aos_sandbox::ControllerResourceBankOpeningV1>>>,
    pub(in crate::controller_service) first_global_prefix:
        Option<aos_sandbox::ControllerFirstGlobalPrefixAttemptV1>,

    pub(in crate::controller_service) snapshot_ownership: Option<SnapshotOwnershipDonationV3>,
    pub(in crate::controller_service) pending_snapshot_derivative:
        Option<storage_snapshot::authorization::SnapshotDerivativeAttemptV3>,
    #[cfg(feature = "online-nix")]
    pub(in crate::controller_service) nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
    #[cfg(feature = "online-nix")]
    pub(in crate::controller_service) nix_generation_enabled: bool,
    #[cfg(feature = "online-nix")]
    pub(in crate::controller_service) nix_generation_profile:
        Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
    pub(in crate::controller_service) sessions: SharedControllerBrokerSessions,
    pub(in crate::controller_service) request_scope: ControllerRequestScopeV1,
    pub(in crate::controller_service) broker_plan_signer: Option<ControllerBrokerPlanSignerV1>,
    pub(in crate::controller_service) attachment_host:
        Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    pub(in crate::controller_service) attachment_mount:
        Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    pub(in crate::controller_service) pending_attachment_slot_attempt:
        Option<aos_sandbox::destination_slot_effect::DurableCurrentDestinationSlotAttemptV1>,
    pub(in crate::controller_service) pending_attachment_catalog_query:
        Option<attachment_physical::PendingAttachmentCatalogQueryV1>,
    pub(in crate::controller_service) pending_attachment_mount_attempt:
        Option<aos_sandbox::attachment_mount::DurableCurrentAttachmentMountAttemptV1>,
    pub(in crate::controller_service) pending_attachment_source_attempt:
        Option<aos_sandbox::attachment_source::DurableCurrentAttachmentSourceDispatchV1>,
    pub(in crate::controller_service) pending_attachment_source_consume:
        Option<aos_sandbox::attachment_mount::CompletedCurrentAttachmentMountAttemptV1>,
    pub(in crate::controller_service) source_domains: ProtectedSourceDomainJournalOwnerV1,
    pub(in crate::controller_service) cache_inventory: Option<CacheResidencyProtectedOwnerV1>,
    pub(in crate::controller_service) cache_resident_usage:
        aos_sandbox::cache_residency::CacheResidentInitializationV1,
    pub(in crate::controller_service) cache_mutation: cache_mutation::ControllerCacheMutationV1,
    pub(in crate::controller_service) cache_physical: Option<DormantCacheOwnerV1>,
    pub(in crate::controller_service) cache_physical_limits: Option<CacheOwnerLimitsV1>,
    pub(in crate::controller_service) pending_cache_pin:
        Option<cache_pin::PendingControllerCachePinV1>,
    pub(in crate::controller_service) pending_cache_unpin:
        Option<cache_unpin::PendingControllerCacheUnpinV1>,
    pub(in crate::controller_service) controller_uid: u32,
    transfer_inventory: Option<aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1>,
    pub(in crate::controller_service) node: NodeId,
    process_start: Option<([u8; 16], u64)>,
    pending_source_commit: Option<PendingSourceCommit>,
    pending_snapshot_coordination: Option<PendingSnapshotCoordinationV2>,
    pub(in crate::controller_service) pending_atomic_snapshot:
        Option<storage_snapshot::PendingAtomicSnapshotV1>,
    pub(in crate::controller_service) q04: Option<create_q04::OriginalQ04ControllerSelectionV1>,
}

struct PendingSourceCommit {
    operation_id: OperationId,
    receipt: Option<EffectReceipt>,
    pending: LifecycleProgressOutcomeUnknownV1,
}

/// Retains the actual selected result; legacy retry custody is independent.
struct PendingSnapshotCoordinationV2 {
    operation_id: OperationId,
    outcome: Result<LifecycleProgressCommitOutcomeV1, LifecycleProtectedJournalErrorV1>,
    readback_debt: Option<LifecycleProtectedJournalErrorV1>,
}

enum AuxiliaryPublicationDisposition {
    Current,
    OutcomeUnknown(LifecycleProgressOutcomeUnknownV1),
    Diverged(LifecycleProgressOutcomeUnknownV1),
}

struct ProductionCancellationRequest {
    target_operation: OperationId,
    idempotency: LifecycleCancelIdempotencyDigestV1,
    requested_at: LifecycleTimeV1,
}

impl ProductionEffectExecutor {
    /// Opens and recovers the original fixed Source owner before executor assembly.
    ///
    /// # Errors
    ///
    /// Returns the original credential, protected opening, replay or project-recovery error.
    pub(in crate::controller_service) fn open(
        journal: &mut Journal,
        sessions: SharedControllerBrokerSessions,
        request_scope: ControllerRequestScopeV1,
        controller_uid: u32,
        node: NodeId,
        attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
        attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    ) -> Result<Self, ControllerRuntimeError> {
        let broker_plan_signer = ControllerBrokerPlanSignerV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)?;
        validate_process_cache_readback_credentials_v1(
            broker_plan_signer
                .as_ref()
                .map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
        )
        .map_err(|_| ControllerRuntimeError::InvalidCacheReadbackCredential)?;
        validate_process_controller_hold_credentials_v1(
            broker_plan_signer
                .as_ref()
                .map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
        )
        .map_err(|_| ControllerRuntimeError::InvalidControllerHoldCredential)?;
        let (mut source_domains, _) =
            ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)?;
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut source_domains)?
            .replay()?;
        crate::controller_service::project_admission::recover_source_project_admission_v1(
            journal,
            &mut source_domains,
            request_scope,
        )
        .map_err(ControllerRuntimeError::ProjectAdmissionRecovery)?;

        Ok(Self::from_retained_source(
            sessions,
            request_scope,
            broker_plan_signer,
            attachment_host,
            attachment_mount,
            source_domains,
            controller_uid,
            node,
            current_boot_and_boottime(),
        ))
    }

    // All fallible admission precedes this infallible move. Ordinary opening
    // retains its old checks/order; issue mode supplies its parked SAME owner.
    /// Moves the already retained original Source owner into the same executor slots.
    pub(in crate::controller_service) fn from_retained_source(
        sessions: SharedControllerBrokerSessions,
        request_scope: ControllerRequestScopeV1,
        broker_plan_signer: Option<ControllerBrokerPlanSignerV1>,
        attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
        attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
        source_domains: ProtectedSourceDomainJournalOwnerV1,
        controller_uid: u32,
        node: NodeId,
        process_start: Option<([u8; 16], u64)>,
    ) -> Self {
        Self {
            resource_bank: None,
            first_global_prefix: None,
            snapshot_ownership: None,
            pending_snapshot_derivative: None,
            #[cfg(feature = "online-nix")]
            nix_start: None,
            #[cfg(feature = "online-nix")]
            nix_generation_enabled: false,
            #[cfg(feature = "online-nix")]
            nix_generation_profile: None,
            sessions,
            request_scope,
            broker_plan_signer,
            attachment_host,
            attachment_mount,
            pending_attachment_slot_attempt: None,
            pending_attachment_catalog_query: None,
            pending_attachment_mount_attempt: None,
            pending_attachment_source_attempt: None,
            pending_attachment_source_consume: None,
            source_domains,
            cache_inventory: None,
            cache_resident_usage: aos_sandbox::cache_residency::CacheResidentInitializationV1::new(),
            cache_mutation: cache_mutation::ControllerCacheMutationV1::default(),
            cache_physical: None,
            cache_physical_limits: None,
            pending_cache_pin: None,
            pending_cache_unpin: None,
            controller_uid,
            transfer_inventory: None,
            node,
            process_start,
            pending_source_commit: None,
            pending_snapshot_coordination: None,
            pending_atomic_snapshot: None,
            q04: None,
        }
    }

    fn ensure_cache_inventory_owner(&mut self) -> Result<(), EffectFailure> {
        if self.q04.is_some() {
            return Err(EffectFailure::Permanent(
                "original Q04 Cache writers cannot be reopened or used by ordinary mutation".to_owned(),
            ));
        }
        if self.cache_resident_usage.started() {
            self.cache_resident_usage.fence_unsupported_transition();
            return Err(EffectFailure::Permanent(
                "legacy Cache transition is unsupported under resident custody".to_owned(),
            ));
        }
        let (mut cache_source, _) =
            CacheReplayControllerBootstrapOwnerV1::open_fixed_protected_for_uid(
                self.controller_uid,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if self.cache_inventory.is_none() {
            let owner = match CacheResidencyProtectedOwnerV1::open_fixed_protected_for_uid(
                self.controller_uid,
            ) {
                Ok((owner, _)) => owner,
                Err(open_error) => {
                    let first = cache_source.partitions().next().ok_or_else(|| {
                        EffectFailure::Permanent(
                            "controller Cache bootstrap source has no partitions".to_owned(),
                        )
                    })?;
                    let (owner, _) = cache_source
                        .bootstrap_fixed_cache(first)
                        .map_err(|error| {
                            EffectFailure::Permanent(format!(
                                "protected Cache replay failed: {open_error}; clean bootstrap failed: {error}"
                            ))
                        })?;
                    owner
                }
            };
            self.cache_inventory = Some(owner);
        }
        let cache = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
        })?;
        cache_source
            .reconcile_fixed_cache(cache)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        Ok(())
    }

    /// Reconciles the original Cache envelope before acquiring its physical owner.
    ///
    /// # Errors
    ///
    /// Retains the original resident refusal, quota, inventory or physical-opening failure.
    pub(in crate::controller_service) fn ensure_cache_physical_owner(
        &mut self,
    ) -> Result<(), EffectFailure> {
        if self.cache_resident_usage.started() {
            let protected = self.cache_inventory.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("resident protected Cache inventory is unavailable".to_owned())
            })?;
            return self.cache_resident_usage.prepare_existing_physical_owner(
                protected, &mut self.cache_physical, self.node, CACHE_OWNER_MEMORY_BYTES,
            ).map_err(|_| self.resident_cache_failure());
        }
        self.ensure_cache_inventory_owner()?;
        let quotas = self
            .cache_inventory
            .as_mut()
            .ok_or_else(|| {
                EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
            })?
            .reconstructed_node_quotas()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if quotas
            .iter()
            .any(|quota| quota.partition.node().as_bytes() != self.node.as_bytes())
        {
            return Err(EffectFailure::Permanent(
                "protected Cache partition belongs to another controller node".to_owned(),
            ));
        }
        let limits = CacheOwnerLimitsV1::from_node_quotas(CACHE_OWNER_MEMORY_BYTES, quotas)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if self.cache_physical_limits == Some(limits) && self.cache_physical.is_some() {
            return Ok(());
        }

        // A changed protected partition set changes the owner-wide envelope.
        // Release the old lock before reopening and validating that manifest.
        self.cache_physical = None;
        self.cache_physical_limits = None;
        let physical = DormantCacheOwnerV1::open_fixed(limits)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        self.cache_physical = Some(physical);
        self.cache_physical_limits = Some(limits);
        Ok(())
    }

    fn ensure_lifecycle_inventory_owners(&mut self) -> Result<(), EffectFailure> {
        self.ensure_cache_inventory_owner()?;

        if self.transfer_inventory.is_none() {
            let (mut owner, _, initial) =
                aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected()
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some(initial) = initial {
                match initial {
                    aos_sandbox::local_inventory::ProtectedRecordCommitOutcomeV1::Committed(_) => {}
                    aos_sandbox::local_inventory::ProtectedRecordCommitOutcomeV1::RecoveryRequired(
                        recovery,
                    ) => match owner.resolve_store_write(recovery) {
                        aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::RecordCommitted(
                            _,
                        ) => {}
                        aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::CheckpointCommitted(
                            _,
                        )
                        | aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                            ..
                        } => {
                            return Err(EffectFailure::Permanent(
                                "protected Transfer bootstrap durability is unresolved".to_owned(),
                            ));
                        }
                    },
                }
            }
            self.transfer_inventory = Some(owner);
        }
        Ok(())
    }
}
