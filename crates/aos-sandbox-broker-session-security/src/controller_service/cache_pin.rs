//! Controller custody for source-proven public Cache pin acquisition.
//!
//! A recovered protected event names its original partition and physical pin;
//! only a state-only transaction may compile the current sealed View source and
//! select a fresh destination.

use aos_filesystem_view_core::{ProjectionLimits, TreeCompileLimits};
use aos_sandbox::cache_residency::{CacheOwnerErrorV1, CacheOwnerPinSettlementErrorV1};
use aos_sandbox::filesystem_view_state::current_filesystem_view_revision_v1;
use aos_sandbox::production_operation_compiler::RecheckedCacheConsumerV1;
use aos_sandbox_core::DecodeLimits;
use sha2::{Digest as _, Sha256};

use super::{
    DormantSandboxRequestKindV1, EffectFailure, EffectReceipt, Journal, OperationId,
    ProductionEffectExecutor,
};
use crate::{
    CacheCompiledSourceLimitsV1, CacheSourceMembershipLimitsV1, ProjectSealedViewObjectSourceV1,
    PublicCachePinExecutionV1, PublicCachePinRecoveryV1,
    execute_public_cache_pin_from_project_revision_v1, public_cache_pin_transaction_id_v1,
    recover_public_cache_pin_v1,
};

#[path = "cache_custody.rs"]
pub(super) mod cache_custody;

use cache_custody::{
    CacheCustodyMessages, CacheCustodyV1, PendingControllerCacheCustodyV1,
    cache_custody_from_commit, recover_pending_cache_custody,
};

/// Retains an ambiguous protected or physical acquisition until its outcome is known.
pub(super) type PendingControllerCachePinV1 = PendingControllerCacheCustodyV1<()>;

const PIN_CUSTODY_MESSAGES: CacheCustodyMessages = CacheCustodyMessages {
    owners_unavailable: "Cache owners are unavailable while exact pin custody is retained",
    another_operation: "another public Cache pin still requires exact recovery",
    physical_unresolved: "physical Cache pin recovery remains unresolved",
    protected_pending: "protected Cache pin recovery remains unresolved",
    protected_indeterminate: "protected Cache pin recovery remains unresolved",
    protected_diverged: "protected Cache pin transaction diverged",
    physical_unknown: "physical Cache pin durability remains unknown",
};

impl ProductionEffectExecutor {
    /// Recovers an existing pin or acquires a new source-proven pin.
    ///
    /// # Errors
    ///
    /// Returns a retryable error while source execution or exact physical
    /// recovery is pending, or when protected replay cannot validate the pin.
    pub(super) fn apply_public_cache_pin(
        &mut self,
        operation_id: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        self.ensure_cache_physical_owner()?;
        self.recover_pending_cache_pin(operation_id)?;

        let protected = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
        })?;
        let physical = self.cache_physical.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
        })?;
        let recovery = recover_public_cache_pin_v1(protected, physical, consumer, operation_id)
            .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
        match recovery {
            PublicCachePinRecoveryV1::Acquired(_) | PublicCachePinRecoveryV1::Retained(_) => {
                cache_pin_receipt(operation_id)
            }
            PublicCachePinRecoveryV1::StateOnly => {
                self.acquire_public_cache_pin(operation_id, consumer, journal, request)
            }
            PublicCachePinRecoveryV1::PhysicalError(CacheOwnerPinSettlementErrorV1::Owner(
                CacheOwnerErrorV1::OutcomeUnknown(physical),
            )) => {
                self.pending_cache_pin = Some(PendingControllerCachePinV1 {
                    operation_id,
                    payload: (),
                    custody: CacheCustodyV1::Physical(physical),
                });
                Err(EffectFailure::Retryable(
                    "physical Cache pin acquisition requires exact recovery".to_owned(),
                ))
            }
            PublicCachePinRecoveryV1::PhysicalError(error) => {
                Err(EffectFailure::Retryable(error.to_string()))
            }
        }
    }

    fn acquire_public_cache_pin(
        &mut self,
        operation_id: OperationId,
        consumer: &RecheckedCacheConsumerV1,
        journal: &Journal,
        request: &DormantSandboxRequestKindV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        let revision = current_filesystem_view_revision_v1(journal, consumer.view())
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Permanent("public Cache pin View revision is absent".to_owned())
            })?;
        let mut source = ProjectSealedViewObjectSourceV1::open_fixed(consumer.project())
            .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
        let protected = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
        })?;
        let physical = self.cache_physical.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("physical Cache owner is unavailable".to_owned())
        })?;
        let compiler_abi: [u8; 32] = Sha256::digest(b"aos.sandbox.cache.pin-compiler.v1\0").into();
        let execution = execute_public_cache_pin_from_project_revision_v1(
            protected,
            physical,
            &mut source,
            &revision,
            consumer,
            journal,
            request,
            operation_id,
            self.node,
            compiler_abi,
            controller_cache_source_limits(),
        )
        .map_err(|error| EffectFailure::Retryable(error.to_string()))?;
        match execution.into_confirmed() {
            Ok(_) => cache_pin_receipt(operation_id),
            Err(PublicCachePinExecutionV1::Committed {
                outcome,
                settlement,
            }) => {
                if let Some(custody) = cache_custody_from_commit(outcome, settlement) {
                    self.pending_cache_pin = Some(PendingControllerCachePinV1 {
                        operation_id,
                        payload: (),
                        custody,
                    });
                }
                Err(EffectFailure::Retryable(
                    "public Cache pin requires exact protected or physical recovery".to_owned(),
                ))
            }
            Err(PublicCachePinExecutionV1::Retained(_)) => Err(EffectFailure::Permanent(
                "retained Cache pin unexpectedly lacks confirmation".to_owned(),
            )),
        }
    }

    /// Resolves retained physical custody for the same public operation.
    ///
    /// # Errors
    ///
    /// Returns a retryable error when another operation owns the custody or
    /// the physical owner cannot confirm its exact outcome.
    pub(super) fn recover_pending_cache_pin(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        recover_pending_cache_custody(
            &mut self.pending_cache_pin,
            &mut self.cache_inventory,
            &mut self.cache_physical,
            operation_id,
            |_| public_cache_pin_transaction_id_v1(operation_id),
            &PIN_CUSTODY_MESSAGES,
        )
    }
}

fn controller_cache_source_limits() -> CacheCompiledSourceLimitsV1 {
    const MIB: u64 = 1024 * 1024;

    // The controller runs in a 512-MiB cgroup. Keep source compilation well
    // below that envelope until a dedicated bounded compiler worker exists.
    let tree = TreeCompileLimits {
        object_bytes: (4 * MIB) as usize,
        nodes: 65_536,
        directory_entries: 65_536,
        depth: 256,
        name_bytes: 16 * MIB,
        symlink_bytes: 4 * MIB,
        xattr_bytes: 8 * MIB,
        xattrs: 65_536,
        acl_entries: 65_536,
        extents: 65_536,
        hardlink_groups: 65_536,
        hardlink_members: 65_536,
        logical_bytes: u64::MAX,
        working_bytes: 32 * MIB,
        index_bytes: 8 * MIB,
        index_record_bytes: 4 * MIB,
    };
    let projection = ProjectionLimits {
        decode: DecodeLimits {
            maximum_bytes: (4 * MIB) as usize,
            ..DecodeLimits::default()
        },
        maximum_actions: 65_536,
        maximum_source_records: 65_536,
        maximum_projected_nodes: 65_536,
        maximum_path_components: 256,
        maximum_path_bytes: 16 * MIB,
        maximum_working_bytes: 32 * MIB,
    };

    CacheCompiledSourceLimitsV1 {
        tree,
        membership: CacheSourceMembershipLimitsV1 {
            maximum_index_bytes: 8 * MIB,
            maximum_index_working_bytes: 16 * MIB,
            projection,
        },
        maximum_memory_bytes: 64 * MIB,
    }
}

fn cache_pin_receipt(operation_id: OperationId) -> Result<EffectReceipt, EffectFailure> {
    let mut receipt = Vec::with_capacity(24);
    receipt.extend_from_slice(b"AOSCPN01");
    receipt.extend_from_slice(operation_id.as_bytes());
    EffectReceipt::new(receipt).map_err(|error| EffectFailure::Permanent(error.to_string()))
}
