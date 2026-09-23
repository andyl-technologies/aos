//! Partition-independent lookup of retained public logical cache pins.

use std::sync::Arc;

use aos_sandbox_core::{AttachmentId, ObjectDescriptor, OperationId, ProjectId, ViewId};

use super::{
    CacheAuthorityPurposeV1, CachePinV1, CacheRecoveryInventoryV1,
    CacheResidencyAuthorityRequestV1, CacheResidencyCommitOutcomeV1,
    CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedOwnerV1, PhysicalPartitionId, ProtectedDomainJournalErrorV1,
    ValidatedCacheResidencyPostcommitV1,
};
use crate::cache_residency::{CachePinKindV1, protected_journal::reconstruct_cache_history};
use crate::production_operation_compiler::RecheckedCacheConsumerV1;

impl CacheResidencyProtectedOwnerV1 {
    /// Commits one public logical-pin release under its exact protected drain record.
    ///
    /// The postcommit callback can turn a confirmed release into a physical
    /// Cache-owner admission. No public completion is implied by the journal
    /// commit alone; ambiguous outcomes retain their recovery state.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched consumer or pin, stale authority,
    /// invalid typed successor, or failed protected commit.
    pub fn commit_public_logical_pin_release<R>(
        &mut self,
        transaction_id: [u8; 16],
        consumer: &RecheckedCacheConsumerV1,
        pin: &CachePinV1,
        operation: OperationId,
        handoff: impl for<'current> FnOnce(ValidatedCacheResidencyPostcommitV1<'current>) -> R,
    ) -> Result<(CacheResidencyCommitOutcomeV1, Option<R>), CacheResidencyProtectedJournalErrorV1>
    {
        let request = self.prepare_logical_pin_drain(consumer, pin)?;
        let inventory = self.reconstructed_partition(pin.partition)?;
        self.commit_authorized_pin_release(
            transaction_id,
            vec![request],
            |controller| controller.seal_logical_pin_release(&inventory, pin, operation),
            handoff,
        )
    }

    /// Issues bounded drain authority for an exact retained public logical pin.
    ///
    /// The consumer was independently rechecked against desired state. The
    /// retained pin supplies the old physical partition and acquisition
    /// evidence; a changed View or attachment does not erase that obligation.
    /// This does not commit the release. The next protected transaction must
    /// select and verify the returned PinDrain record before sealing it.
    ///
    /// # Errors
    ///
    /// Returns an error unless the consumer is a release request for this
    /// exact protected pin, or when authority issuance cannot be confirmed.
    pub fn prepare_logical_pin_drain(
        &mut self,
        consumer: &RecheckedCacheConsumerV1,
        pin: &CachePinV1,
    ) -> Result<CacheResidencyAuthorityRequestV1, CacheResidencyProtectedJournalErrorV1> {
        if consumer.acquisition_fence().is_some()
            || consumer.object() != &pin.object
            || consumer.project() != pin.project
            || consumer.view() != pin.view
            || consumer.attachment() != pin.attachment
        {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        let retained = self.retained_logical_pin(
            pin.partition,
            consumer.object(),
            consumer.project(),
            consumer.view(),
            consumer.attachment(),
        )?;
        if retained.as_ref() != Some(pin) {
            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
        }
        let record_key = self.authority.issue_logical_pin_drain_record(pin)?;
        CacheResidencyAuthorityRequestV1::new(CacheAuthorityPurposeV1::PinDrain, record_key)
            .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord.into())
    }

    /// Reconstructs one exact partition beneath current protected Replay authority.
    ///
    /// This is retained state, not permission to acquire or drain a pin. A
    /// controller must still present the partition's current purpose-specific
    /// capability to the protected commit path.
    ///
    /// # Errors
    ///
    /// Returns an error when replay, currentness, or partition selection fails.
    pub fn reconstructed_partition(
        &mut self,
        partition: PhysicalPartitionId,
    ) -> Result<CacheRecoveryInventoryV1, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let inventory = reconstruct_cache_history(projection.records(), &validator)?
                .into_iter()
                .find(|inventory| inventory.global.node_quota.partition == partition)
                .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
            refresh()?;
            Ok(inventory)
        })
    }

    /// Finds every retained partition pin for a public consumer and object.
    ///
    /// Public unpin requests carry no physical partition. This lookup scans
    /// every partition in one protected replay. A migrated consumer may have
    /// an old and a new physical obligation; unpin must drain each one rather
    /// than choosing an arbitrary partition. Historical state is not current
    /// drain or acquisition authority.
    ///
    /// # Errors
    ///
    /// Returns an error if protected replay or currentness fails, or if a
    /// partition contains more than one logical pin for this consumer/object.
    pub fn retained_consumer_logical_pins(
        &mut self,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Result<Vec<CachePinV1>, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let inventories = reconstruct_cache_history(projection.records(), &validator)?;
            let mut retained = Vec::new();
            for inventory in inventories {
                let mut partition_pin = None;
                for payload in inventory.reconstructed {
                    if &payload.plan.descriptor != object || payload.plan.project != project {
                        continue;
                    }
                    for pin in payload.pins {
                        if pin.partition != payload.plan.partition
                            || &pin.object != object
                            || pin.project != project
                            || pin.view != view
                            || pin.attachment != attachment
                            || pin.kind != CachePinKindV1::LogicalLease
                        {
                            continue;
                        }
                        if partition_pin.replace(pin).is_some() {
                            return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
                        }
                    }
                }
                if let Some(pin) = partition_pin {
                    retained.push(pin);
                }
            }
            refresh()?;
            Ok(retained)
        })
    }
}
