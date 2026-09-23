//! Partition-independent lookup of retained public logical cache pins.

use std::sync::Arc;

use aos_sandbox_core::{AttachmentId, ObjectDescriptor, ProjectId, ViewId};

use super::{
    CachePinV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedOwnerV1, ProtectedDomainJournalErrorV1,
};
use crate::cache_residency::{CachePinKindV1, protected_journal::reconstruct_cache_history};

impl CacheResidencyProtectedOwnerV1 {
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
