//! Partition-independent lookup of retained public logical cache pins.

use std::{collections::BTreeMap, sync::Arc};

use aos_sandbox_core::{AttachmentId, ObjectDescriptor, ObjectDigest, ProjectId, ViewId};

use super::{
    CachePinV1, CacheResidencyProtectedJournalErrorV1, CacheResidencyProtectedJournalV1,
    CacheResidencyProtectedOwnerV1, CacheResidencyProtectedRecordKindV1,
    ProtectedDomainJournalErrorV1, decode_cache_payload_for_lifecycle,
};
use crate::cache_residency::CachePinKindV1;

impl CacheResidencyProtectedOwnerV1 {
    /// Finds the sole retained logical pin for a public consumer and object.
    ///
    /// Public unpin requests carry no physical partition. This lookup scans
    /// every partition in one protected replay and rejects an ambiguous
    /// cross-partition obligation instead of releasing an arbitrary pin.
    /// Historical state is not current drain or acquisition authority.
    ///
    /// # Errors
    ///
    /// Returns an error if protected replay or currentness fails, or if more
    /// than one partition retains this consumer/object obligation.
    pub fn retained_consumer_logical_pin(
        &mut self,
        object: &ObjectDescriptor,
        project: ProjectId,
        view: ViewId,
        attachment: Option<AttachmentId>,
    ) -> Result<Option<CachePinV1>, CacheResidencyProtectedJournalErrorV1> {
        let authority = Arc::clone(&self.authority);
        authority.while_authority_current(&[], |_owner, _capabilities, _now, validator, refresh| {
            let journal = self
                .state_journal
                .as_mut()
                .ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
            let projection =
                CacheResidencyProtectedJournalV1::claim(journal, validator.clone())?.replay()?;
            let mut latest = BTreeMap::<ObjectDigest, (u64, Vec<CachePinV1>)>::new();

            for envelope in projection.records().iter().filter(|envelope| {
                envelope.key().kind() == CacheResidencyProtectedRecordKindV1::Pin
            }) {
                let payload = decode_cache_payload_for_lifecycle(envelope, &validator)?
                    .ok_or(ProtectedDomainJournalErrorV1::NonCanonicalRecord)?;
                if &payload.plan.descriptor != object || payload.plan.project != project {
                    continue;
                }
                let partition = payload.plan.partition.digest();
                let entry = latest.entry(partition).or_insert_with(|| (0, Vec::new()));
                if payload.record.sequence > entry.0 {
                    *entry = (payload.record.sequence, payload.pins);
                }
            }

            let mut retained = None;
            for (partition, (_, pins)) in latest {
                for pin in pins {
                    if pin.partition.digest() != partition
                        || &pin.object != object
                        || pin.project != project
                        || pin.view != view
                        || pin.attachment != attachment
                        || pin.kind != CachePinKindV1::LogicalLease
                    {
                        continue;
                    }
                    if retained.replace(pin).is_some() {
                        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord.into());
                    }
                }
            }
            refresh()?;
            Ok(retained)
        })
    }
}
