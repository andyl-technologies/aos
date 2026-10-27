//! Observes retained executable capacities without kernel reads or lease renewal.
//!
//! The enclosing Rc allocation belongs to the caller's roster. An acquired lease
//! retains opaque worker backing and therefore refuses this complete-capacity
//! component; legacy byte observers continue to report that backing as unknown.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::records::{
    MetadataCapacityRecord, MetadataRecordKind,
};
use std::mem::size_of;

impl OriginalExecutable {
    /// Records the actual paths, content reference and retained descriptor Arc.
    ///
    /// # Errors
    /// Refuses another creator, opaque lease-worker backing, checked geometry
    /// overflow, exhausted rows or unavailable physical backing.
    pub(in crate::node_adapters::cnp::semantic) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_precredit_data()?;
        let Self {
            creator,
            thread,
            process_path,
            original_target,
            original,
            revision,
            expected,
            revoked,
            bounded_birth,
        } = self;
        let descriptor = original.retained_capacity_data();
        if descriptor.has_lease_worker {
            return Err(RuntimeError::UnsupportedFacet);
        }

        census.observe_inline_data(creator)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(&revoked.get())?;
        census.observe_inline_data(bounded_birth)?;
        let FileRevision {
            device,
            inode,
            length,
            mode,
            uid,
            gid,
            links,
            modified,
            changed,
        } = revision;
        census.observe_inline_data(&(*device, *inode, *length, *mode, *uid, *gid, *links))?;
        census.observe_inline_data(modified)?;
        census.observe_inline_data(changed)?;

        // Unix PathBuf capacity is the original OsString byte bank, including
        // spare capacity. No lossy text projection or serialized length is used.
        for path in [process_path, original_target] {
            census.record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Vector,
                extent: path.capacity(),
                element_bytes: 1,
                alignment: 1,
            })?;
        }
        census.observe(expected)?;
        census.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Shared,
            extent: descriptor.descriptor_value_bytes,
            element_bytes: 1,
            alignment: descriptor.descriptor_value_alignment,
        })?;
        self.storage_origin_precredit_data()
    }

    /// Names the defining borrowed roster, path iterator and descriptor DATA.
    pub(in crate::node_adapters::cnp::semantic) fn capacity_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<crucible_host_resources::LinuxReadLeaseFileCapacityData>()
            + size_of::<[&PathBuf; 2]>()
            + size_of::<std::array::IntoIter<&PathBuf, 2>>()
            + size_of::<(u64, u64, u64, u32, u32, u32, u64)>()
            + size_of::<(
                &u32,
                &ThreadId,
                &PathBuf,
                &PathBuf,
                &LinuxReadLeaseFile,
                &FileRevision,
                &ContentRef,
                &Cell<bool>,
                &bool,
            )>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<bool>()
    }
}
