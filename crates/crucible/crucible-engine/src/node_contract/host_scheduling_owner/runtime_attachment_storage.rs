//! Quotes original Host attachment ownership and independently repeated reports.
//!
//! The Source handle clones one world hash while retaining a Weak to the already
//! quoted scheduler. Each closed scalar observer reports that Weak layout again;
//! those reports are demand, not additional scheduler allocations or permission.

use super::*;
use crate::node_admission::InstalledConformancePlan;
use crate::node_contract::{NodeRuntime, PreparedHostSchedulingNode};
use std::mem::size_of;

/// Separates original attachment requests from existing and future report views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalHostRuntimeAttachmentStorageData {
    retained_requested_bytes: usize,
    existing_source_observation_bytes: usize,
    attached_weak_observation_bytes: usize,
}

impl OriginalHostRuntimeAttachmentStorageData {
    /// Bounds the real new world-hash clone retained by the attached Source handle.
    ///
    /// Existing String capacities bound the clone; a clone may trim spare capacity.
    pub fn retained_requested_bytes(&self) -> usize {
        self.retained_requested_bytes
    }

    /// Returns one complete existing source root and original metadata report.
    pub fn existing_source_observation_bytes(&self) -> usize {
        self.existing_source_observation_bytes
    }

    /// Returns the conservative inline scheduler allocation retained by a Weak view.
    pub fn attached_weak_observation_bytes(&self) -> usize {
        self.attached_weak_observation_bytes
    }

    /// Returns the additional metadata demand of one future attached Source report.
    ///
    /// # Errors
    /// Refuses checked requested-layout overflow.
    pub fn attached_observation_bytes(&self) -> Result<usize, RuntimeError> {
        self.retained_requested_bytes
            .checked_add(self.attached_weak_observation_bytes)
            .ok_or(RuntimeError::ResourceLimit)
    }

    fn checked_component_bytes(&self) -> Result<usize, RuntimeError> {
        self.existing_source_observation_bytes
            .checked_add(self.attached_observation_bytes()?)
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl HostSchedulingSource {
    /// Names fixed original node, Source and quote-result views before observation.
    pub fn original_initial_runtime_attachment_counter_scratch_data() -> usize {
        Self::retained_original_metadata_counter_scratch_data()
            + size_of::<OriginalHostRuntimeAttachmentStorageData>()
            + size_of::<Result<OriginalHostRuntimeAttachmentStorageData, RuntimeError>>()
            + size_of::<&Rc<Self>>()
            + size_of::<&PreparedHostSchedulingNode>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<std::cell::Ref<'static, Weak<()>>>()
            + size_of::<std::cell::Ref<'static, Option<OriginalSchedulingSource>>>()
            + size_of::<[usize; 5]>()
            + size_of::<(usize, usize)>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            // The node-anchor guard owns this temporary downgrade while its
            // original anchor loan remains live. The attached loan starts only
            // after that guard returns; each typed borrow/result view is named.
            + size_of::<Weak<()>>()
            // The optional retained-plan guard precedes the anchor comparison.
            // ptr_eq then borrows the original loan and temporary downgrade.
            + size_of::<Option<&InstalledConformancePlan>>()
            + size_of::<&Weak<()>>() // original anchor operand
            + size_of::<&Weak<()>>() // temporary downgrade operand
            + size_of::<Result<std::cell::Ref<'static, Weak<()>>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'static, Weak<()>>, RuntimeError>>()
            + size_of::<Result<std::cell::Ref<'static, Option<OriginalSchedulingSource>>, std::cell::BorrowError>>()
            + size_of::<Result<std::cell::Ref<'static, Option<OriginalSchedulingSource>>, RuntimeError>>()
            // Creator checks finish before metadata observation. Checked scalar
            // and closed guard results are reused across sequential checks.
            + size_of::<thread::Thread>()
            + size_of::<thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<bool>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<&Self>()
    }

    /// Quotes the same genuine inactive Host node's original scheduler attachment.
    ///
    /// The caller separately funds the scheduler allocation and the actual named
    /// observer paths. The result creates no node, graph, attachment or grant.
    /// This closed initial route never accepts a historical/restored Host source.
    ///
    /// # Errors
    /// Refuses another creator, node, anchor or original plan, an unsupported or
    /// spent Source, busy actual owners, overflow or the supplied data bound.
    pub fn original_initial_runtime_attachment_storage_data(
        self: &Rc<Self>,
        node: &PreparedHostSchedulingNode,
        plan: &InstalledConformancePlan,
        maximum: usize,
    ) -> Result<OriginalHostRuntimeAttachmentStorageData, RuntimeError> {
        node.authenticate_original_runtime_attachment_storage_data(self, plan)?;
        self.original_unattached_runtime_storage_data(maximum)
    }

    pub(super) fn original_unattached_runtime_storage_data(
        &self,
        maximum: usize,
    ) -> Result<OriginalHostRuntimeAttachmentStorageData, RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
            || self.archive_ticket.is_some()
            || self.revoked.get()
            || self.attachment_attempted.get()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let attached = self
            .attached
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        if attached.is_some() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let (world, weak) =
            OriginalSchedulingSource::construction_metadata_storage_data(&self.world, maximum)?;
        let existing = NodeRuntime::capture_shared_allocation_storage::<Self>()
            .checked_add(
                self.retained_original_metadata_bytes_excluding_runtime_precredit_data(maximum)?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        let data = OriginalHostRuntimeAttachmentStorageData {
            retained_requested_bytes: world,
            existing_source_observation_bytes: existing,
            attached_weak_observation_bytes: weak,
        };
        if data.checked_component_bytes()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(data)
    }
}
