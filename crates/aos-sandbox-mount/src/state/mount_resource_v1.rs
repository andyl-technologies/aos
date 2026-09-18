//! Stable hard-cut durable state for broker-owned mount resources.
//!
//! A resource is allocated in the journal before the broker performs any
//! kernel or descriptor-store effect. Its opaque handle and descriptor-store
//! key remain stable until release. The table validates lifecycle, mount and
//! slot uniqueness, replacement ordering, and bounded recovery. It deliberately
//! does not commit transactions: mutation methods return [`JournalRecord`]s for
//! the broker to combine atomically with its operation and idempotency records.
//!
//! The serialized value is a versioned JSON envelope:
//!
//! ```text
//! {"version":2,"resource":{...}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox::journal::{Journal, JournalRecord, RecordNamespace};
use aos_sandbox_core::{
    DecodeLimits, DescriptorRole, MediaType, ObjectDescriptor, ObjectDigest, decode_view_source,
    encode_view_source, model::ViewSource, validate_descriptor_role,
};
pub(crate) use aos_sandbox_protocol::mount_source_consumption_state::{
    AssignmentBindingV1, DetachedMountIdentityV1, InstalledMountObservationV1, MountFaultPhaseV1,
    MountPolicyV1, MountRecipeV1, MountResourceStateV1, MountResourceV1, MountSourceConsistencyV1,
    NativeMutationV1, ObjectDescriptorV1, OperationCorrelationV1, OwnedMountAttributeV1,
    PublicationCorrelationV1,
};
use aos_sandbox_protocol::mount_source_consumption_state::{
    MOUNT_RESOURCE_KEY_PREFIX_V2 as KEY_PREFIX, decode_mount_resource_key_v2,
    decode_mount_resource_value_v2, encode_mount_resource_value_v2, mount_resource_key_v2,
};
use aos_sandbox_protocol::{
    MountSourcePhysicalProofV1, SourceRealizationBindingV1, mount_source_physical_proof_digest_v1,
    mount_source_realization_handle_v1,
};

use crate::source_pin::{SourcePinProofClassV1, SourceRealizationHandleV1};
use crate::{MountError, Result};

const RETIRED_KEY_PREFIX: &[u8] = b"aos.mount.resource.v1\0";
const RESOURCE_FAMILY_PREFIX: &[u8] = b"aos.mount.resource.";

/// Opaque, stable identity of one broker-owned mount resource.
pub(crate) type MountHandleV1 = [u8; 32];

/// Returns the sole descriptor-store key permitted for a mount handle.
///
/// [`crate::keeper::KernelMountName`] encodes these exact bytes in its
/// versioned activation name. Keeping the persisted key identical to the
/// handle prevents a recovered row from redirecting custody to another name.
pub(crate) const fn canonical_fd_store_key(handle: MountHandleV1) -> [u8; 32] {
    handle
}

type DestinationSlotKeyV1 = ([u8; 16], [u8; 16], [u8; 16]);

/// Bounds recovery and every newly encoded resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountResourceLimitsV1 {
    /// Hard V1 lifecycle-history cap; V1 does not retire released tombstones.
    pub(crate) resources: usize,
    /// Maximum non-released resources that may retain kernel or FD-store state.
    pub(crate) live_resources: usize,
    /// Maximum encoded bytes retained across all resource values.
    pub(crate) materialized_bytes: usize,
    /// Maximum bytes in one encoded resource value.
    pub(crate) value_bytes: usize,
    /// Maximum bytes in either observed kernel path.
    pub(crate) path_bytes: usize,
}

impl Default for MountResourceLimitsV1 {
    fn default() -> Self {
        Self {
            // Inventory V1 is deliberately unpaginated, so every admitted
            // tombstone and live row must fit in one authoritative response.
            resources: 1024,
            live_resources: 1024,
            materialized_bytes: 16 * 1024 * 1024,
            value_bytes: 64 * 1024,
            path_bytes: 4096,
        }
    }
}

trait AssignmentBindingV1Ext {
    fn strictly_advances(&self, predecessor: &Self) -> bool;
}

impl AssignmentBindingV1Ext for AssignmentBindingV1 {
    fn strictly_advances(&self, predecessor: &Self) -> bool {
        self.sandbox_id == predecessor.sandbox_id
            && self.incarnation_id == predecessor.incarnation_id
            && self.namespace_generation == predecessor.namespace_generation
            && (self.assignment_epoch, self.desired_generation)
                > (predecessor.assignment_epoch, predecessor.desired_generation)
    }
}

trait MountPolicyV1Ext {
    fn validate(&self) -> Result<()>;
}

impl MountPolicyV1Ext for MountPolicyV1 {
    fn validate(&self) -> Result<()> {
        if self.attributes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(state_error(
                "mount attributes are not in canonical strict order",
            ));
        }
        let is_read_only = self.attributes.contains(&OwnedMountAttributeV1::ReadOnly);
        if !self.attributes.contains(&OwnedMountAttributeV1::NoSuid)
            || !self.attributes.contains(&OwnedMountAttributeV1::NoDevice)
            || is_read_only != matches!(self.mutation, NativeMutationV1::ReadOnly)
        {
            return Err(state_error(
                "mount policy violates the V1 security baseline",
            ));
        }
        Ok(())
    }
}

pub(crate) trait ObjectDescriptorV1Ext: Sized {
    fn to_runtime(&self) -> Result<ObjectDescriptor>;

    fn from_runtime(descriptor: &ObjectDescriptor) -> Result<Self>;
}

impl ObjectDescriptorV1Ext for ObjectDescriptorV1 {
    /// Converts and registry-validates this DTO for the filesystem-view role.
    fn to_runtime(&self) -> Result<ObjectDescriptor> {
        if self.sha256_digest == [0; 32] || self.encoded_size == 0 {
            return Err(state_error("view descriptor contains a sentinel value"));
        }
        let media_type = MediaType::new(self.media_type.clone())
            .map_err(|error| state_error(error.to_string()))?;
        let descriptor = ObjectDescriptor::new(
            media_type,
            ObjectDigest::from_bytes(self.sha256_digest),
            self.encoded_size,
        );
        validate_descriptor_role(DescriptorRole::FilesystemViewRevision, &descriptor)
            .map_err(|error| state_error(error.to_string()))?;
        Ok(descriptor)
    }

    /// Converts a validated runtime view descriptor into its stable V1 DTO.
    fn from_runtime(descriptor: &ObjectDescriptor) -> Result<Self> {
        validate_descriptor_role(DescriptorRole::FilesystemViewRevision, descriptor)
            .map_err(|error| state_error(error.to_string()))?;
        if descriptor.digest().as_bytes() == &[0; 32] || descriptor.encoded_size() == 0 {
            return Err(state_error("view descriptor contains a sentinel value"));
        }
        Ok(Self {
            media_type: descriptor.media_type().as_str().to_owned(),
            sha256_digest: *descriptor.digest().as_bytes(),
            encoded_size: descriptor.encoded_size(),
        })
    }
}

/// Materializes and validates the broker's V1 mount-resource keyspace.
#[derive(Debug)]
pub(crate) struct MountResourceTableV1 {
    limits: MountResourceLimitsV1,
    current_kernel_boot_id: [u8; 16],
    resources: BTreeMap<MountHandleV1, MountResourceV1>,
    materialized_bytes: usize,
}

impl MountResourceTableV1 {
    /// Reconstructs the bounded resource table from committed journal records.
    pub(crate) fn recover(
        journal: &Journal,
        limits: MountResourceLimitsV1,
        current_kernel_boot_id: [u8; 16],
    ) -> Result<Self> {
        validate_limits(limits)?;
        if current_kernel_boot_id == [0; 16] {
            return Err(state_error("current kernel boot identity is a sentinel"));
        }
        let mut resources = BTreeMap::new();
        let mut materialized_bytes = 0usize;
        for (key, value) in journal.records(RecordNamespace::Operation) {
            let Some(handle) = decode_key(key)? else {
                continue;
            };
            materialized_bytes = materialized_bytes
                .checked_add(value.len())
                .ok_or_else(|| state_error("mount resource byte accounting overflow"))?;
            if value.len() > limits.value_bytes
                || materialized_bytes > limits.materialized_bytes
                || resources.len() >= limits.resources
            {
                return Err(state_error(
                    "mount resource recovery exceeds configured bounds",
                ));
            }
            let resource = decode_value(value, limits)?;
            if resource.handle != handle || resources.insert(handle, resource).is_some() {
                return Err(state_error("mount resource key or handle is inconsistent"));
            }
        }
        let table = Self {
            limits,
            current_kernel_boot_id,
            resources,
            materialized_bytes,
        };
        table.validate_table()?;
        Ok(table)
    }

    /// Returns a resource by its opaque handle.
    pub(crate) fn get(&self, handle: &MountHandleV1) -> Option<&MountResourceV1> {
        self.resources.get(handle)
    }

    /// Iterates over all retained rows in canonical handle order.
    pub(crate) fn resources(&self) -> impl Iterator<Item = &MountResourceV1> {
        self.resources.values()
    }

    /// Derives exact source-realization references from authenticated phases.
    pub(crate) fn source_realization_references(
        &self,
    ) -> Result<BTreeMap<SourceRealizationHandleV1, usize>> {
        let mut counts = BTreeMap::new();
        for resource in self.resources.values() {
            if resource.kernel_boot_id != self.current_kernel_boot_id
                || !resource.retains_source_reference()
            {
                continue;
            }
            let count = counts
                .entry(resource.recipe.source_realization_handle)
                .or_insert(0usize);
            *count = count
                .checked_add(1)
                .ok_or_else(|| state_error("source-realization reference count overflowed"))?;
        }
        Ok(counts)
    }

    /// Reports whether no retained mount resource claims one physical slot.
    pub(crate) fn destination_slot_is_unused(
        &self,
        sandbox_id: &[u8; 16],
        incarnation_id: &[u8; 16],
        namespace_generation: u64,
        destination_slot_id: &[u8; 16],
    ) -> bool {
        !self.resources.values().any(|resource| {
            resource.binding.sandbox_id == *sandbox_id
                && resource.binding.incarnation_id == *incarnation_id
                && resource.binding.namespace_generation == namespace_generation
                && resource.recipe.destination_slot_id == *destination_slot_id
                && is_slot_claim(&resource.state)
        })
    }

    /// Plans creation of a fresh `Allocated` record before any external effect.
    pub(crate) fn plan_allocate(&self, resource: &MountResourceV1) -> Result<Vec<JournalRecord>> {
        if resource.revision != 1
            || !matches!(resource.state, MountResourceStateV1::Allocated { .. })
            || self.resources.contains_key(&resource.handle)
        {
            return Err(state_error(
                "mount allocation is not fresh pre-effect intent",
            ));
        }
        self.plan_updates([resource])
    }

    /// Plans one compare-and-swap lifecycle transition.
    pub(crate) fn plan_transition(
        &self,
        expected_revision: u64,
        next: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        let current = self
            .resources
            .get(&next.handle)
            .ok_or_else(|| state_error("mount resource handle is unknown"))?;
        validate_transition(current, next, expected_revision)?;
        self.plan_updates([next])
    }

    /// Plans atomic successor installation and predecessor draining.
    pub(crate) fn plan_confirm_replacement(
        &self,
        expected_successor_revision: u64,
        successor: &MountResourceV1,
        expected_predecessor_revision: u64,
        predecessor: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        if successor.handle == predecessor.handle {
            return Err(state_error("replacement resources share one handle"));
        }
        let current_successor = self
            .resources
            .get(&successor.handle)
            .ok_or_else(|| state_error("replacement successor is unknown"))?;
        let current_predecessor = self
            .resources
            .get(&predecessor.handle)
            .ok_or_else(|| state_error("replacement predecessor is unknown"))?;
        validate_transition(current_successor, successor, expected_successor_revision)?;
        validate_transition(
            current_predecessor,
            predecessor,
            expected_predecessor_revision,
        )?;

        let declared = publication(&current_successor.state).and_then(|value| value.replaces)
            == Some(predecessor.handle);
        let linked = matches!(
            (&successor.state, &predecessor.state),
            (
                MountResourceStateV1::Installed { .. },
                MountResourceStateV1::Draining { replaced_by, .. }
            ) if *replaced_by == successor.handle
        );
        if !declared
            || !linked
            || successor.kernel_boot_id != predecessor.kernel_boot_id
            || successor.recipe.attachment_id != predecessor.recipe.attachment_id
            || successor.recipe.destination_slot_id != predecessor.recipe.destination_slot_id
            || !successor.binding.strictly_advances(&predecessor.binding)
            || successor.recipe.resource_attachment_generation
                <= predecessor.recipe.resource_attachment_generation
        {
            return Err(state_error(
                "replacement does not exactly and monotonically link its pair",
            ));
        }
        self.plan_updates([successor, predecessor])
    }

    /// Plans atomic retirement of a drained predecessor and its successor edge.
    pub(crate) fn plan_finish_replacement(
        &self,
        expected_successor_revision: u64,
        successor: &MountResourceV1,
        expected_predecessor_revision: u64,
        predecessor: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        let current_successor = self
            .resources
            .get(&successor.handle)
            .ok_or_else(|| state_error("replacement successor is unknown"))?;
        let current_predecessor = self
            .resources
            .get(&predecessor.handle)
            .ok_or_else(|| state_error("replacement predecessor is unknown"))?;
        if publication(&current_successor.state).and_then(|value| value.replaces)
            != Some(predecessor.handle)
            || draining_successor(&current_predecessor.state) != Some(successor.handle)
        {
            return Err(state_error("replacement retirement pair is not reciprocal"));
        }
        validate_transition(current_successor, successor, expected_successor_revision)?;
        validate_transition(
            current_predecessor,
            predecessor,
            expected_predecessor_revision,
        )?;
        self.plan_updates([successor, predecessor])
    }

    /// Plans release of both sides when an installed successor faulted.
    #[allow(dead_code)]
    pub(crate) fn plan_abandon_faulted_replacement(
        &self,
        expected_successor_revision: u64,
        successor: &MountResourceV1,
        expected_predecessor_revision: u64,
        predecessor: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        let current_successor = self
            .resources
            .get(&successor.handle)
            .ok_or_else(|| state_error("faulted replacement successor is unknown"))?;
        let current_predecessor = self
            .resources
            .get(&predecessor.handle)
            .ok_or_else(|| state_error("faulted replacement predecessor is unknown"))?;
        let successor_faulted_after_install = matches!(
            current_successor.state,
            MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Installed,
                ..
            }
        );
        if !successor_faulted_after_install
            || publication(&current_successor.state).and_then(|value| value.replaces)
                != Some(predecessor.handle)
            || draining_successor(&current_predecessor.state) != Some(successor.handle)
        {
            return Err(state_error(
                "faulted replacement release pair is not reciprocal",
            ));
        }
        validate_transition(current_successor, successor, expected_successor_revision)?;
        validate_transition(
            current_predecessor,
            predecessor,
            expected_predecessor_revision,
        )?;
        self.plan_updates([successor, predecessor])
    }

    /// Applies records only after the broker has durably committed them.
    ///
    /// # Errors
    ///
    /// Returns an error when records are outside this keyspace, malformed, or
    /// do not produce the same valid bounded table that was planned.
    pub(crate) fn apply_committed(&mut self, records: &[JournalRecord]) -> Result<()> {
        if records.is_empty() {
            return Err(state_error("empty mount resource mutation"));
        }
        let mut candidate = self.resources.clone();
        let mut changed = BTreeSet::new();
        for record in records {
            if record.namespace() != RecordNamespace::Operation {
                return Err(state_error(
                    "mount resource mutation uses the wrong namespace",
                ));
            }
            let handle = decode_key(record.key())?
                .ok_or_else(|| state_error("mount resource mutation uses the wrong keyspace"))?;
            let value = record
                .value()
                .ok_or_else(|| state_error("V1 resources are retained as released tombstones"))?;
            let resource = decode_value(value, self.limits)?;
            if resource.handle != handle {
                return Err(state_error("mount mutation key does not match its handle"));
            }
            if !changed.insert(handle) {
                return Err(state_error("mount mutation repeats one handle"));
            }
            match self.resources.get(&handle) {
                Some(current) => validate_transition(current, &resource, current.revision)?,
                None if resource.revision == 1
                    && matches!(resource.state, MountResourceStateV1::Allocated { .. }) => {}
                None => {
                    return Err(state_error(
                        "mount mutation creates a resource after an external effect",
                    ));
                }
            }
            candidate.insert(handle, resource);
        }
        let materialized_bytes = encoded_total(&candidate, self.limits)?;
        let next = Self {
            limits: self.limits,
            current_kernel_boot_id: self.current_kernel_boot_id,
            resources: candidate,
            materialized_bytes,
        };
        next.validate_table()?;
        *self = next;
        Ok(())
    }

    fn plan_updates<'a>(
        &self,
        updates: impl IntoIterator<Item = &'a MountResourceV1>,
    ) -> Result<Vec<JournalRecord>> {
        let mut candidate = self.resources.clone();
        let mut records = Vec::new();
        for resource in updates {
            resource.validate(self.limits)?;
            let value = encode_value(resource, self.limits)?;
            candidate.insert(resource.handle, resource.clone());
            records.push(JournalRecord::put(
                RecordNamespace::Operation,
                encode_key(resource.handle),
                value,
            ));
        }
        encoded_total(&candidate, self.limits)?;
        Self {
            limits: self.limits,
            current_kernel_boot_id: self.current_kernel_boot_id,
            resources: candidate,
            materialized_bytes: 0,
        }
        .validate_table()?;
        Ok(records)
    }

    fn validate_table(&self) -> Result<()> {
        if self.resources.len() > self.limits.resources
            || self.materialized_bytes > self.limits.materialized_bytes
        {
            return Err(state_error(
                "mount resource table exceeds configured bounds",
            ));
        }
        let mut mount_id_owners = BTreeMap::new();
        let mut fd_store_key_owners = BTreeMap::new();
        let live_resources = self
            .resources
            .values()
            .filter(|resource| !matches!(resource.state, MountResourceStateV1::Released { .. }))
            .count();
        if live_resources > self.limits.live_resources {
            return Err(state_error(
                "live mount resources exceed the descriptor-store capacity",
            ));
        }
        let mut active_stale_slot_boots = BTreeSet::new();
        for resource in self.resources.values().filter(|resource| {
            resource.kernel_boot_id != self.current_kernel_boot_id
                && is_slot_claim(&resource.state)
                && !matches!(resource.state, MountResourceStateV1::Faulted { .. })
        }) {
            active_stale_slot_boots.insert((
                resource.kernel_boot_id,
                resource.binding.sandbox_id,
                resource.binding.incarnation_id,
                resource.recipe.destination_slot_id,
            ));
        }

        let mut slots: BTreeMap<DestinationSlotKeyV1, Vec<&MountResourceV1>> = BTreeMap::new();
        for resource in self.resources.values() {
            resource.validate(self.limits)?;
            if fd_store_key_owners
                .insert(resource.fd_store_key, resource.handle)
                .is_some()
            {
                return Err(state_error(
                    "descriptor-store key is assigned to multiple resource rows",
                ));
            }
            if let Some(identity) = detached_identity(&resource.state) {
                register_mount_id_owner(
                    &mut mount_id_owners,
                    resource.kernel_boot_id,
                    identity.unique_mount_id,
                    resource.handle,
                )?;
            }
            if let Some(observation) = installed_observation(&resource.state) {
                register_mount_id_owner(
                    &mut mount_id_owners,
                    resource.kernel_boot_id,
                    observation.unique_mount_id,
                    resource.handle,
                )?;
            }
            let stale_slot_boot = (
                resource.kernel_boot_id,
                resource.binding.sandbox_id,
                resource.binding.incarnation_id,
                resource.recipe.destination_slot_id,
            );
            if is_slot_claim(&resource.state)
                && (resource.kernel_boot_id == self.current_kernel_boot_id
                    || active_stale_slot_boots.contains(&stale_slot_boot))
            {
                slots
                    .entry((
                        resource.binding.sandbox_id,
                        resource.binding.incarnation_id,
                        resource.recipe.destination_slot_id,
                    ))
                    .or_default()
                    .push(resource);
            }
        }
        validate_replacement_edges(&self.resources)?;
        for claimants in slots.values() {
            validate_slot_claimants(claimants)?;
        }
        Ok(())
    }
}

pub(crate) trait MountResourceV1Ext {
    fn retains_source_reference(&self) -> bool;

    fn validate(&self, limits: MountResourceLimitsV1) -> Result<()>;
}

impl MountResourceV1Ext for MountResourceV1 {
    /// Reports whether this durable phase still owns its source realization.
    fn retains_source_reference(&self) -> bool {
        !matches!(self.state, MountResourceStateV1::Released { .. })
    }

    fn validate(&self, limits: MountResourceLimitsV1) -> Result<()> {
        if self.handle == [0; 32]
            || self.kernel_boot_id == [0; 16]
            || self.revision == 0
            || self.binding.sandbox_id == [0; 16]
            || self.binding.incarnation_id == [0; 16]
            || self.binding.assignment_epoch == 0
            || self.binding.desired_generation == 0
            || self.binding.assignment_digest == [0; 32]
            || self.binding.namespace_generation == 0
            || self.recipe.attachment_id == [0; 16]
            || self.recipe.destination_slot_id == [0; 16]
            || self.recipe.source_generation == 0
            || self.recipe.resource_attachment_generation == 0
            || self.recipe.source_view_id == [0; 16]
            || self.recipe.source_realization_handle == [0; 32]
            || self.recipe.source_physical_proof_digest == [0; 32]
            || self.recipe.source_kernel_boot_id == [0; 16]
            || self.recipe.source_device == 0
            || self.recipe.source_inode == 0
            || self.recipe.source_unique_mount_id == 0
            || self.recipe.source_provider_authority_id == [0; 16]
            || self.recipe.source_provider_authority_generation == 0
            || self.recipe.source_provider_authority_digest == [0; 32]
            || self.recipe.source_provider_resource_id == [0; 32]
            || self.recipe.source_provider_resource_generation == 0
            || self.recipe.source_provider_resource_digest == [0; 32]
            || self.recipe.source_provider_catalog_generation == 0
            || self.recipe.source_provider_catalog_digest == [0; 32]
        {
            return Err(state_error("mount resource contains a sentinel identity"));
        }
        if self.recipe.source_kernel_boot_id != self.kernel_boot_id {
            return Err(state_error(
                "mount resource and source realization belong to different kernel boots",
            ));
        }
        let proof_matches_consistency = matches!(
            (
                self.recipe.source_proof_class,
                self.recipe.source_consistency
            ),
            (
                SourcePinProofClassV1::ImmutableTree,
                MountSourceConsistencyV1::ImmutableRevision
            ) | (
                SourcePinProofClassV1::LocalLive,
                MountSourceConsistencyV1::LocalLive
            ) | (
                SourcePinProofClassV1::BestEffortReplica,
                MountSourceConsistencyV1::BestEffortReplica
            )
        );
        if !proof_matches_consistency {
            return Err(state_error(
                "mount resource proof class differs from source consistency",
            ));
        }
        if self.recipe.source_incarnation_id.is_some()
            != matches!(
                self.recipe.source_consistency,
                MountSourceConsistencyV1::LocalLive
            )
            || self.recipe.source_incarnation_id == Some([0; 16])
        {
            return Err(state_error(
                "mount resource source incarnation differs from its consistency contract",
            ));
        }
        if self.fd_store_key != canonical_fd_store_key(self.handle) {
            return Err(state_error(
                "mount resource descriptor-store key is not canonical for its handle",
            ));
        }
        self.recipe.policy.validate()?;
        self.recipe.view_revision.to_runtime()?;
        validate_source_handle(
            &self.recipe,
            &self.recipe.source_handle,
            &self.recipe.source_binding_digest,
        )?;
        if publication(&self.state).is_some_and(|value| {
            value.target_namespace_generation != self.binding.namespace_generation
        }) {
            return Err(state_error(
                "publication namespace generation differs from its binding",
            ));
        }
        self.state.validate(limits, self.handle)
    }
}

fn validate_source_handle(
    recipe: &MountRecipeV1,
    source_handle: &[u8],
    source_binding_digest: &[u8; 32],
) -> Result<()> {
    let source = decode_view_source(source_handle, DecodeLimits::default())
        .map_err(|error| state_error(error.to_string()))?;
    if encode_view_source(&source) != source_handle {
        return Err(state_error("mount source handle is not canonical"));
    }
    let compatible = matches!(
        (&source, recipe.source_consistency),
        (
            ViewSource::ImmutableTree { .. },
            MountSourceConsistencyV1::ImmutableRevision
        ) | (
            ViewSource::LiveExport { .. },
            MountSourceConsistencyV1::LocalLive | MountSourceConsistencyV1::BestEffortReplica
        )
    );
    if !compatible {
        return Err(state_error(
            "mount source handle differs from its consistency contract",
        ));
    }
    let binding = SourceRealizationBindingV1::new(
        recipe.source_view_id,
        recipe.source_generation,
        recipe.view_revision.to_runtime()?,
        source,
        match recipe.source_consistency {
            MountSourceConsistencyV1::ImmutableRevision => aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            MountSourceConsistencyV1::LocalLive => aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            MountSourceConsistencyV1::BestEffortReplica => aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA,
        },
        recipe.source_incarnation_id,
    )
    .map_err(|error| state_error(error.to_string()))?;
    if binding.digest().as_bytes() != source_binding_digest {
        return Err(state_error(
            "mount source binding digest differs from its canonical recipe",
        ));
    }
    let physical_proof_digest = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: *source_binding_digest,
        proof_class: recipe.source_proof_class,
        provider_authority_id: recipe.source_provider_authority_id,
        provider_authority_generation: recipe.source_provider_authority_generation,
        provider_authority_digest: recipe.source_provider_authority_digest,
        provider_resource_id: recipe.source_provider_resource_id,
        provider_resource_generation: recipe.source_provider_resource_generation,
        provider_resource_digest: recipe.source_provider_resource_digest,
        provider_catalog_generation: recipe.source_provider_catalog_generation,
        provider_catalog_digest: recipe.source_provider_catalog_digest,
        kernel_boot_id: recipe.source_kernel_boot_id,
        device: recipe.source_device,
        inode: recipe.source_inode,
        unique_mount_id: recipe.source_unique_mount_id,
    });
    if physical_proof_digest != recipe.source_physical_proof_digest
        || mount_source_realization_handle_v1(*source_binding_digest, physical_proof_digest)
            != recipe.source_realization_handle
    {
        return Err(state_error(
            "mount source physical proof or realization handle is not canonical",
        ));
    }
    Ok(())
}

trait MountResourceStateV1Ext {
    fn validate(&self, limits: MountResourceLimitsV1, own_handle: MountHandleV1) -> Result<()>;
}

impl MountResourceStateV1Ext for MountResourceStateV1 {
    fn validate(&self, limits: MountResourceLimitsV1, own_handle: MountHandleV1) -> Result<()> {
        if let Some(value) = creation(self) {
            validate_operation(value)?;
        }
        if let Some(value) = publication(self) {
            validate_publication(value, own_handle)?;
        }
        match self {
            Self::Allocated { .. } => {}
            Self::Prepared { detached, .. } | Self::Publishing { detached, .. } => {
                validate_detached_mount_identity(detached)?;
            }
            Self::Installed {
                detached,
                installed,
                publication,
            } => {
                validate_detached_mount_identity(detached)?;
                validate_installed_mount_observation(installed, limits)?;
                if installed.target_mount_namespace_id != publication.target_mount_namespace_id {
                    return Err(state_error(
                        "installed mount is in the wrong target namespace",
                    ));
                }
                validate_same_mount_identity(detached, installed)?;
            }
            Self::Detaching {
                detached,
                installed,
                detachment,
            } => {
                validate_detached_mount_identity(detached)?;
                validate_installed_mount_observation(installed, limits)?;
                validate_same_mount_identity(detached, installed)?;
                validate_operation(detachment)?;
            }
            Self::Draining {
                detached,
                installed,
                replaced_by,
            } => {
                validate_detached_mount_identity(detached)?;
                validate_installed_mount_observation(installed, limits)?;
                validate_same_mount_identity(detached, installed)?;
                if *replaced_by == [0; 32] || *replaced_by == own_handle {
                    return Err(state_error("draining resource has an invalid successor"));
                }
            }
            Self::Releasing {
                detached,
                installed,
                release,
                replaced_by,
            } => {
                validate_detached_mount_identity(detached)?;
                validate_operation(release)?;
                if let Some(observation) = installed {
                    validate_installed_mount_observation(observation, limits)?;
                    validate_same_mount_identity(detached, observation)?;
                }
                if installed.is_some() != replaced_by.is_some()
                    || replaced_by.is_some_and(|handle| handle == [0; 32] || handle == own_handle)
                {
                    return Err(state_error("releasing resource has an invalid successor"));
                }
            }
            Self::Released {
                last_detached_mount_id,
                last_installed_mount_id,
            } => {
                if *last_detached_mount_id == Some(0) || *last_installed_mount_id == Some(0) {
                    return Err(state_error("released resource has a sentinel mount ID"));
                }
            }
            Self::Faulted { .. } => validate_fault(self, limits, own_handle)?,
        }
        Ok(())
    }
}

fn validate_fault(
    state: &MountResourceStateV1,
    limits: MountResourceLimitsV1,
    own_handle: MountHandleV1,
) -> Result<()> {
    let MountResourceStateV1::Faulted {
        from,
        creation,
        publication,
        detachment,
        release,
        replaced_by,
        detached,
        installed,
        failure_digest,
        ..
    } = state
    else {
        return Err(state_error("fault validator received a non-fault state"));
    };
    if *failure_digest == [0; 32] {
        return Err(state_error("faulted resource has a sentinel digest"));
    }
    let creation_phase = matches!(
        *from,
        MountFaultPhaseV1::Allocated | MountFaultPhaseV1::Prepared
    );
    let publication_phase = matches!(
        *from,
        MountFaultPhaseV1::Publishing | MountFaultPhaseV1::Installed
    );
    let detachment_phase = *from == MountFaultPhaseV1::Detaching;
    let release_phase = *from == MountFaultPhaseV1::Releasing;
    if creation_phase != creation.is_some()
        || publication_phase != publication.is_some()
        || detachment_phase != detachment.is_some()
        || release_phase != release.is_some()
        || (*from == MountFaultPhaseV1::Draining && replaced_by.is_none())
        || (!matches!(
            *from,
            MountFaultPhaseV1::Draining | MountFaultPhaseV1::Releasing
        ) && replaced_by.is_some())
    {
        return Err(state_error(
            "faulted resource does not retain its originating correlation",
        ));
    }
    if let Some(value) = creation.as_ref() {
        validate_operation(value)?;
    }
    if let Some(value) = publication.as_ref() {
        validate_publication(value, own_handle)?;
    }
    if let Some(value) = detachment.as_ref() {
        validate_operation(value)?;
    }
    if let Some(value) = release.as_ref() {
        validate_operation(value)?;
    }
    if replaced_by.is_some_and(|handle| handle == [0; 32] || handle == own_handle) {
        return Err(state_error("faulted resource has an invalid successor"));
    }
    if let Some(identity) = detached.as_ref() {
        validate_detached_mount_identity(identity)?;
    }
    if let Some(observation) = installed.as_ref() {
        validate_installed_mount_observation(observation, limits)?;
    }
    if let (Some(identity), Some(observation)) = (detached.as_ref(), installed.as_ref()) {
        validate_same_mount_identity(identity, observation)?;
    }
    let evidence_matches_phase = match from {
        MountFaultPhaseV1::Allocated => detached.is_none() && installed.is_none(),
        MountFaultPhaseV1::Prepared | MountFaultPhaseV1::Publishing => {
            detached.is_some() && installed.is_none()
        }
        MountFaultPhaseV1::Installed
        | MountFaultPhaseV1::Detaching
        | MountFaultPhaseV1::Draining => detached.is_some() && installed.is_some(),
        MountFaultPhaseV1::Releasing => {
            detached.is_some() && (installed.is_some() == replaced_by.is_some())
        }
    };
    if !evidence_matches_phase {
        return Err(state_error(
            "faulted resource evidence differs from its recorded phase",
        ));
    }
    Ok(())
}

fn validate_same_mount_identity(
    detached: &DetachedMountIdentityV1,
    installed: &InstalledMountObservationV1,
) -> Result<()> {
    if detached.unique_mount_id != installed.unique_mount_id {
        return Err(state_error(
            "published mount changed its unique kernel mount identity",
        ));
    }
    Ok(())
}

fn validate_detached_mount_identity(identity: &DetachedMountIdentityV1) -> Result<()> {
    if identity.unique_mount_id == 0 {
        return Err(state_error("detached mount identity is incomplete"));
    }
    Ok(())
}

fn validate_installed_mount_observation(
    observation: &InstalledMountObservationV1,
    limits: MountResourceLimitsV1,
) -> Result<()> {
    if observation.unique_mount_id == 0
        || observation.parent_mount_id == 0
        || observation.target_mount_namespace_id == 0
        || observation.identity_map_digest == [0; 32]
        || observation.root.is_empty()
        || observation.mount_point.is_empty()
        || observation.root.len() > limits.path_bytes
        || observation.mount_point.len() > limits.path_bytes
        || observation.root.contains(&0)
        || observation.mount_point.contains(&0)
    {
        return Err(state_error(
            "installed mount observation is incomplete or unbounded",
        ));
    }
    Ok(())
}

fn validate_transition(
    current: &MountResourceV1,
    next: &MountResourceV1,
    expected_revision: u64,
) -> Result<()> {
    if current.revision != expected_revision
        || next.revision
            != expected_revision
                .checked_add(1)
                .ok_or_else(|| state_error("mount resource revision overflow"))?
        || current.handle != next.handle
        || current.fd_store_key != next.fd_store_key
        || current.kernel_boot_id != next.kernel_boot_id
        || current.binding != next.binding
        || current.recipe != next.recipe
        || !valid_phase_transition(&current.state, &next.state)
    {
        return Err(state_error(
            "mount resource compare-and-swap transition is invalid",
        ));
    }
    Ok(())
}

fn valid_phase_transition(current: &MountResourceStateV1, next: &MountResourceStateV1) -> bool {
    use MountResourceStateV1 as State;
    match (current, next) {
        (
            State::Allocated { creation: left, .. },
            State::Prepared {
                creation: right, ..
            },
        ) => left == right,
        (
            State::Prepared {
                detached: left,
                creation,
            },
            State::Publishing {
                detached: right,
                publication,
            },
        ) => left == right && creation.operation_id != publication.operation.operation_id,
        (
            State::Publishing { detached: left, .. },
            State::Installed {
                detached: right, ..
            },
        ) => left == right && publication(current) == publication(next),
        (State::Installed { .. }, State::Draining { .. }) => {
            detached_identity(current) == detached_identity(next)
                && installed_observation(current) == installed_observation(next)
        }
        (
            State::Prepared {
                detached: left,
                creation,
            },
            State::Releasing {
                detached: right,
                installed: None,
                release,
                replaced_by: None,
            },
        ) => left == right && creation.operation_id != release.operation_id,
        (
            State::Draining {
                detached: left_detached,
                installed: left_installed,
                replaced_by: left_successor,
            },
            State::Releasing {
                detached: right_detached,
                installed: Some(right_installed),
                release: _,
                replaced_by: Some(right_successor),
            },
        ) => {
            left_detached == right_detached
                && left_installed == right_installed
                && left_successor == right_successor
        }
        (State::Installed { .. }, State::Installed { .. }) => {
            valid_replacement_edge_retirement(current, next)
        }
        (State::Installed { publication, .. }, State::Detaching { detachment, .. }) => {
            detached_identity(current) == detached_identity(next)
                && installed_observation(current) == installed_observation(next)
                && publication.operation.operation_id != detachment.operation_id
        }
        (
            State::Allocated { .. }
            | State::Prepared { .. }
            | State::Detaching { .. }
            | State::Draining { .. }
            | State::Releasing { .. }
            | State::Faulted { .. },
            State::Released { .. },
        ) => release_ids_match(current, next),
        (_, State::Faulted { from, .. }) => {
            fault_phase(current) == Some(*from)
                && detached_identity(current) == detached_identity(next)
                && installed_observation(current) == installed_observation(next)
                && fault_correlation_matches(current, next)
        }
        _ => false,
    }
}

fn valid_replacement_edge_retirement(
    current: &MountResourceStateV1,
    next: &MountResourceStateV1,
) -> bool {
    let (
        MountResourceStateV1::Installed {
            detached: current_detached,
            installed: current_installed,
            publication: current_publication,
        },
        MountResourceStateV1::Installed {
            detached: next_detached,
            installed: next_installed,
            publication: next_publication,
        },
    ) = (current, next)
    else {
        return false;
    };
    current_detached == next_detached
        && current_installed == next_installed
        && current_publication.replaces.is_some()
        && next_publication.replaces.is_none()
        && current_publication.operation == next_publication.operation
        && current_publication.target_mount_namespace_id
            == next_publication.target_mount_namespace_id
        && current_publication.target_namespace_generation
            == next_publication.target_namespace_generation
}

fn validate_slot_claimants(claimants: &[&MountResourceV1]) -> Result<()> {
    if claimants.len() == 1 {
        if has_replacement_edge(&claimants[0].state) {
            return Err(state_error(
                "destination slot has a dangling replacement edge",
            ));
        }
        return Ok(());
    }
    if claimants.len() != 2 {
        return Err(state_error("destination slot has too many live claimants"));
    }
    let left = claimants[0];
    let right = claimants[1];
    let pair_is_linked = declares_replacement(left, right) || declares_replacement(right, left);
    if !pair_is_linked {
        return Err(state_error(
            "destination slot claimants are not one replacement pair",
        ));
    }
    Ok(())
}

fn register_mount_id_owner(
    owners: &mut BTreeMap<([u8; 16], u64), MountHandleV1>,
    kernel_boot_id: [u8; 16],
    mount_id: u64,
    handle: MountHandleV1,
) -> Result<()> {
    let identity = (kernel_boot_id, mount_id);
    match owners.get(&identity) {
        Some(owner) if *owner != handle => Err(state_error(
            "one unique mount ID is claimed by multiple live handles",
        )),
        Some(_) => Ok(()),
        None => {
            owners.insert(identity, handle);
            Ok(())
        }
    }
}

fn declares_replacement(successor: &MountResourceV1, predecessor: &MountResourceV1) -> bool {
    let forward =
        publication(&successor.state).and_then(|value| value.replaces) == Some(predecessor.handle);
    let phases_match = (is_publishing_phase(&successor.state)
        && is_installed_phase(&predecessor.state))
        || (is_installed_phase(&successor.state)
            && draining_successor(&predecessor.state) == Some(successor.handle));
    forward
        && phases_match
        && successor.kernel_boot_id == predecessor.kernel_boot_id
        && successor.recipe.attachment_id == predecessor.recipe.attachment_id
        && successor.recipe.destination_slot_id == predecessor.recipe.destination_slot_id
        && successor.binding.strictly_advances(&predecessor.binding)
        && successor.recipe.resource_attachment_generation
            > predecessor.recipe.resource_attachment_generation
}

fn validate_replacement_edges(resources: &BTreeMap<MountHandleV1, MountResourceV1>) -> Result<()> {
    for resource in resources.values() {
        if let Some(predecessor_handle) =
            publication(&resource.state).and_then(|value| value.replaces)
        {
            let predecessor = resources
                .get(&predecessor_handle)
                .ok_or_else(|| state_error("replacement predecessor is missing"))?;
            if !declares_replacement(resource, predecessor) {
                return Err(state_error("replacement forward edge is inconsistent"));
            }
        }
        if let Some(successor_handle) = draining_successor(&resource.state) {
            let successor = resources
                .get(&successor_handle)
                .ok_or_else(|| state_error("replacement successor is missing"))?;
            if !declares_replacement(successor, resource) {
                return Err(state_error("replacement back edge is inconsistent"));
            }
        }
    }
    Ok(())
}

fn has_replacement_edge(state: &MountResourceStateV1) -> bool {
    publication(state).is_some_and(|value| value.replaces.is_some())
        || draining_successor(state).is_some()
}

fn validate_publication(
    publication: &PublicationCorrelationV1,
    own_handle: MountHandleV1,
) -> Result<()> {
    validate_operation(&publication.operation)?;
    if publication.target_mount_namespace_id == 0
        || publication.target_namespace_generation == 0
        || publication
            .replaces
            .is_some_and(|handle| handle == [0; 32] || handle == own_handle)
    {
        return Err(state_error("publication correlation is incomplete"));
    }
    Ok(())
}

fn validate_operation(operation: &OperationCorrelationV1) -> Result<()> {
    if operation.operation_id == [0; 16] || operation.request_digest == [0; 32] {
        return Err(state_error("operation correlation is incomplete"));
    }
    Ok(())
}

fn creation(state: &MountResourceStateV1) -> Option<&OperationCorrelationV1> {
    match state {
        MountResourceStateV1::Allocated { creation }
        | MountResourceStateV1::Prepared { creation, .. } => Some(creation),
        MountResourceStateV1::Faulted { creation, .. } => creation.as_ref(),
        MountResourceStateV1::Publishing { .. }
        | MountResourceStateV1::Installed { .. }
        | MountResourceStateV1::Detaching { .. }
        | MountResourceStateV1::Draining { .. }
        | MountResourceStateV1::Releasing { .. }
        | MountResourceStateV1::Released { .. } => None,
    }
}

fn publication(state: &MountResourceStateV1) -> Option<&PublicationCorrelationV1> {
    match state {
        MountResourceStateV1::Publishing { publication, .. }
        | MountResourceStateV1::Installed { publication, .. } => Some(publication),
        MountResourceStateV1::Faulted { publication, .. } => publication.as_ref(),
        MountResourceStateV1::Allocated { .. }
        | MountResourceStateV1::Prepared { .. }
        | MountResourceStateV1::Detaching { .. }
        | MountResourceStateV1::Draining { .. }
        | MountResourceStateV1::Releasing { .. }
        | MountResourceStateV1::Released { .. } => None,
    }
}

fn detached_identity(state: &MountResourceStateV1) -> Option<&DetachedMountIdentityV1> {
    match state {
        MountResourceStateV1::Prepared { detached, .. }
        | MountResourceStateV1::Publishing { detached, .. }
        | MountResourceStateV1::Installed { detached, .. }
        | MountResourceStateV1::Detaching { detached, .. }
        | MountResourceStateV1::Draining { detached, .. }
        | MountResourceStateV1::Releasing { detached, .. } => Some(detached),
        MountResourceStateV1::Faulted { detached, .. } => detached.as_ref(),
        MountResourceStateV1::Allocated { .. } | MountResourceStateV1::Released { .. } => None,
    }
}

fn installed_observation(state: &MountResourceStateV1) -> Option<&InstalledMountObservationV1> {
    match state {
        MountResourceStateV1::Installed { installed, .. }
        | MountResourceStateV1::Detaching { installed, .. }
        | MountResourceStateV1::Draining { installed, .. }
        | MountResourceStateV1::Releasing {
            installed: Some(installed),
            ..
        } => Some(installed),
        MountResourceStateV1::Faulted { installed, .. } => installed.as_ref(),
        MountResourceStateV1::Allocated { .. }
        | MountResourceStateV1::Prepared { .. }
        | MountResourceStateV1::Publishing { .. }
        | MountResourceStateV1::Releasing {
            installed: None, ..
        }
        | MountResourceStateV1::Released { .. } => None,
    }
}

fn fault_phase(state: &MountResourceStateV1) -> Option<MountFaultPhaseV1> {
    match state {
        MountResourceStateV1::Allocated { .. } => Some(MountFaultPhaseV1::Allocated),
        MountResourceStateV1::Prepared { .. } => Some(MountFaultPhaseV1::Prepared),
        MountResourceStateV1::Publishing { .. } => Some(MountFaultPhaseV1::Publishing),
        MountResourceStateV1::Installed { .. } => Some(MountFaultPhaseV1::Installed),
        MountResourceStateV1::Detaching { .. } => Some(MountFaultPhaseV1::Detaching),
        MountResourceStateV1::Draining { .. } => Some(MountFaultPhaseV1::Draining),
        MountResourceStateV1::Releasing { .. } => Some(MountFaultPhaseV1::Releasing),
        MountResourceStateV1::Released { .. } | MountResourceStateV1::Faulted { .. } => None,
    }
}

fn release_ids_match(current: &MountResourceStateV1, next: &MountResourceStateV1) -> bool {
    let MountResourceStateV1::Released {
        last_detached_mount_id,
        last_installed_mount_id,
    } = next
    else {
        return false;
    };
    detached_identity(current).map(|value| value.unique_mount_id) == *last_detached_mount_id
        && installed_observation(current).map(|value| value.unique_mount_id)
            == *last_installed_mount_id
}

fn is_slot_claim(state: &MountResourceStateV1) -> bool {
    matches!(
        state,
        MountResourceStateV1::Publishing { .. }
            | MountResourceStateV1::Installed { .. }
            | MountResourceStateV1::Detaching { .. }
            | MountResourceStateV1::Draining { .. }
            | MountResourceStateV1::Releasing {
                installed: Some(_),
                ..
            }
            | MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Publishing
                    | MountFaultPhaseV1::Installed
                    | MountFaultPhaseV1::Detaching
                    | MountFaultPhaseV1::Draining,
                ..
            }
    ) || matches!(
        state,
        MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Releasing,
            installed: Some(_),
            ..
        }
    )
}

fn fault_correlation_matches(current: &MountResourceStateV1, next: &MountResourceStateV1) -> bool {
    let MountResourceStateV1::Faulted {
        creation: fault_creation,
        publication: fault_publication,
        detachment: fault_detachment,
        release: fault_release,
        replaced_by,
        ..
    } = next
    else {
        return false;
    };
    fault_creation.as_ref() == creation(current)
        && fault_publication.as_ref() == publication(current)
        && fault_detachment.as_ref() == detachment(current)
        && fault_release.as_ref() == release(current)
        && *replaced_by == draining_successor(current)
}

fn detachment(state: &MountResourceStateV1) -> Option<&OperationCorrelationV1> {
    match state {
        MountResourceStateV1::Detaching { detachment, .. } => Some(detachment),
        MountResourceStateV1::Faulted { detachment, .. } => detachment.as_ref(),
        _ => None,
    }
}

fn release(state: &MountResourceStateV1) -> Option<&OperationCorrelationV1> {
    match state {
        MountResourceStateV1::Releasing { release, .. } => Some(release),
        MountResourceStateV1::Faulted { release, .. } => release.as_ref(),
        _ => None,
    }
}

fn is_publishing_phase(state: &MountResourceStateV1) -> bool {
    matches!(
        state,
        MountResourceStateV1::Publishing { .. }
            | MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Publishing,
                ..
            }
    )
}

fn is_installed_phase(state: &MountResourceStateV1) -> bool {
    matches!(
        state,
        MountResourceStateV1::Installed { .. }
            | MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Installed,
                ..
            }
    )
}

fn draining_successor(state: &MountResourceStateV1) -> Option<MountHandleV1> {
    match state {
        MountResourceStateV1::Draining { replaced_by, .. }
        | MountResourceStateV1::Releasing {
            replaced_by: Some(replaced_by),
            ..
        }
        | MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Draining | MountFaultPhaseV1::Releasing,
            replaced_by: Some(replaced_by),
            ..
        } => Some(*replaced_by),
        _ => None,
    }
}

fn encoded_total(
    resources: &BTreeMap<MountHandleV1, MountResourceV1>,
    limits: MountResourceLimitsV1,
) -> Result<usize> {
    if resources.len() > limits.resources {
        return Err(state_error(
            "mount resource count exceeds its configured bound",
        ));
    }
    resources.values().try_fold(0usize, |total, resource| {
        let bytes = encode_value(resource, limits)?.len();
        let next = total
            .checked_add(bytes)
            .ok_or_else(|| state_error("mount resource byte accounting overflow"))?;
        if next > limits.materialized_bytes {
            return Err(state_error(
                "mount resource bytes exceed their configured bound",
            ));
        }
        Ok(next)
    })
}

fn encode_value(resource: &MountResourceV1, limits: MountResourceLimitsV1) -> Result<Vec<u8>> {
    resource.validate(limits)?;
    let bytes =
        encode_mount_resource_value_v2(resource).map_err(|error| state_error(error.to_string()))?;
    if bytes.len() > limits.value_bytes {
        return Err(state_error(
            "mount resource value exceeds its configured bound",
        ));
    }
    Ok(bytes)
}

fn decode_value(bytes: &[u8], limits: MountResourceLimitsV1) -> Result<MountResourceV1> {
    if bytes.is_empty() || bytes.len() > limits.value_bytes {
        return Err(state_error("mount resource value length is invalid"));
    }
    let resource =
        decode_mount_resource_value_v2(bytes).map_err(|error| state_error(error.to_string()))?;
    resource.validate(limits)?;
    Ok(resource)
}

/// Validates one exact fresh Allocated Mount resource companion record.
pub(crate) fn validate_source_consumption_record(
    record: &JournalRecord,
    expected: &MountResourceV1,
) -> Result<()> {
    if record.namespace() != RecordNamespace::Operation
        || record.value().is_none()
        || decode_key(record.key())? != Some(expected.handle)
        || decode_value(
            record
                .value()
                .ok_or_else(|| state_error("Mount consumption resource is a delete"))?,
            MountResourceLimitsV1::default(),
        )? != *expected
    {
        return Err(state_error(
            "Mount consumption resource differs from the final Create",
        ));
    }
    Ok(())
}

fn encode_key(handle: MountHandleV1) -> Vec<u8> {
    mount_resource_key_v2(handle)
}

fn decode_key(key: &[u8]) -> Result<Option<MountHandleV1>> {
    if key.starts_with(RETIRED_KEY_PREFIX) {
        return Err(state_error(
            "pre-source-realization Mount resource schema is unsupported",
        ));
    }
    if key.starts_with(RESOURCE_FAMILY_PREFIX) && !key.starts_with(KEY_PREFIX) {
        return Err(state_error(
            "unknown Mount resource schema in the reserved key family",
        ));
    }
    if !key.starts_with(KEY_PREFIX) {
        return Ok(None);
    }
    let handle: MountHandleV1 =
        decode_mount_resource_key_v2(key).map_err(|error| state_error(error.to_string()))?;
    if handle == [0; 32] {
        return Err(state_error("mount resource journal handle is a sentinel"));
    }
    Ok(Some(handle))
}

fn validate_limits(limits: MountResourceLimitsV1) -> Result<()> {
    if limits.resources == 0
        || limits.live_resources == 0
        || limits.live_resources > limits.resources
        || limits.materialized_bytes == 0
        || limits.value_bytes == 0
        || limits.path_bytes == 0
        || limits.value_bytes > limits.materialized_bytes
    {
        return Err(state_error("mount resource limits are invalid"));
    }
    Ok(())
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox::JournalTransaction;
    use aos_sandbox_core::PortableMediaType;

    use super::*;

    fn table() -> MountResourceTableV1 {
        MountResourceTableV1 {
            limits: MountResourceLimitsV1::default(),
            current_kernel_boot_id: [10; 16],
            resources: BTreeMap::new(),
            materialized_bytes: 0,
        }
    }

    fn policy() -> MountPolicyV1 {
        MountPolicyV1 {
            attributes: vec![
                OwnedMountAttributeV1::ReadOnly,
                OwnedMountAttributeV1::NoExec,
                OwnedMountAttributeV1::NoSuid,
                OwnedMountAttributeV1::NoDevice,
                OwnedMountAttributeV1::NoAtime,
            ],
            mutation: NativeMutationV1::ReadOnly,
        }
    }

    #[test]
    fn default_table_fits_one_complete_v1_inventory() {
        let limits = MountResourceLimitsV1::default();
        assert_eq!(limits.resources, 1024);
        assert_eq!(limits.live_resources, 1024);
    }

    #[test]
    fn closed_mutation_model_covers_every_portable_v1_value() {
        let modes = [
            NativeMutationV1::ReadOnly,
            NativeMutationV1::ReadWrite,
            NativeMutationV1::PrivateCow,
            NativeMutationV1::AppendOnly,
            NativeMutationV1::Service,
        ];
        assert_eq!(modes.len(), 5);
    }

    fn publication(replaces: Option<MountHandleV1>) -> PublicationCorrelationV1 {
        PublicationCorrelationV1 {
            operation: OperationCorrelationV1 {
                operation_id: [11; 16],
                request_digest: [12; 32],
            },
            target_mount_namespace_id: 13,
            target_namespace_generation: 6,
            replaces,
        }
    }

    fn creation() -> OperationCorrelationV1 {
        OperationCorrelationV1 {
            operation_id: [14; 16],
            request_digest: [15; 32],
        }
    }

    fn resource(handle: u8, generation: u64, _replaces: Option<MountHandleV1>) -> MountResourceV1 {
        let source = ViewSource::ImmutableTree {
            tree: ObjectDescriptor::new(
                MediaType::new(PortableMediaType::Tree.as_str().to_owned()).unwrap(),
                ObjectDigest::from_bytes([16; 32]),
                17,
            ),
        };
        let view = ObjectDescriptor::new(
            MediaType::new(PortableMediaType::View.as_str().to_owned()).unwrap(),
            ObjectDigest::from_bytes([9; 32]),
            10,
        );
        let source_binding_digest = *SourceRealizationBindingV1::new(
            [13; 16],
            11,
            view,
            source.clone(),
            aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        )
        .unwrap()
        .digest()
        .as_bytes();
        let source_physical_proof_digest =
            mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
                binding_digest: source_binding_digest,
                proof_class: SourcePinProofClassV1::ImmutableTree,
                provider_authority_id: [51; 16],
                provider_authority_generation: 52,
                provider_authority_digest: [45; 32],
                provider_resource_id: [46; 32],
                provider_resource_generation: 47,
                provider_resource_digest: [48; 32],
                provider_catalog_generation: 49,
                provider_catalog_digest: [50; 32],
                kernel_boot_id: [10; 16],
                device: 41,
                inode: 42,
                unique_mount_id: 44,
            });
        let source_realization_handle =
            mount_source_realization_handle_v1(source_binding_digest, source_physical_proof_digest);
        MountResourceV1 {
            handle: [handle; 32],
            fd_store_key: [handle; 32],
            kernel_boot_id: [10; 16],
            revision: 1,
            binding: AssignmentBindingV1 {
                sandbox_id: [1; 16],
                incarnation_id: [2; 16],
                assignment_epoch: 3,
                desired_generation: generation,
                assignment_digest: [handle; 32],
                namespace_generation: 6,
            },
            recipe: MountRecipeV1 {
                attachment_id: [7; 16],
                destination_slot_id: [8; 16],
                view_revision: ObjectDescriptorV1 {
                    media_type: PortableMediaType::View.as_str().to_owned(),
                    sha256_digest: [9; 32],
                    encoded_size: 10,
                },
                source_generation: 11,
                resource_attachment_generation: generation,
                source_view_id: [13; 16],
                source_incarnation_id: None,
                source_consistency: MountSourceConsistencyV1::ImmutableRevision,
                source_handle: encode_view_source(&source),
                source_binding_digest,
                source_realization_handle,
                source_physical_proof_digest,
                source_kernel_boot_id: [10; 16],
                source_device: 41,
                source_inode: 42,
                source_proof_class: SourcePinProofClassV1::ImmutableTree,
                source_unique_mount_id: 44,
                source_provider_authority_id: [51; 16],
                source_provider_authority_generation: 52,
                source_provider_authority_digest: [45; 32],
                source_provider_resource_id: [46; 32],
                source_provider_resource_generation: 47,
                source_provider_resource_digest: [48; 32],
                source_provider_catalog_generation: 49,
                source_provider_catalog_digest: [50; 32],
                policy: policy(),
            },
            state: MountResourceStateV1::Allocated {
                creation: creation(),
            },
        }
    }

    #[test]
    fn source_references_are_derived_from_exact_resource_phases() {
        let mut resources = table();
        let allocated = resource(1, 1, None);
        let handle = allocated.recipe.source_realization_handle;

        let mut prepared = resource(2, 2, None);
        prepared.state = MountResourceStateV1::Prepared {
            detached: detached(2, 102),
            creation: creation(),
        };
        let mut installed_resource = resource(3, 3, None);
        installed_resource.state = MountResourceStateV1::Installed {
            detached: detached(3, 103),
            installed: installed(203),
            publication: publication(None),
        };
        let mut draining = resource(4, 4, None);
        draining.state = MountResourceStateV1::Draining {
            detached: detached(4, 104),
            installed: installed(204),
            replaced_by: [5; 32],
        };
        let mut released = resource(5, 5, None);
        released.state = MountResourceStateV1::Released {
            last_detached_mount_id: Some(105),
            last_installed_mount_id: None,
        };

        for resource in [allocated, prepared, installed_resource, draining, released] {
            resources.resources.insert(resource.handle, resource);
        }
        let counts = resources.source_realization_references().unwrap();

        assert_eq!(counts.get(&handle), Some(&4));
    }

    #[test]
    fn exact_v2_resource_round_trips_and_rejects_other_versions() {
        let resource = resource(1, 1, None);
        let encoded = encode_value(&resource, MountResourceLimitsV1::default()).unwrap();
        assert_eq!(
            decode_value(&encoded, MountResourceLimitsV1::default()).unwrap(),
            resource
        );

        let mut future: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        future["version"] = serde_json::Value::from(3);
        assert!(
            decode_value(
                &serde_json::to_vec(&future).unwrap(),
                MountResourceLimitsV1::default(),
            )
            .is_err()
        );

        let mut missing_source: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        missing_source["resource"]["recipe"]
            .as_object_mut()
            .unwrap()
            .remove("source_handle");
        assert!(
            decode_value(
                &serde_json::to_vec(&missing_source).unwrap(),
                MountResourceLimitsV1::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn recovery_rejects_future_mount_resource_keys_but_ignores_other_operations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) = Journal::open(&path, Default::default()).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [90; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        b"aos.other.operation.v1\0fixture".to_vec(),
                        b"unrelated".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(MountResourceTableV1::recover(&journal, Default::default(), [10; 16]).is_ok());

        journal
            .commit(
                &JournalTransaction::new(
                    [91; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::Operation,
                        b"aos.mount.resource.v3\0future".to_vec(),
                        b"{}".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(MountResourceTableV1::recover(&journal, Default::default(), [10; 16]).is_err());
    }

    fn detached(_handle: u8, mount_id: u64) -> DetachedMountIdentityV1 {
        DetachedMountIdentityV1 {
            unique_mount_id: mount_id,
        }
    }

    fn installed(mount_id: u64) -> InstalledMountObservationV1 {
        InstalledMountObservationV1 {
            unique_mount_id: mount_id,
            parent_mount_id: 21,
            target_mount_namespace_id: 13,
            device_major: 22,
            device_minor: 23,
            superblock_magic: 24,
            superblock_flags: 25,
            mount_attributes: 26,
            propagation: 27,
            root: b"/source".to_vec(),
            mount_point: b"/target".to_vec(),
            identity_map_digest: [28; 32],
        }
    }

    fn set_kernel_boot(resource: &mut MountResourceV1, boot_id: [u8; 16]) {
        resource.kernel_boot_id = boot_id;
        resource.recipe.source_kernel_boot_id = boot_id;
        resource.recipe.source_physical_proof_digest =
            mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
                binding_digest: resource.recipe.source_binding_digest,
                proof_class: resource.recipe.source_proof_class,
                provider_authority_id: resource.recipe.source_provider_authority_id,
                provider_authority_generation: resource.recipe.source_provider_authority_generation,
                provider_authority_digest: resource.recipe.source_provider_authority_digest,
                provider_resource_id: resource.recipe.source_provider_resource_id,
                provider_resource_generation: resource.recipe.source_provider_resource_generation,
                provider_resource_digest: resource.recipe.source_provider_resource_digest,
                provider_catalog_generation: resource.recipe.source_provider_catalog_generation,
                provider_catalog_digest: resource.recipe.source_provider_catalog_digest,
                kernel_boot_id: resource.recipe.source_kernel_boot_id,
                device: resource.recipe.source_device,
                inode: resource.recipe.source_inode,
                unique_mount_id: resource.recipe.source_unique_mount_id,
            });
        resource.recipe.source_realization_handle = mount_source_realization_handle_v1(
            resource.recipe.source_binding_digest,
            resource.recipe.source_physical_proof_digest,
        );
    }

    fn stale_faulted_replacement_pair() -> (MountResourceV1, MountResourceV1) {
        let mut predecessor = resource(70, 4, None);
        set_kernel_boot(&mut predecessor, [9; 16]);
        predecessor.revision = 5;
        predecessor.state = MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Draining,
            creation: None,
            publication: None,
            detachment: None,
            release: None,
            replaced_by: Some([71; 32]),
            detached: Some(detached(70, 170)),
            installed: Some(installed(170)),
            failure_digest: [72; 32],
        };

        let mut successor = resource(71, 5, None);
        set_kernel_boot(&mut successor, [9; 16]);
        successor.revision = 5;
        successor.state = MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Installed,
            creation: None,
            publication: Some(publication(Some([70; 32]))),
            detachment: None,
            release: None,
            replaced_by: None,
            detached: Some(detached(71, 171)),
            installed: Some(installed(171)),
            failure_digest: [73; 32],
        };
        (predecessor, successor)
    }

    fn table_with(resources: impl IntoIterator<Item = MountResourceV1>) -> MountResourceTableV1 {
        MountResourceTableV1 {
            limits: MountResourceLimitsV1::default(),
            current_kernel_boot_id: [10; 16],
            resources: resources
                .into_iter()
                .map(|resource| (resource.handle, resource))
                .collect(),
            materialized_bytes: 0,
        }
    }

    fn commit_planned(table: &mut MountResourceTableV1, records: &[JournalRecord]) {
        table.apply_committed(records).unwrap();
    }

    fn allocate(table: &mut MountResourceTableV1, resource: &MountResourceV1) {
        let records = table.plan_allocate(resource).unwrap();
        commit_planned(table, &records);
    }

    fn transition(
        table: &mut MountResourceTableV1,
        expected_revision: u64,
        resource: &MountResourceV1,
    ) {
        let records = table.plan_transition(expected_revision, resource).unwrap();
        commit_planned(table, &records);
    }

    #[test]
    fn allocation_is_the_only_fresh_pre_effect_state() {
        let table = table();
        let allocated = resource(30, 4, None);
        assert_eq!(table.plan_allocate(&allocated).unwrap().len(), 1);

        let mut prepared = allocated.clone();
        prepared.state = MountResourceStateV1::Prepared {
            detached: detached(30, 100),
            creation: creation(),
        };
        assert!(table.plan_allocate(&prepared).is_err());
    }

    #[test]
    fn descriptor_store_key_is_stable_through_release() {
        let mut table = table();
        let allocated = resource(31, 4, None);
        allocate(&mut table, &allocated);

        let released = MountResourceV1 {
            revision: 2,
            state: MountResourceStateV1::Released {
                last_detached_mount_id: None,
                last_installed_mount_id: None,
            },
            ..allocated
        };
        transition(&mut table, 1, &released);
        assert_eq!(table.get(&[31; 32]), Some(&released));
    }

    #[test]
    fn prepared_mount_introduces_a_distinct_later_install_correlation() {
        let mut table = table();
        let mut prepared = resource(54, 4, None);
        allocate(&mut table, &prepared);
        prepared.revision = 2;
        prepared.state = MountResourceStateV1::Prepared {
            detached: detached(54, 154),
            creation: creation(),
        };
        transition(&mut table, 1, &prepared);

        let mut same_operation = publication(None);
        same_operation.operation = creation();
        let publishing = MountResourceV1 {
            revision: 3,
            state: MountResourceStateV1::Publishing {
                detached: detached(54, 154),
                publication: same_operation,
            },
            ..prepared
        };
        assert!(table.plan_transition(2, &publishing).is_err());

        let later_install = MountResourceV1 {
            state: MountResourceStateV1::Publishing {
                detached: detached(54, 154),
                publication: publication(None),
            },
            ..publishing
        };
        assert!(table.plan_transition(2, &later_install).is_ok());
    }

    #[test]
    fn fault_preserves_creation_correlation_for_allocated_resource() {
        let mut table = table();
        let allocated = resource(34, 4, None);
        allocate(&mut table, &allocated);

        let mut wrong_creation = creation();
        wrong_creation.request_digest = [99; 32];
        let faulted = MountResourceV1 {
            revision: 2,
            state: MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Allocated,
                creation: Some(wrong_creation),
                publication: None,
                detachment: None,
                release: None,
                replaced_by: None,
                detached: None,
                installed: None,
                failure_digest: [35; 32],
            },
            ..allocated
        };
        assert!(table.plan_transition(1, &faulted).is_err());

        let faulted = MountResourceV1 {
            state: MountResourceStateV1::Faulted {
                from: MountFaultPhaseV1::Allocated,
                creation: Some(creation()),
                publication: None,
                detachment: None,
                release: None,
                replaced_by: None,
                detached: None,
                installed: None,
                failure_digest: [35; 32],
            },
            ..faulted
        };
        transition(&mut table, 1, &faulted);
        let retry = MountResourceV1 {
            revision: 3,
            state: MountResourceStateV1::Prepared {
                detached: detached(34, 134),
                creation: creation(),
            },
            ..faulted.clone()
        };
        assert!(table.plan_transition(2, &retry).is_err());

        let released = MountResourceV1 {
            revision: 3,
            state: MountResourceStateV1::Released {
                last_detached_mount_id: None,
                last_installed_mount_id: None,
            },
            ..faulted
        };
        assert!(table.plan_transition(2, &released).is_ok());
    }

    #[test]
    fn independent_live_claimants_for_one_slot_are_rejected() {
        let mut table = table();
        let mut first = resource(32, 4, None);
        allocate(&mut table, &first);
        first.revision = 2;
        first.state = MountResourceStateV1::Prepared {
            detached: detached(32, 132),
            creation: creation(),
        };
        transition(&mut table, 1, &first);

        let mut second = resource(33, 5, None);
        allocate(&mut table, &second);
        second.revision = 2;
        second.state = MountResourceStateV1::Prepared {
            detached: detached(33, 133),
            creation: creation(),
        };
        transition(&mut table, 1, &second);

        first.revision = 3;
        first.state = MountResourceStateV1::Publishing {
            detached: detached(32, 132),
            publication: publication(None),
        };
        transition(&mut table, 2, &first);
        second.revision = 3;
        second.state = MountResourceStateV1::Publishing {
            detached: detached(33, 133),
            publication: publication(None),
        };
        assert!(table.plan_transition(2, &second).is_err());
    }

    #[test]
    fn stale_boot_faulted_install_does_not_wedge_current_slot_publication() {
        let mut table = table();
        table.current_kernel_boot_id = [11; 16];

        let mut stale = resource(60, 4, None);
        allocate(&mut table, &stale);
        stale.revision = 2;
        stale.state = MountResourceStateV1::Prepared {
            detached: detached(60, 160),
            creation: creation(),
        };
        transition(&mut table, 1, &stale);
        stale.revision = 3;
        stale.state = MountResourceStateV1::Publishing {
            detached: detached(60, 160),
            publication: publication(None),
        };
        transition(&mut table, 2, &stale);
        stale.revision = 4;
        stale.state = MountResourceStateV1::Installed {
            detached: detached(60, 160),
            installed: installed(160),
            publication: publication(None),
        };
        transition(&mut table, 3, &stale);

        stale.revision = 5;
        stale.state = MountResourceStateV1::Faulted {
            from: MountFaultPhaseV1::Installed,
            creation: None,
            publication: Some(publication(None)),
            detachment: None,
            release: None,
            replaced_by: None,
            detached: Some(detached(60, 160)),
            installed: Some(installed(160)),
            failure_digest: [61; 32],
        };
        transition(&mut table, 4, &stale);

        let mut current = resource(62, 5, None);
        set_kernel_boot(&mut current, [11; 16]);
        allocate(&mut table, &current);
        current.revision = 2;
        current.state = MountResourceStateV1::Prepared {
            detached: detached(62, 162),
            creation: creation(),
        };
        transition(&mut table, 1, &current);
        current.revision = 3;
        current.state = MountResourceStateV1::Publishing {
            detached: detached(62, 162),
            publication: publication(None),
        };
        transition(&mut table, 2, &current);
    }

    #[test]
    fn cross_boot_replacement_pair_is_rejected() {
        let mut predecessor = resource(63, 4, None);
        predecessor.revision = 4;
        predecessor.state = MountResourceStateV1::Installed {
            detached: detached(63, 163),
            installed: installed(163),
            publication: publication(None),
        };

        let mut successor = resource(64, 5, None);
        set_kernel_boot(&mut successor, [11; 16]);
        successor.revision = 3;
        successor.state = MountResourceStateV1::Publishing {
            detached: detached(64, 164),
            publication: publication(Some(predecessor.handle)),
        };

        let resources = BTreeMap::from([
            (predecessor.handle, predecessor),
            (successor.handle, successor),
        ]);
        let malformed = MountResourceTableV1 {
            limits: MountResourceLimitsV1::default(),
            current_kernel_boot_id: [11; 16],
            resources,
            materialized_bytes: 0,
        };
        assert!(malformed.validate_table().is_err());
    }

    #[test]
    fn stale_nonterminal_install_cannot_hide_a_current_install() {
        let mut stale = resource(65, 4, None);
        stale.revision = 4;
        stale.state = MountResourceStateV1::Installed {
            detached: detached(65, 165),
            installed: installed(165),
            publication: publication(None),
        };

        let mut current = resource(66, 5, None);
        set_kernel_boot(&mut current, [11; 16]);
        current.revision = 4;
        current.state = MountResourceStateV1::Installed {
            detached: detached(66, 166),
            installed: installed(166),
            publication: publication(None),
        };

        let resources = BTreeMap::from([(stale.handle, stale), (current.handle, current)]);
        let malformed = MountResourceTableV1 {
            limits: MountResourceLimitsV1::default(),
            current_kernel_boot_id: [11; 16],
            resources,
            materialized_bytes: 0,
        };
        assert!(malformed.validate_table().is_err());
    }

    #[test]
    fn valid_stale_faulted_replacement_history_remains_reciprocal() {
        let (predecessor, successor) = stale_faulted_replacement_pair();
        table_with([predecessor, successor])
            .validate_table()
            .unwrap();
    }

    #[test]
    fn stale_faulted_replacement_history_rejects_dangling_edges() {
        let (predecessor, successor) = stale_faulted_replacement_pair();
        assert!(table_with([successor]).validate_table().is_err());
        assert!(table_with([predecessor]).validate_table().is_err());
    }

    #[test]
    fn stale_faulted_replacement_history_rejects_cross_boot_edges() {
        let (predecessor, mut successor) = stale_faulted_replacement_pair();
        set_kernel_boot(&mut successor, [8; 16]);
        assert!(
            table_with([predecessor, successor])
                .validate_table()
                .is_err()
        );
    }

    #[test]
    fn stale_faulted_replacement_cannot_link_to_unrelated_current_resource() {
        let (predecessor, mut successor) = stale_faulted_replacement_pair();
        let mut current = resource(74, 6, None);
        current.revision = 4;
        current.state = MountResourceStateV1::Installed {
            detached: detached(74, 174),
            installed: installed(174),
            publication: publication(None),
        };
        let MountResourceStateV1::Faulted { publication, .. } = &mut successor.state else {
            panic!("successor fixture must be faulted");
        };
        publication
            .as_mut()
            .unwrap_or_else(|| panic!("successor publication must exist"))
            .replaces = Some(current.handle);

        assert!(
            table_with([predecessor, successor, current])
                .validate_table()
                .is_err()
        );
    }

    #[test]
    fn dangling_replacement_edge_is_rejected_table_wide() {
        let mut table = table();
        let mut successor = resource(43, 5, None);
        successor.recipe.destination_slot_id = [43; 16];
        allocate(&mut table, &successor);
        successor.revision = 2;
        successor.state = MountResourceStateV1::Prepared {
            detached: detached(43, 143),
            creation: creation(),
        };
        transition(&mut table, 1, &successor);
        successor.revision = 3;
        successor.state = MountResourceStateV1::Publishing {
            detached: detached(43, 143),
            publication: publication(Some([99; 32])),
        };
        assert!(table.plan_transition(2, &successor).is_err());
    }

    #[test]
    fn mount_attributes_require_canonical_strict_order() {
        let mut duplicate = resource(35, 4, None);
        duplicate
            .recipe
            .policy
            .attributes
            .insert(1, OwnedMountAttributeV1::ReadOnly);
        assert!(table().plan_allocate(&duplicate).is_err());

        let mut reversed = resource(36, 4, None);
        reversed.recipe.policy.attributes.swap(0, 1);
        assert!(table().plan_allocate(&reversed).is_err());
    }

    #[test]
    fn view_descriptor_dto_enforces_registry_role_and_round_trips() {
        let dto = resource(37, 4, None).recipe.view_revision;
        let runtime = dto.to_runtime().unwrap();
        assert_eq!(ObjectDescriptorV1::from_runtime(&runtime).unwrap(), dto);

        let mut wrong_role = dto;
        wrong_role.media_type = PortableMediaType::Tree.as_str().to_owned();
        assert!(wrong_role.to_runtime().is_err());
    }

    #[test]
    fn mount_id_owner_domain_rejects_cross_role_owners() {
        let mut owners = BTreeMap::new();
        register_mount_id_owner(&mut owners, [1; 16], 138, [38; 32]).unwrap();
        assert!(register_mount_id_owner(&mut owners, [1; 16], 138, [39; 32]).is_err());
        register_mount_id_owner(&mut owners, [1; 16], 138, [38; 32]).unwrap();
        register_mount_id_owner(&mut owners, [2; 16], 138, [39; 32]).unwrap();
    }

    #[test]
    fn installed_publication_preserves_detached_unique_mount_id() {
        let mut table = table();
        let mut first = resource(38, 4, None);
        first.recipe.destination_slot_id = [38; 16];
        allocate(&mut table, &first);
        first.revision = 2;
        first.state = MountResourceStateV1::Prepared {
            detached: detached(38, 138),
            creation: creation(),
        };
        transition(&mut table, 1, &first);
        first.revision = 3;
        first.state = MountResourceStateV1::Publishing {
            detached: detached(38, 138),
            publication: publication(None),
        };
        transition(&mut table, 2, &first);
        first.revision = 4;
        first.state = MountResourceStateV1::Installed {
            detached: detached(38, 138),
            installed: installed(139),
            publication: publication(None),
        };
        assert!(table.plan_transition(3, &first).is_err());
    }

    #[test]
    fn ordinary_detach_has_durable_intent_before_release() {
        let mut table = table();
        let mut current = resource(42, 4, None);
        current.recipe.destination_slot_id = [42; 16];
        allocate(&mut table, &current);
        current.revision = 2;
        current.state = MountResourceStateV1::Prepared {
            detached: detached(42, 142),
            creation: creation(),
        };
        transition(&mut table, 1, &current);
        current.revision = 3;
        current.state = MountResourceStateV1::Publishing {
            detached: detached(42, 142),
            publication: publication(None),
        };
        transition(&mut table, 2, &current);
        current.revision = 4;
        current.state = MountResourceStateV1::Installed {
            detached: detached(42, 142),
            installed: installed(142),
            publication: publication(None),
        };
        transition(&mut table, 3, &current);
        current.revision = 5;
        current.state = MountResourceStateV1::Detaching {
            detached: detached(42, 142),
            installed: installed(142),
            detachment: creation(),
        };
        transition(&mut table, 4, &current);

        current.revision = 6;
        current.state = MountResourceStateV1::Released {
            last_detached_mount_id: Some(142),
            last_installed_mount_id: Some(142),
        };
        transition(&mut table, 5, &current);
    }

    #[test]
    fn replacement_requires_one_atomic_monotonic_pair() {
        let mut table = table();
        let mut old = resource(40, 4, None);
        allocate(&mut table, &old);
        old.revision = 2;
        old.state = MountResourceStateV1::Prepared {
            detached: detached(40, 140),
            creation: creation(),
        };
        transition(&mut table, 1, &old);
        old.revision = 3;
        old.state = MountResourceStateV1::Publishing {
            detached: detached(40, 140),
            publication: publication(None),
        };
        transition(&mut table, 2, &old);
        old.revision = 4;
        old.state = MountResourceStateV1::Installed {
            detached: detached(40, 140),
            installed: installed(140),
            publication: publication(None),
        };
        transition(&mut table, 3, &old);

        let mut new = resource(41, 5, Some(old.handle));
        allocate(&mut table, &new);
        new.revision = 2;
        new.state = MountResourceStateV1::Prepared {
            detached: detached(41, 141),
            creation: creation(),
        };
        transition(&mut table, 1, &new);
        new.revision = 3;
        new.state = MountResourceStateV1::Publishing {
            detached: detached(41, 141),
            publication: publication(Some(old.handle)),
        };
        transition(&mut table, 2, &new);

        let successor = MountResourceV1 {
            revision: 4,
            state: MountResourceStateV1::Installed {
                detached: detached(41, 141),
                installed: installed(141),
                publication: publication(Some(old.handle)),
            },
            ..new
        };
        assert!(table.plan_transition(3, &successor).is_err());

        let predecessor = MountResourceV1 {
            revision: 5,
            state: MountResourceStateV1::Draining {
                detached: detached(40, 140),
                installed: installed(140),
                replaced_by: successor.handle,
            },
            ..old
        };
        let records = table
            .plan_confirm_replacement(3, &successor, 4, &predecessor)
            .unwrap();
        assert_eq!(records.len(), 2);
        commit_planned(&mut table, &records);

        let retired_successor = MountResourceV1 {
            revision: 5,
            state: MountResourceStateV1::Installed {
                detached: detached(41, 141),
                installed: installed(141),
                publication: publication(None),
            },
            ..successor
        };
        let released_predecessor = MountResourceV1 {
            revision: 6,
            state: MountResourceStateV1::Released {
                last_detached_mount_id: Some(140),
                last_installed_mount_id: Some(140),
            },
            ..predecessor
        };
        let records = table
            .plan_finish_replacement(4, &retired_successor, 5, &released_predecessor)
            .unwrap();
        commit_planned(&mut table, &records);
    }

    #[test]
    fn descriptor_store_key_must_be_derived_from_handle() {
        let table = table();
        let mut redirected_key = resource(50, 4, None);
        redirected_key.fd_store_key = [51; 32];
        assert!(table.plan_allocate(&redirected_key).is_err());

        let mut sentinel_key = resource(50, 4, None);
        sentinel_key.fd_store_key = [0; 32];
        assert!(table.plan_allocate(&sentinel_key).is_err());
    }

    #[test]
    fn source_recipe_fields_are_validated_as_durable_identity() {
        let mut sentinel_generation = resource(51, 4, None);
        sentinel_generation.recipe.resource_attachment_generation = 0;

        assert!(table().plan_allocate(&sentinel_generation).is_err());

        let mut sentinel_view = resource(51, 4, None);
        sentinel_view.recipe.source_view_id = [0; 16];
        assert!(table().plan_allocate(&sentinel_view).is_err());

        let mut missing_incarnation = resource(51, 4, None);
        missing_incarnation.recipe.source_consistency = MountSourceConsistencyV1::LocalLive;
        assert!(table().plan_allocate(&missing_incarnation).is_err());

        let mut extraneous_incarnation = resource(51, 4, None);
        extraneous_incarnation.recipe.source_incarnation_id = Some([14; 16]);
        assert!(table().plan_allocate(&extraneous_incarnation).is_err());
    }

    #[test]
    fn descriptor_store_and_materialized_bounds_fail_closed() {
        let mut table = table();

        let first = resource(50, 4, None);
        allocate(&mut table, &first);
        let mut duplicate_key = resource(51, 4, None);
        duplicate_key.recipe.destination_slot_id = [51; 16];
        duplicate_key.fd_store_key = first.fd_store_key;
        assert!(table.plan_allocate(&duplicate_key).is_err());

        table.limits.materialized_bytes = 1;
        assert!(table.plan_allocate(&resource(52, 4, None)).is_err());
    }

    #[test]
    fn live_resource_bound_is_distinct_from_tombstone_history_bound() {
        let mut table = table();
        table.limits.live_resources = 1;
        let first = resource(52, 4, None);
        allocate(&mut table, &first);

        let mut second = resource(53, 4, None);
        second.recipe.destination_slot_id = [53; 16];
        assert!(table.plan_allocate(&second).is_err());

        let released = MountResourceV1 {
            revision: 2,
            state: MountResourceStateV1::Released {
                last_detached_mount_id: None,
                last_installed_mount_id: None,
            },
            ..first
        };
        transition(&mut table, 1, &released);
        allocate(&mut table, &second);
        assert_eq!(table.resources.len(), 2);
    }
}
