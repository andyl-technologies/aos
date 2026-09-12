//! Journal-backed source-realization authority and PID 1 custody.
//!
//! Mount persists source pins in the common checksummed journal. The closed
//! `AOSMSP01` envelope has no independent snapshot or mutable reference count;
//! references are derived from authenticated Mount resource phases. Mutations
//! return records for a caller-owned journal transaction so source and resource
//! state can advance atomically.
//!
//! Provider acquisition is deliberately absent in this stage. Production can
//! reopen already-admitted same-boot custody, but cannot manufacture provider
//! authority from a pathname, descriptor number, or journal row.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;

use aos_sandbox::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_linux::inventory::MountId;
use aos_sandbox_linux::path::ResolvedPath;
use aos_sandbox_protocol::{
    MountSourcePhysicalProofV1, MountSourceProviderHistoryV1, SourceRealizationBindingV1,
    mount_source_physical_proof_digest_v1, mount_source_provider_history_is_valid_v1,
    mount_source_realization_handle_v1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::broker::fault_stale_boot_resources;
use crate::keeper::{SourceCustodyEvidence, SourceDescriptorStore, SourcePinName};
use crate::state::mount_resource_v1::{
    MountResourceLimitsV1, MountResourceStateV1, MountResourceTableV1, MountResourceV1,
};
use crate::{MountError, Result};

const SCHEMA: &str = "AOSMSP01";
const FORMAT_VERSION: u16 = 1;
const KEY_PREFIX: &[u8] = b"aos.mount.source-pin.v1\0";
const MAXIMUM_BINDING_BYTES: usize = 64 * 1024;
const MAXIMUM_VALUE_BYTES: usize = 128 * 1024;

/// Maximum source-realization tombstones retained by one Mount journal.
pub const MAXIMUM_SOURCE_PINS: usize = 1_024;

/// Opaque Mount-minted identity of one physical source realization.
pub(crate) type SourceRealizationHandleV1 = [u8; 32];

/// Carries durable recipe fields extracted from an authenticated realization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRealizationEvidenceV1 {
    pub(crate) handle: SourceRealizationHandleV1,
    pub(crate) physical_proof_digest: [u8; 32],
    pub(crate) unique_mount_id: u64,
    pub(crate) provider_authority_digest: [u8; 32],
    pub(crate) provider_authority_id: [u8; 16],
    pub(crate) provider_authority_generation: u64,
    pub(crate) provider_resource_id: [u8; 32],
    pub(crate) provider_resource_generation: u64,
    pub(crate) provider_resource_digest: [u8; 32],
    pub(crate) provider_catalog_generation: u64,
    pub(crate) provider_catalog_digest: [u8; 32],
    pub(crate) kernel_boot_id: [u8; 16],
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) proof_class: SourcePinProofClassV1,
}

impl SourceRealizationEvidenceV1 {
    /// Verifies that Mount, rather than a provider or caller, derived the handle.
    pub(crate) fn validate_for_binding(self, binding: &SourceRealizationBindingV1) -> Result<()> {
        SourcePinRowV1::active(binding, self, [1; 16], [1; 32]).map(|_| ())
    }
}

pub(crate) use aos_sandbox_protocol::MountSourceProofClassV1 as SourcePinProofClassV1;

/// Records the durable lifecycle of one realization handle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourcePinLifecycleV1 {
    /// PID 1 custody exists and Mount resources may reference the pin.
    Active,
    /// New references are forbidden and acknowledged removal is pending.
    Reaping,
    /// Removal was acknowledged; the row remains as an anti-replay tombstone.
    Released,
}

/// Persists exact logical, provider, physical, and admission authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourcePinRowV1 {
    pub(crate) handle: SourceRealizationHandleV1,
    pub(crate) revision: u64,
    pub(crate) binding_bytes: Vec<u8>,
    pub(crate) binding_digest: [u8; 32],
    pub(crate) proof_class: SourcePinProofClassV1,
    pub(crate) provider_authority_id: [u8; 16],
    pub(crate) provider_authority_generation: u64,
    pub(crate) provider_authority_digest: [u8; 32],
    pub(crate) provider_resource_id: [u8; 32],
    pub(crate) provider_resource_generation: u64,
    pub(crate) provider_resource_digest: [u8; 32],
    pub(crate) provider_catalog_generation: u64,
    pub(crate) provider_catalog_digest: [u8; 32],
    pub(crate) kernel_boot_id: [u8; 16],
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) unique_mount_id: u64,
    pub(crate) physical_proof_digest: [u8; 32],
    pub(crate) admission_operation_id: [u8; 16],
    pub(crate) admission_request_digest: [u8; 32],
    pub(crate) current: bool,
    pub(crate) lifecycle: SourcePinLifecycleV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSourcePinV1 {
    schema: String,
    version: u16,
    row: SourcePinRowV1,
}

/// Materializes the bounded source-pin keyspace in the common Mount journal.
#[derive(Debug)]
pub struct SourcePinTableV1 {
    rows: BTreeMap<SourceRealizationHandleV1, SourcePinRowV1>,
    current_kernel_boot_id: [u8; 16],
}

impl SourcePinTableV1 {
    /// Reconstructs and validates every `AOSMSP01` row.
    ///
    /// # Errors
    ///
    /// Returns an error for a corrupt, unsupported, non-canonical, aliased, or
    /// over-limit source-pin table or a sentinel current boot identity.
    pub fn recover(journal: &Journal, current_kernel_boot_id: [u8; 16]) -> Result<Self> {
        if current_kernel_boot_id == [0; 16] {
            return Err(state_error("current kernel boot identity is a sentinel"));
        }

        let mut rows = BTreeMap::new();
        for (key, value) in journal.records(RecordNamespace::MountSourcePin) {
            let (binding_digest, handle) = decode_key(key)?;
            let row = decode_value(value)?;
            if row.binding_digest != binding_digest
                || row.handle != handle
                || rows.insert(handle, row).is_some()
            {
                return Err(state_error("source-pin key and row identity disagree"));
            }
        }
        let table = Self {
            rows,
            current_kernel_boot_id,
        };
        table.validate_table()?;
        Ok(table)
    }

    /// Returns rows in canonical realization-handle order.
    pub(crate) fn rows(&self) -> impl Iterator<Item = &SourcePinRowV1> {
        self.rows.values()
    }

    /// Returns one exact realization row.
    pub(crate) fn get(&self, handle: &SourceRealizationHandleV1) -> Option<&SourcePinRowV1> {
        self.rows.get(handle)
    }

    /// Returns the sole current realization for a logical binding.
    pub(crate) fn current_handle(&self, binding_digest: [u8; 32]) -> Option<[u8; 32]> {
        self.rows
            .values()
            .find(|row| row.binding_digest == binding_digest && row.current)
            .map(|row| row.handle)
    }

    /// Reports whether a pin is eligible to reap once its final reference ends.
    pub(crate) fn is_noncurrent_active(&self, handle: [u8; 32]) -> bool {
        self.rows
            .get(&handle)
            .is_some_and(|row| row.lifecycle == SourcePinLifecycleV1::Active && !row.current)
    }

    /// Returns pending source removals in canonical handle order.
    pub(crate) fn reaping_handles(&self) -> impl Iterator<Item = SourceRealizationHandleV1> + '_ {
        self.rows
            .values()
            .filter(|row| row.lifecycle == SourcePinLifecycleV1::Reaping)
            .map(|row| row.handle)
    }

    /// Validates reuse of an existing current realization by another resource.
    pub(crate) fn validate_existing_reference(
        &self,
        binding: &SourceRealizationBindingV1,
        evidence: SourceRealizationEvidenceV1,
    ) -> Result<()> {
        let row = self
            .rows
            .get(&evidence.handle)
            .ok_or_else(|| state_error("source realization handle is absent"))?;
        if row.lifecycle != SourcePinLifecycleV1::Active
            || !row.current
            || row.binding_bytes != binding.canonical_bytes()
            || row.binding_digest != *binding.digest().as_bytes()
            || row.evidence() != evidence
        {
            return Err(state_error(
                "existing source realization evidence equivocated",
            ));
        }
        Ok(())
    }

    /// Validates that every live Mount resource references one exact Active pin.
    pub(crate) fn validate_resource_references(
        &self,
        resources: &MountResourceTableV1,
    ) -> Result<()> {
        self.validate_resource_references_inner(resources, true)
    }

    pub(crate) fn validate_resource_references_before_reboot_repair(
        &self,
        resources: &MountResourceTableV1,
    ) -> Result<()> {
        self.validate_resource_references_inner(resources, false)
    }

    fn validate_resource_references_inner(
        &self,
        resources: &MountResourceTableV1,
        require_current_boot: bool,
    ) -> Result<()> {
        let references = resources.source_realization_references()?;
        for (handle, count) in references {
            let row = self.rows.get(&handle).ok_or_else(|| {
                state_error("live Mount resource references an absent source pin")
            })?;
            if count == 0 || row.lifecycle != SourcePinLifecycleV1::Active {
                return Err(state_error(
                    "live Mount resource references a non-Active source pin",
                ));
            }
            if require_current_boot && row.kernel_boot_id != self.current_kernel_boot_id {
                return Err(state_error(
                    "live Mount resource references a wrong-boot source pin",
                ));
            }
        }
        for resource in resources
            .resources()
            .filter(|resource| resource.retains_source_reference())
        {
            let row = self
                .rows
                .get(&resource.recipe.source_realization_handle)
                .ok_or_else(|| state_error("live resource source-pin row disappeared"))?;
            let stale_resource_still_retains_source = !require_current_boot
                && resource.kernel_boot_id != self.current_kernel_boot_id
                && !matches!(
                    resource.state,
                    MountResourceStateV1::Faulted { .. } | MountResourceStateV1::Released { .. }
                );
            if stale_resource_still_retains_source && row.lifecycle != SourcePinLifecycleV1::Active
            {
                return Err(state_error(
                    "wrong-boot retained resource references a non-Active source pin",
                ));
            }
            if resource.recipe.source_binding_digest != row.binding_digest
                || resource.recipe.source_physical_proof_digest != row.physical_proof_digest
                || resource.recipe.source_kernel_boot_id != row.kernel_boot_id
                || resource.recipe.source_device != row.device
                || resource.recipe.source_inode != row.inode
                || resource.recipe.source_proof_class != row.proof_class
                || resource.recipe.source_unique_mount_id != row.unique_mount_id
                || resource.recipe.source_provider_authority_id != row.provider_authority_id
                || resource.recipe.source_provider_authority_generation
                    != row.provider_authority_generation
                || resource.recipe.source_provider_authority_digest != row.provider_authority_digest
                || resource.recipe.source_provider_resource_id != row.provider_resource_id
                || resource.recipe.source_provider_resource_generation
                    != row.provider_resource_generation
                || resource.recipe.source_provider_resource_digest != row.provider_resource_digest
                || resource.recipe.source_provider_catalog_generation
                    != row.provider_catalog_generation
                || resource.recipe.source_provider_catalog_digest != row.provider_catalog_digest
            {
                return Err(state_error(
                    "live Mount resource recipe differs from its source pin",
                ));
            }
        }
        Ok(())
    }

    /// Plans atomic pin activation and Mount resource allocation.
    pub(crate) fn plan_activate_with_resource(
        &self,
        resources: &MountResourceTableV1,
        row: &SourcePinRowV1,
        expected_current: Option<SourceRealizationHandleV1>,
        resource: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        if resource.recipe.source_realization_handle != row.handle
            || resource.recipe.source_binding_digest != row.binding_digest
            || resource.recipe.source_physical_proof_digest != row.physical_proof_digest
            || resource.recipe.source_kernel_boot_id != row.kernel_boot_id
            || resource.recipe.source_device != row.device
            || resource.recipe.source_inode != row.inode
            || resource.recipe.source_proof_class != row.proof_class
            || resource.recipe.source_unique_mount_id != row.unique_mount_id
            || resource.recipe.source_provider_authority_id != row.provider_authority_id
            || resource.recipe.source_provider_authority_generation
                != row.provider_authority_generation
            || resource.recipe.source_provider_authority_digest != row.provider_authority_digest
            || resource.recipe.source_provider_resource_id != row.provider_resource_id
            || resource.recipe.source_provider_resource_generation
                != row.provider_resource_generation
            || resource.recipe.source_provider_resource_digest != row.provider_resource_digest
            || resource.recipe.source_provider_catalog_generation != row.provider_catalog_generation
            || resource.recipe.source_provider_catalog_digest != row.provider_catalog_digest
        {
            return Err(state_error(
                "Mount resource recipe differs from source-pin admission",
            ));
        }

        let mut records = self.plan_activation(
            row,
            expected_current,
            Some(resources.source_realization_references()?),
        )?;
        records.extend(resources.plan_allocate(resource)?);
        Ok(records)
    }

    /// Plans a binding-current CAS and activation without committing it.
    ///
    /// Cutover demotes the old row and activates the new row in one transaction.
    /// Old resources can continue referencing the non-current Active row.
    #[cfg(test)]
    pub(crate) fn plan_activate(
        &self,
        row: &SourcePinRowV1,
        expected_current: Option<SourceRealizationHandleV1>,
    ) -> Result<Vec<JournalRecord>> {
        self.plan_activation(row, expected_current, None)
    }

    fn plan_activation(
        &self,
        row: &SourcePinRowV1,
        expected_current: Option<SourceRealizationHandleV1>,
        references: Option<BTreeMap<SourceRealizationHandleV1, usize>>,
    ) -> Result<Vec<JournalRecord>> {
        row.validate()?;
        if row.lifecycle != SourcePinLifecycleV1::Active || !row.current || row.revision != 1 {
            return Err(state_error(
                "new source pin is not a fresh current Active row",
            ));
        }
        if self.rows.len() >= MAXIMUM_SOURCE_PINS || self.rows.contains_key(&row.handle) {
            return Err(state_error("source-pin handle is not fresh"));
        }
        if row.kernel_boot_id != self.current_kernel_boot_id {
            return Err(state_error(
                "source-pin admission evidence belongs to another kernel boot",
            ));
        }
        self.validate_provider_progress(row)?;
        self.reject_physical_alias(row)?;

        let current = self
            .rows
            .values()
            .find(|candidate| candidate.binding_digest == row.binding_digest && candidate.current);
        if current.map(|candidate| candidate.handle) != expected_current {
            return Err(state_error("source-pin current realization CAS failed"));
        }

        let mut records = Vec::with_capacity(2);
        if let Some(current) = current {
            let mut demoted = current.clone();
            demoted.revision = next_revision(current.revision)?;
            demoted.current = false;
            if references
                .as_ref()
                .is_some_and(|counts| !counts.contains_key(&current.handle))
            {
                demoted.lifecycle = SourcePinLifecycleV1::Reaping;
            }
            records.push(put_record(&demoted)?);
        }
        records.push(put_record(row)?);

        let mut candidate = self.rows.clone();
        apply_rows(&mut candidate, &records)?;
        validate_rows(&candidate)?;
        Ok(records)
    }

    /// Plans atomic last-resource release and source transition to Reaping.
    #[cfg(test)]
    pub(crate) fn plan_release_with_reaping(
        &self,
        resources: &MountResourceTableV1,
        expected_resource_revision: u64,
        released_resource: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        let reaping =
            self.plan_reaping_after_release_if_last_reference(resources, released_resource)?;
        if reaping.is_empty() {
            return Err(state_error(
                "source pin can enter Reaping only with its atomic last release",
            ));
        }

        let mut records =
            resources.plan_transition(expected_resource_revision, released_resource)?;
        records.extend(reaping);
        Ok(records)
    }

    /// Plans retirement when an accompanying resource update removes the last reference.
    pub(crate) fn plan_reaping_after_release_if_last_reference(
        &self,
        resources: &MountResourceTableV1,
        released_resource: &MountResourceV1,
    ) -> Result<Vec<JournalRecord>> {
        let handle = released_resource.recipe.source_realization_handle;
        if released_resource.retains_source_reference() {
            return Err(state_error(
                "source retirement must accompany a resource release",
            ));
        }

        let references = resources.source_realization_references()?;
        let Some(reference_count) = references.get(&handle) else {
            return Err(state_error("release references an unreferenced source pin"));
        };
        if *reference_count > 1 {
            return Ok(Vec::new());
        }

        let current = self
            .rows
            .get(&handle)
            .ok_or_else(|| state_error("last release references an absent source pin"))?;
        if current.lifecycle != SourcePinLifecycleV1::Active || current.current {
            return Err(state_error(
                "current or non-Active source pin cannot begin retirement",
            ));
        }

        let mut reaping = current.clone();
        reaping.revision = next_revision(current.revision)?;
        reaping.lifecycle = SourcePinLifecycleV1::Reaping;
        Ok(vec![put_record(&reaping)?])
    }

    /// Plans a Reaping-to-Released tombstone after acknowledged PID 1 removal.
    pub(crate) fn plan_finish_reaping(
        &self,
        handle: SourceRealizationHandleV1,
    ) -> Result<Vec<JournalRecord>> {
        let current = self
            .rows
            .get(&handle)
            .ok_or_else(|| state_error("source-pin handle is unknown"))?;
        if current.lifecycle != SourcePinLifecycleV1::Reaping || current.current {
            return Err(state_error("source pin is not a non-current Reaping row"));
        }
        let mut released = current.clone();
        released.revision = next_revision(current.revision)?;
        released.lifecycle = SourcePinLifecycleV1::Released;
        Ok(vec![put_record(&released)?])
    }

    fn plan_recovery_reaping(
        &self,
        references: &BTreeMap<SourceRealizationHandleV1, usize>,
    ) -> Result<Vec<JournalRecord>> {
        let mut records = Vec::new();
        for row in self.rows.values().filter(|row| {
            row.lifecycle == SourcePinLifecycleV1::Active
                && (row.kernel_boot_id != self.current_kernel_boot_id
                    || (!row.current && !references.contains_key(&row.handle)))
        }) {
            if references.contains_key(&row.handle) {
                return Err(state_error(
                    "wrong-boot source pin retains a current-boot resource reference",
                ));
            }
            let mut reaping = row.clone();
            reaping.revision = next_revision(row.revision)?;
            reaping.current = false;
            reaping.lifecycle = SourcePinLifecycleV1::Reaping;
            records.push(put_record(&reaping)?);
        }
        let mut candidate = self.rows.clone();
        apply_rows(&mut candidate, &records)?;
        validate_rows(&candidate)?;
        validate_provider_history(&candidate)?;
        Ok(records)
    }

    /// Applies source-pin records after their containing transaction commits.
    pub(crate) fn apply_committed(&mut self, records: &[JournalRecord]) -> Result<()> {
        let source_records: Vec<_> = records
            .iter()
            .filter(|record| record.namespace() == RecordNamespace::MountSourcePin)
            .cloned()
            .collect();
        if source_records.is_empty() {
            return Err(state_error("transaction contains no source-pin mutation"));
        }
        let mut candidate = self.rows.clone();
        apply_rows(&mut candidate, &source_records)?;
        validate_rows(&candidate)?;
        self.rows = candidate;
        Ok(())
    }

    fn reject_physical_alias(&self, proposed: &SourcePinRowV1) -> Result<()> {
        let alias = self.rows.values().any(|row| {
            row.lifecycle != SourcePinLifecycleV1::Released
                && row.kernel_boot_id == proposed.kernel_boot_id
                && (row.unique_mount_id == proposed.unique_mount_id
                    || (row.device, row.inode) == (proposed.device, proposed.inode))
        });
        if alias {
            return Err(state_error(
                "physical source realization is already assigned to another handle",
            ));
        }
        Ok(())
    }

    fn validate_provider_progress(&self, proposed: &SourcePinRowV1) -> Result<()> {
        let history: Vec<_> = self
            .rows
            .values()
            .map(provider_history)
            .chain(std::iter::once(provider_history(proposed)))
            .collect();
        if !mount_source_provider_history_is_valid_v1(&history) {
            return Err(state_error(
                "source provider history rolled back or equivocated",
            ));
        }

        // Released rows are permanent anti-rollback evidence, not reusable capacity.
        for row in self
            .rows
            .values()
            .filter(|row| row.provider_authority_id == proposed.provider_authority_id)
        {
            if proposed.provider_authority_generation < row.provider_authority_generation
                || proposed.provider_catalog_generation < row.provider_catalog_generation
                || (proposed.provider_authority_generation == row.provider_authority_generation
                    && proposed.provider_authority_digest != row.provider_authority_digest)
                || (proposed.provider_catalog_generation == row.provider_catalog_generation
                    && proposed.provider_catalog_digest != row.provider_catalog_digest)
            {
                return Err(state_error(
                    "source provider authority or catalog rolled back or equivocated",
                ));
            }
            if row.provider_resource_id == proposed.provider_resource_id
                && (proposed.provider_resource_generation < row.provider_resource_generation
                    || (proposed.provider_resource_generation == row.provider_resource_generation
                        && (proposed.provider_resource_digest != row.provider_resource_digest
                            || proposed.physical_proof_digest != row.physical_proof_digest)))
            {
                return Err(state_error(
                    "source provider resource rolled back or equivocated",
                ));
            }
        }
        Ok(())
    }

    fn validate_table(&self) -> Result<()> {
        if self.rows.len() > MAXIMUM_SOURCE_PINS {
            return Err(state_error("source-pin table exceeds its fixed bound"));
        }
        validate_rows(&self.rows)?;
        validate_provider_history(&self.rows)
    }
}

fn validate_provider_history(
    rows: &BTreeMap<SourceRealizationHandleV1, SourcePinRowV1>,
) -> Result<()> {
    let values: Vec<_> = rows.values().collect();
    let history: Vec<_> = rows.values().map(provider_history).collect();
    if !mount_source_provider_history_is_valid_v1(&history) {
        return Err(state_error(
            "recovered source provider history rolled back or equivocated",
        ));
    }
    for current in values.iter().copied().filter(|row| row.current) {
        for predecessor in values.iter().copied().filter(|row| {
            row.handle != current.handle && row.binding_digest == current.binding_digest
        }) {
            if current.provider_authority_id == predecessor.provider_authority_id
                && (current.provider_authority_generation
                    < predecessor.provider_authority_generation
                    || current.provider_catalog_generation
                        < predecessor.provider_catalog_generation
                    || (current.provider_resource_id == predecessor.provider_resource_id
                        && current.provider_resource_generation
                            < predecessor.provider_resource_generation))
            {
                return Err(state_error(
                    "recovered current source provider generation rolled back within its binding",
                ));
            }
        }
    }
    Ok(())
}

fn provider_history(row: &SourcePinRowV1) -> MountSourceProviderHistoryV1 {
    MountSourceProviderHistoryV1 {
        authority_id: row.provider_authority_id,
        authority_generation: row.provider_authority_generation,
        authority_digest: row.provider_authority_digest,
        resource_id: row.provider_resource_id,
        resource_generation: row.provider_resource_generation,
        resource_digest: row.provider_resource_digest,
        catalog_generation: row.provider_catalog_generation,
        catalog_digest: row.provider_catalog_digest,
        physical_proof_digest: row.physical_proof_digest,
    }
}

impl SourcePinRowV1 {
    /// Constructs the sole Mount-owned Active row from authenticated evidence.
    pub(crate) fn active(
        binding: &SourceRealizationBindingV1,
        evidence: SourceRealizationEvidenceV1,
        admission_operation_id: [u8; 16],
        admission_request_digest: [u8; 32],
    ) -> Result<Self> {
        let row = Self {
            handle: evidence.handle,
            revision: 1,
            binding_bytes: binding.canonical_bytes(),
            binding_digest: *binding.digest().as_bytes(),
            proof_class: evidence.proof_class,
            provider_authority_id: evidence.provider_authority_id,
            provider_authority_generation: evidence.provider_authority_generation,
            provider_authority_digest: evidence.provider_authority_digest,
            provider_resource_id: evidence.provider_resource_id,
            provider_resource_generation: evidence.provider_resource_generation,
            provider_resource_digest: evidence.provider_resource_digest,
            provider_catalog_generation: evidence.provider_catalog_generation,
            provider_catalog_digest: evidence.provider_catalog_digest,
            kernel_boot_id: evidence.kernel_boot_id,
            device: evidence.device,
            inode: evidence.inode,
            unique_mount_id: evidence.unique_mount_id,
            physical_proof_digest: evidence.physical_proof_digest,
            admission_operation_id,
            admission_request_digest,
            current: true,
            lifecycle: SourcePinLifecycleV1::Active,
        };
        row.validate()?;
        Ok(row)
    }

    fn validate(&self) -> Result<()> {
        if self.handle == [0; 32]
            || self.binding_bytes.is_empty()
            || self.binding_bytes.len() > MAXIMUM_BINDING_BYTES
            || self.binding_digest == [0; 32]
            || self.provider_authority_id == [0; 16]
            || self.provider_authority_generation == 0
            || self.provider_authority_digest == [0; 32]
            || self.provider_resource_id == [0; 32]
            || self.provider_resource_generation == 0
            || self.provider_resource_digest == [0; 32]
            || self.provider_catalog_generation == 0
            || self.provider_catalog_digest == [0; 32]
            || self.kernel_boot_id == [0; 16]
            || self.device == 0
            || self.inode == 0
            || self.unique_mount_id == 0
            || self.physical_proof_digest == [0; 32]
            || self.admission_operation_id == [0; 16]
            || self.admission_request_digest == [0; 32]
        {
            return Err(state_error(
                "source-pin row contains a sentinel or invalid bound",
            ));
        }
        let binding = SourceRealizationBindingV1::from_canonical_bytes(&self.binding_bytes)
            .map_err(|error| state_error(error.to_string()))?;
        if binding.canonical_bytes() != self.binding_bytes
            || binding.digest().as_bytes() != &self.binding_digest
        {
            return Err(state_error(
                "source-pin binding bytes or digest are not canonical",
            ));
        }
        if proof_class_for_binding(&binding)? != self.proof_class {
            return Err(state_error(
                "source-pin proof class contradicts its logical binding",
            ));
        }
        if physical_proof_digest(self) != self.physical_proof_digest {
            return Err(state_error(
                "source-pin physical proof digest does not reproduce",
            ));
        }
        if mount_minted_handle(self) != self.handle {
            return Err(state_error(
                "source-pin handle is not the Mount-minted identity",
            ));
        }
        if self.current && self.lifecycle != SourcePinLifecycleV1::Active {
            return Err(state_error("only an Active source pin may be current"));
        }
        let canonical_lifecycle_revision = matches!(
            (self.lifecycle, self.current, self.revision),
            (SourcePinLifecycleV1::Active, true, 1)
                | (SourcePinLifecycleV1::Active, false, 2)
                | (SourcePinLifecycleV1::Reaping, false, 2 | 3)
                | (SourcePinLifecycleV1::Released, false, 3 | 4)
        );
        if !canonical_lifecycle_revision {
            return Err(state_error(
                "source-pin lifecycle and revision are not constructible",
            ));
        }
        Ok(())
    }

    fn evidence(&self) -> SourceRealizationEvidenceV1 {
        SourceRealizationEvidenceV1 {
            handle: self.handle,
            physical_proof_digest: self.physical_proof_digest,
            unique_mount_id: self.unique_mount_id,
            provider_authority_digest: self.provider_authority_digest,
            provider_authority_id: self.provider_authority_id,
            provider_authority_generation: self.provider_authority_generation,
            provider_resource_id: self.provider_resource_id,
            provider_resource_generation: self.provider_resource_generation,
            provider_resource_digest: self.provider_resource_digest,
            provider_catalog_generation: self.provider_catalog_generation,
            provider_catalog_digest: self.provider_catalog_digest,
            kernel_boot_id: self.kernel_boot_id,
            device: self.device,
            inode: self.inode,
            proof_class: self.proof_class,
        }
    }
}

#[cfg(test)]
impl SourceRealizationEvidenceV1 {
    pub(crate) fn authenticated_fixture(
        binding: &SourceRealizationBindingV1,
        seed: u8,
        kernel_boot_id: [u8; 16],
    ) -> Result<Self> {
        let binding_digest = *binding.digest().as_bytes();
        let mut identity_bytes = [0; 8];
        identity_bytes.copy_from_slice(&binding_digest[..8]);
        let identity = u64::from_be_bytes(identity_bytes);
        let mut row = SourcePinRowV1 {
            handle: [0; 32],
            revision: 1,
            binding_bytes: binding.canonical_bytes(),
            binding_digest,
            proof_class: proof_class_for_binding(binding)?,
            provider_authority_id: [80; 16],
            provider_authority_generation: u64::from(seed) + 4,
            provider_authority_digest: [seed; 32],
            provider_resource_id: binding_digest,
            provider_resource_generation: u64::from(seed) + 2,
            provider_resource_digest: [seed.wrapping_add(1); 32],
            provider_catalog_generation: u64::from(seed) + 3,
            provider_catalog_digest: [seed.wrapping_add(2); 32],
            kernel_boot_id,
            device: 83,
            inode: identity.wrapping_add(u64::from(seed)).max(1),
            unique_mount_id: identity
                .rotate_left(17)
                .wrapping_add(u64::from(seed))
                .max(1),
            physical_proof_digest: [0; 32],
            admission_operation_id: [16; 16],
            admission_request_digest: [17; 32],
            current: true,
            lifecycle: SourcePinLifecycleV1::Active,
        };
        row.physical_proof_digest = physical_proof_digest(&row);
        row.handle = mount_minted_handle(&row);
        Ok(row.evidence())
    }
}

/// Owns one reopened and completely reauthenticated source descriptor.
#[derive(Debug)]
pub struct ResolvedSourcePin {
    source: ResolvedPath,
    handle: SourceRealizationHandleV1,
    physical_proof_digest: [u8; 32],
    unique_mount_id: u64,
    provider_catalog_generation: u64,
    provider_catalog_digest: [u8; 32],
    provider_resource_id: [u8; 32],
    provider_resource_generation: u64,
    provider_resource_digest: [u8; 32],
    provider_authority_digest: [u8; 32],
    provider_authority_id: [u8; 16],
    provider_authority_generation: u64,
    kernel_boot_id: [u8; 16],
    device: u64,
    inode: u64,
    proof_class: SourcePinProofClassV1,
}

impl ResolvedSourcePin {
    /// Returns the pinned source descriptor used only for CREATE cloning.
    #[must_use]
    pub const fn source(&self) -> &ResolvedPath {
        &self.source
    }

    /// Returns the Mount-minted physical realization handle.
    #[must_use]
    pub const fn handle(&self) -> SourceRealizationHandleV1 {
        self.handle
    }

    /// Returns the complete physical proof digest.
    #[must_use]
    pub const fn physical_proof_digest(&self) -> [u8; 32] {
        self.physical_proof_digest
    }

    /// Returns the source's kernel-lifetime unique mount ID.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }

    /// Returns the exact provider and physical evidence persisted in recipes.
    #[must_use]
    pub(crate) const fn evidence(&self) -> SourceRealizationEvidenceV1 {
        SourceRealizationEvidenceV1 {
            handle: self.handle,
            physical_proof_digest: self.physical_proof_digest,
            unique_mount_id: self.unique_mount_id,
            provider_authority_digest: self.provider_authority_digest,
            provider_authority_id: self.provider_authority_id,
            provider_authority_generation: self.provider_authority_generation,
            provider_resource_id: self.provider_resource_id,
            provider_resource_generation: self.provider_resource_generation,
            provider_resource_digest: self.provider_resource_digest,
            provider_catalog_generation: self.provider_catalog_generation,
            provider_catalog_digest: self.provider_catalog_digest,
            kernel_boot_id: self.kernel_boot_id,
            device: self.device,
            inode: self.inode,
            proof_class: self.proof_class,
        }
    }

    /// Consumes the proof wrapper and returns its source descriptor.
    #[must_use]
    pub fn into_source(self) -> ResolvedPath {
        self.source
    }
}

/// Resolves only previously authenticated journal-backed source custody.
pub(crate) trait SourcePinResolver {
    /// Reopens the exact current Active realization for a logical binding.
    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin>;
}

/// Rejects resolution because provider acquisition is not configured.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableSourcePins;

impl SourcePinResolver for UnavailableSourcePins {
    fn resolve(&self, _binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        Err(MountError::Worker(
            "no authenticated filesystem-view source realization is available".to_owned(),
        ))
    }
}

/// Supplies one self-consistent authenticated source fixture to crate tests.
#[cfg(all(test, feature = "kernel-tests"))]
pub(crate) struct FixtureSourcePins {
    binding: SourceRealizationBindingV1,
    row: SourcePinRowV1,
    source: ResolvedPath,
}

#[cfg(all(test, feature = "kernel-tests"))]
impl FixtureSourcePins {
    pub(crate) fn new(
        binding: SourceRealizationBindingV1,
        source: ResolvedPath,
        kernel_boot_id: [u8; 16],
    ) -> Result<Self> {
        let identity = source.identity();
        if identity.file_type != aos_sandbox_linux::path::FileType::Directory {
            return Err(state_error("source realization is not a directory"));
        }
        let unique_mount_id = MountId::from_fd(source.as_fd())
            .map_err(|error| MountError::Worker(error.to_string()))?
            .get();
        let mut row = SourcePinRowV1 {
            handle: [0; 32],
            revision: 1,
            binding_bytes: binding.canonical_bytes(),
            binding_digest: *binding.digest().as_bytes(),
            proof_class: proof_class_for_binding(&binding)?,
            provider_authority_id: [91; 16],
            provider_authority_generation: 92,
            provider_authority_digest: [93; 32],
            provider_resource_id: *binding.digest().as_bytes(),
            provider_resource_generation: 94,
            provider_resource_digest: [95; 32],
            provider_catalog_generation: 96,
            provider_catalog_digest: [97; 32],
            kernel_boot_id,
            device: identity.device,
            inode: identity.inode,
            unique_mount_id,
            physical_proof_digest: [0; 32],
            admission_operation_id: [98; 16],
            admission_request_digest: [99; 32],
            current: true,
            lifecycle: SourcePinLifecycleV1::Active,
        };
        row.physical_proof_digest = physical_proof_digest(&row);
        row.handle = mount_minted_handle(&row);
        row.validate()?;
        Ok(Self {
            binding,
            row,
            source,
        })
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
impl SourcePinResolver for FixtureSourcePins {
    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        if binding != &self.binding {
            return Err(state_error("fixture source binding differs from request"));
        }
        verify_reopened(&self.row, &self.source)?;
        Ok(resolved_source_pin(
            &self.row,
            duplicate_resolved(&self.source)?,
        ))
    }
}

/// Reopens exact same-boot Active rows from authenticated PID 1 descriptors.
///
/// Recovery is available only through [`recover_source_custody`], which first
/// authenticates the source and resource tables and validates their complete
/// cross-table relationship. The mutation-capable reconciliation helper is not
/// part of the public API:
///
/// ```compile_fail
/// use std::collections::BTreeMap;
///
/// use aos_sandbox::journal::Journal;
/// use aos_sandbox_linux::path::ResolvedPath;
/// use aos_sandbox_mount::keeper::{SourcePinName, SystemdFdStore};
/// use aos_sandbox_mount::source_pin::{ReopenedSourcePins, SourcePinTableV1};
///
/// fn bypass_preflight(
///     journal: &mut Journal,
///     table: &mut SourcePinTableV1,
///     descriptors: BTreeMap<SourcePinName, ResolvedPath>,
///     keeper: &SystemdFdStore,
/// ) {
///     let _ = ReopenedSourcePins::reconcile_preflighted(
///         journal,
///         table,
///         descriptors,
///         keeper,
///     );
/// }
/// ```
#[derive(Debug)]
pub struct ReopenedSourcePins {
    current_rows: BTreeMap<[u8; 32], SourcePinRowV1>,
    descriptors: BTreeMap<SourceRealizationHandleV1, ResolvedPath>,
}

/// Reconciles durable resources and PID 1 source custody during daemon startup.
///
/// Wrong-boot resources are faulted before source references are derived. Their
/// now-unreferenced pins are transitioned through Reaping and acknowledged
/// keeper removal instead of preventing the daemon from serving inventory and
/// cleanup after a host reboot.
///
/// # Errors
///
/// Returns an error for corrupt or equivocal journal state, inconsistent live
/// references, invalid custody, or ambiguous journal/keeper mutations.
pub fn recover_source_custody<K: SourceDescriptorStore>(
    journal: &mut Journal,
    descriptors: BTreeMap<SourcePinName, ResolvedPath>,
    keeper: &K,
    current_kernel_boot_id: [u8; 16],
) -> Result<ReopenedSourcePins> {
    // Authenticate the complete source table before stale-resource repair can
    // write anything to the journal. A corrupt provider history must leave the
    // pre-recovery journal byte-exact.
    let mut table = SourcePinTableV1::recover(journal, current_kernel_boot_id)?;
    let mut resources = MountResourceTableV1::recover(
        journal,
        MountResourceLimitsV1::default(),
        current_kernel_boot_id,
    )?;
    table.validate_resource_references_before_reboot_repair(&resources)?;
    validate_source_custody_before_repair(&table, &descriptors)?;

    fault_stale_boot_resources(journal, &mut resources, current_kernel_boot_id)?;

    table.validate_resource_references(&resources)?;
    let references = resources.source_realization_references()?;
    let records = table.plan_recovery_reaping(&references)?;
    if !records.is_empty() {
        let mut digest = Sha256::new();
        digest.update(b"aos.mount.source-wrong-boot-reaping.v1\0");
        digest.update(current_kernel_boot_id);
        let output = digest.finalize();
        let mut transaction_id = [0_u8; 16];
        transaction_id.copy_from_slice(&output[..16]);
        if transaction_id == [0; 16] {
            transaction_id[0] = 1;
        }
        journal.commit(&JournalTransaction::new(transaction_id, records.clone())?)?;
        table.apply_committed(&records)?;
    }
    ReopenedSourcePins::reconcile_preflighted(journal, &mut table, descriptors, keeper)
}

impl ReopenedSourcePins {
    /// Applies custody mutations after the public entry point validates both
    /// authenticated journal tables and their exact references.
    fn reconcile_preflighted<K: SourceDescriptorStore>(
        journal: &mut Journal,
        table: &mut SourcePinTableV1,
        mut descriptors: BTreeMap<SourcePinName, ResolvedPath>,
        keeper: &K,
    ) -> Result<Self> {
        validate_source_custody_before_repair(table, &descriptors)?;

        let expected: BTreeSet<_> = table
            .rows()
            .filter(|row| row.lifecycle != SourcePinLifecycleV1::Released)
            .map(|row| row.handle)
            .collect();

        let orphans: Vec<_> = descriptors
            .keys()
            .filter(|name| !expected.contains(&name.digest()))
            .cloned()
            .collect();
        for name in orphans {
            if keeper.remove_source(&name)? != SourceCustodyEvidence::ManagerConfirmed {
                return Err(state_error(
                    "PID 1 did not confirm orphan source custody removal",
                ));
            }
            descriptors.remove(&name);
        }

        let mut reopened = BTreeMap::new();
        for row in table
            .rows()
            .filter(|row| row.lifecycle == SourcePinLifecycleV1::Active)
        {
            if row.kernel_boot_id != table.current_kernel_boot_id {
                return Err(state_error(
                    "Active source pin belongs to another kernel boot",
                ));
            }
            let name = SourcePinName::from_digest(row.handle);
            let source = descriptors
                .remove(&name)
                .ok_or_else(|| state_error("Active source pin is missing from PID 1 custody"))?;
            verify_reopened(row, &source)?;
            reopened.insert(row.handle, source);
        }
        let reaping: Vec<_> = table
            .rows()
            .filter(|row| row.lifecycle == SourcePinLifecycleV1::Reaping)
            .map(|row| row.handle)
            .collect();
        for handle in reaping {
            let name = SourcePinName::from_digest(handle);
            let records = table.plan_finish_reaping(handle)?;
            let transaction =
                JournalTransaction::new(reaping_transaction_id(handle), records.clone())?;
            journal.preflight_transactions(std::slice::from_ref(&transaction))?;
            let absence_confirmed = if descriptors.remove(&name).is_some() {
                keeper.remove_source(&name)? == SourceCustodyEvidence::ManagerConfirmed
            } else {
                // The complete socket-activation inventory is an authoritative
                // manager snapshot. Absence there is stronger than an
                // acknowledged FDSTOREREMOVE barrier without property readback.
                true
            };
            if !absence_confirmed {
                continue;
            }
            journal.commit(&transaction)?;
            table.apply_committed(&records)?;
        }
        if !descriptors.is_empty() {
            return Err(state_error("source custody reconciliation left an orphan"));
        }

        let current_rows = table
            .rows()
            .filter(|row| row.lifecycle == SourcePinLifecycleV1::Active && row.current)
            .map(|row| (row.binding_digest, row.clone()))
            .collect();
        Ok(Self {
            current_rows,
            descriptors: reopened,
        })
    }
}

fn validate_source_custody_before_repair(
    table: &SourcePinTableV1,
    descriptors: &BTreeMap<SourcePinName, ResolvedPath>,
) -> Result<()> {
    for row in table.rows().filter(|row| {
        row.lifecycle == SourcePinLifecycleV1::Active
            && row.kernel_boot_id == table.current_kernel_boot_id
    }) {
        let source = descriptors
            .get(&SourcePinName::from_digest(row.handle))
            .ok_or_else(|| state_error("Active source pin is missing from PID 1 custody"))?;
        verify_reopened(row, source)?;
    }
    Ok(())
}

impl SourcePinResolver for ReopenedSourcePins {
    fn resolve(&self, binding: &SourceRealizationBindingV1) -> Result<ResolvedSourcePin> {
        let digest = *binding.digest().as_bytes();
        let row = self.current_rows.get(&digest).ok_or_else(|| {
            MountError::Worker("source binding has no current Active pin".to_owned())
        })?;
        if row.binding_bytes != binding.canonical_bytes() {
            return Err(state_error("source binding digest equivocation detected"));
        }
        let source = self
            .descriptors
            .get(&row.handle)
            .ok_or_else(|| state_error("authenticated source descriptor disappeared"))?;
        verify_reopened(row, source)?;
        Ok(resolved_source_pin(row, duplicate_resolved(source)?))
    }
}

fn resolved_source_pin(row: &SourcePinRowV1, source: ResolvedPath) -> ResolvedSourcePin {
    ResolvedSourcePin {
        source,
        handle: row.handle,
        physical_proof_digest: row.physical_proof_digest,
        unique_mount_id: row.unique_mount_id,
        provider_catalog_generation: row.provider_catalog_generation,
        provider_catalog_digest: row.provider_catalog_digest,
        provider_resource_id: row.provider_resource_id,
        provider_resource_generation: row.provider_resource_generation,
        provider_resource_digest: row.provider_resource_digest,
        provider_authority_digest: row.provider_authority_digest,
        provider_authority_id: row.provider_authority_id,
        provider_authority_generation: row.provider_authority_generation,
        kernel_boot_id: row.kernel_boot_id,
        device: row.device,
        inode: row.inode,
        proof_class: row.proof_class,
    }
}

fn validate_rows(rows: &BTreeMap<SourceRealizationHandleV1, SourcePinRowV1>) -> Result<()> {
    let mut current_bindings = BTreeSet::new();
    let mut physical_files = BTreeSet::new();
    let mut mount_ids = BTreeSet::new();
    for (handle, row) in rows {
        row.validate()?;
        if row.handle != *handle {
            return Err(state_error("source-pin map key differs from row handle"));
        }
        if row.current && !current_bindings.insert(row.binding_digest) {
            return Err(state_error(
                "logical binding has multiple current realizations",
            ));
        }
        if row.lifecycle != SourcePinLifecycleV1::Released
            && (!physical_files.insert((row.kernel_boot_id, row.device, row.inode))
                || !mount_ids.insert((row.kernel_boot_id, row.unique_mount_id)))
        {
            return Err(state_error("live source-pin rows physically alias"));
        }
    }
    Ok(())
}

fn apply_rows(
    rows: &mut BTreeMap<SourceRealizationHandleV1, SourcePinRowV1>,
    records: &[JournalRecord],
) -> Result<()> {
    let mut changed = BTreeSet::new();
    for record in records {
        if record.namespace() != RecordNamespace::MountSourcePin {
            continue;
        }
        let (binding_digest, handle) = decode_key(record.key())?;
        if !changed.insert(handle) {
            return Err(state_error("transaction repeats one source-pin row"));
        }
        let value = record
            .value()
            .ok_or_else(|| state_error("source-pin tombstones cannot be deleted"))?;
        let next = decode_value(value)?;
        if next.binding_digest != binding_digest || next.handle != handle {
            return Err(state_error(
                "source-pin record key differs from row identity",
            ));
        }
        match rows.get(&handle) {
            None if next.revision == 1
                && next.lifecycle == SourcePinLifecycleV1::Active
                && next.current => {}
            Some(current) => validate_transition(current, &next)?,
            None => return Err(state_error("source pin starts after its admission phase")),
        }
        rows.insert(handle, next);
    }
    Ok(())
}

fn validate_transition(current: &SourcePinRowV1, next: &SourcePinRowV1) -> Result<()> {
    let mut expected = current.clone();
    expected.revision = next_revision(current.revision)?;
    let allowed = if current.lifecycle == SourcePinLifecycleV1::Active && current.current {
        expected.current = false;
        let demoted = expected == *next;
        expected.lifecycle = SourcePinLifecycleV1::Reaping;
        demoted || expected == *next
    } else if current.lifecycle == SourcePinLifecycleV1::Active && !current.current {
        expected.lifecycle = SourcePinLifecycleV1::Reaping;
        expected == *next
    } else if current.lifecycle == SourcePinLifecycleV1::Reaping && !current.current {
        expected.lifecycle = SourcePinLifecycleV1::Released;
        expected == *next
    } else {
        false
    };
    if !allowed {
        return Err(state_error(
            "source-pin transition is not the exact next lifecycle step",
        ));
    }
    Ok(())
}

fn put_record(row: &SourcePinRowV1) -> Result<JournalRecord> {
    row.validate()?;
    let value = serde_json::to_vec(&StoredSourcePinV1 {
        schema: SCHEMA.to_owned(),
        version: FORMAT_VERSION,
        row: row.clone(),
    })
    .map_err(|error| state_error(error.to_string()))?;
    if value.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error(
            "encoded source-pin row exceeds its fixed bound",
        ));
    }
    Ok(JournalRecord::put(
        RecordNamespace::MountSourcePin,
        encode_key(row.binding_digest, row.handle),
        value,
    ))
}

#[cfg(test)]
pub(crate) fn source_pin_record_for_test(row: &SourcePinRowV1) -> Result<JournalRecord> {
    put_record(row)
}

fn decode_value(bytes: &[u8]) -> Result<SourcePinRowV1> {
    if bytes.len() > MAXIMUM_VALUE_BYTES {
        return Err(state_error("source-pin row exceeds its fixed bound"));
    }
    let stored: StoredSourcePinV1 =
        serde_json::from_slice(bytes).map_err(|error| state_error(error.to_string()))?;
    if stored.schema != SCHEMA || stored.version != FORMAT_VERSION {
        return Err(state_error("source-pin schema or version is unsupported"));
    }
    stored.row.validate()?;
    if serde_json::to_vec(&stored).map_err(|error| state_error(error.to_string()))? != bytes {
        return Err(state_error("source-pin row is not canonical JSON"));
    }
    Ok(stored.row)
}

fn encode_key(binding_digest: [u8; 32], handle: SourceRealizationHandleV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + binding_digest.len() + handle.len());
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(&binding_digest);
    key.extend_from_slice(&handle);
    key
}

fn decode_key(bytes: &[u8]) -> Result<([u8; 32], SourceRealizationHandleV1)> {
    let suffix = bytes
        .strip_prefix(KEY_PREFIX)
        .ok_or_else(|| state_error("source-pin record uses an unknown key prefix"))?;
    let key: [u8; 64] = suffix
        .try_into()
        .map_err(|_| state_error("source-pin record key has the wrong length"))?;
    let binding_digest = key[..32]
        .try_into()
        .map_err(|_| state_error("source-pin binding key has the wrong length"))?;
    let handle = key[32..]
        .try_into()
        .map_err(|_| state_error("source-pin handle key has the wrong length"))?;
    Ok((binding_digest, handle))
}

fn physical_proof_digest(row: &SourcePinRowV1) -> [u8; 32] {
    mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
        binding_digest: row.binding_digest,
        proof_class: row.proof_class,
        provider_authority_id: row.provider_authority_id,
        provider_authority_generation: row.provider_authority_generation,
        provider_authority_digest: row.provider_authority_digest,
        provider_resource_id: row.provider_resource_id,
        provider_resource_generation: row.provider_resource_generation,
        provider_resource_digest: row.provider_resource_digest,
        provider_catalog_generation: row.provider_catalog_generation,
        provider_catalog_digest: row.provider_catalog_digest,
        kernel_boot_id: row.kernel_boot_id,
        device: row.device,
        inode: row.inode,
        unique_mount_id: row.unique_mount_id,
    })
}

fn mount_minted_handle(row: &SourcePinRowV1) -> SourceRealizationHandleV1 {
    mount_source_realization_handle_v1(row.binding_digest, row.physical_proof_digest)
}

fn proof_class_for_binding(binding: &SourceRealizationBindingV1) -> Result<SourcePinProofClassV1> {
    use aos_proto::aos::sandbox::local::v1::MountSourceConsistency;

    match binding.consistency() {
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION => {
            Ok(SourcePinProofClassV1::ImmutableTree)
        }
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE => {
            Ok(SourcePinProofClassV1::LocalLive)
        }
        MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA => {
            Ok(SourcePinProofClassV1::BestEffortReplica)
        }
        _ => Err(state_error(
            "source-pin binding uses an unsupported consistency",
        )),
    }
}

fn verify_reopened(row: &SourcePinRowV1, source: &ResolvedPath) -> Result<()> {
    let identity = source.identity();
    let mount_id =
        MountId::from_fd(source.as_fd()).map_err(|error| MountError::Worker(error.to_string()))?;
    if identity.file_type != aos_sandbox_linux::path::FileType::Directory
        || identity.device != row.device
        || identity.inode != row.inode
        || mount_id.get() != row.unique_mount_id
    {
        return Err(state_error(
            "reopened source descriptor differs from durable proof",
        ));
    }
    Ok(())
}

fn duplicate_resolved(source: &ResolvedPath) -> Result<ResolvedPath> {
    let duplicated: OwnedFd = rustix::io::fcntl_dupfd_cloexec(source.as_fd(), 3)
        .map_err(|error| MountError::Worker(error.to_string()))?;
    let resolved = ResolvedPath::from_inherited(duplicated)
        .map_err(|error| MountError::Worker(error.to_string()))?;
    if resolved.identity() != source.identity() {
        return Err(state_error("duplicated source descriptor changed identity"));
    }
    Ok(resolved)
}

fn next_revision(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| state_error("source-pin revision overflowed"))
}

fn reaping_transaction_id(handle: [u8; 32]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.mount.source-reaping.v1\0");
    digest.update(handle);
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    id
}

fn state_error(message: impl Into<String>) -> MountError {
    MountError::State(message.into())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest, model::ViewSource};
    use tempfile::tempdir;

    use super::*;
    use crate::state::mount_resource_v1::{
        AssignmentBindingV1, MountPolicyV1, MountRecipeV1, MountResourceLimitsV1,
        MountResourceStateV1, MountSourceConsistencyV1, NativeMutationV1, ObjectDescriptorV1,
        OperationCorrelationV1, OwnedMountAttributeV1,
    };

    #[derive(Default)]
    struct FakeSourceStore {
        names: std::sync::Mutex<BTreeSet<SourcePinName>>,
    }

    impl crate::keeper::sealed::SourceDescriptorStore for FakeSourceStore {}

    impl SourceDescriptorStore for FakeSourceStore {
        fn store_source(
            &self,
            name: &SourcePinName,
            _descriptor: std::os::fd::BorrowedFd<'_>,
        ) -> Result<SourceCustodyEvidence> {
            self.names.lock().unwrap().insert(name.clone());
            Ok(SourceCustodyEvidence::ManagerConfirmed)
        }

        fn remove_source(&self, name: &SourcePinName) -> Result<SourceCustodyEvidence> {
            self.names.lock().unwrap().remove(name);
            Ok(SourceCustodyEvidence::ManagerConfirmed)
        }
    }

    struct UnconfirmedSourceStore;

    impl crate::keeper::sealed::SourceDescriptorStore for UnconfirmedSourceStore {}

    impl SourceDescriptorStore for UnconfirmedSourceStore {
        fn store_source(
            &self,
            _name: &SourcePinName,
            _descriptor: std::os::fd::BorrowedFd<'_>,
        ) -> Result<SourceCustodyEvidence> {
            Ok(SourceCustodyEvidence::Unconfirmed)
        }

        fn remove_source(&self, _name: &SourcePinName) -> Result<SourceCustodyEvidence> {
            Ok(SourceCustodyEvidence::Unconfirmed)
        }
    }

    fn binding() -> SourceRealizationBindingV1 {
        binding_for_view([1; 16])
    }

    fn binding_for_view(source_view_id: [u8; 16]) -> SourceRealizationBindingV1 {
        SourceRealizationBindingV1::new(
            source_view_id,
            2,
            ObjectDescriptor::new(
                MediaType::new("application/vnd.aos.sandbox.view.v1+cbor".to_owned()).unwrap(),
                ObjectDigest::from_bytes([3; 32]),
                4,
            ),
            ViewSource::ImmutableTree {
                tree: ObjectDescriptor::new(
                    MediaType::new("application/vnd.aos.sandbox.tree.v1+cbor".to_owned()).unwrap(),
                    ObjectDigest::from_bytes([5; 32]),
                    6,
                ),
            },
            aos_proto::aos::sandbox::local::v1::MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        )
        .unwrap()
    }

    fn bind_row_to(row: &mut SourcePinRowV1, binding: &SourceRealizationBindingV1) {
        row.binding_bytes = binding.canonical_bytes();
        row.binding_digest = *binding.digest().as_bytes();
        row.physical_proof_digest = physical_proof_digest(row);
        row.handle = mount_minted_handle(row);
    }

    fn row(seed: u8, device: u64, inode: u64, mount_id: u64) -> SourcePinRowV1 {
        let binding = binding();
        let mut row = SourcePinRowV1 {
            handle: [0; 32],
            revision: 1,
            binding_bytes: binding.canonical_bytes(),
            binding_digest: *binding.digest().as_bytes(),
            proof_class: SourcePinProofClassV1::ImmutableTree,
            provider_authority_id: [7; 16],
            provider_authority_generation: 8,
            provider_authority_digest: [9; 32],
            provider_resource_id: [seed; 32],
            provider_resource_generation: 11,
            provider_resource_digest: [12; 32],
            provider_catalog_generation: 13,
            provider_catalog_digest: [14; 32],
            kernel_boot_id: [15; 16],
            device,
            inode,
            unique_mount_id: mount_id,
            physical_proof_digest: [0; 32],
            admission_operation_id: [16; 16],
            admission_request_digest: [seed; 32],
            current: true,
            lifecycle: SourcePinLifecycleV1::Active,
        };
        row.physical_proof_digest = physical_proof_digest(&row);
        row.handle = mount_minted_handle(&row);
        row
    }

    fn empty_table() -> SourcePinTableV1 {
        SourcePinTableV1 {
            rows: BTreeMap::new(),
            current_kernel_boot_id: [15; 16],
        }
    }

    fn resolved_directory(path: &std::path::Path) -> ResolvedPath {
        let descriptor = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        ResolvedPath::from_inherited(descriptor).unwrap()
    }

    fn resource(row: &SourcePinRowV1) -> MountResourceV1 {
        let binding = SourceRealizationBindingV1::from_canonical_bytes(&row.binding_bytes).unwrap();
        MountResourceV1 {
            handle: [60; 32],
            fd_store_key: [60; 32],
            kernel_boot_id: row.kernel_boot_id,
            revision: 1,
            binding: AssignmentBindingV1 {
                sandbox_id: [61; 16],
                incarnation_id: [62; 16],
                assignment_epoch: 1,
                desired_generation: 1,
                assignment_digest: [63; 32],
                namespace_generation: 1,
            },
            recipe: MountRecipeV1 {
                attachment_id: [64; 16],
                destination_slot_id: [65; 16],
                view_revision: ObjectDescriptorV1::from_runtime(binding.view_descriptor()).unwrap(),
                source_generation: binding.source_view_revision(),
                resource_attachment_generation: 1,
                source_view_id: *binding.source_view_id(),
                source_incarnation_id: binding.source_incarnation_id().copied(),
                source_consistency: MountSourceConsistencyV1::ImmutableRevision,
                source_handle: aos_sandbox_core::encode_view_source(binding.source()),
                source_binding_digest: row.binding_digest,
                source_realization_handle: row.handle,
                source_physical_proof_digest: row.physical_proof_digest,
                source_kernel_boot_id: row.kernel_boot_id,
                source_device: row.device,
                source_inode: row.inode,
                source_proof_class: row.proof_class,
                source_unique_mount_id: row.unique_mount_id,
                source_provider_authority_id: row.provider_authority_id,
                source_provider_authority_generation: row.provider_authority_generation,
                source_provider_authority_digest: row.provider_authority_digest,
                source_provider_resource_id: row.provider_resource_id,
                source_provider_resource_generation: row.provider_resource_generation,
                source_provider_resource_digest: row.provider_resource_digest,
                source_provider_catalog_generation: row.provider_catalog_generation,
                source_provider_catalog_digest: row.provider_catalog_digest,
                policy: MountPolicyV1 {
                    attributes: vec![
                        OwnedMountAttributeV1::ReadOnly,
                        OwnedMountAttributeV1::NoSuid,
                        OwnedMountAttributeV1::NoDevice,
                    ],
                    mutation: NativeMutationV1::ReadOnly,
                },
            },
            state: MountResourceStateV1::Allocated {
                creation: OperationCorrelationV1 {
                    operation_id: [66; 16],
                    request_digest: [67; 32],
                },
            },
        }
    }

    fn resource_with_handle(row: &SourcePinRowV1, handle: u8) -> MountResourceV1 {
        let mut resource = resource(row);
        resource.handle = [handle; 32];
        resource.fd_store_key = [handle; 32];
        resource.binding.assignment_digest = [handle; 32];
        resource
    }

    #[test]
    fn canonical_row_round_trips_and_rejects_unknown_schema() {
        let row = row(1, 20, 21, 22);
        let record = put_record(&row).unwrap();
        assert_eq!(decode_value(record.value().unwrap()).unwrap(), row);

        let mut value: serde_json::Value = serde_json::from_slice(record.value().unwrap()).unwrap();
        value["schema"] = serde_json::Value::String("AOSMSP00".to_owned());
        assert!(decode_value(&serde_json::to_vec(&value).unwrap()).is_err());
        value["schema"] = serde_json::Value::String(SCHEMA.to_owned());
        value["reserved"] = serde_json::Value::from(1);
        assert!(decode_value(&serde_json::to_vec(&value).unwrap()).is_err());

        value["reserved"] = serde_json::Value::from(0);
        value["row"]["lifecycle"] = serde_json::Value::String("unknown".to_owned());
        assert!(decode_value(&serde_json::to_vec(&value).unwrap()).is_err());

        value["row"]["lifecycle"] = serde_json::Value::String("active".to_owned());
        value["row"]["proof_class"] = serde_json::Value::String("unknown".to_owned());
        assert!(decode_value(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn lifecycle_revisions_accept_exact_constructible_compacted_states() {
        let current = row(1, 20, 21, 22);
        assert!(current.validate().is_ok());

        for (lifecycle, current, revisions) in [
            (SourcePinLifecycleV1::Active, false, &[2_u64][..]),
            (SourcePinLifecycleV1::Reaping, false, &[2_u64, 3][..]),
            (SourcePinLifecycleV1::Released, false, &[3_u64, 4][..]),
        ] {
            for revision in revisions {
                let mut candidate = row(1, 20, 21, 22);
                candidate.lifecycle = lifecycle;
                candidate.current = current;
                candidate.revision = *revision;
                assert!(candidate.validate().is_ok());
            }
        }

        for (lifecycle, current, revision) in [
            (SourcePinLifecycleV1::Active, true, 2),
            (SourcePinLifecycleV1::Active, false, 1),
            (SourcePinLifecycleV1::Reaping, false, 4),
            (SourcePinLifecycleV1::Released, false, 2),
            (SourcePinLifecycleV1::Released, true, 3),
        ] {
            let mut impossible = row(1, 20, 21, 22);
            impossible.lifecycle = lifecycle;
            impossible.current = current;
            impossible.revision = revision;
            assert!(impossible.validate().is_err());
        }
    }

    #[test]
    fn recovery_rejects_composite_key_substitution() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let pin = row(1, 20, 21, 22);
        let mut wrong_binding = pin.binding_digest;
        wrong_binding[0] ^= 1;
        let record = JournalRecord::put(
            RecordNamespace::MountSourcePin,
            encode_key(wrong_binding, pin.handle),
            put_record(&pin).unwrap().value().unwrap().to_vec(),
        );
        journal
            .commit(&JournalTransaction::new([89; 16], vec![record]).unwrap())
            .unwrap();

        assert!(SourcePinTableV1::recover(&journal, [15; 16]).is_err());
    }

    #[test]
    fn recovery_rejects_provider_equivocation_and_current_rollback() {
        for corrupt_history in ["equivocation", "rollback"] {
            let directory = tempdir().unwrap();
            let (mut journal, _) = Journal::open(
                directory.path().join("journal"),
                aos_sandbox::journal::JournalLimits::default(),
            )
            .unwrap();
            let mut predecessor = row(1, 20, 21, 22);
            predecessor.current = false;
            predecessor.revision = 2;
            let mut current = row(2, 30, 31, 32);
            match corrupt_history {
                "equivocation" => current.provider_authority_digest[0] ^= 1,
                "rollback" => {
                    current.provider_authority_generation -= 1;
                    current.provider_catalog_generation -= 1;
                }
                _ => unreachable!(),
            }
            current.physical_proof_digest = physical_proof_digest(&current);
            current.handle = mount_minted_handle(&current);
            journal
                .commit(
                    &JournalTransaction::new(
                        [92; 16],
                        vec![
                            put_record(&predecessor).unwrap(),
                            put_record(&current).unwrap(),
                        ],
                    )
                    .unwrap(),
                )
                .unwrap();

            let orphan_name = SourcePinName::from_digest([93; 32]);
            let keeper = FakeSourceStore::default();
            keeper.names.lock().unwrap().insert(orphan_name.clone());
            assert!(
                recover_source_custody(
                    &mut journal,
                    BTreeMap::from([(orphan_name.clone(), resolved_directory(directory.path()),)]),
                    &keeper,
                    [15; 16],
                )
                .is_err()
            );
            assert!(keeper.names.lock().unwrap().contains(&orphan_name));
        }
    }

    #[test]
    fn provider_or_caller_cannot_select_a_handle() {
        let mut invalid = row(1, 20, 21, 22);
        invalid.handle = [99; 32];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn admission_rejects_file_and_mount_aliases() {
        let mut table = empty_table();
        let first = row(1, 20, 21, 22);
        let records = table.plan_activate(&first, None).unwrap();
        table.apply_committed(&records).unwrap();

        assert!(
            table
                .plan_activate(&row(2, 20, 21, 23), Some(first.handle))
                .is_err()
        );
        assert!(
            table
                .plan_activate(&row(2, 24, 25, 22), Some(first.handle))
                .is_err()
        );
    }

    #[test]
    fn cutover_keeps_referenced_old_and_new_active_with_one_current_pointer() {
        let directory = tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let mut resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let mut table = empty_table();
        let first = row(1, 20, 21, 22);
        let first_resource = resource_with_handle(&first, 60);
        let records = table
            .plan_activate_with_resource(&resources, &first, None, &first_resource)
            .unwrap();
        table.apply_committed(&records).unwrap();
        resources
            .apply_committed(
                &records
                    .iter()
                    .filter(|record| record.namespace() == RecordNamespace::Operation)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let second = row(2, 30, 31, 32);
        let second_resource = resource_with_handle(&second, 70);
        let records = table
            .plan_activate_with_resource(&resources, &second, Some(first.handle), &second_resource)
            .unwrap();
        table.apply_committed(&records).unwrap();

        assert_eq!(
            table.get(&first.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Active
        );
        assert!(!table.get(&first.handle).unwrap().current);
        assert!(table.get(&second.handle).unwrap().current);
    }

    #[test]
    fn admission_rejects_provider_rollback_and_equivocation() {
        let mut table = empty_table();
        let first = row(1, 20, 21, 22);
        let records = table.plan_activate(&first, None).unwrap();
        table.apply_committed(&records).unwrap();

        let mut rollback = row(2, 30, 31, 32);
        rollback.provider_catalog_generation = first.provider_catalog_generation - 1;
        rollback.physical_proof_digest = physical_proof_digest(&rollback);
        rollback.handle = mount_minted_handle(&rollback);
        assert!(table.plan_activate(&rollback, Some(first.handle)).is_err());

        let mut equivocation = row(3, 40, 41, 42);
        equivocation.provider_authority_digest[0] ^= 1;
        equivocation.physical_proof_digest = physical_proof_digest(&equivocation);
        equivocation.handle = mount_minted_handle(&equivocation);
        assert!(
            table
                .plan_activate(&equivocation, Some(first.handle))
                .is_err()
        );
    }

    #[test]
    fn provider_process_restart_preserves_stable_authority_across_recovery() {
        #[derive(Clone, Copy)]
        struct ProviderProcessFixture {
            process_instance_id: [u8; 16],
        }

        impl ProviderProcessFixture {
            fn realize(
                self,
                binding: &SourceRealizationBindingV1,
                seed: u8,
                provider_generation: u64,
            ) -> SourcePinRowV1 {
                assert_ne!(self.process_instance_id, [0; 16]);
                let mut realized = row(
                    seed,
                    20 + u64::from(seed),
                    30 + u64::from(seed),
                    40 + u64::from(seed),
                );
                realized.provider_authority_generation = provider_generation;
                realized.provider_catalog_generation = provider_generation;
                realized.provider_authority_digest = [provider_generation as u8; 32];
                realized.provider_catalog_digest = [(provider_generation + 1) as u8; 32];
                bind_row_to(&mut realized, binding);
                realized
            }
        }

        let first_process = ProviderProcessFixture {
            process_instance_id: [41; 16],
        };
        let restarted_process = ProviderProcessFixture {
            process_instance_id: [42; 16],
        };
        let first_binding = binding_for_view([1; 16]);
        let first = first_process.realize(&first_binding, 1, 5);
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let mut table = empty_table();
        let first_records = table.plan_activate(&first, None).unwrap();
        journal
            .commit(&JournalTransaction::new([88; 16], first_records.clone()).unwrap())
            .unwrap();
        table.apply_committed(&first_records).unwrap();

        let restarted_first = restarted_process.realize(&first_binding, 1, 5);
        assert_ne!(
            first_process.process_instance_id,
            restarted_process.process_instance_id
        );
        assert_eq!(restarted_first, first);
        table
            .validate_existing_reference(&first_binding, restarted_first.evidence())
            .unwrap();

        let second_binding = binding_for_view([2; 16]);
        let second = restarted_process.realize(&second_binding, 2, 6);
        let second_records = table.plan_activate(&second, None).unwrap();
        journal
            .commit(&JournalTransaction::new([89; 16], second_records.clone()).unwrap())
            .unwrap();
        table.apply_committed(&second_records).unwrap();
        drop(journal);

        let (journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let recovered = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        assert_eq!(
            recovered.current_handle(first.binding_digest),
            Some(first.handle)
        );
        assert_eq!(
            recovered.current_handle(second.binding_digest),
            Some(second.handle)
        );
        assert_eq!(recovered.get(&first.handle).unwrap(), &first);
        assert_eq!(recovered.get(&second.handle).unwrap(), &second);
    }

    #[test]
    fn wrong_boot_evidence_is_rejected_at_admission() {
        let table = empty_table();
        let mut proposed = row(1, 20, 21, 22);
        proposed.kernel_boot_id = [44; 16];
        proposed.physical_proof_digest = physical_proof_digest(&proposed);
        proposed.handle = mount_minted_handle(&proposed);

        assert!(table.plan_activate(&proposed, None).is_err());
    }

    #[test]
    fn zero_reference_cutover_reaps_predecessor_but_current_unreferenced_is_reusable() {
        let directory = tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let mut table = empty_table();
        let first = row(1, 20, 21, 22);
        let records = table.plan_activate(&first, None).unwrap();
        table.apply_committed(&records).unwrap();
        table
            .validate_existing_reference(&binding(), first.evidence())
            .unwrap();

        let second = row(2, 30, 31, 32);
        let successor = resource_with_handle(&second, 70);
        let records = table
            .plan_activate_with_resource(&resources, &second, Some(first.handle), &successor)
            .unwrap();
        table.apply_committed(&records).unwrap();

        assert_eq!(
            table.get(&first.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Reaping
        );
        assert_eq!(
            table.get(&second.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Active
        );
        assert!(table.get(&second.handle).unwrap().current);
    }

    #[test]
    fn shared_noncurrent_release_reaps_only_the_exact_last_reference() {
        let directory = tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let mut resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let mut table = empty_table();
        let first = row(1, 20, 21, 22);
        let first_resource = resource_with_handle(&first, 60);
        let records = table
            .plan_activate_with_resource(&resources, &first, None, &first_resource)
            .unwrap();
        table.apply_committed(&records).unwrap();
        resources
            .apply_committed(
                &records
                    .iter()
                    .filter(|record| record.namespace() == RecordNamespace::Operation)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let second_reference = resource_with_handle(&first, 61);
        let records = resources.plan_allocate(&second_reference).unwrap();
        resources.apply_committed(&records).unwrap();

        let second = row(2, 30, 31, 32);
        let successor = resource_with_handle(&second, 70);
        let records = table
            .plan_activate_with_resource(&resources, &second, Some(first.handle), &successor)
            .unwrap();
        table.apply_committed(&records).unwrap();

        let mut first_released = first_resource.clone();
        first_released.revision += 1;
        first_released.state = MountResourceStateV1::Released {
            last_detached_mount_id: None,
            last_installed_mount_id: None,
        };
        assert!(
            table
                .plan_reaping_after_release_if_last_reference(&resources, &first_released)
                .unwrap()
                .is_empty()
        );
        let records = resources
            .plan_transition(first_resource.revision, &first_released)
            .unwrap();
        resources.apply_committed(&records).unwrap();

        let mut last_released = second_reference.clone();
        last_released.revision += 1;
        last_released.state = MountResourceStateV1::Released {
            last_detached_mount_id: None,
            last_installed_mount_id: None,
        };
        assert_eq!(
            table
                .plan_reaping_after_release_if_last_reference(&resources, &last_released)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn activation_and_resource_allocation_are_one_record_set() {
        let directory = tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let pin = row(1, 20, 21, 22);
        let resource = resource(&pin);
        let records = table
            .plan_activate_with_resource(&resources, &pin, None, &resource)
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .any(|record| record.namespace() == RecordNamespace::MountSourcePin)
        );
        assert!(
            records
                .iter()
                .any(|record| record.namespace() == RecordNamespace::Operation)
        );
    }

    #[test]
    fn last_release_and_reaping_are_one_record_set() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let mut resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let mut table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let first = row(1, 20, 21, 22);
        let resource = resource(&first);
        let records = table
            .plan_activate_with_resource(&resources, &first, None, &resource)
            .unwrap();
        journal
            .commit(&JournalTransaction::new([70; 16], records.clone()).unwrap())
            .unwrap();
        table.apply_committed(&records).unwrap();
        resources
            .apply_committed(
                &records
                    .iter()
                    .filter(|record| record.namespace() == RecordNamespace::Operation)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        let second = row(2, 30, 31, 32);
        let cutover = table.plan_activate(&second, Some(first.handle)).unwrap();
        table.apply_committed(&cutover).unwrap();
        let mut released = resource.clone();
        released.revision = 2;
        released.state = MountResourceStateV1::Released {
            last_detached_mount_id: None,
            last_installed_mount_id: None,
        };
        let records = table
            .plan_release_with_reaping(&resources, 1, &released)
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .any(|record| record.namespace() == RecordNamespace::MountSourcePin)
        );
        assert!(
            records
                .iter()
                .any(|record| record.namespace() == RecordNamespace::Operation)
        );

        table.apply_committed(&records).unwrap();
        resources
            .apply_committed(
                &records
                    .iter()
                    .filter(|record| record.namespace() == RecordNamespace::Operation)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .unwrap();

        let retired = table.get(&first.handle).unwrap();
        assert_eq!(retired.lifecycle, SourcePinLifecycleV1::Reaping);
        assert!(!retired.current);

        let reusable = table.get(&second.handle).unwrap();
        assert_eq!(reusable.lifecycle, SourcePinLifecycleV1::Active);
        assert!(reusable.current);
        assert_eq!(
            resources
                .source_realization_references()
                .unwrap()
                .get(&second.handle),
            None
        );

        let released = table.plan_finish_reaping(first.handle).unwrap();
        table.apply_committed(&released).unwrap();
        assert_eq!(
            table.get(&first.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Released
        );
        assert!(table.plan_activate(&first, None).is_err());
    }

    #[test]
    fn resource_references_require_the_exact_active_source_row() {
        let directory = tempdir().unwrap();
        let (journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let pin = row(1, 20, 21, 22);
        let mut resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let source_pins = empty_table();
        let mounted = resource(&pin);
        let allocation = resources.plan_allocate(&mounted).unwrap();
        resources.apply_committed(&allocation).unwrap();
        assert!(
            source_pins
                .validate_resource_references(&resources)
                .is_err()
        );

        let mut source_pins = empty_table();
        let activation = source_pins.plan_activate(&pin, None).unwrap();
        source_pins.apply_committed(&activation).unwrap();
        assert!(source_pins.validate_resource_references(&resources).is_ok());

        let mut mismatched_resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let mismatched_pin = row(2, 30, 31, 32);
        let mismatched = resource(&mismatched_pin);
        let allocation = mismatched_resources.plan_allocate(&mismatched).unwrap();
        mismatched_resources.apply_committed(&allocation).unwrap();
        assert!(
            source_pins
                .validate_resource_references(&mismatched_resources)
                .is_err()
        );
    }

    #[test]
    fn recovery_rejects_noncanonical_rows() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let row = row(1, 20, 21, 22);
        let mut value = put_record(&row).unwrap().value().unwrap().to_vec();
        value.push(b' ');
        let transaction = aos_sandbox::journal::JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::MountSourcePin,
                encode_key(row.binding_digest, row.handle),
                value,
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        assert!(SourcePinTableV1::recover(&journal, [15; 16]).is_err());
    }

    #[test]
    fn startup_rejects_missing_active_custody() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let pin = row(1, 20, 21, 22);
        journal
            .commit(&JournalTransaction::new([90; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();

        assert!(
            recover_source_custody(
                &mut journal,
                BTreeMap::new(),
                &FakeSourceStore::default(),
                [15; 16],
            )
            .is_err()
        );
    }

    #[test]
    fn startup_adopts_exact_active_custody_and_resolves_it() {
        let directory = tempdir().unwrap();
        let source = resolved_directory(directory.path());
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let pin = row(1, identity.device, identity.inode, mount_id);
        let name = SourcePinName::from_digest(pin.handle);
        let keeper = FakeSourceStore::default();
        keeper.names.lock().unwrap().insert(name.clone());
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(&JournalTransaction::new([90; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();

        let reopened = recover_source_custody(
            &mut journal,
            BTreeMap::from([(name, source)]),
            &keeper,
            [15; 16],
        )
        .unwrap();
        let resolved = reopened.resolve(&binding()).unwrap();

        assert_eq!(resolved.evidence(), pin.evidence());
        assert_eq!(resolved.source().identity(), identity);
    }

    #[test]
    fn startup_releases_unreferenced_wrong_boot_pin_without_descriptor_reconstruction() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let pin = row(1, 20, 21, 22);
        journal
            .commit(&JournalTransaction::new([90; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();

        let reopened = recover_source_custody(
            &mut journal,
            BTreeMap::new(),
            &FakeSourceStore::default(),
            [44; 16],
        );
        assert!(reopened.is_ok());
        let table = SourcePinTableV1::recover(&journal, [44; 16]).unwrap();
        assert_eq!(
            table.get(&pin.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Released
        );
    }

    #[test]
    fn host_reboot_faults_resources_and_releases_old_boot_source_custody() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let pin = row(1, 20, 21, 22);
        let mounted = resource(&pin);
        let records = table
            .plan_activate_with_resource(&resources, &pin, None, &mounted)
            .unwrap();
        journal
            .commit(&JournalTransaction::new([93; 16], records).unwrap())
            .unwrap();

        let recovered = recover_source_custody(
            &mut journal,
            BTreeMap::new(),
            &FakeSourceStore::default(),
            [44; 16],
        )
        .unwrap();
        assert!(recovered.current_rows.is_empty());
        assert!(recovered.descriptors.is_empty());
        let source_pins = SourcePinTableV1::recover(&journal, [44; 16]).unwrap();
        assert_eq!(
            source_pins.get(&pin.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Released
        );
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [44; 16])
                .unwrap();
        assert!(matches!(
            resources.get(&mounted.handle).unwrap().state,
            MountResourceStateV1::Faulted {
                from: crate::state::mount_resource_v1::MountFaultPhaseV1::Allocated,
                ..
            }
        ));
    }

    #[test]
    fn malformed_source_state_prevents_stale_resource_repair_mutation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let pin = row(1, 20, 21, 22);
        let stale_resource = resource(&pin);
        let records = table
            .plan_activate_with_resource(&resources, &pin, None, &stale_resource)
            .unwrap();
        journal
            .commit(&JournalTransaction::new([95; 16], records).unwrap())
            .unwrap();
        let corrupt = JournalRecord::put(
            RecordNamespace::MountSourcePin,
            encode_key(pin.binding_digest, pin.handle),
            b"{".to_vec(),
        );
        journal
            .commit(&JournalTransaction::new([96; 16], vec![corrupt]).unwrap())
            .unwrap();
        let before = std::fs::read(&path).unwrap();

        assert!(
            recover_source_custody(
                &mut journal,
                BTreeMap::new(),
                &FakeSourceStore::default(),
                [44; 16],
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn wrong_boot_retained_resource_cannot_reference_a_reaping_pin_before_repair() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let pin = row(1, 20, 21, 22);
        let retained = resource(&pin);
        let records = table
            .plan_activate_with_resource(&resources, &pin, None, &retained)
            .unwrap();
        journal
            .commit(&JournalTransaction::new([97; 16], records).unwrap())
            .unwrap();

        let mut reaping = pin.clone();
        reaping.revision = 2;
        reaping.current = false;
        reaping.lifecycle = SourcePinLifecycleV1::Reaping;
        journal
            .commit(
                &JournalTransaction::new([98; 16], vec![put_record(&reaping).unwrap()]).unwrap(),
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let keeper = FakeSourceStore::default();

        assert!(recover_source_custody(&mut journal, BTreeMap::new(), &keeper, [44; 16]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(keeper.names.lock().unwrap().is_empty());
    }

    #[test]
    fn referenced_reaping_pin_cannot_bypass_resource_preflight() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("journal");
        let source = resolved_directory(directory.path());
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let (mut journal, _) =
            Journal::open(&path, aos_sandbox::journal::JournalLimits::default()).unwrap();
        let resources =
            MountResourceTableV1::recover(&journal, MountResourceLimitsV1::default(), [15; 16])
                .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let pin = row(1, identity.device, identity.inode, mount_id);
        let retained = resource(&pin);
        let records = table
            .plan_activate_with_resource(&resources, &pin, None, &retained)
            .unwrap();
        journal
            .commit(&JournalTransaction::new([99; 16], records).unwrap())
            .unwrap();

        let mut reaping = pin.clone();
        reaping.revision = 2;
        reaping.current = false;
        reaping.lifecycle = SourcePinLifecycleV1::Reaping;
        journal
            .commit(
                &JournalTransaction::new([100; 16], vec![put_record(&reaping).unwrap()]).unwrap(),
            )
            .unwrap();
        let name = SourcePinName::from_digest(pin.handle);
        let keeper = FakeSourceStore::default();
        keeper.names.lock().unwrap().insert(name.clone());
        let journal_before = std::fs::read(&path).unwrap();
        let custody_before = keeper.names.lock().unwrap().clone();

        assert!(
            recover_source_custody(
                &mut journal,
                BTreeMap::from([(name, source)]),
                &keeper,
                [15; 16],
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), journal_before);
        assert_eq!(*keeper.names.lock().unwrap(), custody_before);
        let recovered = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        assert_eq!(
            recovered.get(&pin.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Reaping
        );
    }

    #[test]
    fn startup_reaps_same_boot_noncurrent_zero_reference_pin() {
        let directory = tempdir().unwrap();
        let source = resolved_directory(directory.path());
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let mut pin = row(1, identity.device, identity.inode, mount_id);
        pin.current = false;
        pin.revision = 2;
        let name = SourcePinName::from_digest(pin.handle);
        let keeper = FakeSourceStore::default();
        keeper.names.lock().unwrap().insert(name.clone());
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(&JournalTransaction::new([94; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();

        let reopened = recover_source_custody(
            &mut journal,
            BTreeMap::from([(name.clone(), source)]),
            &keeper,
            [15; 16],
        )
        .unwrap();

        assert!(reopened.current_rows.is_empty());
        assert!(!keeper.names.lock().unwrap().contains(&name));
        let recovered = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        let released = recovered.get(&pin.handle).unwrap();
        assert_eq!(released.lifecycle, SourcePinLifecycleV1::Released);
        assert_eq!(released.revision, 4);
    }

    #[test]
    fn startup_does_not_accept_a_descriptor_under_the_wrong_source_name() {
        let directory = tempdir().unwrap();
        let source = resolved_directory(directory.path());
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let pin = row(1, identity.device, identity.inode, mount_id);
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(&JournalTransaction::new([90; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();
        let wrong_name = SourcePinName::from_digest([91; 32]);
        let keeper = FakeSourceStore::default();
        keeper.names.lock().unwrap().insert(wrong_name.clone());
        let journal_before = std::fs::read(directory.path().join("journal")).unwrap();

        assert!(
            recover_source_custody(
                &mut journal,
                BTreeMap::from([(wrong_name.clone(), source)]),
                &keeper,
                [15; 16],
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(directory.path().join("journal")).unwrap(),
            journal_before
        );
        assert!(keeper.names.lock().unwrap().contains(&wrong_name));
    }

    #[test]
    fn startup_removes_unjournaled_source_custody() {
        let directory = tempdir().unwrap();
        let (mut journal, _) = Journal::open(
            directory.path().join("journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let name = SourcePinName::from_digest([91; 32]);
        let keeper = FakeSourceStore::default();
        keeper.names.lock().unwrap().insert(name.clone());
        let descriptors = BTreeMap::from([(name.clone(), resolved_directory(directory.path()))]);

        recover_source_custody(&mut journal, descriptors, &keeper, [15; 16]).unwrap();
        assert!(!keeper.names.lock().unwrap().contains(&name));
    }

    #[test]
    fn startup_never_publishes_orphan_absence_or_released_from_unconfirmed_removal() {
        let directory = tempdir().unwrap();
        let (mut orphan_journal, _) = Journal::open(
            directory.path().join("orphan-journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        let orphan_name = SourcePinName::from_digest([91; 32]);
        assert!(
            recover_source_custody(
                &mut orphan_journal,
                BTreeMap::from([(orphan_name, resolved_directory(directory.path()),)]),
                &UnconfirmedSourceStore,
                [15; 16],
            )
            .is_err()
        );

        let source = resolved_directory(directory.path());
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let mut pin = row(1, identity.device, identity.inode, mount_id);
        pin.current = false;
        pin.lifecycle = SourcePinLifecycleV1::Reaping;
        pin.revision = 2;
        let name = SourcePinName::from_digest(pin.handle);
        let (mut journal, _) = Journal::open(
            directory.path().join("reaping-journal"),
            aos_sandbox::journal::JournalLimits::default(),
        )
        .unwrap();
        journal
            .commit(&JournalTransaction::new([95; 16], vec![put_record(&pin).unwrap()]).unwrap())
            .unwrap();

        recover_source_custody(
            &mut journal,
            BTreeMap::from([(name, source)]),
            &UnconfirmedSourceStore,
            [15; 16],
        )
        .unwrap();
        let table = SourcePinTableV1::recover(&journal, [15; 16]).unwrap();
        assert_eq!(
            table.get(&pin.handle).unwrap().lifecycle,
            SourcePinLifecycleV1::Reaping
        );
    }

    #[test]
    fn reopened_descriptor_requires_exact_device_inode_and_mount_id() {
        let directory = tempdir().unwrap();
        let source = resolved_directory(directory.path());
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let identity = source.identity();
        let exact = row(1, identity.device, identity.inode, mount_id);
        verify_reopened(&exact, &source).unwrap();

        for mutation in 0..3 {
            let mut changed = exact.clone();
            match mutation {
                0 => changed.device += 1,
                1 => changed.inode += 1,
                2 => changed.unique_mount_id += 1,
                _ => unreachable!(),
            }
            assert!(verify_reopened(&changed, &source).is_err());
        }
    }

    #[test]
    fn reopened_source_descriptor_must_be_a_directory() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("regular");
        drop(std::fs::File::create(&path).unwrap());
        let file = rustix::fs::open(
            &path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let source = ResolvedPath::from_inherited(file).unwrap();
        let identity = source.identity();
        let mount_id = MountId::from_fd(source.as_fd()).unwrap().get();
        let exact_numbers = row(1, identity.device, identity.inode, mount_id);

        assert!(verify_reopened(&exact_numbers, &source).is_err());
    }
}
