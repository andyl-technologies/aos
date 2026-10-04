//! Immutable originals for same-binding storage-local placement copies.
//!
//! The original is a projection of an existing retained topology operation,
//! its sealed targets and one exact provider source. It contains no object
//! bytes, credentials or renewed mutation authority. The physical guard must
//! retain it before a first provider effect and compare it on every retry.
//!
//! ```text
//! original = {version, deployment_id, topology, binding_id,
//!             binding_stable_id, binding_resource_version, snapshot_revision,
//!             source, destination, path, source_object, read_generation,
//!             write_generation, binding_write_revision, profile_digest,
//!             part_bytes, expected_sha256, source_receipt_digest?}
//! source_object = {provider_version?: real provider version,
//!                  etag, bytes, guard_stamp?: permanent source incarnation}
//! copy_id = SHA256(domain, topology.operation_id, destination stable ID, path)
//! ```
//!
//! Version one retains the exact original provider-version wire form. Version
//! two requires a permanent source guard stamp, its positive receipt digest,
//! and a trusted whole-object catalogue hash and size. Absent version-two fields
//! are omitted from version-one canonical bytes and authentication domains.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::db::{SurfacePlacementRecord, TopologyOperationRecord, TopologyOperationTargetRecord};
use crate::direct_upload::{MAX_DIRECT_PART_BYTES, MAX_DIRECT_PARTS, MIN_DIRECT_PART_BYTES};
use crate::domain::Permission;
use crate::storage_authority::{StorageGuardStamp, canonical_digest, lease::LeaseInteger};

/// Compact physical ownership and positive receipt transitions.
pub mod session;

/// Fresh metadata-only application controls and compact retained progress.
pub mod control;

/// Read-only selectors for discovering an already retained copy original.
pub mod original_lookup;

/// Bounded installed-profile and retained-owner queries under a live SQL claim.
pub mod metadata;

/// Compact projections of genuine permanent source closures.
pub mod source;

/// Historical exact codec observations without transport or dispatch permission.
pub mod observation;

/// Independently pinned source and destination domains for cross-binding copies.
pub mod transfer;

pub use transfer::{CopyIncarnationMode, CopySourceBindingPin, CopyTransferPins};

/// Maximum encoded immutable original retained in the physical guard.
pub const MAX_EXTERNAL_COPY_ORIGINAL_BYTES: usize = 16 * 1024;

/// Seals the existing operation's immutable identity and both placement targets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyTopologyOriginal {
    /// Existing durable topology operation identity, never a request UUID.
    pub operation_id: String,
    /// Closed retained operation family.
    pub operation_kind: CopyOperationKind,
    /// Immutable authorization scope captured when the operation was scheduled.
    pub authorization_scope_key: String,
    /// Exact canonical control permission retained by the operation.
    pub control_permission: String,
    /// Original scheduling time, independent of later claim or retry times.
    pub created_at: LeaseInteger,
    /// Sealed source placement target.
    pub source: CopyTarget,
    /// Sealed primary destination placement target.
    pub destination: CopyTarget,
}

/// Distinguishes the two existing placement-copy operation families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyOperationKind {
    /// Copies a placement into another placement.
    ReplicatePlacement,
    /// Repairs a placement using its explicitly sealed source.
    RepairPlacement,
}

/// Retains one sealed placement target without resolving its current SQL row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyTarget {
    /// Stable placement identity retained by the topology operation.
    pub stable_id: String,
    /// Original authorization scope, preserved without aliasing the primary.
    pub authorization_scope_key: String,
    /// Original exact canonical control permission.
    pub control_permission: String,
    /// Exact placement generation captured at scheduling.
    pub generation_key: LeaseInteger,
    /// Original configuration digest, or empty when the sealed target has none.
    pub configuration_digest: String,
}

impl CopyTopologyOriginal {
    /// Projects only immutable fields from an existing operation and targets.
    ///
    /// This does not establish a live claim or current authorization. Native
    /// must independently check both before issuing each provider permission.
    ///
    /// # Errors
    /// Returns an error for another operation family, incorrect target roles,
    /// cross-operation targets, or a primary target different from the original.
    pub fn from_records(
        operation: &TopologyOperationRecord,
        source: &TopologyOperationTargetRecord,
        destination: &TopologyOperationTargetRecord,
    ) -> Result<Self> {
        let operation_kind = match operation.operation_kind.as_str() {
            "replicate_placement" => CopyOperationKind::ReplicatePlacement,
            "repair_placement" => CopyOperationKind::RepairPlacement,
            _ => anyhow::bail!("unsupported external placement copy operation"),
        };
        ensure!(
            source.operation_id == operation.operation_id
                && destination.operation_id == operation.operation_id
                && source.role == "source"
                && destination.role == "primary"
                && source.target_kind == "placement"
                && destination.target_kind == "placement"
                && operation.primary_target_kind == "placement"
                && destination.stable_id == operation.primary_target_stable_id
                && destination.generation_key == operation.primary_target_generation_key
                && destination.configuration_digest
                    == operation.primary_target_configuration_digest,
            "copy targets differ from retained topology original"
        );
        let target = |record: &TopologyOperationTargetRecord| -> Result<CopyTarget> {
            Ok(CopyTarget {
                stable_id: record.stable_id.clone(),
                authorization_scope_key: record.authorization_scope_key.clone(),
                control_permission: record.control_permission.as_str().into(),
                generation_key: LeaseInteger::new(record.generation_key)?,
                configuration_digest: record.configuration_digest.clone(),
            })
        };
        let value = Self {
            operation_id: operation.operation_id.clone(),
            operation_kind,
            authorization_scope_key: operation.authorization_scope_key.clone(),
            control_permission: operation.control_permission.clone(),
            created_at: LeaseInteger::new(operation.created_at)?,
            source: target(source)?,
            destination: target(destination)?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks the closed original without consulting or modifying SQL.
    ///
    /// # Errors
    /// Returns an error for malformed identities, scopes, permissions or pins.
    pub fn validate(&self) -> Result<()> {
        identifier(&self.operation_id)?;
        scope(&self.authorization_scope_key)?;
        ensure!(
            matches!(
                Permission::parse(&self.control_permission),
                Some(Permission::StorageManage | Permission::PlacementManage)
            ) && self.created_at.get() > 0,
            "invalid placement-copy control original"
        );
        // SQL preserves the operation permission on the primary target and
        // assigns PlacementManage to a secondary placement independently.
        for (target, expected_permission) in [
            (&self.source, Permission::PlacementManage.as_str()),
            (&self.destination, self.control_permission.as_str()),
        ] {
            // SQL placement targets include the owning stable identity and
            // '/placement:' suffix. Preserve the existing selector contract;
            // the Native adapter resolves this exact string before pinning IDs.
            ensure!(
                !target.stable_id.trim().is_empty()
                    && target.stable_id == target.stable_id.trim()
                    && target.stable_id.len() <= 255
                    && !target.stable_id.chars().any(char::is_control),
                "invalid sealed copy target identity"
            );
            scope(&target.authorization_scope_key)?;
            ensure!(
                target.control_permission == expected_permission
                    && target.generation_key.get() > 0
                    && (target.configuration_digest.is_empty()
                        || digest_string(&target.configuration_digest)),
                "invalid sealed copy target"
            );
        }
        ensure!(
            self.source.stable_id != self.destination.stable_id,
            "copy requires distinct sealed placements"
        );
        Ok(())
    }
}

/// Freezes the actual placement row paired with its sealed stable target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopyPlacementPin {
    /// Actual SQL placement identity.
    pub placement_id: LeaseInteger,
    /// Actual binding containing this placement.
    pub binding_id: LeaseInteger,
    /// Exact placement resource version.
    pub resource_version: LeaseInteger,
    /// Exact desired write-spec version.
    pub write_spec_version: LeaseInteger,
    /// Registry owning the placement, exclusive with the cache identity.
    pub registry_id: Option<LeaseInteger>,
    /// Binary cache owning the placement, exclusive with the registry identity.
    pub cache_id: Option<LeaseInteger>,
    /// Exact surface-relative placement prefix.
    pub prefix: String,
}

impl CopyPlacementPin {
    /// Projects current row pins without assigning a different stable identity.
    ///
    /// # Errors
    /// Returns an error for a stale sealed target or malformed placement row.
    pub fn from_record(record: &SurfacePlacementRecord, target: &CopyTarget) -> Result<Self> {
        ensure!(
            record.resource_version == target.generation_key.get(),
            "copy placement differs from sealed generation"
        );
        let value = Self {
            placement_id: LeaseInteger::new(record.id)?,
            binding_id: LeaseInteger::new(record.binding_id)?,
            resource_version: LeaseInteger::new(record.resource_version)?,
            write_spec_version: LeaseInteger::new(record.write_spec_version)?,
            registry_id: record.registry_id.map(LeaseInteger::new).transpose()?,
            cache_id: record.cache_id.map(LeaseInteger::new).transpose()?,
            prefix: record.prefix.clone(),
        };
        value.validate(target)?;
        Ok(value)
    }

    fn validate(&self, target: &CopyTarget) -> Result<()> {
        ensure!(
            self.placement_id.get() > 0
                && self.binding_id.get() > 0
                && self.resource_version == target.generation_key
                && self.write_spec_version.get() > 0
                && (self.registry_id.is_some() ^ self.cache_id.is_some())
                && self.registry_id.is_none_or(|id| id.get() > 0)
                && self.cache_id.is_none_or(|id| id.get() > 0)
                && crate::storage_work::valid_relative_path(&self.prefix, true),
            "invalid copy placement pins"
        );
        Ok(())
    }
}

/// Identifies the immutable provider object selected by a conditional source read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySourceObject {
    /// Actual immutable provider version, present only for versioned objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
    /// Actual strong quoted provider entity tag, paired with the version.
    pub etag: String,
    /// Exact known length that bounds all conditional source ranges.
    pub bytes: LeaseInteger,
    /// Positive permanent physical-key incarnation for a versionless object.
    /// The guard must independently verify its actual closed receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_stamp: Option<StorageGuardStamp>,
}

impl CopySourceObject {
    /// Checks exact provider identity and the existing storage-work size bound.
    ///
    /// # Errors
    /// Returns an error for missing or ambiguous incarnation, weak tag or an
    /// excessive length. A valid shape does not establish guard receipt custody.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (match (&self.provider_version, &self.guard_stamp) {
                (Some(version), None) =>
                    crate::storage_work::valid_provider_version(version) && version != "null",
                (None, Some(_)) => true,
                _ => false,
            }) && crate::surface_write::strong_if_match_etag(&self.etag)? == self.etag
                && self.bytes.get() as u64 <= crate::storage_work::MAX_VERIFY_SOURCE_BYTES,
            "external copy requires a bounded immutable source incarnation"
        );
        Ok(())
    }

    /// Borrows the immutable provider version without accepting a guard stamp.
    ///
    /// # Errors
    /// Returns an error for a protected versionless incarnation or invalid shape.
    pub fn require_provider_version(&self) -> Result<&str> {
        self.validate()?;
        self.provider_version
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("immutable provider version required"))
    }
}

/// Retains the full original for one object in a same-binding topology copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCopyOriginal {
    /// One/two retain same-binding forms; three independently pins both bindings.
    pub version: u8,
    /// Original Native and Worker deployment identity.
    pub deployment_id: String,
    /// Existing durable topology operation and exact sealed targets.
    pub topology: CopyTopologyOriginal,
    /// Actual destination binding, shared by both placements in versions one/two.
    pub binding_id: LeaseInteger,
    /// Immutable logical binding identity.
    pub binding_stable_id: String,
    /// Exact SQL binding resource version.
    pub binding_resource_version: LeaseInteger,
    /// Exact nonsecret immutable provider snapshot revision.
    pub snapshot_revision: String,
    /// Source placement row paired with the sealed source target.
    pub source: CopyPlacementPin,
    /// Destination placement row paired with the sealed primary target.
    pub destination: CopyPlacementPin,
    /// Unmodified relative object path, bounded by the existing path contract.
    pub path: String,
    /// Provider incarnation selected before any destination mutation.
    pub source_object: CopySourceObject,
    /// Independently selected purpose-local read credential generation.
    pub read_generation: LeaseInteger,
    /// Independently selected purpose-local write credential generation.
    pub write_generation: LeaseInteger,
    /// Current immutable destination writer revision.
    pub binding_write_revision: LeaseInteger,
    /// Independently accepted producer/runtime profile commitment.
    pub profile_digest: String,
    /// Negotiated part size; stream chunks remain separately bounded.
    pub part_bytes: LeaseInteger,
    /// Existing authoritative SHA-256, when known before the conditional read.
    /// Absence requires computing the complete source hash beside storage.
    pub expected_sha256: Option<String>,
    /// Exact retained positive source receipt commitment for a versionless copy.
    /// Absence preserves the original version-one byte contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt_digest: Option<String>,
    /// Independent cross-binding domains; omitted from old canonical originals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer: Option<transfer::CopyTransferPins>,
}

impl ExternalCopyOriginal {
    /// Checks closed geometry and exact same-binding original pins.
    ///
    /// # Errors
    /// Returns an error for malformed, cross-surface or cross-placement pins,
    /// source identity, missing credential generations or multipart geometry.
    pub fn validate(&self) -> Result<()> {
        self.topology.validate()?;
        self.source.validate(&self.topology.source)?;
        self.destination.validate(&self.topology.destination)?;
        self.source_object.validate()?;
        identifier(&self.deployment_id)?;
        identifier(&self.binding_stable_id)?;
        let part_bytes = self.part_bytes.get() as u64;
        let binding_geometry = match (&self.transfer, self.version) {
            (None, 1 | 2) => {
                self.source.binding_id == self.binding_id
                    && self.source.prefix != self.destination.prefix
            }
            (Some(transfer), 3) => {
                transfer.validate(&self.source, &self.destination)?;
                ensure!(
                    transfer.source_binding.binding_stable_id != self.binding_stable_id
                        && transfer.source_binding.read_generation == self.read_generation
                        && part_bytes <= transfer.maximum_source_range_bytes.get() as u64,
                    "cross-binding source identity or multipart range differs"
                );
                true
            }
            _ => false,
        };
        let source_incarnation = match self.source_incarnation()? {
            transfer::CopyIncarnationMode::ProviderVersion => {
                self.source_object.provider_version.is_some()
                    && self.source_receipt_digest.is_none()
            }
            transfer::CopyIncarnationMode::GuardedClosure => {
                self.source_object.guard_stamp.is_some()
                    && self
                        .source_receipt_digest
                        .as_ref()
                        .is_some_and(|value| digest_string(value))
                    && self.expected_sha256.is_some()
                    && self.transfer.as_ref().is_none_or(|transfer| {
                        self.source_object
                            .guard_stamp
                            .as_ref()
                            .is_some_and(|stamp| {
                                stamp.physical_authority_id
                                    == transfer.source_binding.physical_authority_id
                            })
                    })
            }
        };
        ensure!(
            source_incarnation
                && binding_geometry
                && self.binding_id.get() > 0
                && self.binding_resource_version.get() > 0
                && self.destination.binding_id == self.binding_id
                && self.source.placement_id != self.destination.placement_id
                && self.source.registry_id == self.destination.registry_id
                && self.source.cache_id == self.destination.cache_id
                && digest_string(&self.snapshot_revision)
                && digest_string(&self.profile_digest)
                && self.read_generation.get() > 0
                && self.write_generation.get() > 0
                && self.binding_write_revision.get() > 0
                && crate::storage_work::valid_relative_path(&self.path, false)
                && (MIN_DIRECT_PART_BYTES..=MAX_DIRECT_PART_BYTES).contains(&part_bytes)
                && self
                    .expected_sha256
                    .as_ref()
                    .is_none_or(|hash| digest_string(hash)),
            "invalid external copy original"
        );
        ensure!(
            self.part_count()? <= MAX_DIRECT_PARTS
                && serde_json::to_vec(self)?.len() <= MAX_EXTERNAL_COPY_ORIGINAL_BYTES,
            "external copy original or multipart count exceeds bound"
        );
        Ok(())
    }

    /// Checks positive destination incarnation against this original's protocol.
    ///
    /// # Errors
    /// Returns an error for an invalid destination, a changed byte count,
    /// a versionless receipt on version one, or a different physical authority.
    pub fn validate_destination(&self, destination: &CopySourceObject) -> Result<()> {
        self.validate()?;
        destination.validate()?;
        ensure!(
            destination.bytes == self.source_object.bytes,
            "copy destination length differs"
        );
        ensure!(
            match self.destination_incarnation()? {
                transfer::CopyIncarnationMode::ProviderVersion =>
                    destination.provider_version.is_some(),
                transfer::CopyIncarnationMode::GuardedClosure => destination
                    .guard_stamp
                    .as_ref()
                    .is_some_and(|destination| match &self.transfer {
                        Some(transfer) =>
                            destination.physical_authority_id
                                == transfer.destination_physical_authority_id,
                        None => self
                            .source_object
                            .guard_stamp
                            .as_ref()
                            .is_some_and(|source| {
                                destination.physical_authority_id == source.physical_authority_id
                            }),
                    }),
            },
            "copy destination incarnation protocol differs"
        );
        Ok(())
    }

    /// Returns the declared source incarnation mode without granting Read permission.
    ///
    /// # Errors
    /// Refuses an unknown version or a missing version-three transfer projection.
    pub fn source_incarnation(&self) -> Result<transfer::CopyIncarnationMode> {
        match self.version {
            1 => Ok(transfer::CopyIncarnationMode::ProviderVersion),
            2 => Ok(transfer::CopyIncarnationMode::GuardedClosure),
            3 => self
                .transfer
                .as_ref()
                .map(|pins| pins.source_incarnation)
                .ok_or_else(|| anyhow::anyhow!("cross-binding source mode absent")),
            _ => anyhow::bail!("copy incarnation version unknown"),
        }
    }

    /// Returns the independently declared destination completion protocol.
    ///
    /// # Errors
    /// Refuses an unknown version or a missing version-three transfer projection.
    pub fn destination_incarnation(&self) -> Result<transfer::CopyIncarnationMode> {
        match self.version {
            1 => Ok(transfer::CopyIncarnationMode::ProviderVersion),
            2 => Ok(transfer::CopyIncarnationMode::GuardedClosure),
            3 => self
                .transfer
                .as_ref()
                .map(|pins| pins.destination_incarnation)
                .ok_or_else(|| anyhow::anyhow!("cross-binding destination mode absent")),
            _ => anyhow::bail!("copy incarnation version unknown"),
        }
    }

    /// Returns the canonical immutable original commitment.
    ///
    /// # Errors
    /// Returns an error for an invalid original or failed serialization.
    pub fn fingerprint(&self) -> Result<String> {
        self.validate()?;
        canonical_digest(self)
    }

    /// Derives one permanent retry identity from the scheduled owner and path.
    ///
    /// Source incarnation and fresh request time are deliberately excluded.
    /// Changing either cannot address a different guard owner after an unknown
    /// first attempt; the guard must compare the full fingerprint instead.
    ///
    /// # Errors
    /// Returns an error for an invalid original or failed serialization.
    pub fn copy_id(&self) -> Result<String> {
        self.validate()?;
        original_lookup::CopyOriginalSelector::from_original(self)?.copy_id()
    }

    /// Returns the exact count of conditional source ranges, including zero.
    ///
    /// # Errors
    /// Returns an error for zero part geometry or an overflowing part count.
    pub fn part_count(&self) -> Result<u32> {
        let part_bytes = self.part_bytes.get() as u64;
        ensure!(part_bytes > 0, "zero copy part size");
        let count = (self.source_object.bytes.get() as u64).div_ceil(part_bytes);
        Ok(u32::try_from(count)?)
    }

    /// Returns the exact offset and known length of one one-based part.
    ///
    /// # Errors
    /// Returns an error for an invalid original, number or overflowing range.
    pub fn part_range(&self, number: u32) -> Result<(u64, u64)> {
        self.validate()?;
        ensure!(
            number > 0 && number <= self.part_count()?,
            "invalid copy part number"
        );
        let offset = u64::from(number - 1)
            .checked_mul(self.part_bytes.get() as u64)
            .ok_or_else(|| anyhow::anyhow!("copy range overflow"))?;
        let size =
            (self.source_object.bytes.get() as u64 - offset).min(self.part_bytes.get() as u64);
        Ok((offset, size))
    }
}

pub(crate) fn digest_string(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            }),
        "invalid external copy identity"
    );
    Ok(())
}

fn scope(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control),
        "invalid external copy authorization scope"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
