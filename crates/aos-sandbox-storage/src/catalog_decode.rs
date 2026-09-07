//! Strict typed recovery for the node-local resolved Storage catalog.
//!
//! The encoder lives beside the catalog types. This decoder deliberately
//! reconstructs those types only through their checked constructors, then the
//! caller re-encodes and byte-compares the result. That makes redundant
//! postcondition fields and unused operation fields part of the canonical
//! contract without maintaining a second semantic validator here.

use std::str;

use aos_sandbox_core::ObjectDigest;

use crate::{
    ActiveHoldEvidence, CatalogPlanV1, CatalogSemanticError, HoldId, ManagedDatasetRoot,
    PlannedDataset, PlannedSnapshot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
    ResolvedSnapshot, StorageDomainsV1, WorkspaceSpacePolicyV1,
};

const FORMAT_MAGIC: &[u8; 8] = b"AOSSCAT1";
const FORMAT_VERSION: u16 = 2;
const MAXIMUM_CANONICAL_BYTES: usize = 16 * 1024;

pub(crate) fn decode_catalog(
    bytes: &[u8],
) -> Result<(u64, StorageDomainsV1, CatalogPlanV1), CatalogSemanticError> {
    if bytes.is_empty() || bytes.len() > MAXIMUM_CANONICAL_BYTES {
        return Err(CatalogSemanticError::MalformedEncoding);
    }

    let mut decoder = Decoder::new(bytes);
    if required_array::<8>(decoder.field(1)?)? != *FORMAT_MAGIC {
        return Err(CatalogSemanticError::MalformedEncoding);
    }
    let version = required_u16(decoder.field(2)?)?;
    if version != FORMAT_VERSION {
        return Err(CatalogSemanticError::UnsupportedEncodingVersion);
    }
    let generation = required_u64(decoder.field(3)?)?;
    let pool = required_text(decoder.field(4)?)?;
    let dataset_prefix = required_text(decoder.field(5)?)?;
    let root_guid = required_u64(decoder.field(6)?)?;
    let domains = StorageDomainsV1::new(
        ObjectDigest::from_bytes(required_array(decoder.field(7)?)?),
        ObjectDigest::from_bytes(required_array(decoder.field(8)?)?),
        ObjectDigest::from_bytes(required_array(decoder.field(9)?)?),
        ObjectDigest::from_bytes(required_array(decoder.field(10)?)?),
    )?;
    let root = ManagedDatasetRoot::from_catalog(pool, dataset_prefix, root_guid)?;

    let operation_code = required_byte(decoder.field(11)?)?;
    let primary_name = text(decoder.field(12)?)?;
    let primary_guid = required_u64(decoder.field(13)?)?;
    let destination_name = text(decoder.field(14)?)?;
    let hold_id = optional_array(decoder.field(15)?)?
        .map(HoldId::from_bytes)
        .transpose()?;
    let raw_space = RawSpace::decode(&mut decoder)?;
    let primary_dataset_guid = required_u64(decoder.field(23)?)?;
    let ancestor_handle = optional_array(decoder.field(24)?)?;
    let storage_handle = optional_array(decoder.field(26)?)?;
    let version_handle = optional_array(decoder.field(27)?)?;

    // These redundant fields must be present in exact order. The caller's
    // re-encoding comparison validates their full contents against `plan`.
    for tag in 28..=37 {
        let _ = decoder.field(tag)?;
    }
    decoder.finish()?;

    let space = raw_space.finish(&root, domains, ancestor_handle)?;
    let plan = decode_plan(
        operation_code,
        &root,
        domains,
        primary_name,
        primary_guid,
        primary_dataset_guid,
        destination_name,
        hold_id,
        space,
        storage_handle,
        version_handle,
    )?;

    Ok((generation, domains, plan))
}

#[allow(clippy::too_many_arguments)]
fn decode_plan(
    operation_code: u8,
    root: &ManagedDatasetRoot,
    domains: StorageDomainsV1,
    primary_name: &str,
    primary_guid: u64,
    primary_dataset_guid: u64,
    destination_name: &str,
    hold_id: Option<HoldId>,
    space: Option<(WorkspaceSpacePolicyV1, ProjectAncestorPolicyV1)>,
    storage_handle: Option<[u8; 32]>,
    version_handle: Option<[u8; 32]>,
) -> Result<CatalogPlanV1, CatalogSemanticError> {
    match operation_code {
        1 => {
            let (space, ancestor) = required_space(space)?;
            Ok(CatalogPlanV1::CreateWorkspace {
                destination: PlannedDataset::from_catalog(root.clone(), destination_name, domains)?,
                space,
                ancestor,
            })
        }
        2 => {
            let storage_handle = required_value(storage_handle)?;
            let source = ResolvedDataset::from_catalog(
                root.clone(),
                primary_name,
                primary_guid,
                storage_handle,
                domains,
            )?;
            let (_, component) = snapshot_name(destination_name)?;
            Ok(CatalogPlanV1::Snapshot {
                destination: PlannedSnapshot::from_catalog(source.clone(), component)?,
                source,
            })
        }
        3 | 4 => {
            let snapshot = resolved_snapshot(
                root,
                domains,
                primary_name,
                primary_guid,
                primary_dataset_guid,
                required_value(storage_handle)?,
                required_value(version_handle)?,
            )?;
            let hold_id = required_value(hold_id)?;
            if operation_code == 3 {
                Ok(CatalogPlanV1::HoldSnapshot { snapshot, hold_id })
            } else {
                Ok(CatalogPlanV1::ReleaseHold { snapshot, hold_id })
            }
        }
        5 => {
            let source = resolved_snapshot(
                root,
                domains,
                primary_name,
                primary_guid,
                primary_dataset_guid,
                required_value(storage_handle)?,
                required_value(version_handle)?,
            )?;
            let hold_id = required_value(hold_id)?;
            let (space, ancestor) = required_space(space)?;
            Ok(CatalogPlanV1::Clone {
                origin_hold: ActiveHoldEvidence::from_catalog(primary_guid, hold_id)?,
                source: Box::new(source),
                destination: PlannedDataset::from_catalog(root.clone(), destination_name, domains)?,
                space,
                ancestor,
            })
        }
        6 => {
            let (space, ancestor) = required_space(space)?;
            Ok(CatalogPlanV1::SetQuota {
                dataset: ResolvedDataset::from_catalog(
                    root.clone(),
                    primary_name,
                    primary_guid,
                    required_value(storage_handle)?,
                    domains,
                )?,
                space,
                ancestor,
            })
        }
        7 => Ok(CatalogPlanV1::DestroyDataset {
            dataset: ResolvedDataset::from_catalog(
                root.clone(),
                primary_name,
                primary_guid,
                required_value(storage_handle)?,
                domains,
            )?,
        }),
        8 => Ok(CatalogPlanV1::DestroySnapshot {
            snapshot: resolved_snapshot(
                root,
                domains,
                primary_name,
                primary_guid,
                primary_dataset_guid,
                required_value(storage_handle)?,
                required_value(version_handle)?,
            )?,
        }),
        _ => Err(CatalogSemanticError::MalformedEncoding),
    }
}

fn resolved_snapshot(
    root: &ManagedDatasetRoot,
    domains: StorageDomainsV1,
    name: &str,
    snapshot_guid: u64,
    dataset_guid: u64,
    storage_handle: [u8; 32],
    version_handle: [u8; 32],
) -> Result<ResolvedSnapshot, CatalogSemanticError> {
    let (dataset_name, component) = snapshot_name(name)?;
    let dataset = ResolvedDataset::from_catalog(
        root.clone(),
        dataset_name,
        dataset_guid,
        storage_handle,
        domains,
    )?;
    ResolvedSnapshot::from_catalog(dataset, component, snapshot_guid, version_handle)
}

fn snapshot_name(name: &str) -> Result<(&str, &str), CatalogSemanticError> {
    name.rsplit_once('@')
        .filter(|(dataset, component)| !dataset.is_empty() && !component.is_empty())
        .ok_or(CatalogSemanticError::MalformedEncoding)
}

fn required_space(
    value: Option<(WorkspaceSpacePolicyV1, ProjectAncestorPolicyV1)>,
) -> Result<(WorkspaceSpacePolicyV1, ProjectAncestorPolicyV1), CatalogSemanticError> {
    required_value(value)
}

fn required_value<T>(value: Option<T>) -> Result<T, CatalogSemanticError> {
    value.ok_or(CatalogSemanticError::MalformedEncoding)
}

struct RawSpace<'a> {
    quota: Option<u64>,
    reservation: &'a [u8],
    ancestor_name: &'a str,
    ancestor_guid: Option<u64>,
    ancestor_quota: Option<u64>,
    filesystem_limit: Option<u64>,
    snapshot_limit: Option<u64>,
}

impl<'a> RawSpace<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> Result<Self, CatalogSemanticError> {
        Ok(Self {
            quota: optional_u64(decoder.field(16)?)?,
            reservation: decoder.field(17)?,
            ancestor_name: text(decoder.field(18)?)?,
            ancestor_guid: optional_u64(decoder.field(19)?)?,
            ancestor_quota: optional_u64(decoder.field(20)?)?,
            filesystem_limit: optional_u64(decoder.field(21)?)?,
            snapshot_limit: optional_u64(decoder.field(22)?)?,
        })
    }

    fn finish(
        self,
        root: &ManagedDatasetRoot,
        domains: StorageDomainsV1,
        ancestor_handle: Option<[u8; 32]>,
    ) -> Result<Option<(WorkspaceSpacePolicyV1, ProjectAncestorPolicyV1)>, CatalogSemanticError>
    {
        let absent = self.quota.is_none()
            && self.reservation.is_empty()
            && self.ancestor_name.is_empty()
            && self.ancestor_guid.is_none()
            && self.ancestor_quota.is_none()
            && self.filesystem_limit.is_none()
            && self.snapshot_limit.is_none()
            && ancestor_handle.is_none();
        if absent {
            return Ok(None);
        }

        let reservation = match self.reservation {
            [0] => ReservationPolicy::None,
            [1, bytes @ ..] if bytes.len() == 8 => ReservationPolicy::Exact(u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| CatalogSemanticError::MalformedEncoding)?,
            )),
            _ => return Err(CatalogSemanticError::MalformedEncoding),
        };
        let space = WorkspaceSpacePolicyV1::new(required_value(self.quota)?, reservation)?;
        let ancestor_dataset = ResolvedDataset::from_catalog(
            root.clone(),
            self.ancestor_name,
            required_value(self.ancestor_guid)?,
            required_value(ancestor_handle)?,
            domains,
        )?;
        let ancestor = ProjectAncestorPolicyV1::new(
            ancestor_dataset,
            required_value(self.ancestor_quota)?,
            required_value(self.filesystem_limit)?,
            required_value(self.snapshot_limit)?,
        )?;
        Ok(Some((space, ancestor)))
    }
}

fn required_text(bytes: &[u8]) -> Result<&str, CatalogSemanticError> {
    let value = text(bytes)?;
    if value.is_empty() {
        Err(CatalogSemanticError::MalformedEncoding)
    } else {
        Ok(value)
    }
}

fn text(bytes: &[u8]) -> Result<&str, CatalogSemanticError> {
    str::from_utf8(bytes).map_err(|_| CatalogSemanticError::MalformedEncoding)
}

fn required_byte(bytes: &[u8]) -> Result<u8, CatalogSemanticError> {
    required_array::<1>(bytes).map(|value| value[0])
}

fn required_u16(bytes: &[u8]) -> Result<u16, CatalogSemanticError> {
    required_array(bytes).map(u16::from_be_bytes)
}

fn required_u64(bytes: &[u8]) -> Result<u64, CatalogSemanticError> {
    required_array(bytes).map(u64::from_be_bytes)
}

fn optional_u64(bytes: &[u8]) -> Result<Option<u64>, CatalogSemanticError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        required_u64(bytes).map(Some)
    }
}

fn required_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CatalogSemanticError> {
    bytes
        .try_into()
        .map_err(|_| CatalogSemanticError::MalformedEncoding)
}

fn optional_array<const N: usize>(bytes: &[u8]) -> Result<Option<[u8; N]>, CatalogSemanticError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        required_array(bytes).map(Some)
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn field(&mut self, expected_tag: u8) -> Result<&'a [u8], CatalogSemanticError> {
        let header_end = self
            .offset
            .checked_add(5)
            .ok_or(CatalogSemanticError::MalformedEncoding)?;
        let header = self
            .bytes
            .get(self.offset..header_end)
            .ok_or(CatalogSemanticError::MalformedEncoding)?;
        if header[0] != expected_tag {
            return Err(CatalogSemanticError::MalformedEncoding);
        }
        let length = u32::from_be_bytes(
            header[1..]
                .try_into()
                .map_err(|_| CatalogSemanticError::MalformedEncoding)?,
        ) as usize;
        let end = header_end
            .checked_add(length)
            .ok_or(CatalogSemanticError::MalformedEncoding)?;
        let value = self
            .bytes
            .get(header_end..end)
            .ok_or(CatalogSemanticError::MalformedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), CatalogSemanticError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CatalogSemanticError::MalformedEncoding)
        }
    }
}
