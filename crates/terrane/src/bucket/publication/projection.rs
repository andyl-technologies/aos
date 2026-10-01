//! Reconstructs complete portable projections from exact selected snapshots.

use super::{Selected, corrupt};
use crate::bucket::{BucketBinding, FileBucket};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use std::collections::BTreeMap;
use terrane_core::bucket::{BucketCapabilities, BucketKey, GenerationManifest};
use terrane_core::gc::publication::{
    CommittedSelection, PortableCurrent, PortableSnapshot, PublicationState, SelectedHistory,
};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::refs::{RefClass, RefName, RefRecord};

/// Preserves whole selected bytes and explicit absence for every logical key.
pub(super) type Values = BTreeMap<String, Option<Vec<u8>>>;

/// Identifies registered logical values retained by a portable snapshot.
pub(super) fn projectable(key: &str) -> bool {
    matches!(
        key,
        "CAPABILITIES" | "publication/SELECTED-HISTORY" | "gc/lease"
    ) || key.starts_with("refs/")
        || key.starts_with("objects/index/")
}

/// Projects selected payload data while discarding physical collector ownership.
pub(super) fn portable(logical: &Values) -> Values {
    logical
        .iter()
        .filter(|(key, _)| projectable(key))
        .map(|(key, value)| {
            (
                key.clone(),
                if key == "gc/lease" {
                    None
                } else {
                    value.clone()
                },
            )
        })
        .collect()
}

/// Reconstructs a complete checkpoint or a delta over its verified predecessor.
///
/// # Errors
/// Rejects a delta whose exact predecessor projection is unavailable.
pub(super) fn apply(
    snapshot: &PortableSnapshot,
    previous: Option<&Values>,
) -> Result<Values, StoreFailure> {
    let mut values = if snapshot.predecessor.is_some() {
        previous.ok_or_else(corrupt)?.clone()
    } else {
        Values::new()
    };
    for row in &snapshot.projection {
        values.insert(row.key.clone(), row.value.clone());
    }
    Ok(values)
}

/// Borrows mandatory present bytes from a verified selected logical map.
///
/// # Errors
/// Rejects a missing key or explicit absence.
pub(super) fn value<'a>(logical: &'a Values, key: &str) -> Result<&'a [u8], StoreFailure> {
    logical
        .get(key)
        .and_then(Option::as_deref)
        .ok_or_else(corrupt)
}

/// Decodes the whole selected capability value without consulting its cache.
///
/// # Errors
/// Rejects absent or malformed selected capability bytes.
pub(super) fn capabilities(logical: &Values) -> Result<BucketCapabilities, StoreFailure> {
    BucketCapabilities::decode(value(logical, "CAPABILITIES")?).map_err(|_| corrupt())
}

/// Checks monotone capability and complete ref-inventory transition data.
///
/// # Errors
/// Rejects profile, layout or activation changes, generation regression, and
/// disappearance of any previously inventoried ref name.
pub(super) fn validate_successor(previous: &Values, next: &Values) -> Result<(), StoreFailure> {
    let before = capabilities(previous)?;
    let after = capabilities(next)?;
    if before.profile != after.profile
        || before.layout_version != after.layout_version
        || before.publication_protocol != after.publication_protocol
        || after.generation < before.generation
        || before
            .ref_names
            .as_ref()
            .ok_or_else(corrupt)?
            .iter()
            .any(|name| {
                !after
                    .ref_names
                    .as_ref()
                    .is_some_and(|names| names.contains(name))
            })
    {
        return Err(corrupt());
    }
    Ok(())
}

/// Checks complete inventory, retained history, profile and selected catalog bytes.
///
/// # Errors
/// Rejects missing or contradictory logical values and invalid immutable artifacts.
pub(super) fn validate<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
    state: &PublicationState,
    logical: &Values,
) -> Result<(), StoreFailure> {
    let cap = capabilities(logical)?;
    if cap.layout_version != 2
        || cap.profile != bucket.profile()
        || cap.publication_protocol != Some(1)
        || !cap.create_if_absent
        || !cap.compare_and_swap
        || !cap.multi_writer
    {
        return Err(corrupt());
    }
    let names = cap.ref_names.as_ref().ok_or_else(corrupt)?;
    let mut branches = Vec::new();
    for name in names {
        let parsed = RefName::parse(name).map_err(|_| corrupt())?;
        let key = format!("{name}:record");
        let selected = logical.get(&key).ok_or_else(corrupt)?;
        if matches!(
            parsed.class(),
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        ) {
            let retained = state
                .branches
                .iter()
                .find(|row| row.name == *name)
                .ok_or_else(corrupt)?;
            if let Some(bytes) = selected {
                let record = RefRecord::decode(bytes).map_err(|_| corrupt())?;
                if retained.selection != CommittedSelection::Selected(record.into()) {
                    return Err(corrupt());
                }
            }
            branches.push(name.as_str());
        } else if parsed.class() != RefClass::Notes {
            selected
                .as_deref()
                .map(RefRecord::decode)
                .transpose()
                .map_err(|_| corrupt())?;
        }
    }
    if state
        .branches
        .iter()
        .map(|row| row.name.as_str())
        .collect::<Vec<_>>()
        != branches
        || logical
            .keys()
            .filter_map(|key| key.strip_suffix(":record"))
            .any(|name| {
                names
                    .binary_search_by(|item| item.as_bytes().cmp(name.as_bytes()))
                    .is_err()
            })
    {
        return Err(corrupt());
    }
    let history = SelectedHistory::decode(value(logical, "publication/SELECTED-HISTORY")?)
        .map_err(|_| corrupt())?;
    if history.branches != state.branches
        || history.origin != state.binding
        || !logical.contains_key("gc/lease")
    {
        return Err(corrupt());
    }
    if let Some(bytes) = logical.get("gc/lease").and_then(Option::as_deref) {
        terrane_core::gc::GcLease::decode(bytes).map_err(|_| corrupt())?;
    }

    let generation = cap.generation.ok_or_else(corrupt)?;
    let manifest_key = format!("objects/index/{generation}/MANIFEST");
    let manifest =
        GenerationManifest::decode(value(logical, &manifest_key)?).map_err(|_| corrupt())?;
    if manifest.generation != generation
        || manifest.inventory.is_none()
        || manifest.exclusions.is_none()
    {
        return Err(corrupt());
    }
    state
        .check_manifest_burns(&manifest)
        .map_err(|_| corrupt())?;
    for entry in &manifest.shards {
        let index_key = format!("objects/index/{generation}/{}.idx", entry.shard);
        verify(
            value(logical, &index_key)?,
            IdentityKind::Index,
            entry.index_hash,
            entry.index_size,
        )?;
        let shard = u8::try_from(entry.shard).map_err(|_| corrupt())?;
        crate::pack::MergedShard::decode(value(logical, &index_key)?, generation, shard)
            .map_err(|_| corrupt())?;
        if let Some((hash, size)) = entry.filter {
            let filter_key = format!("objects/index/{generation}/{}.flt", entry.shard);
            verify(
                value(logical, &filter_key)?,
                IdentityKind::Filter,
                hash,
                size,
            )?;
        }
    }
    Ok(())
}

fn verify(bytes: &[u8], kind: IdentityKind, hash: [u8; 32], size: u64) -> Result<(), StoreFailure> {
    if bytes.len() as u64 != size {
        return Err(corrupt());
    }
    let identity = TERRANE_V1.from_digest(kind, &hash).map_err(|_| corrupt())?;
    TERRANE_V1.verify(&identity, bytes).map_err(|_| corrupt())
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Makes the selected pointer durable before refreshing any individual cache.
    ///
    /// # Errors
    /// Preserves indeterminate durability failures and rejects conflicting immutable
    /// artifacts. The caller retains stable namespace exclusion throughout.
    pub(super) async fn flush_publication_locked(
        &self,
        selected: &Selected,
    ) -> Result<(), StoreFailure> {
        let control = super::control::Control::open(self, false).await?;
        if control.binding != selected.state.binding {
            return Err(corrupt());
        }
        let pointer = BucketKey::parse("publication/PORTABLE").map_err(|_| corrupt())?;
        let bytes = selected.snapshot.encode().map_err(|_| corrupt())?;
        if self.read_optional(&pointer).await?.as_deref() != Some(bytes.as_slice()) {
            let present = self.read_optional(&pointer).await?.is_some();
            if !self.install(&pointer, &bytes, present).await? {
                return Err(corrupt());
            }
        }

        for (key, value) in &selected.logical {
            control.recheck(&self.inner.fs).await?;
            let key = BucketKey::parse(key).map_err(|_| corrupt())?;
            let current = self.read_optional(&key).await?;
            if current == *value {
                continue;
            }
            match value {
                Some(bytes) => {
                    let replace = current.is_some()
                        && key.mutability() == terrane_core::bucket::Mutability::CompareAndSwap;
                    if !self.install(&key, bytes, replace).await?
                        && self.read_optional(&key).await?.as_ref() != Some(bytes)
                    {
                        return Err(corrupt());
                    }
                }
                None if current.is_some()
                    && key.mutability() == terrane_core::bucket::Mutability::CompareAndSwap =>
                {
                    let path = self.path(&key);
                    self.inner
                        .fs
                        .remove_file(&path)
                        .await
                        .map_err(super::files::io_failure)?;
                    self.inner
                        .fs
                        .sync_directory(path.parent().ok_or_else(corrupt)?)
                        .await
                        .map_err(super::files::io_failure)?;
                }
                None => {}
            }
        }
        control.recheck(&self.inner.fs).await?;
        Ok(())
    }

    /// Reads an exact staged immutable snapshot without discovering by listing.
    ///
    /// # Errors
    /// Rejects missing, mismatched or malformed snapshot bytes.
    pub(super) async fn read_portable_snapshot(
        &self,
        pointer: &PortableCurrent,
    ) -> Result<Vec<u8>, StoreFailure> {
        let key = BucketKey::parse(&pointer.key).map_err(|_| corrupt())?;
        let bytes = self.read_optional(&key).await?.ok_or_else(corrupt)?;
        pointer.check_snapshot(&bytes).map_err(|_| corrupt())?;
        Ok(bytes)
    }
}
