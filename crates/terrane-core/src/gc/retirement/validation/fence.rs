//! Checks complete represented fence inventories, stamps and selected payloads.
//!
//! No data check proves roots are exhaustive or an actual backend is current.

use super::*;
use crate::bucket::{BucketCapabilities, GenerationManifest};
use crate::gc::publication::{CommittedSelection, PortableCurrent};
use crate::refs::{RefClass, RefName, RefRecord};

fn cycle_key(pointer: &RecordPointer, leaf: &str) -> Result<u64, RetirementError> {
    let mut parts = pointer.key.split('/');
    if parts.next() != Some("gc") {
        return Err(RetirementError::Schema);
    }
    let cycle = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next() != Some(leaf) || parts.next().is_some() {
        return Err(RetirementError::Schema);
    }
    Ok(cycle)
}

pub(super) fn fence_pointer(pointer: &RecordPointer) -> Result<(u64, u64), RetirementError> {
    let mut parts = pointer.key.split('/');
    if parts.next() != Some("gc") {
        return Err(RetirementError::Schema);
    }
    let cycle = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next() != Some("fence") {
        return Err(RetirementError::Schema);
    }
    let revision = decimal(parts.next().ok_or(RetirementError::Schema)?)?;
    if parts.next().is_some() {
        return Err(RetirementError::Schema);
    }
    Ok((cycle, revision))
}

/// Checks one represented ref row and returns its canonical class.
///
/// Notes retain opaque current bytes under their existing format. No row check
/// establishes completeness, source authority or actual serving eligibility.
///
/// # Errors
/// Rejects malformed names/current records or contradictory selection/log values.
pub(in crate::gc::retirement) fn ref_row(row: &FenceRef) -> Result<RefClass, RetirementError> {
    let class = RefName::parse(&row.name)
        .map_err(|_| RetirementError::Schema)?
        .class();
    crate::bucket::BucketKey::parse(&row.name).map_err(|_| RetirementError::Schema)?;
    let branch = matches!(
        class,
        RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
    );
    if class != RefClass::Notes {
        let current = row
            .current
            .as_deref()
            .map(RefRecord::decode)
            .transpose()
            .map_err(|error| RetirementError::Publication(PublicationError::Ref(error)))?;
        if branch
            && let Some(current) = current
            && row.selection != CommittedSelection::Selected(current.into())
        {
            return Err(RetirementError::Contradiction);
        }
    }

    match (&row.selection, &row.log) {
        (CommittedSelection::Selected(record), Some(log)) if log.record == **record => {
            log.encode()
                .map_err(|error| RetirementError::Publication(PublicationError::Ref(error)))?;
        }
        (CommittedSelection::Never | CommittedSelection::Unknown, None) => {}
        _ => return Err(RetirementError::Contradiction),
    }
    Ok(class)
}

pub(in crate::gc::retirement) fn current(
    value: &CurrentCollectionFence,
) -> Result<(), RetirementError> {
    value.state.encode()?;
    value.backend.encode()?;
    let capabilities = BucketCapabilities::decode(&value.capabilities)?;
    if value.state.binding != value.backend || value.state.guard != Some(value.guard) {
        return Err(RetirementError::Contradiction);
    }
    if cycle_key(&value.roots, "roots")? != cycle_key(&value.marks, "state")? {
        return Err(RetirementError::Contradiction);
    }
    let names = capabilities
        .ref_names
        .as_ref()
        .ok_or(RetirementError::Contradiction)?;
    if names.len() != value.refs.len() {
        return Err(RetirementError::Contradiction);
    }
    let mut branches = Vec::new();
    for (name, row) in names.iter().zip(&value.refs) {
        if name != &row.name {
            return Err(RetirementError::Contradiction);
        }
        let class = ref_row(row)?;
        let branch = matches!(
            class,
            RefClass::Heads | RefClass::Jobs | RefClass::Conflicts | RefClass::Derived
        );
        if branch {
            let retained = value
                .state
                .branches
                .iter()
                .find(|prior| &prior.name == name)
                .ok_or(RetirementError::Contradiction)?;
            if retained.selection != row.selection {
                return Err(RetirementError::Contradiction);
            }
            branches.push(name);
        }
    }
    if value
        .state
        .branches
        .iter()
        .map(|row| &row.name)
        .collect::<Vec<_>>()
        != branches
    {
        return Err(RetirementError::Contradiction);
    }

    match (&value.manifest, capabilities.generation) {
        (Some(bytes), Some(generation)) => {
            let manifest = GenerationManifest::decode(bytes)?;
            if manifest.generation != generation {
                return Err(RetirementError::Contradiction);
            }
            value.state.check_manifest_burns(&manifest)?;
        }
        (None, None) => {
            if value
                .state
                .burn_owners
                .as_ref()
                .is_some_and(|owners| !owners.is_empty())
            {
                return Err(RetirementError::Contradiction);
            }
        }
        _ => return Err(RetirementError::Contradiction),
    }
    let mut previous = None;
    for pin in &value.controls {
        pin.encode()?;
        let owner = pin.owner.encode()?;
        let current = (pin.kind, owner, pin.key.as_str());
        if previous.as_ref().is_some_and(|prior| prior >= &current) {
            return Err(RetirementError::Schema);
        }
        previous = Some(current);
    }
    Ok(())
}

pub(in crate::gc::retirement) fn copied(
    value: &CopiedPlacementFence,
) -> Result<(), RetirementError> {
    current(&value.current_fields())?;
    let manifest = GenerationManifest::decode(&value.manifest)?;
    if manifest.inventory.is_none()
        || manifest.exclusions.is_none()
        || manifest.burns.is_none()
        || value.state.burn_owners.is_none()
        || value.genesis.revision != 0
    {
        return Err(RetirementError::Contradiction);
    }
    let projection = PortableCurrent {
        key: value.projection.key.clone(),
        digest: value.projection.digest,
    };
    projection.encode()?;
    let suffix = value
        .projection
        .key
        .strip_prefix("publication/snapshots/")
        .ok_or(RetirementError::Schema)?;
    let (revision, _) = suffix.split_once(':').ok_or(RetirementError::Schema)?;
    if decimal(revision)? != value.state.revision {
        return Err(RetirementError::Contradiction);
    }
    Ok(())
}

impl CopiedPlacementFence {
    /// Forms the common current-fence fields without changing their meaning.
    pub(crate) fn current_fields(&self) -> CurrentCollectionFence {
        CurrentCollectionFence {
            capabilities: self.capabilities.clone(),
            manifest: Some(self.manifest.clone()),
            refs: self.refs.clone(),
            guard: self.guard,
            state: self.state.clone(),
            roots: self.roots.clone(),
            marks: self.marks.clone(),
            backend: self.backend.clone(),
            controls: self.controls.clone(),
        }
    }
}

impl CurrentCollectionFence {
    /// Checks this exact fence's key, digest and represented predecessor revision.
    ///
    /// # Errors
    /// Rejects malformed fences, a wrong cycle/revision or raw digest mismatch.
    pub fn check_pointer(&self, pointer: &RecordPointer) -> Result<(), RetirementError> {
        let bytes = self.encode()?;
        let (cycle, revision) = fence_pointer(pointer)?;
        if cycle != cycle_key(&self.roots, "roots")?
            || revision != self.state.revision
            || pointer.digest != *blake3::hash(&bytes).as_bytes()
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}

impl CopiedPlacementFence {
    /// Checks this exact placement fence's key, digest and predecessor revision.
    ///
    /// # Errors
    /// Rejects malformed fences, a wrong cycle/revision or raw digest mismatch.
    pub fn check_pointer(&self, pointer: &RecordPointer) -> Result<(), RetirementError> {
        let bytes = self.encode()?;
        let (cycle, revision) = fence_pointer(pointer)?;
        if cycle != cycle_key(&self.roots, "roots")?
            || revision != self.state.revision
            || pointer.digest != *blake3::hash(&bytes).as_bytes()
        {
            return Err(RetirementError::Contradiction);
        }
        Ok(())
    }
}
