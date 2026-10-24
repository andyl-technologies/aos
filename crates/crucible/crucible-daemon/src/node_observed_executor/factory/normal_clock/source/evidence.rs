//! Retains original Clock evidence and authenticates its complete stored closure.

use std::collections::{BTreeMap, BTreeSet};

use crate::node_qualification::{OriginalCompletionObservation, OriginalCompletionWitness};
use crucible_engine::node_state::NativeArchiveRecord;
use serde::Serialize;

use super::*;

const MAXIMUM_OBJECTS: usize = 4096;
const MAXIMUM_RETAINED_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct Evidence {
    bodies: BTreeMap<ContentRef, Vec<u8>>,
    archives: Vec<NativeArchiveRecord>,
}

impl Evidence {
    pub(super) fn new(
        unit: &unit::Unit,
        population: &population::Population,
    ) -> Result<Self, QualificationError> {
        let mut this = Self {
            bodies: BTreeMap::new(),
            archives: Vec::new(),
        };
        this.archives
            .try_reserve_exact(3)
            .map_err(|_| reject("Clock retained archive slot reservation"))?;
        for (reference, body) in unit.content.iter().chain(&population.content) {
            this.insert(reference, body)?;
        }
        Ok(this)
    }

    fn insert(&mut self, reference: &ContentRef, body: &[u8]) -> Result<(), QualificationError> {
        reference.verify(body)?;
        if let Some(original) = self.bodies.get(reference) {
            return if original.as_slice() == body {
                Ok(())
            } else {
                Err(reject("Clock original body collision"))
            };
        }
        let retained = self
            .bodies
            .values()
            .try_fold(body.len(), |total, next| total.checked_add(next.capacity()))
            .ok_or(reject("Clock original evidence extent overflow"))?;
        if self.bodies.len() >= MAXIMUM_OBJECTS || retained > MAXIMUM_RETAINED_BYTES {
            return Err(reject("Clock whole original evidence credit"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(body.len())
            .map_err(|_| reject("Clock original body reservation"))?;
        bytes.extend_from_slice(body);
        self.bodies.insert(reference.clone(), bytes);
        Ok(())
    }

    pub(super) fn retain_exact(
        &mut self,
        witness: &OriginalCompletionWitness<'_, '_>,
    ) -> Result<(), QualificationError> {
        let OriginalCompletionObservation::Exact(original) = witness.observation() else {
            return Err(reject("Clock evidence is not an exact original"));
        };
        self.insert(witness.reference(), witness.bytes())?;
        self.insert(&original.snapshot_ref, original.snapshot.as_slice())?;
        for object in &original.objects {
            self.insert(&object.reference, &object.bytes)?;
        }
        Ok(())
    }

    pub(super) fn retain_state(
        &mut self,
        witness: &OriginalClockStateWitness<'_>,
    ) -> Result<(), QualificationError> {
        witness.authenticate_current().map_err(failure)?;
        for object in witness.original.admission_cases.retained_objects() {
            self.insert(&object.reference, &object.bytes)?;
        }
        if !self.archives.is_empty() {
            return Err(reject("Clock original archive owners already retained"));
        }
        // These are descriptor-backed authenticated records, not decoded report
        // references or mutable native owners. They keep the genuine signed
        // object inventory readable after original retirement.
        let source = witness
            .programme
            .record
            .as_ref()
            .ok_or(reject("Clock original archive absent"))?;
        source
            .retained_record_requested_storage_data()
            .map_err(failure)?;
        self.archives.push(source.clone());
        for branch in &witness.programme.branches {
            let original = branch
                .future
                .as_ref()
                .ok_or(reject("Clock fresh archive absent"))?;
            original
                .retained_record_requested_storage_data()
                .map_err(failure)?;
            self.archives.push(original.clone());
        }
        Ok(())
    }

    pub(super) fn verify(
        &self,
        reference: &ContentRef,
        maximum_bytes: u64,
        maximum_dependencies: usize,
    ) -> Result<Option<Vec<ContentRef>>, QualificationError> {
        if reference.length.get() > maximum_bytes {
            return Err(reject("Clock evidence object byte ceiling"));
        }
        if let Some(bytes) = self.bodies.get(reference) {
            reference.verify(bytes)?;
            let dependencies = if reference.media_type == "application/json" {
                let value = canonical::parse_json(bytes, MAXIMUM_RETAINED_BYTES)?;
                references(&value, maximum_dependencies)?
            } else {
                Vec::new()
            };
            return Ok(Some(dependencies));
        }
        let maximum = usize::try_from(maximum_bytes)
            .map_err(|_| reject("Clock evidence address-space ceiling"))?;
        for archive in &self.archives {
            if let Some(dependencies) = archive
                .verify_retained_evidence_data(reference, maximum, maximum_dependencies)
                .map_err(failure)?
            {
                return Ok(Some(dependencies));
            }
        }
        Ok(None)
    }

    pub(super) fn retain_result(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), QualificationError> {
        self.insert(reference, bytes)
    }
}

pub(super) fn references(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<ContentRef>, QualificationError> {
    let value = serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)?;
    let mut output = BTreeSet::new();
    let mut pending = vec![(&value, 0usize)];
    let mut visited = 0usize;
    while let Some((value, depth)) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or(reject("Clock evidence node overflow"))?;
        if depth > 64 || visited > 262_144 {
            return Err(reject("Clock evidence metadata geometry"));
        }
        match value {
            serde_json::Value::Object(object) => {
                if object.contains_key("hash")
                    && object.contains_key("length")
                    && object.contains_key("media_type")
                {
                    let reference = serde_json::from_value::<ContentRef>(value.clone())
                        .map_err(crucible_node_format::ContractError::from)?;
                    if !output.contains(&reference) && output.len() >= maximum {
                        return Err(reject("Clock evidence dependency ceiling"));
                    }
                    output.insert(reference);
                } else {
                    if visited
                        .checked_add(pending.len())
                        .and_then(|n| n.checked_add(object.len()))
                        .is_none_or(|n| n > 262_144)
                    {
                        return Err(reject("Clock evidence traversal scratch ceiling"));
                    }
                    pending
                        .try_reserve(object.len())
                        .map_err(|_| reject("Clock evidence scratch reservation"))?;
                    for child in object.values() {
                        pending.push((child, depth + 1));
                    }
                }
            }
            serde_json::Value::Array(array) => {
                if visited
                    .checked_add(pending.len())
                    .and_then(|n| n.checked_add(array.len()))
                    .is_none_or(|n| n > 262_144)
                {
                    return Err(reject("Clock evidence traversal scratch ceiling"));
                }
                pending
                    .try_reserve(array.len())
                    .map_err(|_| reject("Clock evidence scratch reservation"))?;
                for child in array {
                    pending.push((child, depth + 1));
                }
            }
            _ => {}
        }
    }
    Ok(output.into_iter().collect())
}

impl crate::node_qualification::RetainedMetadataOwned for Evidence {
    fn charge(
        &self,
        counter: &mut crate::node_qualification::RetainedMetadataCounter,
    ) -> Result<(), QualificationError> {
        let Self { bodies, archives } = self;
        counter.charge(bodies)?;
        counter.add(
            archives
                .capacity()
                .checked_mul(std::mem::size_of::<NativeArchiveRecord>())
                .ok_or(reject("Clock evidence archive slots overflow"))?,
        )?;
        for archive in archives {
            // The actual existing record method includes its inline header.
            // Those headers are already in the Vec slots; count only children.
            let children = archive
                .retained_record_requested_storage_data()
                .map_err(failure)?
                .checked_sub(std::mem::size_of::<NativeArchiveRecord>())
                .ok_or(reject("Clock evidence archive layout inconsistent"))?;
            counter.add(children)?;
        }
        Ok(())
    }
}
