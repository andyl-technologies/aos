//! Complete consumed proof leaves under bounded replay-native capture credit.

use super::*;

pub(super) struct ReplayDependencies<'a> {
    objects: BTreeMap<&'a ContentRef, &'a [u8]>,
    inventories: Vec<InputPayload>,
    total: usize,
}

impl<'a> ReplayDependencies<'a> {
    pub(super) fn prepare(
        source: &'a AuthenticatedTranscript,
        next: usize,
        qualification: &'a InputPayload,
        inputs: &[&'a SavedRuntimeInput],
        custody: impl Iterator<Item = &'a InputPayload>,
        limits: NativeCaptureLimits,
    ) -> Result<Self, OperationFailure> {
        let records = source.data.records.get(..next).ok_or_else(|| {
            failure(
                "replay dependency cursor exceeds source",
                EffectKnowledge::None,
            )
        })?;
        let mut objects = BTreeMap::new();
        objects.insert(source.reference(), source.bytes());
        objects.insert(&qualification.reference, qualification.bytes.as_slice());
        for object in records
            .iter()
            .flat_map(|record| &record.evidence)
            .chain(inputs.iter().flat_map(|input| &input.payloads))
            .chain(custody)
        {
            if objects.len() >= limits.maximum_objects && !objects.contains_key(&object.reference) {
                return Err(failure(
                    "replay native dependency count exceeds credit",
                    EffectKnowledge::None,
                ));
            }
            if objects
                .insert(&object.reference, &object.bytes)
                .is_some_and(|original| original != object.bytes)
            {
                return Err(failure(
                    "replay native dependency body differs",
                    EffectKnowledge::None,
                ));
            }
        }
        let mut total = 0usize;
        for (reference, bytes) in &objects {
            reference
                .verify(bytes)
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            total = checked_extent(total, bytes.len(), limits)?;
        }
        let mut inventories = Vec::new();
        let mut inventory_refs = BTreeSet::new();
        for input in inputs {
            if objects.contains_key(&input.inventory) || !inventory_refs.insert(&input.inventory) {
                continue;
            }
            let length = usize::try_from(input.inventory.length.get())
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            // This is the coordinator's original canonical inventory encoding,
            // not a synthesized native receipt. Its full original typed identity
            // must verify before any body enters the dependency registry.
            checked_extent(total, length, limits)?;
            if objects
                .len()
                .checked_add(inventories.len())
                .and_then(|count| count.checked_add(2))
                .is_none_or(|count| count > limits.maximum_objects)
            {
                return Err(failure(
                    "replay inventory dependency count exceeds credit",
                    EffectKnowledge::None,
                ));
            }
            let bytes = bounded_canonical(&input.deliveries, length)?;
            input
                .inventory
                .verify(&bytes)
                .map_err(|error| failure(error, EffectKnowledge::None))?;
            total = checked_extent(total, bytes.len(), limits)?;
            inventories.push(InputPayload {
                reference: input.inventory.clone(),
                bytes,
            });
        }
        if objects
            .len()
            .checked_add(inventories.len())
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > limits.maximum_objects)
        {
            return Err(failure(
                "complete replay native evidence exceeds object credit",
                EffectKnowledge::None,
            ));
        }
        Ok(Self {
            objects,
            inventories,
            total,
        })
    }

    pub(super) fn bytes(&self) -> usize {
        self.total
    }

    pub(super) fn references(&self) -> BTreeSet<ContentRef> {
        self.objects
            .keys()
            .map(|reference| (*reference).clone())
            .chain(
                self.inventories
                    .iter()
                    .map(|object| object.reference.clone()),
            )
            .collect()
    }

    pub(super) fn verify_registry(
        &self,
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<(), OperationFailure> {
        for (reference, bytes) in &self.objects {
            if content.get(reference) != Some(*bytes) {
                return Err(failure(
                    "original replay native proof leaf absent or changed",
                    EffectKnowledge::None,
                ));
            }
        }
        for object in &self.inventories {
            if content.get(&object.reference) != Some(object.bytes.as_slice()) {
                return Err(failure(
                    "original replay coordinator inventory absent or changed",
                    EffectKnowledge::None,
                ));
            }
        }
        Ok(())
    }

    pub(super) fn materialize(self) -> Vec<InputPayload> {
        self.objects
            .into_iter()
            .map(|(reference, bytes)| InputPayload {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            })
            .chain(self.inventories)
            .collect()
    }
}

fn checked_extent(
    total: usize,
    length: usize,
    limits: NativeCaptureLimits,
) -> Result<usize, OperationFailure> {
    if length > limits.maximum_record_bytes {
        return Err(failure(
            "original replay native proof exceeds record credit",
            EffectKnowledge::None,
        ));
    }
    total
        .checked_add(length)
        .filter(|sum| *sum <= limits.maximum_total_record_bytes)
        .ok_or_else(|| {
            failure(
                "complete replay native proof bytes exceed credit",
                EffectKnowledge::None,
            )
        })
}
