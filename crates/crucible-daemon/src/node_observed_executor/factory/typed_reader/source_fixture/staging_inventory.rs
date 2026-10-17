//! Regenerates the selected input codec from original producer and native bodies.

use super::super::{invalid, launch};
use crucible::{
    node_adapters::cnp::OriginalRuntimeLineage,
    node_contract::{OriginalInputEvidence, OriginalLineageRow, OriginalPublicationClaim},
    node_scheduling::InputPayload,
};
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::{
    ProviderError,
    reference_lineage::{
        INPUT_LINEAGE_MEDIA_TYPE, InputLineageEntry, InputLineageInventory, InputLineageProducer,
        InputLineageRow,
    },
};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn native_input(
    original: &OriginalRuntimeLineage<'_>,
    claims: &[OriginalPublicationClaim],
) -> Result<OriginalInputEvidence, ProviderError> {
    let source = original.source();
    let public = source.input_batch();
    if public.events.len() != claims.len() || claims.len() > 2 {
        return Err(invalid());
    }
    let native = source.measurement_evidence(80, 1024 * 1024)?;
    let mut bytes = 0usize;
    let mut edges = 0usize;
    let mut objects = 0usize;
    // Count every borrowed body and row occurrence before copying any source
    // body. Aliases are deliberately charged repeatedly here.
    for row in native.objects() {
        bytes = bytes.checked_add(row.bytes().len()).ok_or_else(invalid)?;
        edges = edges
            .checked_add(row.dependencies().len())
            .ok_or_else(invalid)?;
        objects = objects.checked_add(1).ok_or_else(invalid)?;
    }
    for claim in claims {
        if claim.objects.len() != claim.rows.len() {
            return Err(invalid());
        }
        for (body, row) in claim.objects.iter().zip(&claim.rows) {
            if body.reference != row.object {
                return Err(invalid());
            }
            body.reference.verify(&body.bytes)?;
            bytes = bytes.checked_add(body.bytes.len()).ok_or_else(invalid)?;
            edges = edges
                .checked_add(row.dependencies.len())
                .ok_or_else(invalid)?;
            objects = objects.checked_add(1).ok_or_else(invalid)?;
        }
    }
    if objects.checked_add(3).is_none_or(|n| n > 4096)
        || bytes
            .checked_add(3 * 65536)
            .is_none_or(|n| n > MAXIMUM_BYTES)
        || edges.checked_add(14).is_none_or(|n| n > 65536)
    {
        return Err(invalid());
    }
    super::super::super::programme::count(&Metadata(&native), 1024 * 1024)?;
    let mut bodies: BTreeMap<ContentRef, (Vec<u8>, Vec<ContentRef>)> = BTreeMap::new();
    for row in native.objects() {
        insert(
            &mut bodies,
            row.reference(),
            row.bytes(),
            row.dependencies(),
        )?;
    }
    let mut inventory_rows = BTreeMap::new();
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(claims.len())
        .map_err(|_| invalid())?;
    for (delivered, claim) in public.events.iter().zip(claims) {
        for (body, row) in claim.objects.iter().zip(&claim.rows) {
            insert(&mut bodies, &body.reference, &body.bytes, &row.dependencies)?;
            if inventory_rows
                .insert(row.object.clone(), row.dependencies.clone())
                .is_some_and(|old| old != row.dependencies)
            {
                return Err(invalid());
            }
        }
        let bytes = launch::encode(delivered, 65536)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let mut dependencies = vec![delivered.payload.clone(), delivered.provenance_ref.clone()];
        dependencies.sort();
        dependencies.dedup();
        insert(&mut bodies, &reference, &bytes, &dependencies)?;
        if inventory_rows
            .insert(reference.clone(), dependencies)
            .is_some()
        {
            return Err(invalid());
        }
        let origin = &claim.origin;
        entries.push(InputLineageEntry {
            delivered: reference,
            published: claim.published.clone(),
            producer: InputLineageProducer {
                owner_binding_hash: origin.owner_binding_hash.clone(),
                execution_owner_id: origin.execution_owner_id.clone(),
                session_id: origin.session_id.clone(),
                world_binding_hash: origin.world_binding_hash.clone(),
                activation_id: origin.activation_id.clone(),
                world_generation: origin.world_generation,
                incarnation_id: origin.incarnation_id.clone(),
                owner_generation: origin.owner_generation,
                operation_id: origin.operation_id.clone(),
                grant_id: origin.grant_id.clone(),
                observation_batch: origin.observation_batch.clone(),
                stop_receipt: origin.stop_receipt.clone(),
                measurement: origin.measurement.clone(),
            },
        });
    }
    let inventory = InputLineageInventory {
        schema_version: 1,
        execution_owner_id: public.execution_owner_id.clone(),
        owner_generation: source.stop().owner_generation,
        input_epoch: public.input_epoch.clone(),
        batch_id: public.batch_id.clone(),
        batch_sequence: public.batch_sequence,
        entries,
        dependencies: inventory_rows
            .into_iter()
            .map(|(object, dependencies)| InputLineageRow {
                object,
                dependencies,
            })
            .collect(),
    };
    inventory.validate_bodies(public, source.stop().owner_generation, |reference| {
        bodies
            .get(reference)
            .map(|row| row.0.as_slice())
            .ok_or_else(invalid)
    })?;
    let public_bytes = launch::encode(public, 65536)?;
    let public_ref = canonical::content_ref(&public_bytes, "application/json")?;
    let row = bodies.get(&public_ref).ok_or_else(invalid)?;
    if row.0 != public_bytes {
        return Err(invalid());
    }
    let selected: Vec<_> = row
        .1
        .iter()
        .filter(|reference| reference.media_type == INPUT_LINEAGE_MEDIA_TYPE)
        .collect();
    let [selected] = selected.as_slice() else {
        return Err(invalid());
    };
    let selected = (*selected).clone();
    let maximum = usize::try_from(selected.length.get())
        .map_err(|_| invalid())?
        .min(65536);
    let inventory_bytes = launch::encode(&inventory, maximum)?;
    selected.verify(&inventory_bytes)?;
    let mut dependencies = Vec::new();
    for entry in &inventory.entries {
        dependencies.extend([
            entry.delivered.clone(),
            entry.published.clone(),
            entry.producer.observation_batch.clone(),
            entry.producer.stop_receipt.clone(),
            entry.producer.measurement.clone(),
        ]);
    }
    dependencies.sort();
    dependencies.dedup();
    insert(&mut bodies, &selected, &inventory_bytes, &dependencies)?;
    let root = source.stop().input_custody.clone();
    let mut pending = VecDeque::from([root.clone()]);
    let mut reachable = BTreeSet::new();
    let mut total = 0usize;
    while let Some(reference) = pending.pop_front() {
        if !reachable.insert(reference.clone()) {
            continue;
        }
        let row = bodies.get(&reference).ok_or_else(invalid)?;
        total = total
            .checked_add(row.1.len())
            .filter(|n| *n <= 65536)
            .ok_or_else(invalid)?;
        pending.extend(row.1.iter().cloned());
    }
    let mut objects = Vec::new();
    let mut rows = Vec::new();
    objects
        .try_reserve_exact(reachable.len())
        .map_err(|_| invalid())?;
    rows.try_reserve_exact(reachable.len())
        .map_err(|_| invalid())?;
    for reference in reachable {
        let (bytes, dependencies) = bodies.remove(&reference).ok_or_else(invalid)?;
        rows.push(OriginalLineageRow {
            object: reference.clone(),
            dependencies,
        });
        objects.push(InputPayload { reference, bytes });
    }
    Ok(OriginalInputEvidence {
        root,
        objects,
        rows,
    })
}

fn insert(
    map: &mut BTreeMap<ContentRef, (Vec<u8>, Vec<ContentRef>)>,
    reference: &ContentRef,
    bytes: &[u8],
    dependencies: &[ContentRef],
) -> Result<(), ProviderError> {
    reference.verify(bytes)?;
    if dependencies.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid());
    }
    if let Some(old) = map.get(reference) {
        return if old.0 == bytes && old.1 == dependencies {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    map.insert(reference.clone(), (bytes.to_vec(), dependencies.to_vec()));
    Ok(())
}

struct Metadata<'a>(&'a crucible_node_provider::client::OriginalLineageEvidence<'a>);
impl Serialize for Metadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.objects().len()))?;
        for row in self.0.objects() {
            sequence.serialize_element(&(row.reference(), row.dependencies()))?;
        }
        sequence.end()
    }
}
