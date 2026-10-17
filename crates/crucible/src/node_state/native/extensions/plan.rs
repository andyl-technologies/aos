//! Prepares bounded original semantic bytes before any autonomous capture effect.

use std::collections::{BTreeMap, BTreeSet};

use crucible_node_contract::{ContentRef, Validate, canonical};
use serde::Serialize;

use crate::node_admission::AdmittedGraph;
use crate::node_scheduling::InputPayload;
use crate::node_state::{StateError, StateErrorCode, StateLimits};

use super::{ExtensionDependencyRecord, ExtensionInventory, NativeExtensionPreservationPolicy};

/// Owns prepared semantic data without granting native capture or restoration.
pub(crate) struct PreparedExtensionClosure {
    pub inventory: ExtensionInventory,
    pub objects: Vec<InputPayload>,
    pub record: InputPayload,
}

/// Prepares exact original selected bytes under the installed native codec.
///
/// # Errors
/// Refuses operational scopes, unsupported semantic policies, altered bodies,
/// unknown dependency rows, cycles, excessive depth or unavailable finite credit.
pub(crate) fn prepare(
    graph: &AdmittedGraph,
    policy: &dyn NativeExtensionPreservationPolicy,
    limits: StateLimits,
) -> Result<PreparedExtensionClosure, StateError> {
    let supported = StateLimits::default();
    // Immutable installation artifacts may have a larger operator-selected
    // object allowance. That never enlarges this selected semantic codec.
    let limits = StateLimits {
        maximum_content_bytes: limits
            .maximum_content_bytes
            .min(supported.maximum_content_bytes),
        ..limits
    };
    if limits.maximum_record_bytes > supported.maximum_record_bytes
        || limits.maximum_total_content_bytes > supported.maximum_total_content_bytes
        || limits.maximum_content_objects > supported.maximum_content_objects
        || limits.maximum_dependency_edges > supported.maximum_dependency_edges
        || limits.maximum_dependency_depth > supported.maximum_dependency_depth
    {
        return Err(bounded("supported extension codec ceilings"));
    }
    let selected = graph.selected_extensions();
    if selected.is_empty() {
        return Err(refused(
            "extension-aware edition requires actual selected semantics",
        ));
    }
    // The signed inventory is itself an immutable root and owns every body.
    // Reserve that first edge so this preflight bounds the complete closure.
    let body_depth = limits
        .maximum_dependency_depth
        .checked_sub(1)
        .ok_or_else(|| bounded("complete extension inventory root depth"))?;
    if selected
        .applications()
        .any(|application| !application.scope().record_kind().is_durable())
    {
        return Err(refused(
            "operational extension scopes require an installed original-to-fresh mapping codec",
        ));
    }

    let count = selected
        .objects()
        .len()
        .checked_add(selected.applications().len())
        .and_then(|count| count.checked_add(selected.definitions().len()))
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| bounded("extension object count"))?;
    if count > limits.maximum_content_objects {
        return Err(bounded("extension object slots"));
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(count)
        .map_err(|_| bounded("extension object slots"))?;
    let mut applications = Vec::new();
    applications
        .try_reserve_exact(selected.applications().len())
        .map_err(|_| bounded("extension application slots"))?;
    let mut definitions = Vec::new();
    definitions
        .try_reserve_exact(selected.definitions().len())
        .map_err(|_| bounded("extension definition slots"))?;
    let mut total = 0;
    let mut identities = BTreeSet::new();
    for (reference, bytes) in selected.objects() {
        append(
            &mut objects,
            &mut identities,
            &mut total,
            reference,
            bytes,
            limits,
        )?;
    }
    for application in selected.applications() {
        let bytes = encode(application, limits.maximum_content_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
        append(
            &mut objects,
            &mut identities,
            &mut total,
            &reference,
            &bytes,
            limits,
        )?;
        applications.push(reference);
    }
    for definition in selected.definitions() {
        let bytes = encode(definition, limits.maximum_content_bytes)?;
        let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
        append(
            &mut objects,
            &mut identities,
            &mut total,
            &reference,
            &bytes,
            limits,
        )?;
        definitions.push(reference);
    }

    // None of the data above grants native permission. The installed policy
    // must independently qualify the exact handlers and native preservation
    // profile before a selected body can be interpreted as a complete codec.
    policy.authenticate_selection(graph)?;
    let remaining = limits
        .maximum_total_content_bytes
        .checked_sub(total)
        .ok_or_else(|| bounded("extension policy byte credit"))?;
    let (policy_reference, bytes) = policy.policy(limits.maximum_content_bytes.min(remaining))?;
    append(
        &mut objects,
        &mut identities,
        &mut total,
        &policy_reference,
        &bytes,
        limits,
    )?;

    objects.sort_by(|left, right| left.reference.cmp(&right.reference));
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(objects.len())
        .map_err(|_| bounded("extension dependency rows"))?;
    // The inventory root owns every prepared body; reserve that fanout too.
    let mut remaining_edges = limits
        .maximum_dependency_edges
        .checked_sub(objects.len())
        .ok_or_else(|| bounded("complete extension inventory root edges"))?;
    for object in &objects {
        let row_credit = remaining_edges.min(objects.len());
        let row = policy.dependencies(graph, &object.reference, &object.bytes, row_credit)?;
        if row.len() > row_credit || row.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(bounded("complete sorted extension dependency row"));
        }
        for reference in &row {
            reference.validate().map_err(invalid)?;
            if !identities.contains(reference) {
                return Err(refused(
                    "extension codec dependency is outside exact retained selection",
                ));
            }
        }
        remaining_edges -= row.len();
        dependencies.push(ExtensionDependencyRecord {
            reference: object.reference.clone(),
            dependencies: row,
        });
    }
    check_depth(&dependencies, body_depth)?;

    let inventory = ExtensionInventory {
        schema_version: 1,
        world_binding_hash: graph.world_binding_hash().clone(),
        selection_identity: selected.identity().map_err(invalid)?,
        policy: policy_reference,
        applications,
        definitions,
        dependencies,
    };
    let bytes = encode(&inventory, limits.maximum_record_bytes)?;
    if bytes.len() > limits.maximum_content_bytes
        || total
            .checked_add(bytes.len())
            .is_none_or(|total| total > limits.maximum_total_content_bytes)
    {
        return Err(bounded("complete extension inventory byte credit"));
    }
    let reference = canonical::content_ref(&bytes, "application/json").map_err(invalid)?;
    Ok(PreparedExtensionClosure {
        inventory,
        objects,
        record: InputPayload { reference, bytes },
    })
}

fn append(
    objects: &mut Vec<InputPayload>,
    identities: &mut BTreeSet<ContentRef>,
    total: &mut usize,
    reference: &ContentRef,
    bytes: &[u8],
    limits: StateLimits,
) -> Result<(), StateError> {
    if bytes.len() > limits.maximum_content_bytes {
        return Err(bounded("extension body byte credit"));
    }
    reference.verify(bytes).map_err(invalid)?;
    if identities.contains(reference) {
        return Ok(());
    }
    let next = total
        .checked_add(bytes.len())
        .ok_or_else(|| bounded("extension bytes"))?;
    if next > limits.maximum_total_content_bytes {
        return Err(bounded("extension body byte credit"));
    }
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(bytes.len())
        .map_err(|_| bounded("extension body allocation"))?;
    retained.extend_from_slice(bytes);
    objects.push(InputPayload {
        reference: reference.clone(),
        bytes: retained,
    });
    identities.insert(reference.clone());
    *total = next;
    Ok(())
}

fn check_depth(rows: &[ExtensionDependencyRecord], maximum: usize) -> Result<(), StateError> {
    let graph: BTreeMap<_, _> = rows
        .iter()
        .map(|row| (&row.reference, &row.dependencies))
        .collect();
    let mut heights: BTreeMap<ContentRef, usize> = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(rows.len())
        .map_err(|_| bounded("extension dependency traversal"))?;
    for root in rows {
        pending.push((&root.reference, false));
        while let Some((reference, closing)) = pending.pop() {
            if heights.contains_key(reference) {
                continue;
            }
            let dependencies = graph
                .get(reference)
                .ok_or_else(|| refused("extension dependency row absent"))?;
            if closing {
                let mut height = 0;
                for dependency in dependencies.iter() {
                    let child_height: usize = *heights
                        .get(dependency)
                        .ok_or_else(|| refused("extension dependency was not closed"))?;
                    height = height.max(
                        child_height
                            .checked_add(1)
                            .ok_or_else(|| bounded("extension dependency depth"))?,
                    );
                }
                if height > maximum {
                    return Err(refused("extension dependency depth is unsupported"));
                }
                active.remove(reference);
                heights.insert(reference.clone(), height);
                continue;
            }
            if !active.insert(reference) {
                return Err(refused("extension dependency cycle is unsupported"));
            }
            pending
                .try_reserve(dependencies.len().saturating_add(1))
                .map_err(|_| bounded("extension dependency traversal"))?;
            pending.push((reference, true));
            for dependency in dependencies.iter().rev() {
                pending.push((dependency, false));
            }
        }
    }
    Ok(())
}

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, StateError> {
    crate::node_state::closure::bounded_record(value, maximum)?;
    let value = serde_json::to_value(value).map_err(invalid)?;
    let bytes = canonical::canonical_json(&value).map_err(invalid)?;
    if bytes.len() > maximum {
        return Err(bounded("extension canonical record"));
    }
    Ok(bytes)
}

fn refused(reason: impl Into<String>) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "native extension closure",
        reason,
    )
}

fn bounded(component: &str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        component,
        "finite extension closure credit exhausted",
    )
}

fn invalid(error: impl std::fmt::Display) -> StateError {
    StateError::new(
        StateErrorCode::Content,
        "native extension closure",
        error.to_string(),
    )
}
