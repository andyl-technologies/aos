//! Enumerates explicitly selected native and recording evidence dependencies.
//!
//! This table begins with the independently inspected native codec rows. Only
//! two closed recording metadata codecs add edges. Unknown bodies remain absent
//! and must refuse; a missing row never denotes a leaf.

use std::collections::BTreeMap;

use crucible::node_contract::{
    SavedOriginalInputLineage, SavedOriginalPublication, SavedRuntimeActivation,
};
use crucible_node_contract::{ContentRef, HashRef, Id, canonical};
use serde::Deserialize;

use super::{conditional_capture_scope::refused, conditional_profile::ConditionalProfile};
use crucible::node_state::StateError;

pub(super) const MAXIMUM_ROWS: usize = 4096;
const MAXIMUM_EDGES: usize = 65_536;
const PROOF_MEDIA: &str = "application/vnd.crucible.transcript-producer-proof+json;version=1";
const LINEAGE_MEDIA: &str = "application/vnd.crucible.transcript-original-lineage+json;version=2";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofClosure {
    schema_version: u16,
    world: HashRef,
    node: Id,
    owners: Vec<crucible::node_contract::OwnerIdentity>,
    root: ContentRef,
    dependencies: Vec<ContentRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLineage {
    schema_version: u16,
    source_capture: SavedRuntimeActivation,
    node: Id,
    interaction: Id,
    lineage: RecordedKind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RecordedKind {
    Publication {
        publication: Box<SavedOriginalPublication>,
    },
    Input {
        input: Box<SavedOriginalInputLineage>,
    },
}

/// Reuses original codec rows only after the complete native history inspector.
pub(super) fn original_rows(
    profile: &ConditionalProfile,
) -> Result<BTreeMap<ContentRef, Vec<ContentRef>>, StateError> {
    // Count even repeated occurrences conservatively before copying any native
    // vector. Deduplication later cannot enlarge this declared reservation.
    let mut occurrences = 0usize;
    let mut edges = 0usize;
    for claim in &profile.history.publications {
        for row in &claim.rows {
            precredit(&mut occurrences, &mut edges, row.dependencies.len())?;
        }
    }
    for source in profile.history.originals.values() {
        for record in &source.transcript().records {
            for object in &record.evidence {
                let count = match object.reference.media_type.as_str() {
                    PROOF_MEDIA | LINEAGE_MEDIA => {
                        metadata_credit(&object.reference, &object.bytes)?
                    }
                    _ => continue,
                };
                precredit(&mut occurrences, &mut edges, count)?;
            }
        }
    }

    let mut rows = BTreeMap::new();
    for claim in &profile.history.publications {
        for row in &claim.rows {
            let bytes = profile
                .history
                .objects
                .get(&row.object)
                .ok_or_else(|| refused("inspected native body is absent"))?;
            row.object.verify(bytes).map_err(refused)?;
            insert(&mut rows, row.object.clone(), row.dependencies.clone())?;
        }
    }

    for (node, source) in &profile.history.originals {
        let origin = &source.transcript().origin;
        for record in &source.transcript().records {
            for object in &record.evidence {
                let edges = match object.reference.media_type.as_str() {
                    PROOF_MEDIA => {
                        let data: ProofClosure = decode(&object.reference, &object.bytes)?;
                        if data.schema_version != 1
                            || data.world != origin.activation.world_binding_hash
                            || data.node != *node
                            || data.owners != origin.route.owners
                            || data.dependencies.contains(&data.root)
                        {
                            return Err(refused("original producer proof closure changed scope"));
                        }
                        let mut edges = data.dependencies;
                        if edges.len() >= MAXIMUM_ROWS {
                            return Err(refused("original producer proof adjacency exhausted"));
                        }
                        edges.push(data.root);
                        edges
                    }
                    LINEAGE_MEDIA => {
                        let data: RecordedLineage = decode(&object.reference, &object.bytes)?;
                        if data.schema_version != 2
                            || data.source_capture != origin.activation
                            || data.node != *node
                            || data.interaction != record.request.identity
                        {
                            return Err(refused("original recorded lineage changed scope"));
                        }
                        match data.lineage {
                            RecordedKind::Publication { publication } => {
                                if !profile.history.publications.contains(&publication) {
                                    return Err(refused(
                                        "uninspected original publication metadata",
                                    ));
                                }
                                publication.objects
                            }
                            RecordedKind::Input { input } => {
                                if !profile.history.inputs.contains(&input) {
                                    return Err(refused("uninspected original input metadata"));
                                }
                                let count = input
                                    .publications
                                    .iter()
                                    .try_fold(0usize, |n, claim| {
                                        n.checked_add(claim.objects.len())
                                            .filter(|n| *n <= MAXIMUM_ROWS)
                                    })
                                    .ok_or_else(|| {
                                        refused("original input metadata adjacency exhausted")
                                    })?;
                                let mut edges = Vec::new();
                                edges.try_reserve_exact(count).map_err(refused)?;
                                for claim in &input.publications {
                                    edges.extend(claim.objects.iter().cloned());
                                }
                                edges
                            }
                        }
                    }
                    _ => continue,
                };
                insert(&mut rows, object.reference.clone(), edges)?;
            }
        }
    }
    super::conditional_terminal_rows::install(profile, &mut rows)?;
    Ok(rows)
}

/// Installs an explicit authenticated row without reclassifying existing roles.
pub(super) fn insert(
    rows: &mut BTreeMap<ContentRef, Vec<ContentRef>>,
    reference: ContentRef,
    mut dependencies: Vec<ContentRef>,
) -> Result<(), StateError> {
    if dependencies.len() > MAXIMUM_ROWS {
        return Err(refused(
            "explicit original adjacency exceeds its declared credit",
        ));
    }
    dependencies.sort();
    dependencies.dedup();
    if let Some(original) = rows.get(&reference) {
        return if original == &dependencies {
            Ok(())
        } else {
            Err(refused(
                "conflicting explicit dependency roles for an original body",
            ))
        };
    }
    let edges = rows.values().try_fold(dependencies.len(), |n, row| {
        n.checked_add(row.len()).filter(|n| *n <= MAXIMUM_EDGES)
    });
    if rows.len() >= MAXIMUM_ROWS || edges.is_none() {
        return Err(refused("explicit original dependency inventory exhausted"));
    }
    rows.insert(reference, dependencies);
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<T, StateError> {
    reference.verify(bytes).map_err(refused)?;
    let value = canonical::parse_json(bytes, 1024 * 1024).map_err(refused)?;
    if canonical::canonical_json(&value).map_err(refused)? != bytes {
        return Err(refused(
            "original recording metadata bytes are not canonical",
        ));
    }
    serde_json::from_value(value).map_err(refused)
}

fn precredit(rows: &mut usize, edges: &mut usize, additional: usize) -> Result<(), StateError> {
    *rows = rows
        .checked_add(1)
        .filter(|count| *count <= MAXIMUM_ROWS)
        .ok_or_else(|| refused("original dependency occurrence credit exhausted"))?;
    *edges = edges
        .checked_add(additional)
        .filter(|count| additional <= MAXIMUM_ROWS && *count <= MAXIMUM_EDGES)
        .ok_or_else(|| refused("original dependency edge credit exhausted"))?;
    Ok(())
}

/// Checks raw named arrays before typed reconstruction allocates their vectors.
fn metadata_credit(reference: &ContentRef, bytes: &[u8]) -> Result<usize, StateError> {
    reference.verify(bytes).map_err(refused)?;
    let value = canonical::parse_json(bytes, 1024 * 1024).map_err(refused)?;
    let array = |value: &serde_json::Value, field: &str| {
        value
            .get(field)
            .and_then(serde_json::Value::as_array)
            .map(|items| items.len())
            .ok_or_else(|| refused("original recording role array is absent"))
    };
    if reference.media_type == PROOF_MEDIA {
        return array(&value, "dependencies")?
            .checked_add(1)
            .ok_or_else(|| refused("original producer proof adjacency overflow"));
    }
    let lineage = value
        .get("lineage")
        .ok_or_else(|| refused("original recording lineage is absent"))?;
    match lineage.get("kind").and_then(serde_json::Value::as_str) {
        Some("publication") => array(&lineage["publication"], "objects"),
        Some("input") => {
            let publications = lineage["input"]
                .get("publications")
                .and_then(serde_json::Value::as_array)
                .filter(|rows| rows.len() <= 64)
                .ok_or_else(|| refused("original input publication credit exhausted"))?;
            publications.iter().try_fold(0usize, |count, row| {
                count
                    .checked_add(array(row, "objects")?)
                    .filter(|count| *count <= MAXIMUM_ROWS)
                    .ok_or_else(|| refused("original input metadata edge credit exhausted"))
            })
        }
        _ => Err(refused("unsupported original recording lineage kind")),
    }
}
