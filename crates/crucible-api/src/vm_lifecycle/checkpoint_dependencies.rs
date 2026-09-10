//! Transitive signal-artifact discovery for production checkpoint closures.
//!
//! The authored program stores only content identities. This module resolves
//! those identities before launch and expands the two artifact formats that
//! contain further references: normalized traces and tiled spatial grids.

use super::*;
use crate::LifecycleResourceLimit;
use crucible::model::{
    FaultResourceLimits, FaultSignalPlan, InverseCdfTable, NormalizedSpatialArtifact,
    SignalNodeKind, SignalSourceSpecification, SignalTraceManifest, SpatialArtifactKind,
};

/// Resolves and authenticates the transitive object closure of a signal plan.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when an object is absent, corrupt, exceeds the
/// plan's resource limits, or contains an unauthenticated transitive reference.
pub fn collect_signal_artifact_objects(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
) -> Result<BTreeMap<ContentHash, Vec<u8>>, LifecycleApiError> {
    collect_signal_artifact_objects_bounded(
        plan,
        store,
        plan.resource_limits().fat_checkpoint_bytes,
    )
}

/// Resolves a signal closure under an additional caller-supplied byte ceiling.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when an object is absent, corrupt, exceeds the
/// plan's resource limits, or would make the retained closure exceed
/// `max_retained_bytes`.
pub fn collect_signal_artifact_objects_bounded(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
    max_retained_bytes: u64,
) -> Result<BTreeMap<ContentHash, Vec<u8>>, LifecycleApiError> {
    collect_signal_artifact_objects_with_budget(
        plan,
        store,
        max_retained_bytes,
        &BTreeSet::new(),
        0,
        max_retained_bytes,
    )
}

/// Resolves a signal closure against lifecycle and publication byte budgets.
///
/// Identities in `precharged_identities` are still authenticated and returned,
/// but their bytes count only through `precharged_bytes` for the publication
/// budget. Every retained signal object counts toward `max_lifecycle_bytes`.
/// This supports one unique-byte allowance shared with another artifact role
/// without weakening the lifecycle-specific allowance.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when an object is absent, corrupt, exceeds the
/// plan's resource limits or `max_lifecycle_bytes`, or would exceed
/// `max_static_bytes` together with `precharged_bytes`.
pub fn collect_signal_artifact_objects_with_budget(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
    max_lifecycle_bytes: u64,
    precharged_identities: &BTreeSet<ContentHash>,
    precharged_bytes: u64,
    max_static_bytes: u64,
) -> Result<BTreeMap<ContentHash, Vec<u8>>, LifecycleApiError> {
    if precharged_bytes > max_static_bytes {
        return Err(capture_limit(
            "finding_production_replay_static_bytes",
            precharged_bytes,
            0,
            max_static_bytes,
            plan.resource_limits().fat_checkpoint_bytes,
        ));
    }
    let budget = SignalCaptureBudget {
        max_lifecycle_bytes,
        precharged_identities,
        precharged_bytes,
        max_static_bytes,
    };
    let mut objects = BTreeMap::new();
    for program in plan.programs() {
        for node in program.nodes() {
            let SignalNodeKind::Source(source) = &node.kind else {
                continue;
            };
            collect_source_bounded(source, store, plan.resource_limits(), budget, &mut objects)?;
        }
    }
    Ok(objects)
}

#[cfg(test)]
fn collect_source(
    source: &SignalSourceSpecification,
    store: &dyn DagStore,
    limits: FaultResourceLimits,
    objects: &mut BTreeMap<ContentHash, Vec<u8>>,
) -> Result<(), LifecycleApiError> {
    collect_source_bounded(
        source,
        store,
        limits,
        SignalCaptureBudget {
            max_lifecycle_bytes: limits.fat_checkpoint_bytes,
            precharged_identities: &BTreeSet::new(),
            precharged_bytes: 0,
            max_static_bytes: limits.fat_checkpoint_bytes,
        },
        objects,
    )
}

#[derive(Clone, Copy)]
struct SignalCaptureBudget<'a> {
    max_lifecycle_bytes: u64,
    precharged_identities: &'a BTreeSet<ContentHash>,
    precharged_bytes: u64,
    max_static_bytes: u64,
}

fn collect_source_bounded(
    source: &SignalSourceSpecification,
    store: &dyn DagStore,
    limits: FaultResourceLimits,
    budget: SignalCaptureBudget<'_>,
    objects: &mut BTreeMap<ContentHash, Vec<u8>>,
) -> Result<(), LifecycleApiError> {
    match source {
        SignalSourceSpecification::Trace {
            artifact,
            raw_provenance,
            ..
        } => {
            let manifest_bytes = retain_object(*artifact, store, limits, budget, objects)?;
            let manifest = SignalTraceManifest::decode_with_chunk_limit(
                &manifest_bytes,
                usize::try_from(limits.trace_chunks_total).map_err(|_| {
                    loop_factory_error("trace chunk limit is not representable on this host")
                })?,
            )
            .map_err(|error| {
                loop_factory_error(format!("decode signal trace manifest: {error}"))
            })?;
            if manifest.content != *artifact
                || manifest.provenance.raw_content != Some(*raw_provenance)
            {
                return Err(loop_factory_error(
                    "signal trace manifest does not authenticate its authored provenance",
                ));
            }
            retain_object(*raw_provenance, store, limits, budget, objects)?;
            for channel in &manifest.channels {
                for chunk in &channel.chunks {
                    retain_object(chunk.content, store, limits, budget, objects)?;
                }
            }
        }
        SignalSourceSpecification::PointSet { artifact, .. }
        | SignalSourceSpecification::RegularGrid { artifact, .. }
        | SignalSourceSpecification::ZoneMap { artifact, .. }
        | SignalSourceSpecification::PathProfile { artifact, .. } => {
            let bytes = retain_object(*artifact, store, limits, budget, objects)?;
            authenticate_spatial_artifact(*artifact, &bytes)?;
        }
        SignalSourceSpecification::TiledGrid { manifest, .. } => {
            let bytes = retain_object(*manifest, store, limits, budget, objects)?;
            let spatial = authenticate_spatial_artifact(*manifest, &bytes)?;
            let SpatialArtifactKind::TiledGrid { tiles } = spatial.kind() else {
                return Err(loop_factory_error(
                    "tiled-grid signal source references another spatial artifact kind",
                ));
            };
            for tile in tiles {
                let bytes = retain_object(tile.content, store, limits, budget, objects)?;
                let tile_artifact = authenticate_spatial_artifact(tile.content, &bytes)?;
                if !matches!(
                    tile_artifact.kind(),
                    SpatialArtifactKind::RegularGrid { .. }
                ) {
                    return Err(loop_factory_error(
                        "tiled-grid manifest references a non-grid tile artifact",
                    ));
                }
            }
        }
        SignalSourceSpecification::TransmitterField { lookup, .. } => {
            let bytes = retain_object(*lookup, store, limits, budget, objects)?;
            authenticate_spatial_artifact(*lookup, &bytes)?;
        }
        SignalSourceSpecification::ExponentialWait { sampler_table, .. }
        | SignalSourceSpecification::WeibullWait { sampler_table, .. } => {
            let bytes = retain_object(*sampler_table, store, limits, budget, objects)?;
            let table = InverseCdfTable::decode(&bytes).map_err(|error| {
                loop_factory_error(format!("decode inverse-CDF signal artifact: {error}"))
            })?;
            if table.content() != *sampler_table {
                return Err(loop_factory_error(
                    "inverse-CDF signal artifact failed content authentication",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn authenticate_spatial_artifact(
    identity: ContentHash,
    bytes: &[u8],
) -> Result<NormalizedSpatialArtifact, LifecycleApiError> {
    let artifact = NormalizedSpatialArtifact::decode(bytes)
        .map_err(|error| loop_factory_error(format!("decode spatial signal artifact: {error}")))?;
    if artifact.content() != identity {
        return Err(loop_factory_error(
            "spatial signal artifact failed content authentication",
        ));
    }
    Ok(artifact)
}

fn retain_object(
    identity: ContentHash,
    store: &dyn DagStore,
    limits: FaultResourceLimits,
    budget: SignalCaptureBudget<'_>,
    objects: &mut BTreeMap<ContentHash, Vec<u8>>,
) -> Result<Vec<u8>, LifecycleApiError> {
    if let Some(bytes) = objects.get(&identity) {
        return Ok(bytes.clone());
    }
    let bytes = store.get(&identity).map_err(|error| {
        loop_factory_error(format!(
            "read signal artifact {}: {error}",
            identity.to_hex()
        ))
    })?;
    if ContentHash::from_bytes(&bytes) != identity {
        return Err(loop_factory_error(format!(
            "signal artifact {} failed content authentication",
            identity.to_hex()
        )));
    }
    let retained = objects.values().try_fold(0_u64, |total, object| {
        total.checked_add(u64::try_from(object.len()).ok()?)
    });
    let retained = retained
        .ok_or_else(|| loop_factory_error("retained signal artifact byte accounting overflow"))?;
    let requested = u64::try_from(bytes.len())
        .map_err(|_| loop_factory_error("signal artifact size is not representable"))?;
    limits
        .reserve("fat_checkpoint_bytes", retained, requested)
        .map_err(|error| loop_factory_error(error.to_string()))?;
    if retained
        .checked_add(requested)
        .is_none_or(|total| total > budget.max_lifecycle_bytes)
    {
        return Err(capture_limit(
            "finding_production_replay_lifecycle_bytes",
            retained,
            requested,
            budget.max_lifecycle_bytes,
            limits.fat_checkpoint_bytes,
        ));
    }
    let effective_retained = objects
        .iter()
        .filter(|(identity, _)| !budget.precharged_identities.contains(identity))
        .try_fold(budget.precharged_bytes, |total, (_, object)| {
            total.checked_add(u64::try_from(object.len()).ok()?)
        })
        .ok_or_else(|| {
            capture_limit(
                "finding_production_replay_static_bytes",
                budget.precharged_bytes,
                u64::MAX,
                budget.max_static_bytes,
                limits.fat_checkpoint_bytes,
            )
        })?;
    let effective_requested = if budget.precharged_identities.contains(&identity) {
        0
    } else {
        requested
    };
    if effective_retained
        .checked_add(effective_requested)
        .is_none_or(|total| total > budget.max_static_bytes)
    {
        return Err(capture_limit(
            "finding_production_replay_static_bytes",
            effective_retained,
            effective_requested,
            budget.max_static_bytes,
            limits.fat_checkpoint_bytes,
        ));
    }
    objects.insert(identity, bytes.clone());
    Ok(bytes)
}

fn capture_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> LifecycleApiError {
    LifecycleApiError::ResourceLimit(LifecycleResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::{
        MemoryDagStore, SignalBoundaryBehavior, SignalDomain, SignalId, SignalInterpolation,
        SignalNode, SignalProgram, SignalResourceLimits, SignalShape, SignalUnit, SignalValue,
        SignalValueType, SpatialTileReference,
    };

    fn id(value: &str) -> SignalId {
        SignalId::parse(value).unwrap_or_else(|error| panic!("test ID must be valid: {error}"))
    }

    fn shape() -> SignalShape {
        SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("test shape must be valid: {error}"))
    }

    fn regular_grid_plan() -> (FaultSignalPlan, MemoryDagStore, ContentHash, usize) {
        let artifact = NormalizedSpatialArtifact::new(
            id("frame"),
            shape(),
            SpatialArtifactKind::RegularGrid {
                origin_mm: [0; 3],
                cell_size_mm: [1; 3],
                dimensions: [1; 3],
                values: vec![SignalValue::I64(7)],
            },
        )
        .unwrap_or_else(|error| panic!("test artifact must be valid: {error}"));
        let encoded = artifact.encode();
        let signal = id("grid");
        let program = SignalProgram::new(
            vec![SignalNode {
                id: signal.clone(),
                domain: SignalDomain::Spatial,
                output: shape(),
                inputs: Vec::new(),
                kind: SignalNodeKind::Source(SignalSourceSpecification::RegularGrid {
                    artifact: artifact.content(),
                    coordinate_frame: id("frame"),
                    origin_mm: [0; 3],
                    cell_size_mm: [1; 3],
                    dimensions: [1; 3],
                    interpolation: SignalInterpolation::Nearest,
                    outside: SignalBoundaryBehavior::Error,
                }),
            }],
            vec![signal],
            SignalResourceLimits::default(),
        )
        .unwrap_or_else(|error| panic!("test program must be valid: {error}"));
        let plan = FaultSignalPlan::new(vec![program], Vec::new(), FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("test plan must be valid: {error}"));
        let store = MemoryDagStore::new();
        store
            .put(&encoded)
            .unwrap_or_else(|error| panic!("store test artifact: {error}"));

        (plan, store, artifact.content(), encoded.len())
    }

    #[test]
    fn budgeted_dependency_walk_enforces_lifecycle_ceiling_independently() {
        let (plan, store, identity, encoded_len) = regular_grid_plan();
        let encoded_len = u64::try_from(encoded_len).expect("test artifact length fits in u64");
        let lifecycle_limit = encoded_len - 1;
        let precharged_identities = BTreeSet::from([identity]);

        let result = collect_signal_artifact_objects_with_budget(
            &plan,
            &store,
            lifecycle_limit,
            &precharged_identities,
            encoded_len,
            encoded_len,
        );

        let Err(LifecycleApiError::ResourceLimit(limit)) = result else {
            panic!("tighter lifecycle allowance must reject the artifact");
        };
        assert_eq!(limit.field, "finding_production_replay_lifecycle_bytes");
        assert_eq!(limit.current, 0);
        assert_eq!(limit.requested, encoded_len);
        assert_eq!(limit.configured, lifecycle_limit);
    }

    #[test]
    fn tiled_grid_dependency_walk_retains_manifest_and_tile() {
        let tile = NormalizedSpatialArtifact::new(
            id("frame"),
            shape(),
            SpatialArtifactKind::RegularGrid {
                origin_mm: [0; 3],
                cell_size_mm: [10; 3],
                dimensions: [1; 3],
                values: vec![SignalValue::I64(7)],
            },
        )
        .unwrap_or_else(|error| panic!("test tile must be valid: {error}"));
        let manifest = NormalizedSpatialArtifact::new(
            id("frame"),
            shape(),
            SpatialArtifactKind::TiledGrid {
                tiles: vec![SpatialTileReference {
                    minimum_mm: [0; 3],
                    maximum_mm: [10; 3],
                    content: tile.content(),
                }],
            },
        )
        .unwrap_or_else(|error| panic!("test manifest must be valid: {error}"));
        let store = MemoryDagStore::new();
        store
            .put(&tile.encode())
            .unwrap_or_else(|error| panic!("store test tile: {error}"));
        store
            .put(&manifest.encode())
            .unwrap_or_else(|error| panic!("store test manifest: {error}"));
        let source = SignalSourceSpecification::TiledGrid {
            manifest: manifest.content(),
            coordinate_frame: id("frame"),
            tile_size_mm: [10; 3],
            interpolation: SignalInterpolation::Nearest,
            outside: SignalBoundaryBehavior::Error,
        };
        let mut objects = BTreeMap::new();

        collect_source(
            &source,
            &store,
            FaultResourceLimits::default(),
            &mut objects,
        )
        .unwrap_or_else(|error| panic!("walk test dependencies: {error}"));

        assert_eq!(objects.len(), 2);
        assert!(objects.contains_key(&tile.content()));
        assert!(objects.contains_key(&manifest.content()));
    }

    #[test]
    fn dependency_walk_rejects_a_missing_transitive_tile() {
        let missing = ContentHash::from_bytes(b"missing tile");
        let manifest = NormalizedSpatialArtifact::new(
            id("frame"),
            shape(),
            SpatialArtifactKind::TiledGrid {
                tiles: vec![SpatialTileReference {
                    minimum_mm: [0; 3],
                    maximum_mm: [10; 3],
                    content: missing,
                }],
            },
        )
        .unwrap_or_else(|error| panic!("test manifest must be valid: {error}"));
        let store = MemoryDagStore::new();
        store
            .put(&manifest.encode())
            .unwrap_or_else(|error| panic!("store test manifest: {error}"));
        let source = SignalSourceSpecification::TiledGrid {
            manifest: manifest.content(),
            coordinate_frame: id("frame"),
            tile_size_mm: [10; 3],
            interpolation: SignalInterpolation::Nearest,
            outside: SignalBoundaryBehavior::Error,
        };

        let result = collect_source(
            &source,
            &store,
            FaultResourceLimits::default(),
            &mut BTreeMap::new(),
        );

        assert!(result.is_err());
    }
}
