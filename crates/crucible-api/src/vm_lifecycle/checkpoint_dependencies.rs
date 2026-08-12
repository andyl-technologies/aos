//! Transitive signal-artifact discovery for production checkpoint closures.
//!
//! The authored program stores only content identities. This module resolves
//! those identities before launch and expands the two artifact formats that
//! contain further references: normalized traces and tiled spatial grids.

use super::*;
use crucible::model::{
    FaultResourceLimits, FaultSignalPlan, InverseCdfTable, NormalizedSpatialArtifact,
    SignalNodeKind, SignalSourceSpecification, SignalTraceManifest, SpatialArtifactKind,
};

pub(super) fn collect_signal_artifact_objects(
    plan: &FaultSignalPlan,
    store: &dyn DagStore,
) -> Result<BTreeMap<ContentHash, Vec<u8>>, LifecycleApiError> {
    let mut objects = BTreeMap::new();
    for program in plan.programs() {
        for node in program.nodes() {
            let SignalNodeKind::Source(source) = &node.kind else {
                continue;
            };
            collect_source(source, store, plan.resource_limits(), &mut objects)?;
        }
    }
    Ok(objects)
}

fn collect_source(
    source: &SignalSourceSpecification,
    store: &dyn DagStore,
    limits: FaultResourceLimits,
    objects: &mut BTreeMap<ContentHash, Vec<u8>>,
) -> Result<(), LifecycleApiError> {
    match source {
        SignalSourceSpecification::Trace {
            artifact,
            raw_provenance,
            ..
        } => {
            let manifest_bytes = retain_object(*artifact, store, limits, objects)?;
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
            retain_object(*raw_provenance, store, limits, objects)?;
            for channel in &manifest.channels {
                for chunk in &channel.chunks {
                    retain_object(chunk.content, store, limits, objects)?;
                }
            }
        }
        SignalSourceSpecification::PointSet { artifact, .. }
        | SignalSourceSpecification::RegularGrid { artifact, .. }
        | SignalSourceSpecification::ZoneMap { artifact, .. }
        | SignalSourceSpecification::PathProfile { artifact, .. } => {
            let bytes = retain_object(*artifact, store, limits, objects)?;
            authenticate_spatial_artifact(*artifact, &bytes)?;
        }
        SignalSourceSpecification::TiledGrid { manifest, .. } => {
            let bytes = retain_object(*manifest, store, limits, objects)?;
            let spatial = authenticate_spatial_artifact(*manifest, &bytes)?;
            let SpatialArtifactKind::TiledGrid { tiles } = spatial.kind() else {
                return Err(loop_factory_error(
                    "tiled-grid signal source references another spatial artifact kind",
                ));
            };
            for tile in tiles {
                let bytes = retain_object(tile.content, store, limits, objects)?;
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
            let bytes = retain_object(*lookup, store, limits, objects)?;
            authenticate_spatial_artifact(*lookup, &bytes)?;
        }
        SignalSourceSpecification::ExponentialWait { sampler_table, .. }
        | SignalSourceSpecification::WeibullWait { sampler_table, .. } => {
            let bytes = retain_object(*sampler_table, store, limits, objects)?;
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
    objects.insert(identity, bytes.clone());
    Ok(bytes)
}
