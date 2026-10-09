//! Authenticates the signed selected closure before native reservation or staging.

use crate::node_admission::AdmittedGraph;
use crate::node_state::{StateError, StateErrorCode, StateLimits};

use super::super::{NativeArchiveRecord, NativeWorldFactory};
use super::{PreparedExtensionClosure, prepare};

/// Resolves the installed selected codec before any native capture callback.
///
/// # Errors
/// Refuses selected semantics without installed support or an invalid closure.
pub(crate) fn prepare_capture(
    graph: &AdmittedGraph,
    factory: &dyn NativeWorldFactory,
    limits: StateLimits,
) -> Result<Option<PreparedExtensionClosure>, StateError> {
    if graph.selected_extensions().is_empty() {
        return Ok(None);
    }
    let policy = factory.extension_preservation_policy().ok_or_else(|| {
        refused("selected extensions have no installed native preservation codec")
    })?;
    prepare(graph, policy, limits).map(Some)
}

/// Authenticates original signed scopes and rows against the installed codec.
///
/// # Errors
/// Refuses inconsistent archive editions, original worlds, source provenance,
/// missing bodies, changed policies/handlers or unauthenticated dependency rows.
pub(crate) fn authenticate_archive(
    record: &NativeArchiveRecord,
    graph: &AdmittedGraph,
    factory: &dyn NativeWorldFactory,
) -> Result<Option<PreparedExtensionClosure>, StateError> {
    if graph.selected_extensions().is_empty() {
        if !matches!(record.index.schema_version, 1 | 2)
            || record.index.selected_extensions.is_some()
        {
            return Err(refused(
                "unselected graph cannot reinterpret an extension-aware source",
            ));
        }
        return Ok(None);
    }
    let Some(reference) = record.index.selected_extensions.as_ref() else {
        return Err(refused("native source omitted selected semantic closure"));
    };
    if record.index.schema_version != 2
        || graph.world_binding_hash() != &record.manifest().world_binding_hash
        || !record.manifest().immutable_refs.contains(reference)
    {
        return Err(refused(
            "selected source edition, immutable root or original world differs",
        ));
    }
    let provenance = record.object(
        &record.manifest().provenance_ref,
        record.limits.state.maximum_record_bytes,
    )?;
    let provenance = crucible_node_contract::canonical::parse_json(
        &provenance,
        record.limits.state.maximum_record_bytes,
    )
    .map_err(crate::node_state::schema)?;
    if provenance.get("native_archive")
        != Some(&serde_json::json!({
            "schema_version":2,
            "content_inventory":2,
            "selected_extensions":reference,
        }))
    {
        return Err(refused(
            "original provenance omitted its selected source edition",
        ));
    }
    let selected = prepare_capture(graph, factory, record.limits.state)?
        .ok_or_else(|| refused("selected source cannot use the legacy native preservation path"))?;
    if reference != &selected.record.reference
        || record.object(reference, record.limits.state.maximum_record_bytes)?
            != selected.record.bytes
    {
        return Err(refused(
            "original selected scopes, handlers, contracts or codec policy differ",
        ));
    }
    for object in selected
        .objects
        .iter()
        .chain(std::iter::once(&selected.record))
    {
        if record.object(&object.reference, record.limits.state.maximum_content_bytes)?
            != object.bytes
        {
            return Err(refused(
                "original selected body differs from installed source closure",
            ));
        }
        let row = record
            .index
            .objects
            .iter()
            .find(|row| row.reference == object.reference)
            .ok_or_else(|| refused("signed selected dependency row is absent"))?;
        let expected = selected.dependencies(&object.reference)?;
        if row.dependencies != expected {
            return Err(refused(
                "signed selected dependencies differ from authenticated codec",
            ));
        }
    }
    Ok(Some(selected))
}

impl PreparedExtensionClosure {
    /// Copies one exact original dependency row after reserving its capacity.
    ///
    /// # Errors
    /// Refuses an absent row or unavailable bounded allocation credit.
    pub(crate) fn dependencies(
        &self,
        reference: &crucible_node_contract::ContentRef,
    ) -> Result<Vec<crucible_node_contract::ContentRef>, StateError> {
        let source = if reference == &self.record.reference {
            None
        } else {
            Some(
                self.inventory
                    .dependencies
                    .iter()
                    .find(|row| &row.reference == reference)
                    .ok_or_else(|| refused("selected original dependency row is absent"))?,
            )
        };
        let count = source.map_or(self.objects.len(), |row| row.dependencies.len());
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(count)
            .map_err(|_| limit("selected dependency row allocation"))?;
        if let Some(row) = source {
            dependencies.extend(row.dependencies.iter().cloned());
        } else {
            dependencies.extend(self.objects.iter().map(|object| object.reference.clone()));
        }
        Ok(dependencies)
    }
}

fn refused(reason: &'static str) -> StateError {
    StateError::new(
        StateErrorCode::NativeEvidence,
        "selected native source",
        reason,
    )
}

fn limit(reason: &'static str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        "selected native source",
        reason,
    )
}
