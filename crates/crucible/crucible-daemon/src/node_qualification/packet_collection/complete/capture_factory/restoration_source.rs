//! Validates historical complete code before the actual fresh owners exist.
//!
//! This factory entry authenticates its original installed graph and codecs.
//! Core separately verifies the actual signed-load receipt and complete archive.
//! The result is an unbound source, never a fresh native hold or restoration MAC.

use super::*;
use crucible_engine::node_admission::{ConformanceGraph, ConformancePlanEvidence};
use crucible_engine::node_contract::{
    CollectingCompleteRestorationSource, HostSchedulingContinuationLimits,
};
use crucible_engine::node_state::CollectingCompleteCaptureProvenance;

impl PacketCompleteCaptureFactory {
    /// Verifies the historical archive under this actual installed code factory.
    ///
    /// The supplied graph belongs to the code-validation installation. Its Host2
    /// code source is separate from the actual restored host built later from a
    /// one-shot ticket. Core retains the signed source and all verified bodies;
    /// a different genuine fresh plan must bind that same source before runtime
    /// preparation. No retired source Child or old native controller is queried.
    ///
    /// # Errors
    /// Refuses foreign or stale installed code/graph, a missing signed-load
    /// receipt, unsupported complete cold codecs, changed historical closure or
    /// exhausted finite storage. No fresh native preparation is inferred.
    pub fn prepare_original_restoration_source(
        &self,
        graph: &ConformanceGraph,
        archive: NativeArchiveRecord,
        limits: HostSchedulingContinuationLimits,
    ) -> Result<CollectingCompleteRestorationSource, StateError> {
        self.current()?;
        ConformanceRuntime::prepare_complete_original_restoration_source(
            graph, archive, self, limits,
        )
    }

    pub(super) fn authenticate_original_archive_code_source(
        &self,
        plan: &InstalledConformancePlan,
        graph: &AdmittedGraph,
        archive: &NativeArchiveRecord,
        scope: &CollectingCompleteCaptureProvenance,
    ) -> Result<(), StateError> {
        self.current()?;
        plan.authenticate_authority(self.authority.as_ref())
            .map_err(error)?;
        self.authenticate_archive_graph_data(graph)?;
        authenticate_scope_data(scope, plan.evidence(), graph.world_binding_hash())?;
        if archive.manifest().world_binding_hash != *graph.world_binding_hash() {
            return Err(refused("historical code graph and archive world differ"));
        }
        // This is not the cold verifier: Core follows this check with its real
        // selected-load origin and full source/native/Host/common conjunction.
        // The distinct fresh-native preparation callback remains unsupported.
        self.current()
    }
}

fn authenticate_scope_data(
    scope: &CollectingCompleteCaptureProvenance,
    plan: ConformancePlanEvidence<'_>,
    world: &crucible_node_format::HashRef,
) -> Result<(), StateError> {
    if scope.schema != "source-owned.collecting-complete-capture/1"
        || scope.ordinary_acceptance
        || &scope.plan != plan.plan_ref
        || &scope.refused != plan.refused_ref
        || scope.sources != plan.sources
        || &scope.world != plan.world
        || &scope.world != world
    {
        return Err(refused("historical collecting code selection differs"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;

    #[test]
    fn historical_code_scope_data_never_upgrades_acceptance_or_changes_world()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan_ref = canonical::content_ref(b"{}", "application/json")?;
        let refused_ref = canonical::content_ref(b"[]", "application/json")?;
        let world = canonical::hash("test.collecting-code-world", b"original")?;
        let sources = vec![plan_ref.clone()];
        let evidence = || ConformancePlanEvidence {
            plan_ref: &plan_ref,
            plan_bytes: b"{}",
            refused_ref: &refused_ref,
            refused_bytes: b"[]",
            world: &world,
            sources: &sources,
        };
        let mut scope = CollectingCompleteCaptureProvenance {
            schema: "source-owned.collecting-complete-capture/1".into(),
            plan: plan_ref.clone(),
            refused: refused_ref.clone(),
            sources: sources.clone(),
            world: world.clone(),
            ordinary_acceptance: false,
        };
        // This invokes only the data join, not factory/native authentication.
        assert!(authenticate_scope_data(&scope, evidence(), &world).is_ok());
        scope.ordinary_acceptance = true;
        assert!(authenticate_scope_data(&scope, evidence(), &world).is_err());
        scope.ordinary_acceptance = false;
        let foreign = canonical::hash("test.collecting-code-world", b"foreign")?;
        assert!(authenticate_scope_data(&scope, evidence(), &foreign).is_err());
        scope.sources.clear();
        assert!(authenticate_scope_data(&scope, evidence(), &world).is_err());
        Ok(())
    }
}
