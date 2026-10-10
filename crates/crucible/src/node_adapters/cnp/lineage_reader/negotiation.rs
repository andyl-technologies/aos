//! Keeps distinct typed reader preparation conjunctive with actual installed graph scope.

use crucible_node_contract::{ExtensionSelection, Id};
use crucible_node_provider::{
    ProviderError, client::OriginalLineageRealization, reference_lineage::LineageSourceGuard,
};

use crate::{node_admission::AdmittedGraph, node_contract::OperationFailure};

use super::{
    LineageControlledReference, LineagePreparationFailure, LineageReferenceQualification,
    LineageRuntimeCustodySlot, readiness,
};

/// Records the constructor that checked the actual original owning source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReaderTransport {
    Legacy,
    Negotiated,
}

impl ReaderTransport {
    pub(super) fn facet(self) -> &'static str {
        match self {
            Self::Legacy => "reference-device/quantized-lineage-reader-v1",
            Self::Negotiated => "reference-device/quantized-lineage-reader-typed-v2",
        }
    }

    pub(super) fn verify_registrar(self, guard: &LineageSourceGuard) -> Result<(), ProviderError> {
        match (self, guard.selected_extensions()) {
            (Self::Legacy, None) => Ok(()),
            (Self::Negotiated, Some(_)) => guard.verify_extension_registrar(),
            _ => Err(ProviderError::Correlation(
                "original lineage registrar and constructor editions differ",
            )),
        }
    }

    pub(super) fn authenticate(
        self,
        guard: &LineageSourceGuard,
        original: &OriginalLineageRealization<'_>,
        qualification: &dyn LineageReferenceQualification,
        admitted: Option<(&AdmittedGraph, &Id)>,
    ) -> Result<(), ProviderError> {
        self.verify_registrar(guard)?;
        if self == Self::Legacy {
            return Ok(());
        }
        let [binding] = original
            .realization()
            .realization_manifest
            .bindings
            .as_slice()
        else {
            return Err(ProviderError::Correlation(
                "typed original binding roster differs",
            ));
        };
        let facets = &binding.compatibility.operating_contract.facets;
        if facets.len() != 1 || facets[0].version != 1 || facets[0].id.as_str() != self.facet() {
            return Err(ProviderError::Correlation(
                "typed original source facet differs",
            ));
        }
        let definition =
            original
                .profile()
                .input_lineage_definition()
                .ok_or(ProviderError::Correlation(
                    "typed lineage source definition absent",
                ))?;
        let expected = std::slice::from_ref(definition.selection());
        if guard.selected_extensions() != Some(expected) {
            return Err(ProviderError::Correlation(
                "original typed lineage selection differs from source definition",
            ));
        }
        require_selected_graph(expected, admitted.map(|(graph, _)| graph))?;
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            qualification.authenticate_peer_extensions(guard, original, expected, admitted)
        }))
        .map_err(|_| ProviderError::Correlation("installed typed lineage callback panicked"))??;
        // Installed code cannot replace the original private gate during a callback.
        self.verify_registrar(guard)
    }
}

fn require_selected_graph(
    selected: &[ExtensionSelection],
    graph: Option<&AdmittedGraph>,
) -> Result<(), ProviderError> {
    if let Some(graph) = graph
        && selected.iter().any(|selection| {
            !graph
                .selected_extensions()
                .definitions()
                .any(|definition| definition.selection() == selection)
        })
    {
        return Err(ProviderError::Correlation(
            "typed peer definition is absent from original admitted graph",
        ));
    }
    Ok(())
}

impl LineageControlledReference {
    /// Takes a distinct typed reader under its original pre-reserved owning capsule.
    ///
    /// The exact surviving registrar and independently installed source policy
    /// are checked around original realization authentication. This read-only
    /// preparation does not issue a graph admission, Ready or input authority.
    /// Legacy source profiles remain on [`Self::from_original`].
    ///
    /// # Errors
    /// Returns the same guard, installed policy and reserved slot on unsupported
    /// selection, stale private registration, callback refusal or invalid credits.
    pub fn from_negotiated_original(
        guard: LineageSourceGuard,
        realization: Id,
        qualification: Box<dyn LineageReferenceQualification>,
        slot: Box<dyn LineageRuntimeCustodySlot>,
        maximum_operations: usize,
    ) -> Result<Self, Box<LineagePreparationFailure>> {
        Self::prepare_original(
            guard,
            realization,
            qualification,
            slot,
            maximum_operations,
            ReaderTransport::Negotiated,
        )
    }

    /// Installs the distinct typed source into its independently admitted node.
    ///
    /// Exact peer definitions must already belong to the frozen admitted set.
    /// The installed policy separately checks this node's qualified durable
    /// applications and original dynamic input reader. The common owner barrier
    /// remains responsible for readiness and operation authority.
    ///
    /// # Errors
    /// Refuses a legacy constructor, changed source descriptor or facet, missing
    /// admitted definition, stale registrar or unsupported installed policy.
    /// Failure transfers original complete custody to its retained supervisor.
    pub fn into_negotiated_node(
        self,
        graph: &AdmittedGraph,
        node: &Id,
        maximum_operations: usize,
    ) -> Result<
        crate::node_adapters::reference_device::ControlledReferenceNode<Self>,
        OperationFailure,
    > {
        self.install_node(graph, node, maximum_operations, ReaderTransport::Negotiated)
    }

    pub(super) fn install_node(
        self,
        graph: &AdmittedGraph,
        node: &Id,
        maximum_operations: usize,
        transport: ReaderTransport,
    ) -> Result<
        crate::node_adapters::reference_device::ControlledReferenceNode<Self>,
        OperationFailure,
    > {
        let state = self.state().map_err(readiness::unknown)?;
        let facets = &state.binding.compatibility.operating_contract.facets;
        if state.transport != transport
            || facets.len() != 1
            || facets[0].version != 1
            || facets[0].id.as_str() != transport.facet()
        {
            return Err(readiness::refused("original selected source facet differs"));
        }
        let original_facet = facets[0].id.clone();

        crate::node_adapters::reference_device::ControlledReferenceNode::from_controlled_prepared(
            graph,
            node,
            self,
            original_facet,
            &|control, descriptor, binding| {
                let state = control.state().map_err(readiness::unknown)?;
                state.verify_native_custody().map_err(readiness::unknown)?;
                if descriptor != &state.profile.descriptor || binding != &state.binding {
                    return Err(readiness::refused(
                        "admitted selected source identity changed",
                    ));
                }
                state
                    .guard
                    .with_original_realization(&state.realization, |original| {
                        transport.authenticate(
                            &state.guard,
                            &original,
                            state.qualification.as_ref(),
                            Some((graph, node)),
                        )
                    })
                    .map_err(readiness::unknown)
            },
            maximum_operations,
        )
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- synthetic graph models panic on explicit fixture failure.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn original_admitted_tuple_remains_exact_before_installed_source_callback() {
        let graph = crate::node_admission::test_model_graph_with_extension();
        let original = graph
            .selected_extensions()
            .definitions()
            .next()
            .unwrap()
            .selection()
            .clone();

        require_selected_graph(std::slice::from_ref(&original), Some(&graph)).unwrap();

        let mut changed_version = original.clone();
        changed_version.semantic_version.patch =
            crucible_node_contract::U64::new(changed_version.semantic_version.patch.get() + 1);
        assert!(require_selected_graph(&[changed_version], Some(&graph)).is_err());

        let mut changed_schema = original;
        changed_schema.schema_digest.digest = "00".repeat(32);
        assert!(require_selected_graph(&[changed_schema], Some(&graph)).is_err());
    }
}
