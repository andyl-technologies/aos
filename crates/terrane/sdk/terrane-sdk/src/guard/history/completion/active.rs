//! Completes required active owner-bound relationships after full signed history.
//!
//! Plans retain only ordinary owned subjects derived from every actual namespace
//! occurrence. Only the enclosing history success path can promote a view.

use super::*;
use crate::store::ContentStore;
use std::collections::BTreeMap;
use terrane_format::identity::Digest;
use terrane_format::tree_format::{Node, NodeItems};

#[cfg(all(test, feature = "tokio", unix))]
#[path = "active/relationship_reuse_tests.rs"]
mod relationship_reuse_tests;

/// Retains exact independently reached owner/attribute subjects without authority.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::guard) struct Plan {
    /// Keeps occurrence order, multiplicity and exact independently selected Tree use.
    pub(super) owners: Vec<(
        terrane_format::identity::Digest,
        Vec<String>,
        tree_format::TreeUse,
    )>,
    /// Keeps the actual selected property, attribute and physical tree revisions.
    pub(super) revisions: crate::indexing::SemanticRevisions,
}

/// Rejects active structural metadata outside its actual namespace roles.
///
/// # Errors
/// Rejects nonroot bindings, every namespace gap binding and structural route
/// attributes on ordinary entries; physical decoding remains independently checked.
pub(in crate::guard) fn check_namespace_node(
    node: &Node<'_>,
    root: bool,
    selection: &properties::selected::Selection,
    attribute_revision: u64,
) -> Result<(), StoreFailure> {
    let revision = match selection {
        properties::selected::Selection::Legacy => 1,
        properties::selected::Selection::Active => 3,
        properties::selected::Selection::Recorded(context) => context.revision(),
    };
    for property in node.props.as_deref().unwrap_or(&[]) {
        if (revision >= 3 && property.name == "index-gaps")
            || (revision >= 2 && property.name == "index-roots" && !root)
        {
            return Err(invalid());
        }
        if revision >= 2 && property.name == "index-roots" {
            IndexRoots::decode_binding(property.value).map_err(malformed)?;
        }
    }
    if let NodeItems::Leaf(entries) = &node.items {
        for item in entries {
            terrane_format::indexing::carrier::validate_namespace_attributes(
                attribute_revision,
                &item.entry,
            )
            .map_err(malformed)?;
        }
    }
    Ok(())
}

/// Captures each actual owner and effective required attributes from complete evidence.
///
/// # Errors
/// Rejects malformed active namespace metadata, unavailable occurrences or
/// forbidden graft-override structural bindings (PROP-29). It creates no completed context.
pub(in crate::guard) fn plan(
    evidence: &TreeEvidence,
    inputs: &SelectedInputs,
) -> Result<Plan, StoreFailure> {
    for (identity, bytes) in &evidence.nodes {
        #[cfg(all(test, feature = "tokio", unix))]
        planning::work::raw_node();
        let node = tree_format::decode_node_for(
            bytes,
            evidence.roots.contains(identity),
            inputs.minimum,
            evidence.usage,
        )
        .map_err(malformed)?;
        check_namespace_node(
            &node,
            evidence.roots.contains(identity),
            &inputs.selection,
            inputs.registries.attribute_revision,
        )?;
    }
    let mut owners = planning::Capture::default();
    #[cfg(all(test, feature = "tokio", unix))]
    planning::work::occurrence_walk();
    for occurrence in evidence.occurrences(inputs.minimum)? {
        #[cfg(all(test, feature = "tokio", unix))]
        planning::work::occurrence();
        for (_, overrides) in &occurrence.layers {
            if inputs.registries.property_revision >= 2
                && overrides
                    .iter()
                    .any(|property| property.name == "index-roots")
            {
                return Err(StoreFailure::new(StoreErrorKind::Invalid(
                    InvalidReason::Upload { rule_id: "PROP-29" },
                )));
            }
        }
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        #[cfg(all(test, feature = "tokio", unix))]
        planning::work::resolution();
        let effective = inputs
            .selection
            .resolve(
                &layers,
                Defaults {
                    store: &inputs.store,
                    private_domain: &evidence.default_domain,
                    home: &inputs.home,
                },
            )
            .map_err(malformed)?;
        let Some(Value::Names(attributes)) = effective.get(PropertyName::Index) else {
            return Err(invalid());
        };
        owners.record(
            occurrence.root,
            attributes,
            &effective,
            evidence.root_usage(occurrence.root),
        );
    }
    Ok(owners.finish(inputs))
}

/// Verifies present immutable relationships while preserving absent binding gaps.
///
/// Successful identical owner/attribute/use relationships share work only within
/// this invocation's immutable plan, revisions, minimum and store. Every occurrence
/// has already resolved its own policy; reuse creates no current authority or
/// completed history, and missing bindings do not enter the successful set.
///
/// # Errors
/// Preserves store/profile/relationship diagnostics for every present binding.
/// An absent binding supplies no verified relationship or lookup coverage;
/// current/Original native checks and writer maintenance remain mandatory.
pub(in crate::guard) async fn check_relationships<S: ContentStore + ?Sized>(
    store: &S,
    plan: &Plan,
    minimum: u64,
) -> Result<(), StoreFailure> {
    let mut completed = BTreeMap::<(Digest, &str), Vec<tree_format::TreeUse>>::new();
    for (owner, attributes, usage) in &plan.owners {
        for attribute in attributes {
            let key = (*owner, attribute.as_str());
            if completed
                .get(&key)
                .is_some_and(|usages| usages.contains(usage))
            {
                continue;
            }

            #[cfg(all(test, feature = "tokio", unix))]
            let trace = HistoryTrace::new(format!(
                "relationship owner={owner:?} attribute={attribute}"
            ));
            let loaded = match crate::indexing::load_for(
                store,
                *owner,
                attribute,
                plan.revisions,
                minimum,
                *usage,
            )
            .await
            {
                Ok(loaded) => loaded,
                // DRV-25/27 permit initial and preserved absent bindings. Signed
                // history completion proves neither a relationship nor complete
                // coverage for this gap; lookup retains its typed incomplete
                // result, and writer maintenance separately refuses dropped
                // required bindings.
                Err(crate::indexing::Error::MissingBinding(_)) => continue,
                Err(error) => return Err(index_failure(error)),
            };
            #[cfg(all(test, feature = "tokio", unix))]
            trace.mark(&format!("load-returned loading={:?}", loaded.loading()));
            // Borrowed Core Trees and Prepared never cross another await.
            let sources = loaded.sources().map_err(index_failure)?;
            #[cfg(all(test, feature = "tokio", unix))]
            trace.mark("sources-returned");
            loaded.prepare(&sources.trees).map_err(index_failure)?;
            #[cfg(all(test, feature = "tokio", unix))]
            trace.mark("prepare-returned");

            // Keep only full successful present relationships. The typed usage
            // list has at most one entry per TreeUse variant; no request, control
            // observation, failed load or missing-binding allowance is reused.
            completed.entry(key).or_default().push(*usage);
        }
    }
    Ok(())
}

fn index_failure(error: crate::indexing::Error) -> StoreFailure {
    let kind = match &error {
        // Preserve the store outcome and the owning Node diagnostic together.
        // StoreFailure::with_source also keeps Denied free of diagnostic detail.
        crate::indexing::Error::Store { failure, .. } => failure.kind().clone(),
        error => {
            // This boundary refuses incomplete view evidence as a failed
            // candidate validation. The exact native typed incomplete cause
            // remains attached; direct loader/query outcomes are unchanged.
            match error.kind() {
                crate::indexing::ErrorKind::Incomplete => {
                    StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-27" })
                }
                crate::indexing::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
                crate::indexing::ErrorKind::Invalid | crate::indexing::ErrorKind::Store => {
                    StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
                }
            }
        }
    };
    StoreFailure::with_source(kind, error)
}

#[cfg(all(test, feature = "tokio", unix))]
impl<S: crate::store::Store, C: crate::store::Clock> Guard<S, C> {
    /// Borrows exact staged namespace evidence for strict loader diagnostics.
    ///
    /// The existing overlay is read-only and supplies no publication authority.
    ///
    /// # Errors
    /// Preserves immutable overlay validation failures.
    pub(crate) fn staged_index_inputs_for_tests<'evidence>(
        &'evidence self,
        evidence: &'evidence TreeEvidence,
    ) -> Result<impl ContentStore + 'evidence, StoreFailure> {
        indexes::Inputs::new(self.store(), evidence, &[])
    }

    /// Observes the exact private dropped-binding diagnostic without authority.
    ///
    /// This test-only projection performs no I/O or relationship verification.
    pub(crate) fn dropped_index_binding_for_tests<'failure>(
        &self,
        failure: &'failure StoreFailure,
    ) -> Option<(terrane_format::identity::Digest, &'failure str)> {
        use core::error::Error;

        let cause = failure
            .source()?
            .downcast_ref::<crate::guard::admission::index_writer::DroppedBinding>()?;
        Some((cause.owner, cause.attribute.as_str()))
    }
}

/// Observes ordinary history phases without providing deadline or authority input.
#[cfg(all(test, feature = "tokio", unix))]
pub(in crate::guard) struct HistoryTrace {
    started: Option<crate::diagnostic_clock::Tick>,
    subject: String,
}

#[cfg(all(test, feature = "tokio", unix))]
impl HistoryTrace {
    /// Starts an opt-in phase observation.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(in crate::guard) fn new(subject: String) -> Self {
        let trace = Self {
            started: std::env::var_os("TERRANE_REF_PHASE_TRACE")
                .is_some()
                .then(crate::diagnostic_clock::tick),
            subject,
        };
        trace.mark("entry");
        trace
    }

    /// Reports one successful boundary.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(in crate::guard) fn mark(&self, phase: &str) {
        if let Some(started) = self.started {
            eprintln!(
                "history-phase subject={} task={:?} elapsed={:?} phase={phase}",
                self.subject,
                tokio::task::try_id(),
                crate::diagnostic_clock::elapsed(started),
            );
        }
    }

    /// Samples elapsed diagnostic time without consulting the request clock.
    pub(in crate::guard) fn elapsed(&self) -> std::time::Duration {
        self.started
            .map_or(std::time::Duration::ZERO, crate::diagnostic_clock::elapsed)
    }
}

#[cfg(all(test, feature = "tokio", unix))]
impl Drop for HistoryTrace {
    fn drop(&mut self) {
        // A missing success marker retains the phase in which an error returned.
        self.mark("scope-exit");
    }
}
