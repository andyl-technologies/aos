//! Completes required active owner-bound relationships after full signed history.
//!
//! Plans retain only ordinary owned subjects derived from every actual namespace
//! occurrence. Only the enclosing history success path can promote a view.

use super::*;
use crate::store::ContentStore;
use terrane_core::tree_format::{Node, NodeItems};

/// Retains exact independently reached owner/attribute subjects without authority.
pub(in crate::guard) struct Plan {
    owners: Vec<(terrane_core::identity::Digest, Vec<String>)>,
}

/// Rejects active structural metadata outside its actual namespace roles.
///
/// # Errors
/// Rejects nonroot bindings, every namespace gap binding and structural route
/// attributes on ordinary entries; physical decoding remains independently checked.
pub(in crate::guard) fn check_namespace_node(
    node: &Node<'_>,
    root: bool,
) -> Result<(), StoreFailure> {
    for property in node.props.as_deref().unwrap_or(&[]) {
        if property.name == "index-gaps" || (property.name == "index-roots" && !root) {
            return Err(invalid());
        }
        if property.name == "index-roots" {
            IndexRoots::decode_binding(property.value).map_err(malformed)?;
        }
    }
    if let NodeItems::Leaf(entries) = &node.items {
        for item in entries {
            terrane_core::indexing::carrier::validate_namespace_attributes(2, &item.entry)
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
        let node = tree_format::decode_node_for(
            bytes,
            evidence.roots.contains(identity),
            inputs.minimum,
            tree_format::TreeUse::Ordinary,
        )
        .map_err(malformed)?;
        check_namespace_node(&node, evidence.roots.contains(identity))?;
    }
    let mut owners = Vec::new();
    for occurrence in evidence.occurrences(inputs.minimum)? {
        for (_, overrides) in &occurrence.layers {
            if overrides
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
        let effective = properties::selected::Selection::Active
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
        let mut checked = attributes
            .iter()
            .map(|attribute| (*attribute).to_owned())
            .collect::<Vec<_>>();
        if let Some(bindings) = effective.active_index_roots() {
            checked.extend(
                bindings
                    .as_bindings()
                    .iter()
                    .map(|binding| binding.attribute.to_owned()),
            );
        }
        checked.sort();
        checked.dedup();
        owners.push((occurrence.root, checked));
    }
    Ok(Plan { owners })
}

/// Verifies every actual required immutable relationship before owning promotion.
///
/// # Errors
/// Preserves typed missing/store/profile/relationship diagnostics. No partial
/// success yields completion; current/Original native checks remain mandatory.
pub(in crate::guard) async fn check_relationships<S: ContentStore + ?Sized>(
    store: &S,
    plan: &Plan,
    minimum: u64,
) -> Result<(), StoreFailure> {
    for (owner, attributes) in &plan.owners {
        for attribute in attributes {
            let loaded = crate::indexing::load(
                store,
                *owner,
                attribute,
                crate::indexing::SemanticRevisions {
                    property: 3,
                    attribute: 2,
                    tree: 1,
                },
                minimum,
            )
            .await
            .map_err(index_failure)?;
            // Borrowed Core Trees and Prepared never cross another await.
            let sources = loaded.sources().map_err(index_failure)?;
            loaded.prepare(&sources.trees).map_err(index_failure)?;
        }
    }
    Ok(())
}

fn index_failure(error: crate::indexing::Error) -> StoreFailure {
    match error {
        crate::indexing::Error::Store { failure, .. } => failure,
        error => {
            // This boundary refuses incomplete view evidence as a failed
            // candidate validation. The exact native typed incomplete cause
            // remains attached; direct loader/query outcomes are unchanged.
            let kind = match error.kind() {
                crate::indexing::ErrorKind::Incomplete => {
                    StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-27" })
                }
                crate::indexing::ErrorKind::Unsupported => StoreErrorKind::Unsupported,
                crate::indexing::ErrorKind::Invalid | crate::indexing::ErrorKind::Store => {
                    StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
                }
            };
            StoreFailure::with_source(kind, error)
        }
    }
}
