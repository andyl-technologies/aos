//! Prepares unindexed Legacy view data without completing signed-history checks.
//!
//! Only the enclosing history owner promotes prepared data after every reached
//! view's Original, entry-origin and attribute-producer verification succeeds.

mod requirements;

use terrane_core::gc::publication::evidence::{
    ConfiguredRegistryInputs, ConsumedRootLayer, ConsumedRootPolicy, ConsumedViewInterpretation,
    ConsumedViewPolicy, ViewInterpretationMode,
};
use terrane_core::indexing::IndexRoots;
use terrane_core::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_core::provenance::VerifiedCommit;
use terrane_core::tree_format::Property;
use terrane_core::{cbor, properties, tree_format};

use crate::guard::{Guard, TreeEvidence, invalid};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Identifies the actual ordinary interpretation selected by Guard construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::guard) enum InterpretationSelection {
    /// Selects the existing ordinary Legacy resolver, independently of lineage data.
    Legacy,
}

/// Captures the concrete selected Legacy profile before candidate staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::guard) struct LegacyInputs {
    selection: InterpretationSelection,
    /// Retains the complete actual registered ordinary semantic inputs.
    pub(in crate::guard) registries: ConfiguredRegistryInputs,
    store: String,
    home: String,
    minimum: u64,
}

impl<S, C> Guard<S, C> {
    /// Captures the real constructor selection and full registered ordinary profile.
    ///
    /// # Errors
    /// Refuses an unregistered property vocabulary. This value grants no authority.
    pub(in crate::guard) fn completion_inputs(&self) -> Result<LegacyInputs, StoreFailure> {
        let mut names = PropertyName::ALL
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        let property_revision =
            ConfiguredRegistryInputs::property_revision_for(&names).map_err(malformed)?;
        Ok(LegacyInputs {
            selection: self.interpretation,
            registries: ConfiguredRegistryInputs {
                property_revision,
                behavioral_properties: names,
                attribute_revision: 1,
                selector_revision: 1,
                tree_revision: 1,
                chunk_revision: 1,
                identity_profile: "terrane-v1".into(),
                later_properties: Vec::new(),
            },
            store: self.config().store_name.clone(),
            home: self
                .config()
                .home
                .region
                .as_deref()
                .unwrap_or("local")
                .to_owned(),
            minimum: self.config().min_chunk_size,
        })
    }
}

/// Retains prepared signed-view inputs before the owning full history finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::guard) struct PendingViewUse {
    /// Retains the selected interpretation and original signed namespace root.
    pub(super) context: ConsumedViewInterpretation,
    /// Retains every reached occurrence and its complete ordered root layers.
    pub(super) policy: ConsumedViewPolicy,
}

impl PendingViewUse {
    /// Prepares every occurrence from actual addressed ordinary namespace evidence.
    ///
    /// # Errors
    /// Refuses missing or contradictory signed requirements, required indexes,
    /// any local active binding, or malformed namespace/property evidence.
    pub(in crate::guard) fn prepare(
        inputs: &LegacyInputs,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
    ) -> Result<Self, StoreFailure> {
        if commit.commit().tree != evidence.root {
            return Err(invalid());
        }
        let mode = match inputs.selection {
            InterpretationSelection::Legacy => ViewInterpretationMode::Legacy,
        };
        let context = ConsumedViewInterpretation {
            view: commit.identity(),
            original_root: commit.commit().tree,
            mode,
            registries: inputs.registries.clone(),
        };
        context
            .check_signed_view_data(commit.commit())
            .map_err(malformed)?;
        context
            .check_supported_interpretation()
            .map_err(malformed)?;
        let defaults = Defaults {
            store: &inputs.store,
            private_domain: &evidence.default_domain,
            home: &inputs.home,
        };
        requirements::check(commit, evidence, defaults, inputs.minimum)?;

        // A valid owner-local binding still needs the real relationship loader.
        // No binding is ignored merely because the inherited Index result is empty.
        for (identity, bytes) in &evidence.nodes {
            let node = tree_format::decode_node_for(
                bytes,
                evidence.roots.contains(identity),
                inputs.minimum,
                tree_format::TreeUse::Ordinary,
            )
            .map_err(malformed)?;
            reject_bindings(node.props.as_deref().unwrap_or(&[]))?;
        }
        let mut roots = Vec::new();
        for occurrence in evidence.occurrences(inputs.minimum)? {
            for (properties, overrides) in &occurrence.layers {
                reject_bindings(properties)?;
                reject_bindings(overrides)?;
            }
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = properties::resolve(&layers, defaults).map_err(malformed)?;
            match effective.get(PropertyName::Index) {
                Some(Value::Names(names)) if names.is_empty() => {}
                Some(Value::Names(_)) => return Err(unsupported()),
                _ => return Err(invalid()),
            }
            roots.push(ConsumedRootPolicy {
                root: occurrence.root,
                path: occurrence.path,
                layers: occurrence
                    .layers
                    .iter()
                    .map(|(properties, overrides)| ConsumedRootLayer {
                        properties: property_map(properties),
                        overrides: property_map(overrides),
                    })
                    .collect(),
            });
        }
        Ok(Self {
            context,
            policy: ConsumedViewPolicy {
                view: commit.identity(),
                default_domain: evidence.default_domain.clone(),
                roots,
            },
        })
    }

    /// Borrows the actual occurrence policies without completing them.
    pub(in crate::guard) fn policy(&self) -> &ConsumedViewPolicy {
        &self.policy
    }

    /// Borrows prepared data for contradiction detection, without completing it.
    pub(in crate::guard) fn context(&self) -> &ConsumedViewInterpretation {
        &self.context
    }
}

fn reject_bindings(properties: &[Property<'_>]) -> Result<(), StoreFailure> {
    for property in properties {
        if property.name == "index-roots" {
            IndexRoots::decode_binding(property.value).map_err(malformed)?;
            return Err(unsupported());
        }
    }
    Ok(())
}

fn property_map(properties: &[Property<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, properties.len());
    for property in properties {
        cbor::write_text(&mut bytes, property.name);
        bytes.extend_from_slice(property.value);
    }
    bytes
}

fn malformed(error: impl core::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        error,
    )
}

fn unsupported() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unsupported)
}
