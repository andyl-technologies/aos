//! Prepares explicitly selected view data without completing signed-history checks.
//!
//! Only the enclosing history owner promotes prepared data after every reached
//! view's Original, entry-origin, attribute-producer and active relationships succeed.

mod owner_preparation;
mod planning;
mod requirements;

pub(in crate::guard) mod active;
pub(in crate::guard) mod indexes;

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

#[cfg(all(test, feature = "tokio", unix))]
mod owner_preparation_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod planning_tests;

use terrane_format::gc::publication::evidence::{
    ConfiguredRegistryInputs, ConsumedRootLayer, ConsumedRootPolicy, ConsumedViewInterpretation,
    ConsumedViewPolicy, ViewInterpretationMode,
};
use terrane_format::indexing::IndexRoots;
use terrane_format::properties::{Defaults, PropertyName, RootLayer, Value};
use terrane_format::provenance::VerifiedCommit;
use terrane_format::tree_format::Property;
use terrane_format::{cbor, properties, tree_format};

use crate::guard::{Guard, TreeEvidence, invalid};
use crate::store::{InvalidReason, StoreErrorKind, StoreFailure};

/// Identifies the actual ordinary interpretation selected by Guard construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::guard) enum InterpretationSelection {
    /// Selects the existing ordinary Legacy resolver, independently of lineage data.
    Legacy,
    /// Selects current property3/attribute2/tree1 explicitly.
    Active,
}

impl InterpretationSelection {
    /// Projects the deliberately selected ordinary mode without granting authority.
    pub(in crate::guard) fn semantics(self) -> properties::selected::Selection {
        match self {
            Self::Legacy => properties::selected::Selection::Legacy,
            Self::Active => properties::selected::Selection::Active,
        }
    }
}

/// Captures the concrete constructor-selected profile before candidate staging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::guard) struct SelectedInputs {
    /// Retains the exact independently selected execution, including current revision.
    ///
    /// This ordinary input grants neither Original nor owning-history completeness.
    pub(in crate::guard) selection: properties::selected::Selection,
    /// Retains the complete actual registered ordinary semantic inputs.
    pub(in crate::guard) registries: ConfiguredRegistryInputs,
    store: String,
    home: String,
    minimum: u64,
}

impl<S, C> Guard<S, C> {
    /// Copies the normalized constructor-selected ordinary authoring semantics.
    ///
    /// The returned data grants no current rights or completed-history authority.
    ///
    /// # Errors
    /// Rejects unsupported or unregistered constructor-selected semantics.
    pub(crate) fn authoring_property_selection(
        &self,
    ) -> Result<properties::selected::Selection, StoreFailure> {
        Ok(self.completion_inputs()?.selection)
    }

    /// Captures the real constructor selection and full registered ordinary profile.
    ///
    /// # Errors
    /// Refuses an unregistered property vocabulary. This value grants no authority.
    pub(in crate::guard) fn completion_inputs(&self) -> Result<SelectedInputs, StoreFailure> {
        let (selection, attribute_revision) =
            self.authoring_selection.clone().unwrap_or_else(|| {
                (
                    self.interpretation.semantics(),
                    if self.interpretation == InterpretationSelection::Active {
                        2
                    } else {
                        1
                    },
                )
            });
        self.completion_inputs_for(selection, attribute_revision)
    }

    /// Projects a selected execution into its complete registered ordinary profile.
    ///
    /// # Errors
    /// Rejects unsupported attribute semantics or invalid current Recorded registration.
    /// The returned inputs supply no view association or completion authority.
    pub(in crate::guard) fn completion_inputs_for(
        &self,
        selection: properties::selected::Selection,
        attribute_revision: u64,
    ) -> Result<SelectedInputs, StoreFailure> {
        // Active authoring executes exactly Recorded revision 3/current 3 with
        // no later registrations. Normalize only that independently selected
        // constructor case; historical contexts keep their exact current fence.
        let selection = match selection {
            properties::selected::Selection::Active => properties::selected::Selection::Recorded(
                properties::semantics::RecordedContext::new(3, 3, &[]).map_err(malformed)?,
            ),
            selected => selected,
        };
        let (property_revision, mut names, later_properties): (u64, Vec<String>, Vec<String>) =
            match &selection {
                properties::selected::Selection::Legacy => (
                    1,
                    properties::semantics::RecordedContext::new(1, 1, &[])
                        .map_err(malformed)?
                        .behavioral_names()
                        .map(str::to_owned)
                        .collect(),
                    Vec::new(),
                ),
                properties::selected::Selection::Active => {
                    let names = properties::semantics::RecordedContext::new(3, 3, &[])
                        .map_err(malformed)?
                        .behavioral_names()
                        .map(str::to_owned)
                        .collect();
                    (3, names, Vec::new())
                }
                properties::selected::Selection::Recorded(context) => (
                    context.revision(),
                    context.behavioral_names().map(str::to_owned).collect(),
                    context.later_registered().to_vec(),
                ),
            };
        names.sort();
        if !matches!(attribute_revision, 1 | 2) {
            return Err(unsupported());
        }
        Ok(SelectedInputs {
            selection,
            registries: ConfiguredRegistryInputs {
                property_revision,
                behavioral_properties: names,
                attribute_revision,
                selector_revision: 1,
                tree_revision: 1,
                chunk_revision: 1,
                identity_profile: "terrane-v1".into(),
                later_properties,
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
    /// Retains the exact actual selection until the owning full checks finish.
    ///
    /// Pending data cannot mint completion or replace independently installed inputs.
    pub(super) inputs: SelectedInputs,
}

impl PendingViewUse {
    /// Prepares every occurrence from actual addressed ordinary namespace evidence.
    ///
    /// # Errors
    /// Refuses missing or contradictory signed requirements, malformed namespace
    /// or property evidence, and unsupported bindings. Legacy refuses required
    /// indexes and local active bindings; Active defers actual relationships to
    /// the owning full-history completion before promotion.
    pub(in crate::guard) fn prepare(
        inputs: &SelectedInputs,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
    ) -> Result<Self, StoreFailure> {
        let mut owners = owner_preparation::OwnerPreparation::new(evidence, inputs);
        Self::prepare_with_owners(commit, &mut owners)
    }

    /// Prepares pending policies and their relationship subjects in one synchronous pass.
    ///
    /// The optional plan contains ordinary owned data, never completed-history or
    /// producer authority. Legacy returns no plan. Disclosure still performs its
    /// issuer and pending-policy callbacks before using the successful plan.
    ///
    /// # Errors
    /// Preserves every refusal and its order from `prepare`; collecting subjects
    /// from already resolved policies introduces no additional fallible check.
    pub(in crate::guard) fn prepare_with_plan(
        inputs: &SelectedInputs,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
    ) -> Result<(Self, Option<active::Plan>), StoreFailure> {
        let mut owners = owner_preparation::OwnerPreparation::new(evidence, inputs);
        let mut plan = (inputs.selection != properties::selected::Selection::Legacy)
            .then(planning::Capture::default);
        let pending = Self::prepare_inner(commit, &mut owners, plan.as_mut())?;
        Ok((pending, plan.map(|plan| plan.finish(inputs))))
    }

    /// Keeps occurrence policy and signed-view checks independent of owner reuse.
    fn prepare_with_owners(
        commit: &VerifiedCommit,
        owners: &mut owner_preparation::OwnerPreparation<'_>,
    ) -> Result<Self, StoreFailure> {
        Self::prepare_inner(commit, owners, None)
    }

    /// Shares the original ordered checks while keeping partial plan data private.
    fn prepare_inner(
        commit: &VerifiedCommit,
        owners: &mut owner_preparation::OwnerPreparation<'_>,
        mut plan: Option<&mut planning::Capture>,
    ) -> Result<Self, StoreFailure> {
        let inputs = owners.inputs();
        let evidence = owners.evidence();
        if commit.commit().tree != evidence.root {
            return Err(invalid());
        }
        let mode = match &inputs.selection {
            properties::selected::Selection::Legacy => ViewInterpretationMode::Legacy,
            _ => ViewInterpretationMode::Recorded,
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
        owners.check_requirements(commit, defaults)?;

        // A valid owner-local binding still needs the real relationship loader.
        // No binding is ignored merely because the inherited Index result is empty.
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
            if inputs.selection == properties::selected::Selection::Legacy {
                reject_bindings(node.props.as_deref().unwrap_or(&[]))?;
            } else {
                active::check_namespace_node(
                    &node,
                    evidence.roots.contains(identity),
                    &inputs.selection,
                    inputs.registries.attribute_revision,
                )?;
            }
        }
        let mut roots = Vec::new();
        #[cfg(all(test, feature = "tokio", unix))]
        planning::work::occurrence_walk();
        for occurrence in evidence.occurrences(inputs.minimum)? {
            #[cfg(all(test, feature = "tokio", unix))]
            planning::work::occurrence();
            for (properties, overrides) in &occurrence.layers {
                if inputs.selection == properties::selected::Selection::Legacy {
                    reject_bindings(properties)?;
                    reject_bindings(overrides)?;
                } else if inputs.registries.property_revision >= 2
                    && overrides
                        .iter()
                        .any(|property| property.name == "index-roots")
                {
                    return Err(unsupported());
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
            owners.check(occurrence.root)?;
            #[cfg(all(test, feature = "tokio", unix))]
            planning::work::resolution();
            let effective = inputs
                .selection
                .resolve(&layers, defaults)
                .map_err(malformed)?;
            let attributes = match effective.get(PropertyName::Index) {
                Some(Value::Names(names)) if names.is_empty() => names,
                Some(Value::Names(names)) if inputs.registries.attribute_revision == 2 => names,
                Some(Value::Names(_)) => return Err(unsupported()),
                _ => return Err(invalid()),
            };
            // Collection follows the original support refusal. Partial subjects
            // never escape if a later occurrence fails pending preparation.
            if let Some(plan) = plan.as_deref_mut() {
                plan.record(
                    occurrence.root,
                    attributes,
                    &effective,
                    evidence.root_usage(occurrence.root),
                );
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
            inputs: inputs.clone(),
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

impl PendingViewUse {
    /// Prepares ordinary data under an explicitly supplied full profile.
    ///
    /// The owning history engine uses its captured Native inputs and separately
    /// defers relationships. This compatibility path preserves the existing
    /// direct relationship witnesses without constructing CompletedViewUse.
    ///
    /// # Errors
    /// Rejects root, profile, namespace, signed requirement or index relationship
    /// contradictions and preserves underlying storage failures.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) async fn prepare_with_profile<S: crate::store::Store, C: crate::store::Clock>(
        guard: &Guard<S, C>,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
        interpretation: &crate::guard::recorded_properties::SelectedReadInterpretation,
        uploads: &[crate::guard::StagedUpload],
        profile: &ConfiguredRegistryInputs,
    ) -> Result<Self, StoreFailure> {
        let actual = profile_inputs_with_attribute_revision(
            guard,
            commit,
            interpretation,
            profile.attribute_revision,
        )?;
        if actual != *profile {
            return Err(invalid());
        }
        let inputs =
            guard.completion_inputs_for(interpretation.selection(), profile.attribute_revision)?;
        let prepared = Self::prepare(&inputs, commit, evidence)?;
        let mut requirements = Vec::new();
        for occurrence in evidence.occurrences(guard.config().min_chunk_size)? {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = interpretation.resolve(&layers, guard.defaults_for(evidence))?;
            match effective.get(PropertyName::Index) {
                Some(Value::Names(names)) => requirements.extend(
                    names
                        .iter()
                        .map(|name| (occurrence.root, (*name).to_owned())),
                ),
                _ => return Err(invalid()),
            }
        }
        indexes::verify(
            guard.store(),
            evidence,
            uploads,
            profile,
            requirements,
            guard.config().min_chunk_size,
        )
        .await?;
        Ok(prepared)
    }

    /// Preserves direct preparation witnesses with actual installed view inputs.
    ///
    /// # Errors
    /// Preserves the full-profile preparation and genuine relationship errors.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) async fn prepare_interpreted<S: crate::store::Store, C: crate::store::Clock>(
        guard: &Guard<S, C>,
        commit: &VerifiedCommit,
        evidence: &TreeEvidence,
        interpretation: &crate::guard::recorded_properties::SelectedReadInterpretation,
        uploads: &[crate::guard::StagedUpload],
    ) -> Result<Self, StoreFailure> {
        let profile = profile_inputs(guard, commit, interpretation)?;
        Self::prepare_with_profile(guard, commit, evidence, interpretation, uploads, &profile).await
    }
}

/// Projects the actual installed signed-view profile as ordinary verifier data.
///
/// # Errors
/// Rejects missing selections, root substitutions and interpretation conflicts.
pub(in crate::guard) fn profile_inputs<S: crate::store::Store, C: crate::store::Clock>(
    guard: &Guard<S, C>,
    commit: &VerifiedCommit,
    interpretation: &crate::guard::recorded_properties::SelectedReadInterpretation,
) -> Result<ConfiguredRegistryInputs, StoreFailure> {
    let (actual, profile) =
        guard.selected_view_profile(commit, super::HistoryObservation::default())?;
    if actual != *interpretation {
        return Err(invalid());
    }
    Ok(profile)
}

/// Checks explicitly supplied semantics against actual signed physical inputs.
///
/// # Errors
/// Rejects unsupported physical profiles, attribute revisions and view/root
/// substitutions. This ordinary projection establishes no history authority.
#[cfg(all(test, feature = "tokio", unix))]
pub(in crate::guard) fn profile_inputs_with_attribute_revision<
    S: crate::store::Store,
    C: crate::store::Clock,
>(
    guard: &Guard<S, C>,
    commit: &VerifiedCommit,
    interpretation: &crate::guard::recorded_properties::SelectedReadInterpretation,
    attribute_revision: u64,
) -> Result<ConfiguredRegistryInputs, StoreFailure> {
    if commit.commit().profile_pair.tree_format != 1
        || commit.commit().profile_pair.chunk_profile != guard.config().chunk_profile_name
        || guard.config().chunk_profile_name != "cdc-1m"
        || guard.config().min_chunk_size != guard.config().chunk_profile.minimum() as u64
    {
        return Err(unsupported());
    }
    if let crate::guard::recorded_properties::SelectedReadInterpretation::Recorded(association) =
        interpretation
        && (association.view() != commit.identity()
            || association.original_root() != commit.commit().tree)
    {
        return Err(invalid());
    }
    Ok(guard
        .completion_inputs_for(interpretation.selection(), attribute_revision)?
        .registries)
}
