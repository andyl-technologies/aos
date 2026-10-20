//! Acquires exact old/new inputs before synchronous native index maintenance.
//!
//! Selections are derived from real namespace occurrences and independently
//! chosen view profiles. Missing bindings are data gaps, never caller permits.

mod maintenance;
mod propagation;
mod report;

pub use super::super::snapshot::IndexGraftValidationWork;
pub use report::{
    IndexBindingGap, IndexGraftPreparationWork, IndexGraftPropagationWork, IndexOperationWork,
    IndexPublicationWork,
};

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use terrane_format::gc::publication::evidence::ConfiguredRegistryInputs;
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::indexing::IndexRoots;
use terrane_format::properties::{PropertyName, RootLayer, Value};

use crate::guard::history::completion::indexes::{IndexInputReads, Inputs, failure};
use crate::guard::snapshot::ValidatedGrafts;
use crate::guard::{
    Guard, HistoryObservation, SelectedReadInterpretation, StagedUpload, TreeEvidence, invalid,
};
use crate::indexing::{self, Loaded, LoadedSource, SemanticRevisions};
use crate::store::{Clock, Store, StoreFailure};

/// Binds the actual historical view to its independent namespace inputs.
pub(in crate::guard) struct Previous<'a> {
    /// Exact reached namespace from the independently verified historical view.
    pub(in crate::guard) evidence: &'a TreeEvidence,
    /// Independently selected property interpretation for this exact old view.
    pub(in crate::guard) interpretation: &'a SelectedReadInterpretation,
    /// Actual independently selected historical namespace revisions.
    pub(in crate::guard) profile: ConfiguredRegistryInputs,
}

/// Retains one old immutable owner whose same-context index can be maintained.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Prior {
    owner: Digest,
    required: bool,
}

struct AttributePlan {
    attribute: String,
    binding: Option<Digest>,
    prior: BTreeMap<Option<Prior>, Vec<Vec<u8>>>,
}

struct OwnerPlan {
    owner: Digest,
    depth: usize,
    occurrences: usize,
    attributes: BTreeMap<String, AttributePlan>,
    /// Shared addresses from this exact independently validated namespace.
    grafts: Arc<ValidatedGrafts>,
}

struct Acquired {
    namespace: LoadedSource,
    namespace_reads: IndexInputReads,
    plans: Vec<OwnerPlan>,
    old: BTreeMap<(Digest, String), (Loaded, IndexInputReads)>,
    supplied: BTreeMap<(Digest, String), (Loaded, IndexInputReads)>,
}

/// Binds replay to the output profile and its exact completed signed inputs.
pub(in crate::guard) struct OverlayIndexReplay<'a> {
    /// Independently selected historical output codec and registry inputs.
    pub(in crate::guard) profile: &'a ConfiguredRegistryInputs,
    /// Historical interpretation used for actual output policy occurrences.
    pub(in crate::guard) interpretation: &'a SelectedReadInterpretation,
    /// Ordered signed input identities and their completed namespace evidence.
    pub(in crate::guard) sources: &'a [(Digest, &'a TreeEvidence)],
    /// Owning synchronization and protected-history observation.
    pub(in crate::guard) observation: HistoryObservation<'a>,
}

struct MaintenanceContext<'a> {
    profile: &'a ConfiguredRegistryInputs,
    interpretation: Option<&'a SelectedReadInterpretation>,
    overlay_sources: Option<&'a [(Digest, &'a TreeEvidence)]>,
    observation: HistoryObservation<'a>,
}

/// Owns final unsigned bytes and separately measured actual writer operations.
pub(in crate::guard) struct Output {
    /// Final unsigned namespace identity after actual completion.
    pub(in crate::guard) root: Digest,
    /// Ordinary newly emitted immutable Node bytes.
    pub(in crate::guard) nodes: BTreeMap<Digest, Vec<u8>>,
    /// Separate measured acquisition, validation and maintenance operations.
    pub(in crate::guard) work: IndexPublicationWork,
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Derives the previous profile from its real independently selected signed view.
    ///
    /// # Errors
    /// Preserves full original-history failures and rejects inconsistent selected
    /// roots, property interpretations or namespace profiles.
    pub(super) async fn index_previous_profile(
        &self,
        identity: Digest,
        evidence: &TreeEvidence,
        interpretation: &SelectedReadInterpretation,
    ) -> Result<ConfiguredRegistryInputs, StoreFailure> {
        let previous = self.verified_tree(identity).await?;
        if previous.evidence.root != evidence.root {
            return Err(invalid());
        }
        let (selected, profile) =
            self.selected_view_profile(&previous.commit, HistoryObservation::default())?;
        if selected != *interpretation {
            return Err(invalid());
        }
        Ok(profile)
    }

    /// Independently checks every candidate closure for an explicit metadata-only repair.
    ///
    /// # Errors
    /// Rejects any missing binding, unavailable closure or divergent relationship.
    pub(super) async fn verify_rebuilt_indexes(
        &self,
        candidate: &TreeEvidence,
        uploads: &[StagedUpload],
    ) -> Result<(), StoreFailure> {
        let profile = self.configured_authoring_registries()?;
        let inputs = Inputs::new(self.store(), candidate, uploads)?;
        for plan in self.index_plans(candidate, None, self.config().min_chunk_size)? {
            for attribute in plan.attributes.values() {
                let loaded = indexing::load_for(
                    &inputs,
                    plan.owner,
                    &attribute.attribute,
                    revisions(&profile),
                    self.config().min_chunk_size,
                    candidate.root_usage(plan.owner),
                )
                .await
                .map_err(failure)?;
                let source = loaded.sources().map_err(failure)?;
                loaded.prepare(&source.trees).map_err(failure)?;
            }
        }
        Ok(())
    }

    /// Prepares all required ordinary index changes before receipts and signing.
    ///
    /// # Errors
    /// Rejects invalid namespace/auxiliary inputs, divergent substitutions,
    /// dropped valid required bindings and unsupported maintenance, retaining causes.
    pub(super) async fn maintain_candidate_indexes(
        &self,
        candidate: &TreeEvidence,
        uploads: &[StagedUpload],
        previous: Option<Previous<'_>>,
    ) -> Result<Option<Output>, StoreFailure> {
        let profile = self.configured_authoring_registries()?;
        self.maintain_indexes_for(
            candidate,
            uploads,
            previous,
            MaintenanceContext {
                profile: &profile,
                interpretation: None,
                overlay_sources: None,
                observation: HistoryObservation::default(),
            },
        )
        .await
    }

    /// Rebinds inherited input indexes to the actual ordinary overlay namespace.
    ///
    /// Input bindings are checked against their signed source owner. They never
    /// count as verified output indexes: maintenance computes every emitted row.
    ///
    /// # Errors
    /// Rejects forged source associations, invalid inherited relationships,
    /// dropped required bindings and unsupported namespace maintenance.
    pub(super) async fn maintain_overlay_candidate_indexes(
        &self,
        candidate: &TreeEvidence,
        uploads: &[StagedUpload],
        previous: Option<Previous<'_>>,
        sources: &[(Digest, TreeEvidence)],
        observation: HistoryObservation<'_>,
    ) -> Result<Option<Output>, StoreFailure> {
        let profile = self.configured_authoring_registries()?;
        let sources = sources
            .iter()
            .map(|(identity, evidence)| (*identity, evidence))
            .collect::<Vec<_>>();
        self.maintain_indexes_for(
            candidate,
            uploads,
            previous,
            MaintenanceContext {
                profile: &profile,
                interpretation: None,
                overlay_sources: Some(&sources),
                observation,
            },
        )
        .await
    }

    /// Repeats completion under the output's independently selected historical profile.
    ///
    /// # Errors
    /// Preserves canonical reconstruction, index relationship and maintenance failures.
    pub(in crate::guard) async fn maintain_replayed_indexes(
        &self,
        candidate: &TreeEvidence,
        uploads: &[StagedUpload],
        previous: Option<Previous<'_>>,
        replay: OverlayIndexReplay<'_>,
    ) -> Result<Option<Output>, StoreFailure> {
        self.maintain_indexes_for(
            candidate,
            uploads,
            previous,
            MaintenanceContext {
                profile: replay.profile,
                interpretation: Some(replay.interpretation),
                overlay_sources: Some(replay.sources),
                observation: replay.observation,
            },
        )
        .await
    }

    async fn maintain_indexes_for(
        &self,
        candidate: &TreeEvidence,
        uploads: &[StagedUpload],
        previous: Option<Previous<'_>>,
        context: MaintenanceContext<'_>,
    ) -> Result<Option<Output>, StoreFailure> {
        let profile = context.profile;
        if let Some(sources) = context.overlay_sources {
            if sources.is_empty()
                || candidate.usage != terrane_format::tree_format::TreeUse::Ordinary
            {
                return Err(invalid());
            }
            for (identity, evidence) in sources {
                let commit = evidence.commit.as_ref().ok_or_else(invalid)?;
                if commit.identity().map_err(|_| invalid())? != *identity
                    || commit.tree != evidence.root
                {
                    return Err(invalid());
                }
            }
        }
        if (
            profile.property_revision,
            profile.attribute_revision,
            profile.tree_revision,
        ) != (3, 2, 1)
        {
            return Ok(None);
        }
        let minimum = self.config().min_chunk_size;
        let revisions = revisions(profile);
        let inputs = Inputs::new(self.store(), candidate, uploads)?;
        let namespace = indexing::load_source_for(
            &inputs,
            candidate.root,
            revisions,
            minimum,
            candidate.root_usage(candidate.root),
        )
        .await
        .map_err(failure)?;
        let namespace_reads = inputs.reads();
        let plans = self.index_plans_for(
            candidate,
            previous.as_ref(),
            minimum,
            context.interpretation,
            context.overlay_sources.is_some(),
        )?;
        let mut old = BTreeMap::new();
        let mut supplied = BTreeMap::new();
        for plan in &plans {
            for attribute in plan.attributes.values() {
                let mut prior_roots = BTreeSet::new();
                for prior in attribute.prior.keys().flatten() {
                    let key = (prior.owner, attribute.attribute.clone());
                    if !old.contains_key(&key) {
                        let previous = previous.as_ref().ok_or_else(invalid)?;
                        let inputs = Inputs::new(self.store(), previous.evidence, &[])?;
                        let loaded = indexing::load_for(
                            &inputs,
                            prior.owner,
                            &attribute.attribute,
                            revisions,
                            minimum,
                            previous.evidence.root_usage(prior.owner),
                        )
                        .await
                        .map_err(failure)?;
                        old.insert(key.clone(), (loaded, inputs.reads()));
                    }
                    let loaded = old.get(&key).ok_or_else(invalid)?;
                    prior_roots.insert(loaded.0.index_root());
                }
                if let Some(binding) = attribute.binding
                    && (context.overlay_sources.is_some() || !prior_roots.contains(&binding))
                {
                    let acquired = if let Some(sources) = context.overlay_sources {
                        self.load_inherited_overlay_index(
                            sources,
                            &attribute.attribute,
                            binding,
                            context.observation,
                        )
                        .await?
                        .ok_or_else(invalid)?
                    } else {
                        let supplied_inputs = Inputs::new(self.store(), candidate, uploads)?;
                        let loaded = indexing::load_for(
                            &supplied_inputs,
                            plan.owner,
                            &attribute.attribute,
                            revisions,
                            minimum,
                            candidate.root_usage(plan.owner),
                        )
                        .await
                        .map_err(failure)?;
                        (loaded, supplied_inputs.reads())
                    };
                    supplied.insert((plan.owner, attribute.attribute.clone()), acquired);
                }
            }
        }
        // No Rc-backed Tree or arena borrow crosses an asynchronous operation.
        maintenance::execute(
            Acquired {
                namespace,
                namespace_reads,
                plans,
                old,
                supplied,
            },
            minimum,
        )
        .map(Some)
    }

    /// Acquires a copied binding only under its exact signed input owner context.
    async fn load_inherited_overlay_index(
        &self,
        sources: &[(Digest, &TreeEvidence)],
        attribute: &str,
        binding: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<Option<(Loaded, IndexInputReads)>, StoreFailure> {
        let minimum = self.config().min_chunk_size;
        for (identity, evidence) in sources {
            let matching = evidence
                .roots
                .iter()
                .find_map(|root| {
                    // Discovery reads only verified root metadata. Full owner
                    // reconstruction is acquired and measured after a match.
                    let properties = evidence.root_properties(*root, minimum);
                    match properties.and_then(|properties| bindings(&properties)) {
                        Ok(bindings) if bindings.get(attribute) == Some(&binding) => {
                            Some(Ok(*root))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    }
                })
                .transpose()?;
            let Some(owner) = matching else {
                continue;
            };
            let profile = self
                .selected_view_inputs(*identity, evidence.root, observation)?
                .registries;
            let inputs = Inputs::new(self.store(), evidence, &[])?;
            let loaded = indexing::load_for(
                &inputs,
                owner,
                attribute,
                revisions(&profile),
                minimum,
                evidence.root_usage(owner),
            )
            .await
            .map_err(failure)?;
            if loaded.index_root() != binding {
                return Err(invalid());
            }
            // Acquisition is shared; the synchronous executor independently
            // prepares this owner's exhaustive relationship for each actual
            // occurrence group before recomputing output rows and charges each
            // preparation. No changed-output coverage is inferred here.
            return Ok(Some((loaded, inputs.reads())));
        }
        Ok(None)
    }

    fn index_plans(
        &self,
        candidate: &TreeEvidence,
        previous: Option<&Previous<'_>>,
        minimum: u64,
    ) -> Result<Vec<OwnerPlan>, StoreFailure> {
        self.index_plans_for(candidate, previous, minimum, None, false)
    }

    fn index_plans_for(
        &self,
        candidate: &TreeEvidence,
        previous: Option<&Previous<'_>>,
        minimum: u64,
        interpretation: Option<&SelectedReadInterpretation>,
        overlay: bool,
    ) -> Result<Vec<OwnerPlan>, StoreFailure> {
        let occurrences = candidate.occurrences(minimum)?;
        let grafts = candidate.validated_grafts(minimum)?;
        let old_occurrences = previous
            .map(|old| old.evidence.occurrences(minimum))
            .transpose()?
            .unwrap_or_default();
        let old_active = previous.is_some_and(|old| {
            (
                old.profile.property_revision,
                old.profile.attribute_revision,
                old.profile.tree_revision,
            ) == (3, 2, 1)
        });
        let mut plans: BTreeMap<Digest, OwnerPlan> = BTreeMap::new();
        for occurrence in occurrences {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = match interpretation {
                Some(interpretation) => {
                    interpretation.resolve(&layers, self.defaults_for(candidate))?
                }
                None => self.resolve_authoring(&layers, self.defaults_for(candidate))?,
            };
            let Some(Value::Names(names)) = effective.get(PropertyName::Index) else {
                return Err(invalid());
            };
            let candidate_properties = candidate.root_properties(occurrence.root, minimum)?;
            let candidate_bindings = bindings(&candidate_properties)?;
            let old = old_occurrences
                .iter()
                .find(|old| old.path == occurrence.path);
            let old_required = old
                .zip(previous)
                .map(|(occurrence, previous)| {
                    let layers = occurrence
                        .layers
                        .iter()
                        .map(|(properties, overrides)| RootLayer {
                            properties,
                            overrides,
                        })
                        .collect::<Vec<_>>();
                    let effective = previous
                        .interpretation
                        .resolve(&layers, self.defaults_for(previous.evidence))?;
                    let Some(Value::Names(names)) = effective.get(PropertyName::Index) else {
                        return Err(invalid());
                    };
                    Ok(names
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect::<BTreeSet<_>>())
                })
                .transpose()?
                .unwrap_or_default();
            let old_bindings = if old_active {
                old.zip(previous)
                    .map(|(occurrence, previous)| {
                        let properties = previous
                            .evidence
                            .root_properties(occurrence.root, minimum)?;
                        bindings(&properties)
                    })
                    .transpose()?
                    .unwrap_or_default()
            } else {
                BTreeMap::new()
            };
            let plan = plans.entry(occurrence.root).or_insert_with(|| OwnerPlan {
                owner: occurrence.root,
                depth: occurrence.layers.len(),
                occurrences: 0,
                attributes: BTreeMap::new(),
                grafts: Arc::clone(&grafts),
            });
            plan.depth = plan.depth.max(occurrence.layers.len());
            plan.occurrences = plan.occurrences.checked_add(1).ok_or_else(invalid)?;

            let mut maintained = names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<BTreeSet<_>>();
            if overlay {
                maintained.extend(candidate_bindings.keys().cloned());
            }
            for name in &maintained {
                let prior = old
                    .filter(|_| old_bindings.contains_key(name))
                    .map(|old| Prior {
                        owner: old.root,
                        required: old_required.contains(name),
                    });
                let attribute =
                    plan.attributes
                        .entry(name.clone())
                        .or_insert_with(|| AttributePlan {
                            attribute: name.clone(),
                            binding: candidate_bindings.get(name).copied(),
                            prior: BTreeMap::new(),
                        });
                attribute
                    .prior
                    .entry(prior)
                    .or_default()
                    .push(occurrence.path.clone());
            }
        }
        let mut plans = plans.into_values().collect::<Vec<_>>();
        plans.sort_by(|left, right| {
            right
                .depth
                .cmp(&left.depth)
                .then(left.owner.cmp(&right.owner))
        });
        Ok(plans)
    }
}

fn revisions(profile: &ConfiguredRegistryInputs) -> SemanticRevisions {
    SemanticRevisions {
        property: profile.property_revision,
        attribute: profile.attribute_revision,
        tree: profile.tree_revision,
    }
}

fn bindings(
    properties: &[terrane_format::tree_format::Property<'_>],
) -> Result<BTreeMap<String, Digest>, StoreFailure> {
    let Some(binding) = properties
        .iter()
        .find(|property| property.name == "index-roots")
    else {
        return Ok(BTreeMap::new());
    };
    let roots = IndexRoots::decode_binding(binding.value)
        .map_err(|error| StoreFailure::with_source(invalid().kind().clone(), error))?;
    Ok(roots
        .as_bindings()
        .iter()
        .map(|binding| (binding.attribute.to_owned(), binding.node))
        .collect())
}

/// Refuses an omitted maintained binding after independently validating its predecessor.
#[derive(Debug)]
pub(in crate::guard) struct DroppedBinding {
    /// Actual proposed owner from which the maintained required binding was omitted.
    pub(in crate::guard) owner: Digest,
    /// Actual independently resolved required registered attribute.
    pub(in crate::guard) attribute: String,
}

impl std::fmt::Display for DroppedBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "valid required index {} was dropped from {:?}",
            self.attribute, self.owner
        )
    }
}

impl std::error::Error for DroppedBinding {}

/// Adds only distinct actual immutable Node declarations.
///
/// # Errors
/// Rejects a staged Node whose canonical immutable identity cannot be computed.
pub(super) fn append_nodes(
    uploads: &mut Vec<StagedUpload>,
    nodes: BTreeMap<Digest, Vec<u8>>,
) -> Result<(), StoreFailure> {
    let mut present = BTreeSet::new();
    for upload in uploads.iter() {
        if let StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        } = upload
        {
            present.insert(
                TERRANE_V1
                    .calculate(IdentityKind::Node, bytes)
                    .and_then(|identity| identity.terrane_v1_digest())
                    .map_err(|_| invalid())?,
            );
        }
    }
    for (identity, bytes) in nodes {
        if !present.insert(identity) {
            continue;
        }
        uploads.push(StagedUpload::Meta {
            kind: IdentityKind::Node,
            bytes,
        });
    }
    Ok(())
}
