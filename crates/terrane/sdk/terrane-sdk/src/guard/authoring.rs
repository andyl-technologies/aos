//! Selects owned authoring inputs without replacing current or historical configuration.
//!
//! Recorded contexts retain independently supplied current fences. New namespace
//! validation executes that exact context, while the complete Guard snapshot and
//! each historical view remain independently selected by their owning constructors.

use terrane_format::{
    gc::publication::evidence::ConfiguredRegistryInputs,
    properties::{self, Defaults, EffectiveProperties, RootLayer, semantics::RecordedContext},
    provenance::VerifiedCommit,
};

use super::{Guard, RecordedNamespaceProfiles, SelectedReadInterpretation, invalid};
use crate::store::{Clock, Store, StoreFailure};

#[cfg(all(test, feature = "tokio", unix))]
mod tests;

/// Retains independently chosen property, current and namespace attribute inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoringNamespaceProfile {
    context: RecordedContext,
    registries: ConfiguredRegistryInputs,
}

impl AuthoringNamespaceProfile {
    /// Copies explicit registered authoring semantics and an independent current fence.
    ///
    /// Namespace attribute selection remains independent of property revision.
    /// The current fence is ordinary operator input and is never reconstructed
    /// from compiled names, historical bytes or the complete Guard snapshot.
    ///
    /// # Errors
    /// Rejects invalid revisions, preservation vocabularies or attributes outside1/2.
    pub fn new(
        property_revision: u64,
        current_revision: u64,
        later_registered: &[&str],
        attribute_revision: u64,
    ) -> Result<Self, properties::Error> {
        let context = RecordedContext::new(property_revision, current_revision, later_registered)?;
        if !matches!(attribute_revision, 1 | 2) {
            return Err(properties::Error::InvalidValue);
        }
        let registries = ConfiguredRegistryInputs {
            property_revision,
            behavioral_properties: context.behavioral_names().map(str::to_owned).collect(),
            attribute_revision,
            selector_revision: 1,
            tree_revision: 1,
            chunk_revision: 1,
            identity_profile: "terrane-v1".to_owned(),
            later_properties: context.later_registered().to_vec(),
        };
        Ok(Self {
            context,
            registries,
        })
    }

    /// Borrows the actual owned authoring context, including its current fence.
    pub fn context(&self) -> &RecordedContext {
        &self.context
    }

    /// Borrows exact ordinary registered semantic inputs for the new namespace.
    pub fn registries(&self) -> &ConfiguredRegistryInputs {
        &self.registries
    }
}

impl<S, C> Guard<S, C> {
    /// Projects actual authoring inputs without replacing configured-current inputs.
    ///
    /// # Errors
    /// Rejects invalid actual registered authoring configuration.
    pub(super) fn configured_authoring_registries(
        &self,
    ) -> Result<ConfiguredRegistryInputs, StoreFailure> {
        Ok(self.completion_inputs()?.registries)
    }

    /// Installs explicit authoring inputs on a fresh independently configured Legacy-current Guard.
    ///
    /// Historical reads use strict per-view configuration. Native operators that
    /// select Active current configuration use `new_active` and the guarded
    /// `with_recorded_authoring` builder before native initialization instead.
    /// This constructor initializes no Original or executed-view evidence.
    pub fn new_with_authoring_namespace_profile(
        store: S,
        clock: C,
        keys: Vec<terrane_format::auth::IssuerKey>,
        config: super::GuardConfig,
        authoring: AuthoringNamespaceProfile,
    ) -> Self {
        let mut guard = Self::new(store, clock, keys, config);
        guard.authoring_selection = Some((
            properties::selected::Selection::Recorded(authoring.context),
            authoring.registries.attribute_revision,
        ));
        guard.interpretation = super::history::completion::InterpretationSelection::Active;
        guard
    }

    /// Installs fresh explicit history and authoring while preserving independent current inputs.
    ///
    /// Missing historical mappings refuse; authoring cannot replace any existing
    /// view/root association. Protected Original state starts empty.
    pub fn new_with_recorded_namespace_profiles_and_authoring(
        store: S,
        clock: C,
        keys: Vec<terrane_format::auth::IssuerKey>,
        config: super::GuardConfig,
        profiles: RecordedNamespaceProfiles,
        authoring: AuthoringNamespaceProfile,
    ) -> Self {
        let mut guard =
            Self::new_with_recorded_namespace_profiles(store, clock, keys, config, profiles);
        guard.authoring_selection = Some((
            properties::selected::Selection::Recorded(authoring.context),
            authoring.registries.attribute_revision,
        ));
        guard
    }

    /// Resolves actual authoring layers under their independently captured execution.
    ///
    /// # Errors
    /// Preserves placement, value and preservation-vocabulary failures.
    pub(super) fn resolve_authoring<'p>(
        &self,
        layers: &[RootLayer<'p>],
        defaults: Defaults<'p>,
    ) -> Result<EffectiveProperties<'p>, StoreFailure> {
        self.completion_inputs()?
            .selection
            .resolve(layers, defaults)
            .map_err(|error| StoreFailure::with_source(invalid().kind().clone(), error))
    }
}

impl<S: Store, C: Clock> Guard<S, C> {
    /// Validates the complete candidate under its independently selected namespace revision.
    ///
    /// This synchronous pass also visits unchanged roots and conflict alternatives.
    /// All borrowed Trees are dropped before admission's authorization awaits.
    ///
    /// # Errors
    /// Rejects invalid canonical trees and attribute placement or values under
    /// the selected revision before a candidate signature or immutable effect.
    pub(super) fn validate_candidate_namespace_attributes(
        &self,
        evidence: &super::TreeEvidence,
        attribute_revision: u64,
    ) -> Result<(), StoreFailure> {
        for root in &evidence.roots {
            let tree = evidence.tree(*root, self.config().min_chunk_size)?;
            for item in tree.iter() {
                let mut entries = vec![&item.entry];
                while let Some(entry) = entries.pop() {
                    terrane_format::indexing::carrier::validate_namespace_attributes(
                        attribute_revision,
                        entry,
                    )
                    .map_err(|_| invalid())?;
                    if let terrane_format::tree_format::EntryKind::Conflict { candidates, base } =
                        &entry.kind
                    {
                        entries.extend(candidates);
                        if let Some(Some(base)) = base {
                            entries.push(base);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Derives publication units from canonical witnesses and exact per-view selections.
    ///
    /// The local comparison commit grants no authority and is never signed or
    /// persisted. Existing publication compares against its actual current head,
    /// independently of the immutable target's original signed first parent.
    ///
    /// # Errors
    /// Rejects a missing prior commit for existing publication, mismatched roots
    /// or incomplete canonical evidence.
    pub(super) fn candidate_root_changes(
        &self,
        commit: &terrane_format::refs::Commit,
        candidate: &super::TreeEvidence,
        selection: &properties::selected::Selection,
        previous: Option<super::admission::CandidatePrevious<'_>>,
        fresh: bool,
    ) -> Result<terrane_format::provenance::RootChangePlan, StoreFailure> {
        use terrane_format::{provenance, tree_format::TreeUse};

        if commit.tree != candidate.root {
            return Err(invalid());
        }
        let mut history = provenance::VerifiedHistory::new_selected(
            self.config().min_chunk_size,
            selection.clone(),
        );
        let mut insert = |evidence: &super::TreeEvidence| -> Result<(), StoreFailure> {
            let nodes = evidence
                .nodes
                .iter()
                .map(|(identity, bytes)| (*identity, bytes.clone()))
                .collect::<Vec<_>>();
            for root in &evidence.roots {
                match evidence.root_usage(*root) {
                    TreeUse::Ordinary => history.insert_tree(*root, &nodes),
                    TreeUse::OverlayLayer => history.insert_overlay_tree(*root, &nodes),
                    TreeUse::Index | TreeUse::Surface | TreeUse::ConflictSurface => {
                        return Err(invalid());
                    }
                }
                .map_err(|_| invalid())?;
            }
            Ok(())
        };
        insert(candidate)?;
        if !fresh {
            insert(previous.ok_or_else(invalid)?.evidence)?;
        }
        if fresh {
            return provenance::derive_fresh_roots(&history, commit, self.defaults_for(candidate))
                .map_err(|_| invalid());
        }
        let prior = previous.ok_or_else(invalid)?;
        let verified = prior.commit.ok_or_else(invalid)?;
        if verified.commit().tree != prior.evidence.root {
            return Err(invalid());
        }
        history
            .insert_commit_selected(verified.clone(), prior.interpretation.selection())
            .map_err(|_| invalid())?;
        let mut comparison = commit.clone();
        comparison.parents = vec![verified.identity()];
        provenance::derive_root_changes(&history, &comparison, self.defaults_for(candidate))
            .map_err(|_| invalid())
    }

    /// Projects the actual closed authoring selection into signed-view ordinary data.
    ///
    /// # Errors
    /// Rejects unregistered inputs or signed physical profile substitutions.
    pub(super) fn admitted_authoring_inputs(
        &self,
        commit: &VerifiedCommit,
    ) -> Result<(SelectedReadInterpretation, ConfiguredRegistryInputs), StoreFailure> {
        if commit.commit().profile_pair.chunk_profile != self.config().chunk_profile_name
            || self.config().min_chunk_size != self.config().chunk_profile.minimum() as u64
        {
            return Err(invalid());
        }
        let inputs = self.completion_inputs()?;
        let interpretation = SelectedReadInterpretation::from_selection(
            commit.identity(),
            commit.commit().tree,
            inputs.selection,
        )?;
        Ok((interpretation, inputs.registries))
    }
}
