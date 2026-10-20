//! Selects independently installed immutable-view interpretations.
//!
//! Operator configuration and closed candidate admission supply ordinary semantic
//! inputs. Neither decoded lineage nor a missing association initializes them.

#[cfg(test)]
#[path = "view_selection/adapter_tests.rs"]
mod adapter_tests;

#[cfg(all(test, feature = "tokio", unix))]
#[path = "view_selection/native_fixture.rs"]
pub(crate) mod native_fixture;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use terrane_format::identity::Digest;
use terrane_format::properties::selected::Selection;

use super::history::completion::{InterpretationSelection, SelectedInputs};
use super::{AdmittedCommit, Guard, HistoryObservation, invalid};
use crate::store::{StoreErrorKind, StoreFailure};

/// Binds explicitly installed semantic execution to one signed view and original root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewSelection {
    view: Digest,
    original_root: Digest,
    semantics: Selection,
    attribute_revision: u64,
}

impl ViewSelection {
    /// Creates an ordinary immutable-view configuration association.
    ///
    /// This supplies no Original, current permission or history completeness.
    ///
    /// # Errors
    /// Rejects unsupported attribute semantics or legacy structural interpretation.
    pub fn new(
        view: Digest,
        original_root: Digest,
        semantics: Selection,
        attribute_revision: u64,
    ) -> Result<Self, StoreFailure> {
        if !matches!(attribute_revision, 1 | 2)
            || matches!(semantics, Selection::Active)
            || matches!(semantics, Selection::Legacy) && attribute_revision != 1
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(Self {
            view,
            original_root,
            semantics,
            attribute_revision,
        })
    }
}

/// Captures ordinary candidate inputs from an existing closed admission.
///
/// This immutable data owns no history completeness or publication permission.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CandidateInputs {
    selected: ViewSelection,
    inputs: SelectedInputs,
}

/// Retains immutable operator associations and privately executed input data.
///
/// The shared map supplies configuration only, never graph completion or authority.
#[derive(Clone, Default)]
pub(super) struct ViewSelections {
    installed: Arc<BTreeMap<Digest, ViewSelection>>,
    executed: Arc<RwLock<BTreeMap<Digest, ViewSelection>>>,
}

impl<S, C> Guard<S, C> {
    /// Compares actual immutable table retention for data-only adapter witnesses.
    #[cfg(test)]
    pub(in crate::guard) fn shares_view_selection_configuration<T, D>(
        &self,
        other: &Guard<T, D>,
    ) -> bool {
        Arc::ptr_eq(
            &self.view_selections.installed,
            &other.view_selections.installed,
        ) && Arc::ptr_eq(
            &self.view_selections.executed,
            &other.view_selections.executed,
        )
    }

    /// Retains ordinary configuration with the exact replacement store and clock.
    ///
    /// Native concrete, setup and held adapters use this shared constructor.
    /// Protected Original state starts empty and is separately restored by its
    /// owning adapter; configuration data never manufactures that evidence.
    pub(in crate::guard) fn configuration_adapter<T, D>(&self, store: T, clock: D) -> Guard<T, D> {
        let mut adapted = Guard::new(store, clock, self.keys.clone(), self.config.clone());
        adapted.interpretation = self.interpretation;
        adapted.configured_current = self.configured_current;
        adapted.view_selections = self.view_selections.clone();
        adapted.authoring_selection = self.authoring_selection.clone();
        adapted
    }

    /// Selects explicitly configured Recorded semantics for new authored views.
    ///
    /// # Errors
    /// Rejects unsupported attribute semantics, an invalid full registered profile,
    /// unavailable state, or replacement after native capture or executed history.
    pub fn with_recorded_authoring(
        self,
        context: terrane_format::properties::semantics::RecordedContext,
        attribute_revision: u64,
    ) -> Result<Self, StoreFailure> {
        self.with_authoring_selection(Selection::Recorded(context), attribute_revision)
    }

    /// Selects Legacy execution for new views without changing current configuration.
    ///
    /// # Errors
    /// Rejects replacement after native capture or executed history, or unavailable state.
    pub fn with_legacy_authoring(self) -> Result<Self, StoreFailure> {
        self.with_authoring_selection(Selection::Legacy, 1)
    }

    // Authoring is independent of the immutable full configured-current snapshot.
    fn with_authoring_selection(
        mut self,
        selection: Selection,
        attribute_revision: u64,
    ) -> Result<Self, StoreFailure> {
        if self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .is_some()
        {
            return Err(invalid());
        }
        if !self
            .view_selections
            .executed
            .read()
            .map_err(|_| unavailable())?
            .is_empty()
        {
            return Err(invalid());
        }
        self.completion_inputs_for(selection.clone(), attribute_revision)?;
        self.authoring_selection = Some((selection, attribute_revision));
        self.interpretation = InterpretationSelection::Active;
        Ok(self)
    }

    /// Captures the independently configured complete current registry profile.
    ///
    /// Historical authoring and per-view associations do not replace these inputs.
    ///
    /// # Errors
    /// Rejects an invalid registered current profile.
    pub(in crate::guard) fn configured_current_registries(
        &self,
    ) -> Result<terrane_format::gc::publication::evidence::ConfiguredRegistryInputs, StoreFailure>
    {
        let attribute_revision = match self.configured_current {
            InterpretationSelection::Legacy => 1,
            InterpretationSelection::Active => 2,
        };
        Ok(self
            .completion_inputs_for(self.configured_current.semantics(), attribute_revision)?
            .registries)
    }

    /// Installs explicit historical selections before opening native retention.
    ///
    /// Missing views refuse in Active mode. The Legacy constructor deliberately
    /// retains its explicit legacy policy for views without an installed entry.
    ///
    /// # Errors
    /// Rejects conflicting duplicate views, unavailable state or replacement after completion.
    pub fn with_view_selections(
        mut self,
        entries: Vec<ViewSelection>,
    ) -> Result<Self, StoreFailure> {
        if self
            .original_verifier
            .read()
            .map_err(|_| unavailable())?
            .is_some()
            || !self
                .view_selections
                .executed
                .read()
                .map_err(|_| unavailable())?
                .is_empty()
        {
            return Err(invalid());
        }
        let mut installed = BTreeMap::new();
        for entry in entries {
            if let Some(existing) = installed.get(&entry.view) {
                if existing != &entry {
                    return Err(invalid());
                }
                continue;
            }
            installed.insert(entry.view, entry);
        }
        self.view_selections.installed = Arc::new(installed);
        Ok(self)
    }

    /// Captures the exact candidate interpretation without borrowing mutable staging state.
    ///
    /// Only an existing closed admission supplies the signed identity/root and
    /// independently selected authoring inputs. This capture cannot authorize
    /// history or publication. Native setup, held refresh and final publication
    /// separately compare the complete current configuration with the actual
    /// selected protected Guard snapshot.
    ///
    /// # Errors
    /// Rejects any difference from this Guard's actual authoring and selected-view inputs.
    pub(crate) fn capture_candidate_inputs(
        &self,
        admitted: &AdmittedCommit,
    ) -> Result<CandidateInputs, StoreFailure> {
        let view = admitted.commit.identity();
        let root = admitted.commit.commit().tree;
        let known = self.view_selections.installed.contains_key(&view)
            || self
                .view_selections
                .executed
                .read()
                .map_err(|_| unavailable())?
                .contains_key(&view);
        let actual = if known {
            self.selected_view_inputs(view, root, HistoryObservation::default())?
        } else {
            self.completion_inputs()?
        };
        if actual != admitted.completion_inputs {
            return Err(invalid());
        }
        Ok(CandidateInputs {
            selected: self.candidate_view_selection(admitted),
            inputs: actual,
        })
    }

    /// Selects one independently installed or genuinely admitted signed view.
    ///
    /// # Errors
    /// Rejects missing strict associations, changed signed roots or conflicting inputs.
    pub(in crate::guard) fn selected_view_inputs(
        &self,
        view: Digest,
        original_root: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<SelectedInputs, StoreFailure> {
        let candidate = observation
            .candidate
            .filter(|candidate| candidate.selected.view == view);
        let installed = self.view_selections.installed.get(&view).cloned();
        let executed = self
            .view_selections
            .executed
            .read()
            .map_err(|_| unavailable())?
            .get(&view)
            .cloned();
        if installed
            .as_ref()
            .zip(executed.as_ref())
            .is_some_and(|(left, right)| left != right)
        {
            return Err(invalid());
        }
        let known = installed.or(executed);
        if let Some(candidate) = candidate {
            // A closed admission from another Guard cannot supply this operation's
            // constructor inputs merely by borrowing its signed candidate.
            let actual = match &known {
                Some(selected) => self.completion_inputs_for(
                    selected.semantics.clone(),
                    selected.attribute_revision,
                )?,
                None => self.completion_inputs()?,
            };
            if candidate.inputs != actual {
                return Err(invalid());
            }
            let selected = &candidate.selected;
            if selected.original_root != original_root
                || known.as_ref().is_some_and(|old| old != selected)
            {
                return Err(invalid());
            }
            return Ok(actual);
        }
        match known {
            Some(selected) if selected.original_root == original_root => {
                self.completion_inputs_for(selected.semantics, selected.attribute_revision)
            }
            Some(_) => Err(invalid()),
            None if self.interpretation == InterpretationSelection::Legacy => {
                self.completion_inputs()
            }
            None => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        }
    }

    /// Observes actual independently selected ordinary inputs for owning tests.
    ///
    /// This delegates the production selector and mutates no configuration,
    /// completed history, native publication or authority state.
    ///
    /// # Errors
    /// Preserves strict missing, root/conflict and synchronization refusals.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(crate) fn selected_view_context_for_tests(
        &self,
        view: Digest,
        original_root: Digest,
    ) -> Result<
        (
            Selection,
            terrane_format::gc::publication::evidence::ConfiguredRegistryInputs,
        ),
        StoreFailure,
    > {
        let actual =
            self.selected_view_inputs(view, original_root, HistoryObservation::default())?;
        Ok((actual.selection, actual.registries))
    }

    fn candidate_view_selection(&self, admitted: &AdmittedCommit) -> ViewSelection {
        let inputs = &admitted.completion_inputs;
        ViewSelection {
            view: admitted.commit.identity(),
            original_root: admitted.commit.commit().tree,
            semantics: inputs.selection.clone(),
            attribute_revision: inputs.registries.attribute_revision,
        }
    }

    /// Retains actual executed selection after owning full history or checked cold derivation.
    ///
    /// This map supplies no graph completion or publication authority. Only the
    /// actual producing sites call it after independently checking their inputs.
    ///
    /// # Errors
    /// Rejects contradictory immutable associations or unavailable synchronization.
    pub(super) fn retain_executed_view_inputs(
        &self,
        view: Digest,
        original_root: Digest,
        inputs: &SelectedInputs,
    ) -> Result<(), StoreFailure> {
        let selected = ViewSelection {
            view,
            original_root,
            semantics: inputs.selection.clone(),
            attribute_revision: inputs.registries.attribute_revision,
        };
        if self
            .view_selections
            .installed
            .get(&view)
            .is_some_and(|old| old != &selected)
        {
            return Err(invalid());
        }
        let mut executed = self
            .view_selections
            .executed
            .write()
            .map_err(|_| unavailable())?;
        if executed.get(&view).is_some_and(|old| old != &selected) {
            return Err(invalid());
        }
        executed.insert(view, selected);
        Ok(())
    }
}

fn unavailable() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None })
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "view_selection/historical_tests.rs"]
pub(in crate::guard) mod historical_tests;

impl<S, C> Guard<S, C> {
    /// Installs recorded associations while preserving actual configured-current and authoring inputs.
    ///
    /// The caller chooses `new` or `new_active` independently before this builder.
    /// Historical installation cannot select current policy or overwrite authoring.
    /// Missing historical mappings refuse after installation in strict mode.
    ///
    /// # Errors
    /// Preserves the owning installer's conflict, unavailable-state and post-Original
    /// replacement refusals; rejects an invalid existing authoring profile.
    pub fn with_recorded_views(
        self,
        associations: terrane_format::properties::semantics::associations::RecordedAssociations,
    ) -> Result<Self, StoreFailure> {
        let inputs = self.completion_inputs()?;
        let entries = associations
            .iter()
            .map(|entry| ViewSelection {
                view: entry.view(),
                original_root: entry.original_root(),
                semantics: Selection::Recorded(entry.context().clone()),
                attribute_revision: 1,
            })
            .collect();
        let mut guard = self.with_view_selections(entries)?;
        guard.interpretation = InterpretationSelection::Active;
        guard.authoring_selection = Some((inputs.selection, inputs.registries.attribute_revision));
        Ok(guard)
    }

    /// Installs validated historical namespace profiles without replacing current or authoring.
    ///
    /// # Errors
    /// Preserves unavailable-state, conflicting-association and replacement
    /// refusals from the owning historical installer.
    pub fn with_recorded_namespace_profiles(
        self,
        profiles: super::RecordedNamespaceProfiles,
    ) -> Result<Self, StoreFailure> {
        let inputs = self.completion_inputs()?;
        let entries = profiles
            .iter()
            .map(|profile| {
                let entry = profile.association();
                ViewSelection {
                    view: entry.view(),
                    original_root: entry.original_root(),
                    semantics: Selection::Recorded(entry.context().clone()),
                    attribute_revision: profile.attribute_revision(),
                }
            })
            .collect();
        let mut guard = self.with_view_selections(entries)?;
        guard.interpretation = InterpretationSelection::Active;
        guard.authoring_selection = Some((inputs.selection, inputs.registries.attribute_revision));
        Ok(guard)
    }

    /// Installs immutable recorded inputs with independently retained Legacy current configuration.
    ///
    /// New namespaces deliberately retain Legacy authoring. Missing historical
    /// mappings refuse in strict mode. The supplied contexts retain their own
    /// explicitly chosen current fences, independently of the complete Guard
    /// current profile. No Original or completed history is constructed here.
    pub fn new_with_recorded_views(
        store: S,
        clock: C,
        keys: Vec<terrane_format::auth::IssuerKey>,
        config: super::GuardConfig,
        associations: terrane_format::properties::semantics::associations::RecordedAssociations,
    ) -> Self {
        let entries = associations
            .iter()
            .map(|entry| {
                (
                    entry.view(),
                    ViewSelection {
                        view: entry.view(),
                        original_root: entry.original_root(),
                        semantics: Selection::Recorded(entry.context().clone()),
                        attribute_revision: 1,
                    },
                )
            })
            .collect();
        Self::fresh_recorded_configuration(store, clock, keys, config, entries)
    }

    /// Installs exact recorded property and independent attribute inputs.
    ///
    /// Validated constructor data is copied once into the owning view table.
    /// Current configuration and Legacy authoring stay independently captured;
    /// configuration grants neither Original nor relationship completion.
    pub fn new_with_recorded_namespace_profiles(
        store: S,
        clock: C,
        keys: Vec<terrane_format::auth::IssuerKey>,
        config: super::GuardConfig,
        profiles: super::RecordedNamespaceProfiles,
    ) -> Self {
        let entries = profiles
            .iter()
            .map(|profile| {
                let entry = profile.association();
                (
                    entry.view(),
                    ViewSelection {
                        view: entry.view(),
                        original_root: entry.original_root(),
                        semantics: Selection::Recorded(entry.context().clone()),
                        attribute_revision: profile.attribute_revision(),
                    },
                )
            })
            .collect();
        Self::fresh_recorded_configuration(store, clock, keys, config, entries)
    }

    // The input table types already reject duplicate conflicts, and profile
    // constructors validate attributes. Fresh construction has no Original or
    // executed views to replace; this never bypasses the guarded live installer.
    fn fresh_recorded_configuration(
        store: S,
        clock: C,
        keys: Vec<terrane_format::auth::IssuerKey>,
        config: super::GuardConfig,
        entries: BTreeMap<Digest, ViewSelection>,
    ) -> Self {
        let mut guard = Self::new(store, clock, keys, config);
        guard.interpretation = InterpretationSelection::Active;
        guard.authoring_selection = Some((Selection::Legacy, 1));
        guard.view_selections.installed = Arc::new(entries);
        guard
    }

    /// Copies only actual configuration through the owning shared adapter.
    ///
    /// Protected Original state stays empty until its genuine owning caller
    /// restores it separately. No compatibility table is retained alongside the
    /// actual view selections or independently configured current inputs.
    pub(crate) fn read_configuration_adapter<T, D>(&self, store: T, clock: D) -> Guard<T, D> {
        self.configuration_adapter(store, clock)
    }

    /// Projects one actually selected immutable view into ordinary read inputs.
    ///
    /// # Errors
    /// Preserves missing strict mappings, wrong roots and conflicting admitted
    /// inputs. This projection grants no Original or completed history authority.
    pub(in crate::guard) fn select_view(
        &self,
        view: Digest,
        original_root: Digest,
        observation: HistoryObservation<'_>,
    ) -> Result<super::SelectedReadInterpretation, StoreFailure> {
        super::SelectedReadInterpretation::from_selection(
            view,
            original_root,
            self.selected_view_inputs(view, original_root, observation)?
                .selection,
        )
    }

    /// Projects the owning selector's complete view profile without changing it.
    ///
    /// # Errors
    /// Rejects missing strict inputs, root substitutions and changed captures.
    pub(in crate::guard) fn selected_view_profile(
        &self,
        commit: &terrane_format::provenance::VerifiedCommit,
        observation: HistoryObservation<'_>,
    ) -> Result<
        (
            super::SelectedReadInterpretation,
            terrane_format::gc::publication::evidence::ConfiguredRegistryInputs,
        ),
        StoreFailure,
    > {
        let inputs =
            self.selected_view_inputs(commit.identity(), commit.commit().tree, observation)?;
        let selected = super::SelectedReadInterpretation::from_selection(
            commit.identity(),
            commit.commit().tree,
            inputs.selection,
        )?;
        Ok((selected, inputs.registries))
    }
}

impl CandidateInputs {
    /// Returns the actual signed candidate identity captured at closed admission.
    pub(super) fn view(&self) -> Digest {
        self.selected.view
    }
}

impl<S, C> Guard<S, C> {
    /// Projects the sole configured selection table into ordinary disclosure inputs.
    ///
    /// The returned owned value is operation-local data. It creates no second
    /// association authority and never promotes an unverified candidate.
    ///
    /// # Errors
    /// Rejects conflicting installed/executed inputs, a substituted candidate,
    /// unavailable synchronization, or an unnormalized Active selection.
    pub(super) fn property_selections(
        &self,
        observation: HistoryObservation<'_>,
    ) -> Result<
        terrane_format::properties::semantics::selections::ViewPropertySelections,
        StoreFailure,
    > {
        use terrane_format::properties::semantics::{
            associations::{RecordedAssociation, RecordedAssociations},
            selections::{ViewPropertySelection, ViewPropertySelections},
        };
        let executed = self
            .view_selections
            .executed
            .read()
            .map_err(|_| unavailable())?;
        let mut rows = self.view_selections.installed.as_ref().clone();
        for (view, selection) in executed.iter() {
            if rows
                .get(view)
                .is_some_and(|installed| installed != selection)
            {
                return Err(invalid());
            }
            rows.insert(*view, selection.clone());
        }
        drop(executed);
        if let Some(candidate) = observation.candidate {
            self.selected_view_inputs(
                candidate.selected.view,
                candidate.selected.original_root,
                observation,
            )?;
            if rows
                .get(&candidate.selected.view)
                .is_some_and(|row| row != &candidate.selected)
            {
                return Err(invalid());
            }
            rows.insert(candidate.selected.view, candidate.selected.clone());
        }
        let mut selections = Vec::with_capacity(rows.len());
        for row in rows.into_values() {
            let selected = self.selected_view_inputs(row.view, row.original_root, observation)?;
            selections.push(match selected.selection {
                Selection::Legacy => ViewPropertySelection::Legacy {
                    view: row.view,
                    original_root: row.original_root,
                },
                Selection::Recorded(context) => ViewPropertySelection::Recorded(
                    RecordedAssociation::new(row.view, row.original_root, context),
                ),
                Selection::Active => return Err(invalid()),
            });
        }
        let result = if self.interpretation == InterpretationSelection::Legacy {
            ViewPropertySelections::legacy(selections)
        } else {
            ViewPropertySelections::recorded(
                RecordedAssociations::new([]).map_err(|_| invalid())?,
                selections,
            )
        };
        result.map_err(|_| invalid())
    }
}

impl<S, C> Guard<S, C> {
    /// Reports whether exact ordinary inputs are already independently retained.
    ///
    /// This observation supplies no Original or owning-history completeness.
    ///
    /// # Errors
    /// Rejects unavailable selection synchronization.
    pub(super) fn has_view_selection(&self, view: Digest) -> Result<bool, StoreFailure> {
        Ok(self.view_selections.installed.contains_key(&view)
            || self
                .view_selections
                .executed
                .read()
                .map_err(|_| unavailable())?
                .contains_key(&view))
    }
}

impl<S, C> Guard<S, C> {
    /// Rechecks ordinary candidate inputs against the owning completed history.
    ///
    /// The completed value is constructed only by full owning history. This
    /// bookkeeping retains no second interpretation map and grants no current
    /// actor or native publication permission.
    ///
    /// # Errors
    /// Rejects changed candidate inputs, original root or checked interpretation,
    /// or unavailable retained-selection synchronization.
    pub(crate) fn retain_completed_selection(
        &self,
        candidate: &CandidateInputs,
        completed: &super::history::CompletedCandidateHistory,
        observation: HistoryObservation<'_>,
    ) -> Result<(), StoreFailure> {
        if completed.selection() != candidate {
            return Err(invalid());
        }
        let view = candidate.selected.view;
        let root = candidate.selected.original_root;
        let commit = completed.history().commit(&view).ok_or_else(invalid)?;
        if commit.commit().tree != root
            || completed
                .history()
                .property_selection(view)
                .map_err(|_| invalid())?
                != candidate.inputs.selection
            || self.selected_view_inputs(view, root, observation)? != candidate.inputs
        {
            return Err(invalid());
        }
        self.retain_executed_view_inputs(view, root, &candidate.inputs)
    }
}
