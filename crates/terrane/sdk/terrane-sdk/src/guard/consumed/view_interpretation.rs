//! Tracks prepared views separately from owning successful history completion.

use std::collections::BTreeMap;

#[cfg(all(test, feature = "tokio", unix))]
use crate::guard::recorded_properties::SelectedReadInterpretation;
use terrane_format::gc::publication::evidence::ConsumedViewInterpretation;
#[cfg(all(test, feature = "tokio", unix))]
use terrane_format::gc::publication::evidence::{ConfiguredRegistryInputs, ViewInterpretationMode};
use terrane_format::identity::Digest;
#[cfg(all(test, feature = "tokio", unix))]
use terrane_format::provenance::VerifiedCommit;

use crate::guard::history::CompletedViewUse;
use crate::guard::history::candidate_preparation::Key;
use crate::guard::history::completion::{PendingViewUse, SelectedInputs};
use crate::guard::invalid;
#[cfg(all(test, feature = "tokio", unix))]
use crate::store::StoreErrorKind;
use crate::store::StoreFailure;

/// Retains exact operation-local preparation and completed producer results.
#[derive(Clone, Default)]
pub(super) struct ViewContextTrace {
    pending: BTreeMap<Digest, PendingViewUse>,
    completed: BTreeMap<Digest, PendingViewUse>,
    namespace: BTreeMap<Digest, PendingViewUse>,
    // One bounded key references an existing row, never another policy copy.
    candidate: Option<Key>,
    #[cfg(all(test, feature = "tokio", unix))]
    preparations: usize,
    #[cfg(all(test, feature = "tokio", unix))]
    reused: usize,
}

impl ViewContextTrace {
    /// Records pure candidate data after independently fresh caller checks.
    ///
    /// Only surviving pending rows are reusable. Completed and namespace rows
    /// execute the original preparation and ordinary contradiction checks.
    ///
    /// # Errors
    /// Preserves preparation and contradiction failures; failures are not cached.
    pub(super) fn prepare_candidate(
        &mut self,
        key: Option<Key>,
        inputs: &SelectedInputs,
        commit: &terrane_format::provenance::VerifiedCommit,
        evidence: &super::super::TreeEvidence,
    ) -> Result<(), StoreFailure> {
        let key = key.filter(|key| key.binds(inputs, commit, evidence));
        if let (Some(previous), Some(current)) = (&self.candidate, &key)
            && previous.matches(current)
            && self
                .pending
                .get(&current.view())
                .is_some_and(|pending| current.covers(pending))
        {
            #[cfg(all(test, feature = "tokio", unix))]
            {
                self.reused += 1;
            }
            return Ok(());
        }

        #[cfg(all(test, feature = "tokio", unix))]
        {
            self.preparations += 1;
        }
        let pending = PendingViewUse::prepare(inputs, commit, evidence)?;
        self.pending(&pending)?;
        self.candidate = key.filter(|key| self.pending.contains_key(&key.view()));
        Ok(())
    }

    /// Reports original preparation calls and successful hits for this test trace.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) fn candidate_preparation_work(&self) -> (usize, usize) {
        (self.preparations, self.reused)
    }

    /// Observes an actual pending row without constructing completion evidence.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) fn candidate_preparation_pending(&self, view: Digest) -> Option<PendingViewUse> {
        self.pending.get(&view).cloned()
    }

    /// Records prepared data without promoting it to completed evidence.
    ///
    /// # Errors
    /// Rejects a contradictory repeated preparation or completed view.
    pub(super) fn pending(&mut self, prepared: &PendingViewUse) -> Result<(), StoreFailure> {
        let identity = prepared.context().view;
        if let Some(completed) = self
            .completed
            .get(&identity)
            .or_else(|| self.namespace.get(&identity))
        {
            return if completed == prepared {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self
            .pending
            .get(&identity)
            .is_some_and(|old| old != prepared)
        {
            return Err(invalid());
        }
        self.pending.insert(identity, prepared.clone());
        Ok(())
    }

    /// Consumes only a result privately produced after full history success.
    ///
    /// # Errors
    /// Rejects an absent or contradictory preparation or completed view.
    pub(super) fn complete(&mut self, completed: &CompletedViewUse) -> Result<(), StoreFailure> {
        let prepared = completed.prepared();
        let identity = prepared.context().view;
        if let Some(old) = self.completed.get(&identity) {
            return if old == prepared {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self
            .pending
            .get(&identity)
            .or_else(|| self.namespace.get(&identity))
            != Some(prepared)
        {
            return Err(invalid());
        }
        self.pending.remove(&identity);
        self.namespace.remove(&identity);
        self.forget_candidate(identity);
        self.completed.insert(identity, prepared.clone());
        Ok(())
    }

    /// Resolves only a genuinely authenticated namespace dependency.
    ///
    /// # Errors
    /// Rejects missing or contradictory preparation; grants no serving completion.
    pub(super) fn namespace(
        &mut self,
        checked: &crate::guard::history::SourceResolvedViewUse,
    ) -> Result<(), StoreFailure> {
        let prepared = checked.prepared();
        let identity = prepared.context().view;
        if let Some(old) = self
            .completed
            .get(&identity)
            .or_else(|| self.namespace.get(&identity))
        {
            return if old == prepared {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self.pending.get(&identity) != Some(prepared) {
            return Err(invalid());
        }
        self.pending.remove(&identity);
        self.namespace.insert(identity, prepared.clone());
        self.forget_candidate(identity);
        Ok(())
    }

    /// Observes actual completed map rows without accepting producer evidence.
    #[cfg(all(test, feature = "tokio", unix))]
    pub(super) fn observed_completed(&self) -> Vec<ConsumedViewInterpretation> {
        self.completed
            .values()
            .map(|view| view.context().clone())
            .collect()
    }

    /// Requires auxiliary completion for the exact signed certificate source.
    ///
    /// Authenticated ancestry rows cannot satisfy this source-specific check.
    ///
    /// # Errors
    /// Rejects source-only or absent completion and mismatched signed view data.
    pub(super) fn require_completed(
        &self,
        commit: &terrane_format::provenance::VerifiedCommit,
    ) -> Result<(), StoreFailure> {
        let prepared = self.completed.get(&commit.identity()).ok_or_else(invalid)?;
        prepared
            .context()
            .check_signed_view_data(commit.commit())
            .map_err(|_| invalid())
    }

    /// Serializes authenticated contexts after all pending views are resolved.
    ///
    /// Source-resolved rows describe consumed interpretation data only; they do
    /// not certify auxiliary completion or eligibility as a lineage source.
    ///
    /// # Errors
    /// Rejects unresolved preparations. Absence never selects Legacy.
    pub(super) fn finish(&self) -> Result<Vec<ConsumedViewInterpretation>, StoreFailure> {
        if !self.pending.is_empty() {
            return Err(invalid());
        }
        let mut contexts = self
            .completed
            .values()
            .chain(self.namespace.values())
            .map(|view| view.context().clone())
            .collect::<Vec<_>>();
        contexts.sort_by_key(|context| context.view);
        Ok(contexts)
    }

    fn forget_candidate(&mut self, view: Digest) {
        if self
            .candidate
            .as_ref()
            .is_some_and(|key| key.view() == view)
        {
            self.candidate = None;
        }
    }
}

/// Copies the actual selected inputs for the original signed view.
///
/// `selected` belongs to the verifier that consumed this view. `registries`
/// comes from that verifier's owning implementation, not persisted claims or a
/// global snapshot fallback. This projection creates ordinary data only.
///
/// Legacy preserves its frozen revision-1 vocabulary. Recorded uses
/// the selected association's exact fence, including its inert later names.
///
/// # Errors
/// Rejects unsupported profiles, mismatched view/root associations, revisions,
/// behavioral vocabularies or later-name sets.
#[cfg(all(test, feature = "tokio", unix))]
pub(in crate::guard) fn captured_data(
    selected: &SelectedReadInterpretation,
    commit: &VerifiedCommit,
    registries: &ConfiguredRegistryInputs,
) -> Result<ConsumedViewInterpretation, StoreFailure> {
    let view = commit.identity();
    let original_root = commit.commit().tree;
    let context = selected_data(view, original_root, selected, registries)?;
    context
        .check_signed_view_data(commit.commit())
        .map_err(|_| invalid())?;
    Ok(context)
}

/// Projects ordinary meaning from independently selected view inputs.
///
/// The owning producer must independently establish the signed root and prior
/// completed history before comparing retained lineage. This helper neither
/// verifies a signature nor creates a history or authorization capability.
///
/// # Errors
/// Rejects differing view/root associations, unsupported registry profiles,
/// property vocabularies or preservation names.
#[cfg(all(test, feature = "tokio", unix))]
fn selected_data(
    view: Digest,
    original_root: Digest,
    selected: &SelectedReadInterpretation,
    registries: &ConfiguredRegistryInputs,
) -> Result<ConsumedViewInterpretation, StoreFailure> {
    let (mode, revision, mut names, later) = match selected {
        SelectedReadInterpretation::Legacy => (
            ViewInterpretationMode::Legacy,
            None,
            terrane_format::properties::semantics::RecordedContext::new(1, 1, &[])
                .map_err(|_| invalid())?
                .behavioral_names()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            Vec::new(),
        ),
        SelectedReadInterpretation::Recorded(entry) => {
            if entry.view() != view || entry.original_root() != original_root {
                return Err(invalid());
            }

            let names = entry
                .with_context(|context| {
                    context
                        .behavioral_names()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .map_err(|_| invalid())?;
            (
                ViewInterpretationMode::Recorded,
                Some(entry.revision()),
                names,
                entry.later_registered().to_vec(),
            )
        }
    };
    names.sort_unstable();

    if revision.is_some_and(|revision| revision != registries.property_revision)
        || names != registries.behavioral_properties
        || later != registries.later_properties
    {
        return Err(invalid());
    }

    let context = ConsumedViewInterpretation {
        view,
        original_root,
        mode,
        registries: registries.clone(),
    };
    context
        .check_supported_interpretation()
        .map_err(|_| invalid())?;
    Ok(context)
}

/// Compares retained meaning with an exact independently selected view/root.
///
/// The genuine reuse producer supplies actual configuration and separately
/// checks selected lineage, retained Original controls and current authority.
/// Decoded records cannot select their own interpretation or attribute revision.
///
/// # Errors
/// Returns Unsupported for absent retained context. Rejects differing signed
/// root associations, modes, vocabularies or complete registry inputs.
#[cfg(all(test, feature = "tokio", unix))]
pub(in crate::guard) fn compare_selected_inputs(
    retained: Option<&ConsumedViewInterpretation>,
    view: Digest,
    original_root: Digest,
    selected: &SelectedReadInterpretation,
    registries: &ConfiguredRegistryInputs,
) -> Result<(), StoreFailure> {
    let retained = retained.ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    let current = selected_data(view, original_root, selected, registries)?;
    retained
        .check_selected_data(&current)
        .map_err(|_| invalid())
}

/// Compares retained inputs with the owning verifier's independently selected view.
///
/// The supplied selection has the same ordinary-data contract as
/// [`captured_data`]. This comparison cannot install an interpretation from the
/// retained record, establish current permission or finish index verification.
///
/// # Errors
/// Returns Unsupported when retained context is absent. Rejects different
/// modes, signed roots, registered inputs or unsupported selected profiles.
#[cfg(all(test, feature = "tokio", unix))]
pub(in crate::guard) fn compare_selected_data(
    retained: Option<&ConsumedViewInterpretation>,
    selected: &SelectedReadInterpretation,
    commit: &VerifiedCommit,
    registries: &ConfiguredRegistryInputs,
) -> Result<(), StoreFailure> {
    let retained = retained.ok_or_else(|| StoreFailure::new(StoreErrorKind::Unsupported))?;
    captured_data(selected, commit, registries)?;
    compare_selected_inputs(
        Some(retained),
        commit.identity(),
        commit.commit().tree,
        selected,
        registries,
    )
}
