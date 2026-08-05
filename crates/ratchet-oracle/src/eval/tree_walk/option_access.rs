//! Runtime option-value provenance and executed read observations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::value::{Value, ValueTag};

/// One option read which was actually executed by the evaluator.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OptionReadObservation {
    /// Imported source file containing the executed selection.
    pub source: Vec<u8>,
    /// Actual selected path, including evaluated dynamic segments.
    pub path: Vec<Vec<u8>>,
}

/// A shareable, evaluation-external sink for option-read observations.
#[derive(Default)]
struct OptionReadState {
    observations: BTreeSet<OptionReadObservation>,
    provenance: BTreeMap<u64, OptionValueProvenance>,
}

#[derive(Default)]
struct OptionValueProvenance {
    tag: Option<ValueTag>,
    paths: BTreeSet<Vec<Vec<u8>>>,
}

#[derive(Clone, Default)]
pub struct OptionReadObserver(Arc<Mutex<OptionReadState>>);

impl std::fmt::Debug for OptionReadObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OptionReadObserver")
            .field("observations", &self.snapshot())
            .finish()
    }
}

impl PartialEq for OptionReadObserver {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for OptionReadObserver {}

impl OptionReadObserver {
    /// Records one executed read, ignoring a poisoned diagnostic sink.
    pub(crate) fn record(&self, source: Vec<u8>, path: Vec<Vec<u8>>) {
        if let Ok(mut state) = self.0.lock() {
            state
                .observations
                .insert(OptionReadObservation { source, path });
        }
    }

    /// Associates a heap value with one canonical config option path.
    pub(crate) fn associate(&self, value: Value, path: Vec<Vec<u8>>) {
        if !value.tag().is_heap() {
            return;
        }
        if let Ok(mut state) = self.0.lock() {
            let entry = state
                .provenance
                .entry(value.relocation_sensitive_identity_bits())
                .or_default();
            entry.tag = Some(value.tag());
            entry.paths.insert(path);
        }
    }

    /// Associates a value with every supplied canonical config option path.
    pub(crate) fn associate_all(&self, value: Value, paths: &[Vec<Vec<u8>>]) {
        for path in paths {
            self.associate(value, path.clone());
        }
    }

    /// Returns the option paths currently attached to a heap value.
    pub(crate) fn provenance(&self, value: Value) -> Vec<Vec<Vec<u8>>> {
        if !value.tag().is_heap() {
            return Vec::new();
        }
        self.0
            .lock()
            .ok()
            .and_then(|state| {
                state
                    .provenance
                    .get(&value.relocation_sensitive_identity_bits())
                    .map(|entry| entry.paths.iter().cloned().collect())
            })
            .unwrap_or_default()
    }

    /// Returns the relocation-sensitive identities retained by provenance.
    pub(crate) fn provenance_identities(&self) -> Vec<(u64, ValueTag)> {
        self.0
            .lock()
            .map(|state| {
                state
                    .provenance
                    .iter()
                    .filter_map(|(identity, entry)| entry.tag.map(|tag| (*identity, tag)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Rekeys live provenance and removes dead young identities after minor GC.
    pub(crate) fn repair_relocated_identities(
        &self,
        relocations: &[(u64, u64)],
        dead_young_keys: &[u64],
    ) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        state
            .provenance
            .retain(|key, _| dead_young_keys.binary_search(key).is_err());
        for &(source, destination) in relocations {
            if let Some(provenance) = state.provenance.remove(&source) {
                match state.provenance.entry(destination) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(provenance);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().paths.extend(provenance.paths);
                    }
                }
            }
        }
    }

    /// Returns the canonical observations collected so far.
    pub fn snapshot(&self) -> Vec<OptionReadObservation> {
        self.0
            .lock()
            .map(|state| {
                state
                    .observations
                    .iter()
                    .filter(|candidate| {
                        !state.observations.iter().any(|other| {
                            candidate.source == other.source
                                && candidate.path.len() < other.path.len()
                                && other.path.starts_with(&candidate.path)
                        })
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}
