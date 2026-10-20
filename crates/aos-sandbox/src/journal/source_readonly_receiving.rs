//! Delegates the reached Source semantic geometry to its sole passive recipe.

use aos_sandbox_core::ResourceVector;
use super::{JournalError, JournalTransaction, RecordNamespace};

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(crate) fn semantic_demand(
    state: &State,
    transaction: Option<&JournalTransaction>,
) -> Result<ResourceVector, JournalError> {
    aos_sandbox_ledger_replay::geometry::reached::semantic_demand_v1(state, transaction)
        .map_err(JournalError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::ResourceDimension as D;
    use crate::journal::JournalRecord;

    #[test]
    fn replacement_pays_the_old_and_prospective_typed_rows_together() {
        let key = b"selected-source-hold".to_vec();
        let value = vec![1; 96];
        let mut state = State::new();
        state.insert((RecordNamespace::SourceDomainPolicyHold, key.clone()), value.clone());
        let transaction = JournalTransaction::from_unvalidated_data([1; 16], vec![
            JournalRecord::put(RecordNamespace::SourceDomainPolicyHold, key, value),
        ]);

        let current = semantic_demand(&state, None).unwrap();
        let prospective = semantic_demand(&State::new(), Some(&transaction)).unwrap();
        let together = semantic_demand(&state, Some(&transaction)).unwrap();

        assert_eq!(current, prospective);
        assert_eq!(together, current.checked_add(prospective).unwrap());
    }

    #[test]
    fn deletion_keeps_the_original_value_and_its_reached_typed_geometry() {
        let key = b"selected-source-hold".to_vec();
        let mut state = State::new();
        state.insert((RecordNamespace::SourceDomainPolicyHold, key.clone()), vec![1; 512]);
        let transaction = JournalTransaction::from_unvalidated_data([2; 16], vec![
            JournalRecord::delete(RecordNamespace::SourceDomainPolicyHold, key),
        ]);

        let before = semantic_demand(&state, None).unwrap();
        let during = semantic_demand(&state, Some(&transaction)).unwrap();

        assert!(during.get(D::MemoryBytes) > before.get(D::MemoryBytes));
        assert!(during.get(D::MetadataEntries) > before.get(D::MetadataEntries));
        assert_eq!(state.values().next().unwrap().len(), 512);
    }

    #[test]
    fn hierarchy_prefix_cannot_select_a_cheaper_foreign_namespace_carrier() {
        let mut hierarchy_key = b"\0aos-hierarchy-v1\0".to_vec();
        hierarchy_key.extend_from_slice(&[1, 1]);
        let ordinary_key = vec![7; hierarchy_key.len()];
        let value = vec![1; 64];
        let mut prefixed = State::new();
        prefixed.insert((RecordNamespace::SourceDomainPolicyHold, hierarchy_key), value.clone());
        let mut ordinary = State::new();
        ordinary.insert((RecordNamespace::SourceDomainPolicyHold, ordinary_key), value);

        assert_eq!(semantic_demand(&prefixed, None).unwrap(),
            semantic_demand(&ordinary, None).unwrap());
    }
}
