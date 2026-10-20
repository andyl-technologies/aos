//! Prices additional named selector and compiler entries from actual held input.
//!
//! The readonly cold map/index is already resident and is not invoiced here.
//! SandboxSpec builds descriptor/operation indices. Runtime replay and Publisher
//! replay (including nested project authorization and Git upload history) build
//! at most an outer bucket plus one named row per actual namespace row. Empty
//! namespaces contribute zero. Invalid rows still receive this bounded peak
//! before their canonical validator refuses them.

use aos_sandbox_core::{RecordNamespace, ResourceDimension as D, ResourceVector};
use crate::journal::JournalError;
use std::collections::BTreeMap;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use crate::policy_compiler::create_storage_current::controller_readonly::current_compiler_receiving_demand_v1;

pub(crate) fn current_compiler_complete_receiving_demand_v1(
    encoded_bytes: u64, state: &State, signed: &RootSignedProjectSourcesV1,
) -> Result<ResourceVector, JournalError> {
    let selectors = selector_namespace_entries_v1(state)?;
    let compiler = signed.0.q04_layer_recipe().compiler_namespace_entries_v1(&signed.2)
        .ok_or(JournalError::JournalTooLarge)?;
    let entries = selectors.checked_add(compiler).ok_or(JournalError::JournalTooLarge)?;
    current_compiler_receiving_demand_v1(encoded_bytes)?.checked_add(
        ResourceVector::ZERO.with(D::MetadataEntries, entries))
        .map_err(|_| JournalError::JournalTooLarge)
}


fn selector_namespace_entries_v1(state: &State) -> Result<u64, JournalError> {
    let namespaces = state.keys().filter(|(namespace, _)| matches!(namespace,
        RecordNamespace::SandboxSpec | RecordNamespace::RuntimeAuthority | RecordNamespace::PublisherPolicy))
        .try_fold(0_u64, |rows, _| rows.checked_add(1)).ok_or(JournalError::JournalTooLarge)?;
    namespaces.checked_mul(2).ok_or(JournalError::JournalTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_actual_new_selector_namespaces_contribute_rows() {
        let mut state = State::new();
        assert_eq!(selector_namespace_entries_v1(&state).unwrap(), 0);
        state.insert((RecordNamespace::SandboxSpec, vec![1]), vec![2]);
        state.insert((RecordNamespace::PublisherPolicy, vec![1]), vec![2]);
        state.insert((RecordNamespace::RuntimeAuthority, vec![1]), vec![2]);
        assert_eq!(selector_namespace_entries_v1(&state).unwrap(), 6);
        // Actual cold rows of an unrelated family are already backed and do
        // not become a second selector-map or Rust field fee.
        state.insert((RecordNamespace::DesiredState, vec![1]), vec![2]);
        assert_eq!(selector_namespace_entries_v1(&state).unwrap(), 6);
    }
}
