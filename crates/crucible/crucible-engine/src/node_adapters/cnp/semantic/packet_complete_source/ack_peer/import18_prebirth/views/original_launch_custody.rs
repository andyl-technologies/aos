//! Exercises real immutable ownership and original capacity observations.
//!
//! These ordinary DTO fixtures issue no installation, attempt or Completion.
//! No content digest or test-only pointer is used as an acceptance capability.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::{
    job::SourceBirthJobFailure,
    original_launch::{OriginalSourceBirthLaunch, OriginalSourceBirthLaunches},
};
use crucible_node_transport::retained_metadata::OriginalLaunchMetadataObservation;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn retained(first: PacketNative5SourceLaunch) -> OriginalSourceBirthLaunches {
    let mut input = Some([first, launch(true).0, launch(false).0]);
    let mut output = None;
    OriginalSourceBirthLaunches::retain_into(&mut input, &mut output).unwrap();
    assert!(input.is_none());
    output.unwrap()
}

#[test]
fn selected_lease_keeps_the_moved_original_after_prepared_tuple_release() -> TestResult {
    let original = launch(false).0;
    let pointer = original.selection.provider.supported_profiles.as_ptr();
    let capacity = original.selection.provider.supported_profiles.capacity();
    let group = retained(original);
    let selected = group.selected(0)?;
    let second = selected.clone();
    let mut facts = OriginalLaunchMetadataObservation::empty();
    facts.observe_into(selected.original())?;

    drop(group);
    assert!(selected.same_original(&second));
    assert_eq!(
        selected
            .original()
            .selection
            .provider
            .supported_profiles
            .as_ptr(),
        pointer
    );
    assert_eq!(
        selected
            .original()
            .selection
            .provider
            .supported_profiles
            .capacity(),
        capacity
    );
    facts.remeasure_data(selected.original())?;
    drop(selected);
    facts.remeasure_data(second.original())?;
    Ok(())
}

#[test]
fn equal_content_different_capacities_cannot_replace_the_retained_original() -> TestResult {
    let original = launch(false).0;
    let group = retained(original);
    let held = group.selected(0)?;
    let mut original_facts = OriginalLaunchMetadataObservation::empty();
    original_facts.observe_into(held.original())?;
    let value = serde_json::to_value(held.original())?;
    // A real separate decoded DTO is deliberately a negative candidate.
    let mut replacement: PacketNative5SourceLaunch = serde_json::from_value(value.clone())?;
    let profiles = &mut replacement.selection.provider.supported_profiles;
    profiles.reserve_exact(
        original_facts
            .provider_data()
            .unwrap()
            .vector_capacity_bytes
            / std::mem::size_of::<crucible_node_format::NodeManifest>()
            + 2,
    );
    let id = &replacement.selection.provider.provider_id;
    let mut backing = String::with_capacity(
        original_facts
            .provider_data()
            .unwrap()
            .string_capacity_bytes
            + 1024,
    );
    backing.push_str(id.as_str());
    replacement.selection.provider.provider_id = Id::new(backing)?;
    assert_eq!(serde_json::to_value(&replacement)?, value);
    let replacement_group = retained(replacement);
    let foreign = replacement_group.selected(0)?;
    assert!(!held.same_original(&foreign));
    assert!(original_facts.remeasure_data(foreign.original()).is_err());
    original_facts.remeasure_data(held.original())?;
    let mut other_facts = OriginalLaunchMetadataObservation::empty();
    other_facts.observe_into(foreign.original())?;
    assert_ne!(original_facts, other_facts);
    assert!(
        other_facts.provider_data().unwrap().vector_capacity_bytes
            > original_facts
                .provider_data()
                .unwrap()
                .vector_capacity_bytes
    );
    assert!(
        other_facts.provider_data().unwrap().string_capacity_bytes
            > original_facts
                .provider_data()
                .unwrap()
                .string_capacity_bytes
    );
    Ok(())
}

#[test]
fn occupied_holder_refuses_before_taking_another_original_and_exact_quote_is_required() -> TestResult
{
    let mut input = Some([launch(false).0, launch(true).0, launch(false).0]);
    let original_bytes = canonical::canonical_json(&serde_json::to_value(&input)?)?;
    let mut output = Some(retained(launch(false).0));
    let before = output.as_ref().unwrap().selected(0)?;
    assert!(OriginalSourceBirthLaunches::retain_into(&mut input, &mut output).is_err());
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(&input)?)?,
        original_bytes
    );
    assert!(before.same_original(&output.as_ref().unwrap().selected(0)?));
    let demand = OriginalSourceBirthLaunches::allocation_storage_data(usize::MAX)?;
    assert!(demand > 0);
    assert_eq!(
        OriginalSourceBirthLaunches::allocation_storage_data(demand)?,
        demand
    );
    assert_eq!(
        OriginalSourceBirthLaunches::allocation_storage_data(demand - 1),
        Err(RuntimeError::ResourceLimit)
    );
    Ok(())
}

#[test]
fn actual_observer_failure_stays_partial_once_and_keeps_its_original_typed_cause() {
    let mut original = launch(false).0;
    let mut nested = Value::Null;
    for _ in 0..100 {
        nested = Value::Array(vec![nested]);
    }
    original
        .selection
        .provider
        .extensions
        .insert("original-capacity-depth".into(), nested);
    let group = retained(original);
    let held: OriginalSourceBirthLaunch = group.selected(0).unwrap();
    let mut facts = OriginalLaunchMetadataObservation::empty();
    let error = facts.observe_into(held.original()).unwrap_err();
    assert!(!facts.is_complete_data());
    assert!(facts.selection_data().is_none());
    assert!(facts.remeasure_data(held.original()).is_err());
    assert!(matches!(
        facts.observe_into(held.original()),
        Err(crucible_node_transport::ProviderError::Correlation(_))
    ));
    let owned_failure = SourceBirthJobFailure::OriginalMetadata(error);
    assert!(matches!(
        owned_failure,
        SourceBirthJobFailure::OriginalMetadata(
            crucible_node_transport::ProviderError::ResourceExhausted(_)
        )
    ));
    assert_eq!(
        held.original().selection.provider.extensions.len(),
        group.originals()[0].selection.provider.extensions.len()
    );
}

#[test]
fn optional_original_views_follow_actual_singleton_and_capture_selection() -> TestResult {
    let mut original = launch(false).0;
    original.capture_allocation_selection =
        Some(PacketNative5CaptureAllocationSelection::OriginalObserve12);
    let mut facts = OriginalLaunchMetadataObservation::empty();
    facts.observe_into(&original)?;
    assert!(facts.selection_data().is_some());
    assert!(facts.provider_data().is_some());
    assert!(facts.realization_data().is_some());
    assert!(facts.program_definition_data().is_some());
    assert_eq!(
        facts.hello_guarantees_data().is_some(),
        original.selection.realization.bindings.len() == 1
    );
    assert_eq!(
        facts.report_owner_binding_data().is_some(),
        original.selection.realization.owner_bindings.len() == 1
    );

    original.selection.realization.bindings.clear();
    original.selection.realization.owner_bindings.clear();
    let mut absent = OriginalLaunchMetadataObservation::empty();
    absent.observe_into(&original)?;
    assert!(absent.hello_guarantees_data().is_none());
    assert!(absent.report_owner_binding_data().is_none());
    assert!(facts.remeasure_data(&original).is_err());
    Ok(())
}
