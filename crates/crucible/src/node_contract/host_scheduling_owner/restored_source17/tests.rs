//! Exercises clone-demand and refusal DATA without manufacturing archive tickets.

use super::*;

fn data_row(template: &Rc<HostSchedulingSource>) -> HostRestoredSource17ConstructionData {
    let (retained, transient) = metadata_geometry(template, usize::MAX).unwrap();
    HostRestoredSource17ConstructionData {
        process: std::process::id(),
        thread: thread::current().id(),
        template: Rc::as_ptr(template),
        ticket_source: std::ptr::null(),
        retained,
        transient,
        scratch: HostSchedulingSource::restored_source17_construction_counter_scratch_data(),
        maximum: usize::MAX,
    }
}

#[test]
fn metadata_quote_matches_actual_private_source_children_and_keeps_axes_separate() {
    let owner = super::super::tests::source_owner();
    let source = owner.source();
    let row = data_row(&source);
    let actual = source
        .retained_prebirth_host_metadata_data(usize::MAX)
        .unwrap();

    assert_eq!(row.retained_requested_bytes_data(), actual);
    assert!(row.maximum_simultaneous_transient_bytes_data() > 0);
    assert!(row.declared_counter_scratch_bytes_data() > 0);
    let total = row.requested_bytes_data().unwrap();
    let mut exact = row;
    exact.maximum = total;
    assert_eq!(exact.requested_bytes_data().unwrap(), total);
    exact.maximum -= 1;
    assert!(matches!(
        exact.requested_bytes_data(),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(metadata_geometry(&source, actual - 1).is_err());
}

#[test]
fn spare_vector_capacity_remains_part_of_both_independent_clone_windows() {
    let mut owner = super::super::tests::source_owner();
    let before = metadata_geometry(&owner.source, usize::MAX).unwrap();
    let selected = &mut Rc::get_mut(&mut owner.source).unwrap().selection;
    let original_len = selected.descriptor.roles.len();
    let old_capacity = selected.descriptor.roles.capacity();
    selected.descriptor.roles.reserve_exact(23);
    let added_slots = selected.descriptor.roles.capacity() - old_capacity;
    assert!(added_slots > 0);
    assert_eq!(selected.descriptor.roles.len(), original_len);
    let after = metadata_geometry(&owner.source, usize::MAX).unwrap();

    assert_eq!(after.0 - before.0, added_slots * size_of::<Id>());
    assert_eq!(after.1 - before.1, added_slots * size_of::<Id>());
}

#[test]
fn missing_ticket_cannot_construct_a_source_or_spend_a_template() {
    let owner = super::super::tests::source_owner();
    let source = owner.source();
    let row = data_row(&source);
    let mut ticket = None;
    let mut output = None;

    assert!(matches!(
        HostSchedulingOwner::restore_complete_restored_settled_from_template_into(
            &source,
            &mut ticket,
            &row,
            &mut output,
        ),
        Err(RuntimeError::OwnerUnavailable)
    ));
    assert!(ticket.is_none());
    assert!(output.is_none());
    assert!(!source.node_created.get());
    assert!(!source.attachment_attempted.get());
    // This real source-one fixture never becomes an eligible Host17 template.
    assert!(source.authenticate_original_report_startup_data().is_err());
}

#[test]
fn occupied_output_preserves_the_actual_existing_source() {
    let template_owner = super::super::tests::source_owner();
    let template = template_owner.source();
    let row = data_row(&template);
    let retained = super::super::tests::source_owner();
    let expected = retained.source();
    let mut output = Some(retained);
    let mut ticket = None;

    assert!(matches!(
        HostSchedulingOwner::restore_complete_restored_settled_from_template_into(
            &template,
            &mut ticket,
            &row,
            &mut output,
        ),
        Err(RuntimeError::OutstandingObligations)
    ));
    assert!(Rc::ptr_eq(&output.as_ref().unwrap().source, &expected));
    assert!(ticket.is_none());
    assert!(!template.node_created.get());
}

#[test]
fn durable_selection_comparison_refuses_real_changed_roles_and_world() {
    let owner = super::super::tests::source_owner();
    let source = owner.source();
    let original = source.selection();
    assert!(matching_archived_selection(
        original,
        source.world(),
        original,
        source.world()
    ));

    let mut changed = original.clone();
    changed.domains.coordinator = Id::new("changed/coordinator").unwrap();
    assert!(!matching_archived_selection(
        &changed,
        source.world(),
        original,
        source.world()
    ));
    changed = original.clone();
    changed.owner.owner.id = Id::new("changed/owner").unwrap();
    assert!(!matching_archived_selection(
        &changed,
        source.world(),
        original,
        source.world()
    ));
    changed = original.clone();
    changed.owner.ownership_ref =
        canonical::content_ref(b"changed ownership", "application/json").unwrap();
    assert!(!matching_archived_selection(
        &changed,
        source.world(),
        original,
        source.world()
    ));
    changed = original.clone();
    changed
        .owner
        .extensions
        .insert("changed".into(), serde_json::Value::Bool(true));
    assert!(!matching_archived_selection(
        &changed,
        source.world(),
        original,
        source.world()
    ));
    let different_world = canonical::hash("cnp.world-binding.v1", b"different").unwrap();
    assert!(!matching_archived_selection(
        original,
        &different_world,
        original,
        source.world()
    ));
}

#[test]
fn checked_conjunction_refuses_overflow_without_saturation() {
    assert_eq!(sum(&[0, 1, 2], 3).unwrap(), 3);
    assert!(sum(&[usize::MAX, 1], usize::MAX).is_err());
    assert!(sum(&[3, 1], 3).is_err());
}
