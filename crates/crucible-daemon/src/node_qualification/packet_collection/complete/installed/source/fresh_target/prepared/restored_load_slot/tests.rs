//! Exercises the actual destination constructor and physical-slot census.

use super::*;

#[test]
fn each_one_short_axis_refuses_before_destination_allocation() -> Result<(), RuntimeError> {
    for axis in 0..3 {
        let mut row = ConstructionData::new_data()?;
        let mut admitted = row.requested_storage_data();
        admitted[axis] = admitted[axis]
            .checked_sub(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let mut output = None;

        assert!(matches!(
            row.allocate_into_data(admitted, &mut output),
            Err(RuntimeError::ResourceLimit)
        ));
        assert!(output.is_none());
        let exact = row.requested_storage_data();
        assert!(matches!(
            row.allocate_into_data(exact, &mut output),
            Err(RuntimeError::DuplicateOperation)
        ));
        assert!(output.is_none());
    }
    Ok(())
}

#[test]
fn exact_axes_retain_same_empty_destination_through_census_refusal() -> Result<(), RuntimeError> {
    let mut row = ConstructionData::new_data()?;
    let mut output = None;
    let admitted = row.requested_storage_data();
    row.allocate_into_data(admitted, &mut output)?;
    let original = output.as_deref().ok_or(RuntimeError::OwnerUnavailable)? as *const Destination;
    assert!(
        output
            .as_deref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .is_none()
    );

    let mut one_short = Counter::new(size_of::<Destination>() - 1);
    assert!(matches!(
        charge_retained_data(&output, &mut one_short),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(
        output.as_deref().ok_or(RuntimeError::OwnerUnavailable)? as *const Destination,
        original
    );
    assert!(
        output
            .as_deref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .is_none()
    );

    let mut exact = Counter::new(size_of::<Destination>());
    charge_retained_data(&output, &mut exact)?;
    assert_eq!(exact.bytes(), size_of::<Destination>());
    assert_eq!(
        output.as_deref().ok_or(RuntimeError::OwnerUnavailable)? as *const Destination,
        original
    );
    Ok(())
}

#[test]
fn occupied_slot_refuses_without_replacing_original_allocation() -> Result<(), RuntimeError> {
    let mut row = ConstructionData::new_data()?;
    let mut output = None;
    let admitted = row.requested_storage_data();
    row.allocate_into_data(admitted, &mut output)?;
    let original = output.as_deref().ok_or(RuntimeError::OwnerUnavailable)? as *const Destination;

    // A fresh actual row reaches the occupied-output branch, not entered=true.
    let mut occupied = ConstructionData::new_data()?;
    assert!(matches!(
        occupied.allocate_into_data(admitted, &mut output),
        Err(RuntimeError::DuplicateOperation)
    ));
    // That refused row itself stays spent, even against an empty destination.
    let mut retry = None;
    assert!(matches!(
        occupied.allocate_into_data(admitted, &mut retry),
        Err(RuntimeError::DuplicateOperation)
    ));
    assert!(retry.is_none());
    assert_eq!(
        output.as_deref().ok_or(RuntimeError::OwnerUnavailable)? as *const Destination,
        original
    );
    let mut census = Counter::new(size_of::<Destination>());
    charge_retained_data(&output, &mut census)?;
    assert_eq!(census.bytes(), size_of::<Destination>());
    Ok(())
}

#[test]
fn ordinary_empty_owner_has_no_backing_or_constructor_effect() -> Result<(), RuntimeError> {
    let output = None;
    let mut census = Counter::new(0);
    charge_retained_data(&output, &mut census)?;

    assert_eq!(census.bytes(), 0);
    assert!(output.is_none());
    assert!(size_of::<Owner>() < size_of::<Destination>());
    Ok(())
}

#[test]
fn exact_allocator_envelope_supplier_is_const_data_without_runtime_query()
-> Result<(), RuntimeError> {
    // Const contexts make the selected evaluator explicit in this control too.
    const LAYOUTS: Option<[usize; 4]> =
        crucible::node_contract::NodeRuntime::CAPTURE_GLOBAL_ALLOCATION_LAYOUT_DATA;
    const AXES: Option<[usize; 3]> = CONSTRUCTION_AXES;
    let [fat, thin, residual, branch] = LAYOUTS.ok_or(RuntimeError::UnsupportedFacet)?;
    let [retained, transient, scratch] = AXES.ok_or(RuntimeError::UnsupportedFacet)?;

    // These public field-equivalent controls do not assert private stable ABI.
    assert!(fat >= size_of::<Result<std::ptr::NonNull<[u8]>, ()>>());
    assert!(thin >= size_of::<Result<std::ptr::NonNull<u8>, ()>>());
    assert!(residual >= size_of::<Result<std::convert::Infallible, ()>>());
    assert!(
        branch
            >= size_of::<
                std::ops::ControlFlow<Result<std::convert::Infallible, ()>, std::ptr::NonNull<u8>>,
            >()
    );
    assert_eq!(retained, size_of::<Destination>());
    assert!(scratch >= fat + thin + residual + branch);
    assert!(transient >= size_of::<Destination>() * 8);
    Ok(())
}
