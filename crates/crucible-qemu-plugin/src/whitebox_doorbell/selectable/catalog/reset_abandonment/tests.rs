//! Exact-token reset settlement, finite attempts, and snapshot controls.

use super::*;

fn frozen_catalog(
    per_identifier: u64,
    total: u64,
) -> Result<SelectableCatalog, Box<dyn std::error::Error>> {
    let limits = SelectableCatalogLimits::new(1, per_identifier, total)?;
    let registration = SelectableRegister::new(1, "product.choice", vec![1], vec![1], vec![])?;
    let declaration = SelectableExpectedDeclaration::new(
        "product.choice",
        vec![1],
        vec![1],
        vec![],
        SelectableExpectedPresence::Required,
    )?;
    let expectation = SelectableCatalogExpectation::new(vec![declaration], limits)?;
    let mut catalog = SelectableCatalog::new(limits, expectation)?;
    catalog.register(&registration)?;
    catalog.freeze()?;
    Ok(catalog)
}

fn begin(
    catalog: &mut SelectableCatalog,
    sequence: u64,
) -> Result<SelectablePendingRequest, Box<dyn std::error::Error>> {
    let request = SelectionRequest::new(sequence, "product.choice", "instance-a", None, 128)?;
    Ok(catalog.begin_request(
        &request,
        SelectableCallbackCoordinate::new(100, 5_000, 0),
        GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x4000, 128),
    )?)
}

#[test]
fn reset_abandonment_preserves_frozen_declarations_and_reply_history()
-> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(2, 2)?;
    let old = begin(&mut catalog, 7)?;
    let registered = catalog.registered_declarations().clone();

    catalog.abandon_request_after_reset(&old)?;

    assert_eq!(catalog.phase(), SelectableCatalogPhase::Frozen);
    assert_eq!(catalog.registered_declarations(), &registered);
    assert_eq!(catalog.total_completed_requests(), 0);
    assert_eq!(catalog.last_completed_request_sequence(), None);
    assert_eq!(catalog.total_abandoned_requests(), 1);
    assert_eq!(catalog.last_abandoned_request_sequence(), Some(7));
    assert_eq!(
        catalog.abandoned_request_counts().get("product.choice"),
        Some(&1)
    );
    assert!(catalog.pending_request().is_none());
    assert!(matches!(
        catalog.abandon_request_after_reset(&old),
        Err(SelectableCatalogError::NoPendingRequest)
    ));
    Ok(())
}

#[test]
fn reset_abandonment_rejects_other_catalog_incarnation_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(2, 2)?;
    let old = begin(&mut catalog, 7)?;
    let mut another = frozen_catalog(2, 2)?;
    let foreign = begin(&mut another, 7)?;

    assert!(matches!(
        catalog.abandon_request_after_reset(&foreign),
        Err(SelectableCatalogError::PendingRequestMismatch)
    ));
    assert_eq!(catalog.pending_request(), Some(&old));
    assert_eq!(catalog.total_abandoned_requests(), 0);
    Ok(())
}

#[test]
fn reset_abandonment_roundtrips_and_cannot_reuse_spent_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(2, 2)?;
    let old = begin(&mut catalog, 7)?;
    catalog.abandon_request_after_reset(&old)?;
    let plan = catalog.to_plan()?;
    let encoded = plan.encode()?;
    let decoded = SelectableCatalogPlan::decode(&encoded)?;
    let mut restored = SelectableCatalog::from_plan(&decoded)?;

    assert_eq!(restored.to_plan()?, plan);
    assert_eq!(restored.total_abandoned_requests(), 1);
    assert!(begin(&mut restored, 7).is_err());
    assert!(restored.pending_request().is_none());
    assert!(begin(&mut restored, 8).is_ok());
    Ok(())
}

#[test]
fn reset_abandonment_consumes_original_request_limit() -> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(1, 1)?;
    let old = begin(&mut catalog, 7)?;
    catalog.abandon_request_after_reset(&old)?;

    assert!(begin(&mut catalog, 8).is_err());
    assert!(catalog.pending_request().is_none());
    assert_eq!(catalog.total_completed_requests(), 0);
    assert_eq!(catalog.total_abandoned_requests(), 1);
    Ok(())
}

#[test]
fn reset_abandonment_keeps_completed_and_abandoned_attempts_distinct()
-> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(3, 3)?;
    let completed = begin(&mut catalog, 7)?;
    let reply = SelectionReply::rejected(
        7,
        crucible_protocol::SelectionReplyStatus::Unavailable,
        [0; crucible_protocol::SELECTABLE_DIGEST_BYTES],
        [0; crucible_protocol::SELECTABLE_DIGEST_BYTES],
    )?;
    catalog.complete_request(&completed, &reply)?;
    let abandoned = begin(&mut catalog, 8)?;

    catalog.abandon_request_after_reset(&abandoned)?;
    let plan = catalog.to_plan()?;
    let encoded = plan.encode()?;
    let decoded = SelectableCatalogPlan::decode(&encoded)?;
    let mut restored = SelectableCatalog::from_plan(&decoded)?;

    assert_eq!(restored.total_completed_requests(), 1);
    assert_eq!(restored.last_completed_request_sequence(), Some(7));
    assert_eq!(restored.completed_requests_for("product.choice"), 1);
    assert_eq!(restored.total_abandoned_requests(), 1);
    assert_eq!(restored.last_abandoned_request_sequence(), Some(8));
    assert_eq!(restored.to_plan()?, plan);
    assert!(begin(&mut restored, 8).is_err());

    let final_attempt = begin(&mut restored, 9)?;
    restored.abandon_request_after_reset(&final_attempt)?;
    assert!(begin(&mut restored, 10).is_err());
    assert_eq!(restored.total_completed_requests(), 1);
    assert_eq!(restored.total_abandoned_requests(), 2);
    Ok(())
}

#[test]
fn reset_abandonment_does_not_restore_per_selectable_allowance()
-> Result<(), Box<dyn std::error::Error>> {
    let mut catalog = frozen_catalog(1, 2)?;
    let old = begin(&mut catalog, 7)?;
    catalog.abandon_request_after_reset(&old)?;
    let next = SelectionRequest::new(8, "product.choice", "instance-a", None, 128)?;

    assert!(matches!(
        catalog.begin_request(
            &next,
            SelectableCallbackCoordinate::new(100, 5_000, 0),
            reply_range_for_reset(),
        ),
        Err(SelectableCatalogError::SelectableRequestLimitExceeded { .. })
    ));
    assert!(catalog.pending_request().is_none());
    Ok(())
}

fn reply_range_for_reset() -> GuestMemoryRange {
    GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x4000, 128)
}
