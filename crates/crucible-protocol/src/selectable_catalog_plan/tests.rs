//! Canonical selectable catalog-plan codec and invariant tests.

use super::*;

fn declaration(
    id: &str,
    presence: SelectablePlanPresence,
) -> Result<SelectablePlanDeclaration, SelectableProtocolError> {
    SelectablePlanDeclaration::new(
        id,
        vec![1, 2],
        vec![1],
        vec!["network".to_owned()],
        presence,
    )
}

fn limits() -> Result<SelectablePlanLimits, SelectableCatalogPlanError> {
    SelectablePlanLimits::new(4, 8, 16)
}

fn restored_plan() -> Result<SelectableCatalogPlan, Box<dyn std::error::Error>> {
    let declarations = vec![
        declaration("network.optional", SelectablePlanPresence::Optional)?,
        declaration("network.policy", SelectablePlanPresence::Required)?,
    ];
    let registered = BTreeSet::from(["network.optional".to_owned(), "network.policy".to_owned()]);
    let completed = BTreeMap::from([("network.policy".to_owned(), 3)]);
    let pending = SelectablePlanPendingRequest::new(
        SelectionRequest::new(12, "network.optional", "epoch/7", Some(vec![3, 4]), 160)?,
        900,
        2,
    );
    let continuation = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        registered,
        Some(5),
        completed,
        Some(11),
        Some(pending),
    )?;
    Ok(SelectableCatalogPlan::new(
        limits()?,
        declarations,
        continuation,
    )?)
}

#[test]
fn cold_and_restored_plans_round_trip_with_frozen_header() -> Result<(), Box<dyn std::error::Error>>
{
    let cold = SelectableCatalogPlan::new(
        limits()?,
        vec![declaration(
            "network.policy",
            SelectablePlanPresence::Required,
        )?],
        SelectablePlanContinuation::cold(),
    )?;
    let cold_bytes = cold.encode()?;
    assert_eq!(&cold_bytes[..8], b"CRUCSCP1");
    assert_eq!(&cold_bytes[8..12], &[0, 0, 0, 1]);
    assert_eq!(&cold_bytes[12..16], &[0, 0, 0, 96]);
    assert_eq!(SelectableCatalogPlan::decode(&cold_bytes), Ok(cold));

    let restored = restored_plan()?;
    let bytes = restored.encode()?;
    assert_eq!(u32::from_be_bytes(bytes[20..24].try_into()?), KNOWN_FLAGS);
    assert_eq!(SelectableCatalogPlan::decode(&bytes), Ok(restored));
    Ok(())
}

#[test]
fn plan_rejects_unknown_registered_missing_required_and_limit_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    let unknown = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::from(["network.unknown".to_owned()]),
        Some(1),
        BTreeMap::new(),
        None,
        None,
    )?;
    assert!(matches!(
        SelectableCatalogPlan::new(
            limits()?,
            vec![declaration(
                "network.policy",
                SelectablePlanPresence::Required,
            )?],
            unknown,
        ),
        Err(SelectableCatalogPlanError::UnknownIdentifier {
            field: "registered",
            ..
        })
    ));

    let missing = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::new(),
        None,
        BTreeMap::new(),
        None,
        None,
    )?;
    assert!(matches!(
        SelectableCatalogPlan::new(
            limits()?,
            vec![declaration(
                "network.policy",
                SelectablePlanPresence::Required,
            )?],
            missing,
        ),
        Err(SelectableCatalogPlanError::MissingRequiredDeclaration { .. })
    ));

    let too_many = SelectablePlanContinuation::new(
        SelectablePlanPhase::Frozen,
        BTreeSet::from(["network.policy".to_owned()]),
        Some(1),
        BTreeMap::from([("network.policy".to_owned(), 9)]),
        Some(9),
        None,
    )?;
    assert!(matches!(
        SelectableCatalogPlan::new(
            limits()?,
            vec![declaration(
                "network.policy",
                SelectablePlanPresence::Required,
            )?],
            too_many,
        ),
        Err(SelectableCatalogPlanError::RequestLimitExceeded {
            field: "requests_per_selectable",
            ..
        })
    ));
    Ok(())
}

#[test]
fn decode_rejects_flags_order_reserved_total_and_trailing_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = restored_plan()?.encode()?;

    let mut flags = bytes.clone();
    flags[23] |= 0x80;
    assert!(matches!(
        SelectableCatalogPlan::decode(&flags),
        Err(SelectableCatalogPlanError::UnknownFlags { .. })
    ));

    let mut reserved = bytes.clone();
    reserved[SELECTABLE_CATALOG_PLAN_HEADER_BYTES + 1] = 1;
    assert_eq!(
        SelectableCatalogPlan::decode(&reserved),
        Err(SelectableCatalogPlanError::NonzeroReserved)
    );

    let mut total = bytes.clone();
    total[19] ^= 1;
    assert!(matches!(
        SelectableCatalogPlan::decode(&total),
        Err(SelectableCatalogPlanError::InvalidTotalLength { .. })
    ));

    let mut trailing = bytes.clone();
    trailing.push(0);
    let length = u32::try_from(trailing.len())?;
    trailing[16..20].copy_from_slice(&length.to_be_bytes());
    assert_eq!(
        SelectableCatalogPlan::decode(&trailing),
        Err(SelectableCatalogPlanError::TrailingBytes { bytes: 1 })
    );
    Ok(())
}

#[test]
fn continuation_rejects_runtime_state_before_freeze_and_stale_pending_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        SelectablePlanContinuation::new(
            SelectablePlanPhase::Registering,
            BTreeSet::new(),
            None,
            BTreeMap::new(),
            None,
            Some(SelectablePlanPendingRequest::new(
                SelectionRequest::new(1, "network.policy", "epoch/1", None, 128)?,
                1,
                0,
            )),
        ),
        Err(SelectableCatalogPlanError::InvalidContinuation { .. })
    ));

    assert!(matches!(
        SelectablePlanContinuation::new(
            SelectablePlanPhase::Frozen,
            BTreeSet::from(["network.policy".to_owned()]),
            Some(1),
            BTreeMap::from([("network.policy".to_owned(), 1)]),
            Some(7),
            Some(SelectablePlanPendingRequest::new(
                SelectionRequest::new(7, "network.policy", "epoch/1", None, 128)?,
                1,
                0,
            )),
        ),
        Err(SelectableCatalogPlanError::InvalidContinuation { .. })
    ));
    Ok(())
}
