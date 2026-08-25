//! Catalog reconciliation, freeze, and pending-request tests.

use crucible_protocol::{SELECTABLE_DIGEST_BYTES, SelectionReply, SelectionReplyStatus};

use super::*;

fn limits(
    declarations: usize,
    per_selectable: u64,
    total: u64,
) -> Result<SelectableCatalogLimits, SelectableCatalogError> {
    SelectableCatalogLimits::new(declarations, per_selectable, total)
}

fn registration(
    sequence: u64,
    selectable_id: &str,
    domain: &[u8],
) -> Result<SelectableRegister, SelectableProtocolError> {
    SelectableRegister::new(
        sequence,
        selectable_id,
        domain.to_vec(),
        vec![9],
        vec!["network".to_owned()],
    )
}

fn expected(
    selectable_id: &str,
    domain: &[u8],
    presence: SelectableExpectedPresence,
) -> Result<SelectableExpectedDeclaration, SelectableProtocolError> {
    SelectableExpectedDeclaration::new(
        selectable_id,
        domain.to_vec(),
        vec![9],
        vec!["network".to_owned()],
        presence,
    )
}

fn catalog(
    declarations: Vec<SelectableExpectedDeclaration>,
    limits: SelectableCatalogLimits,
) -> Result<SelectableCatalog, SelectableCatalogError> {
    SelectableCatalog::new(
        limits,
        SelectableCatalogExpectation::new(declarations, limits)?,
    )
}

fn coordinate(icount: u64) -> SelectableCallbackCoordinate {
    SelectableCallbackCoordinate::new(icount, 0)
}

fn request(
    sequence: u64,
    selectable_id: &str,
) -> Result<SelectionRequest, SelectableProtocolError> {
    SelectionRequest::new(sequence, selectable_id, "epoch/7", None, 128)
}

fn reply(sequence: u64) -> Result<SelectionReply, SelectableProtocolError> {
    SelectionReply::rejected(
        sequence,
        SelectionReplyStatus::Unavailable,
        [0; SELECTABLE_DIGEST_BYTES],
        [0; SELECTABLE_DIGEST_BYTES],
    )
}

#[test]
fn catalog_limits_are_nonzero_ordered_and_hard_bounded() {
    assert!(matches!(
        limits(0, 1, 1),
        Err(SelectableCatalogError::InvalidLimit {
            name: "declarations",
            ..
        })
    ));
    assert!(matches!(
        limits(1, 2, 1),
        Err(SelectableCatalogError::PerSelectableLimitExceedsTotal { .. })
    ));
    assert!(matches!(
        limits(SELECTABLE_CATALOG_HARD_MAX_DECLARATIONS + 1, 1, 1),
        Err(SelectableCatalogError::InvalidLimit {
            name: "declarations",
            ..
        })
    ));
    assert!(matches!(
        limits(1, 1, SELECTABLE_CATALOG_HARD_MAX_REQUESTS + 1),
        Err(SelectableCatalogError::InvalidLimit {
            name: "total_requests",
            ..
        })
    ));
}

#[test]
fn expectation_rejects_duplicate_and_over_limit_entries() -> Result<(), Box<dyn std::error::Error>>
{
    let declaration = expected("network.policy", &[1], SelectableExpectedPresence::Required)?;
    assert!(matches!(
        SelectableCatalogExpectation::new(
            vec![declaration.clone(), declaration.clone()],
            limits(2, 1, 1)?,
        ),
        Err(SelectableCatalogError::DuplicateExpectedDeclaration { .. })
    ));
    assert!(SelectableCatalogExpectation::new(vec![declaration], limits(1, 1, 1)?).is_ok());
    let broad_expectation = SelectableCatalogExpectation::new(
        vec![
            expected("network.a", &[1], SelectableExpectedPresence::Required)?,
            expected("network.b", &[1], SelectableExpectedPresence::Required)?,
        ],
        limits(2, 1, 1)?,
    )?;
    assert!(matches!(
        SelectableCatalog::new(limits(1, 1, 1)?, broad_expectation),
        Err(SelectableCatalogError::DeclarationLimitExceeded { .. })
    ));
    assert!(matches!(
        SelectableCatalogExpectation::new(
            vec![
                expected("network.a", &[1], SelectableExpectedPresence::Required)?,
                expected("network.b", &[1], SelectableExpectedPresence::Required)?,
            ],
            limits(1, 1, 1)?,
        ),
        Err(SelectableCatalogError::DeclarationLimitExceeded { .. })
    ));
    Ok(())
}

#[test]
fn setup_registration_requires_expected_exact_contract_and_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(3, 2, 3)?;
    let mut exact_catalog = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;

    let exact = registration(4, "network.policy", &[1])?;
    exact_catalog.register(&exact)?;
    assert!(matches!(
        exact_catalog.register(&exact),
        Err(SelectableCatalogError::SequenceNotIncreasing {
            kind: "registration",
            ..
        })
    ));

    let mut mismatch = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    assert!(matches!(
        mismatch.register(&registration(1, "network.policy", &[2])?),
        Err(SelectableCatalogError::DeclarationContractMismatch { .. })
    ));
    assert!(matches!(
        mismatch.register(&registration(1, "network.unknown", &[1])?),
        Err(SelectableCatalogError::UnexpectedDeclaration { .. })
    ));
    Ok(())
}

#[test]
fn freeze_requires_required_entries_and_accepts_absent_optional()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(2, 2, 4)?;
    let declarations = vec![
        expected(
            "network.required",
            &[1],
            SelectableExpectedPresence::Required,
        )?,
        expected(
            "network.optional",
            &[2],
            SelectableExpectedPresence::Optional,
        )?,
    ];
    let mut missing = catalog(declarations.clone(), limits)?;
    assert_eq!(
        missing.freeze(),
        Err(SelectableCatalogError::MissingRequiredDeclarations {
            missing: vec!["network.required".to_owned()],
        })
    );
    assert_eq!(missing.phase(), SelectableCatalogPhase::Registering);

    let mut complete = catalog(declarations, limits)?;
    complete.register(&registration(1, "network.required", &[1])?)?;
    let freeze = complete.freeze()?;
    assert_eq!(freeze.registered_declarations(), 1);
    assert_eq!(freeze.required_declarations(), 1);
    assert_eq!(complete.phase(), SelectableCatalogPhase::Frozen);
    assert_eq!(
        complete.freeze(),
        Err(SelectableCatalogError::CatalogAlreadyFrozen)
    );
    assert_eq!(
        complete.register(&registration(2, "network.optional", &[2])?),
        Err(SelectableCatalogError::RegistrationAfterFreeze)
    );
    Ok(())
}

#[test]
fn request_is_frozen_catalog_bound_and_retained_until_exact_reply()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 2, 2)?;
    let mut catalog = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    let first = request(7, "network.policy")?;
    assert_eq!(
        catalog.begin_request(&first, coordinate(100)),
        Err(SelectableCatalogError::RequestBeforeFreeze)
    );
    catalog.register(&registration(1, "network.policy", &[1])?)?;
    catalog.freeze()?;

    let pending = catalog.begin_request(&first, coordinate(100))?;
    assert_eq!(pending.request(), &first);
    assert_eq!(pending.coordinate(), coordinate(100));
    assert_eq!(pending.declaration().domain(), [1]);
    assert_eq!(catalog.pending_request(), Some(&pending));
    assert!(matches!(
        catalog.begin_request(&request(8, "network.policy")?, coordinate(101)),
        Err(SelectableCatalogError::RequestAlreadyPending {
            pending_sequence: 7,
            actual_sequence: 8,
        })
    ));
    assert_eq!(
        catalog.complete_request(&pending, &reply(8)?),
        Err(SelectableCatalogError::ReplySequenceMismatch {
            expected: 7,
            actual: 8,
        })
    );
    assert_eq!(catalog.pending_request(), Some(&pending));

    catalog.complete_request(&pending, &reply(7)?)?;
    assert_eq!(catalog.pending_request(), None);
    assert_eq!(catalog.total_completed_requests(), 1);
    assert_eq!(catalog.completed_requests_for("network.policy"), 1);
    Ok(())
}

#[test]
fn pending_token_is_bound_to_one_catalog_incarnation() -> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 1, 1)?;
    let declarations = vec![expected(
        "network.policy",
        &[1],
        SelectableExpectedPresence::Required,
    )?];
    let mut first = catalog(declarations.clone(), limits)?;
    let mut second = catalog(declarations, limits)?;
    for catalog in [&mut first, &mut second] {
        catalog.register(&registration(1, "network.policy", &[1])?)?;
        catalog.freeze()?;
    }
    let request = request(7, "network.policy")?;
    let first_pending = first.begin_request(&request, coordinate(100))?;
    let second_pending = second.begin_request(&request, coordinate(100))?;

    assert_eq!(
        first.complete_request(&second_pending, &reply(7)?),
        Err(SelectableCatalogError::PendingRequestMismatch)
    );
    assert_eq!(first.pending_request(), Some(&first_pending));
    first.complete_request(&first_pending, &reply(7)?)?;
    Ok(())
}

#[test]
fn completed_request_sequences_and_all_request_limits_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(2, 1, 2)?;
    let mut catalog = catalog(
        vec![
            expected("network.a", &[1], SelectableExpectedPresence::Required)?,
            expected("network.b", &[2], SelectableExpectedPresence::Required)?,
        ],
        limits,
    )?;
    catalog.register(&registration(1, "network.a", &[1])?)?;
    catalog.register(&registration(2, "network.b", &[2])?)?;
    catalog.freeze()?;

    let first = catalog.begin_request(&request(10, "network.a")?, coordinate(10))?;
    catalog.complete_request(&first, &reply(10)?)?;
    assert!(matches!(
        catalog.begin_request(&request(10, "network.b")?, coordinate(11)),
        Err(SelectableCatalogError::SequenceNotIncreasing {
            kind: "request",
            ..
        })
    ));
    assert!(matches!(
        catalog.begin_request(&request(11, "network.a")?, coordinate(11)),
        Err(SelectableCatalogError::SelectableRequestLimitExceeded { .. })
    ));

    let second = catalog.begin_request(&request(11, "network.b")?, coordinate(11))?;
    catalog.complete_request(&second, &reply(11)?)?;
    assert!(matches!(
        catalog.begin_request(&request(12, "network.b")?, coordinate(12)),
        Err(SelectableCatalogError::TotalRequestLimitExceeded { maximum: 2 })
    ));
    Ok(())
}
