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

fn reply_range() -> GuestMemoryRange {
    GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x4000, 128)
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

struct FlakyAuthority {
    attempts: usize,
}

impl SelectableDecisionAuthority for FlakyAuthority {
    fn decide_selection(
        &mut self,
        pending: &SelectablePendingRequest,
    ) -> Result<SelectableReplyDisposition, SelectableDoorbellServiceError> {
        self.attempts += 1;
        if self.attempts == 1 {
            Err(SelectableDoorbellServiceError::new(
                "semantic resolver temporarily unavailable",
            ))
        } else {
            reply(pending.request().sequence())
                .map(SelectableReplyDisposition::from)
                .map_err(|error| SelectableDoorbellServiceError::new(error.to_string()))
        }
    }
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
        catalog.begin_request(&first, coordinate(100), reply_range()),
        Err(SelectableCatalogError::RequestBeforeFreeze)
    );
    catalog.register(&registration(1, "network.policy", &[1])?)?;
    catalog.freeze()?;

    let pending = catalog.begin_request(&first, coordinate(100), reply_range())?;
    assert_eq!(pending.request(), &first);
    assert_eq!(pending.coordinate(), coordinate(100));
    assert_eq!(pending.declaration().domain(), [1]);
    assert_eq!(catalog.pending_request(), Some(&pending));
    assert!(matches!(
        catalog.begin_request(
            &request(8, "network.policy")?,
            coordinate(101),
            reply_range(),
        ),
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
    let first_pending = first.begin_request(&request, coordinate(100), reply_range())?;
    let second_pending = second.begin_request(&request, coordinate(100), reply_range())?;

    assert_eq!(
        first.complete_request(&second_pending, &reply(7)?),
        Err(SelectableCatalogError::PendingRequestMismatch)
    );
    assert_eq!(first.pending_request(), Some(&first_pending));
    first.complete_request(&first_pending, &reply(7)?)?;
    Ok(())
}

#[test]
fn combined_service_retains_failed_decision_and_retries_without_readmission()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 1, 1)?;
    let catalog = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    let mut service = CatalogedSelectableService::new(catalog, FlakyAuthority { attempts: 0 });
    service.register_selectable(&registration(1, "network.policy", &[1])?, coordinate(1))?;
    service.freeze()?;
    let request = request(7, "network.policy")?;

    assert_eq!(
        service
            .serve_selection(&request, coordinate(100), reply_range())
            .map(|_reply| ()),
        Err(SelectableDoorbellServiceError::new(
            "semantic resolver temporarily unavailable",
        ))
    );
    assert_eq!(
        service
            .catalog()
            .pending_request()
            .map(SelectablePendingRequest::request),
        Some(&request)
    );
    assert_eq!(service.catalog().total_completed_requests(), 0);

    let resolved = service.resolve_pending()?;
    assert_eq!(resolved, SelectableReplyDisposition::Reply(reply(7)?),);
    assert_eq!(service.catalog().pending_request(), None);
    assert_eq!(service.catalog().total_completed_requests(), 1);
    assert_eq!(service.authority.attempts, 2);
    Ok(())
}

#[test]
fn canonical_plan_round_trip_restores_exact_state_with_fresh_token()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 3, 3)?;
    let mut catalog = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    catalog.register(&registration(4, "network.policy", &[1])?)?;
    catalog.freeze()?;
    let completed = catalog.begin_request(
        &request(7, "network.policy")?,
        coordinate(100),
        reply_range(),
    )?;
    catalog.complete_request(&completed, &reply(7)?)?;
    let old_pending = catalog.begin_request(
        &request(8, "network.policy")?,
        coordinate(120),
        reply_range(),
    )?;

    let encoded = catalog.to_plan()?.encode()?;
    let decoded =
        crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::decode(&encoded)?;
    let mut restored = SelectableCatalog::from_plan(&decoded)?;
    assert_eq!(restored.phase(), SelectableCatalogPhase::Frozen);
    assert_eq!(
        restored.registered_declarations(),
        &BTreeSet::from(["network.policy".to_owned()])
    );
    assert_eq!(restored.last_registration_sequence(), Some(4));
    assert_eq!(restored.completed_requests_for("network.policy"), 1);
    assert_eq!(restored.total_completed_requests(), 1);
    assert_eq!(restored.last_completed_request_sequence(), Some(7));
    let restored_pending = restored
        .pending_request()
        .cloned()
        .ok_or_else(|| std::io::Error::other("restored pending request is missing"))?;
    assert_eq!(restored_pending.request().sequence(), 8);
    assert_eq!(restored_pending.coordinate(), coordinate(120));
    assert_eq!(restored_pending.reply_range(), reply_range());

    assert_eq!(
        restored.complete_request(&old_pending, &reply(8)?),
        Err(SelectableCatalogError::PendingRequestMismatch)
    );
    restored.complete_request(&restored_pending, &reply(8)?)?;
    assert_eq!(restored.total_completed_requests(), 2);
    let final_plan = restored.to_plan()?;
    let final_bytes = final_plan.encode()?;
    assert_eq!(
        crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::decode(&final_bytes),
        Ok(final_plan)
    );
    Ok(())
}

#[test]
fn pending_request_requires_the_exact_guest_virtual_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 1, 1)?;
    let mut catalog = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    catalog.register(&registration(1, "network.policy", &[1])?)?;
    catalog.freeze()?;
    let request = request(2, "network.policy")?;

    assert_eq!(
        catalog.begin_request(
            &request,
            coordinate(10),
            GuestMemoryRange::new(GuestMemoryAddressSpace::Physical, 0x4000, 128),
        ),
        Err(SelectableCatalogError::PendingReplyRangeNotVirtual)
    );
    assert_eq!(
        catalog.begin_request(
            &request,
            coordinate(10),
            GuestMemoryRange::new(GuestMemoryAddressSpace::Virtual, 0x4000, 127),
        ),
        Err(SelectableCatalogError::PendingReplyRangeLengthMismatch {
            range_len: 127,
            request_capacity: 128,
        })
    );
    assert_eq!(catalog.pending_request(), None);
    Ok(())
}

#[test]
fn launch_pair_shares_declaration_bytes_but_not_request_incarnations()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = limits(1, 3, 3)?;
    let mut source = catalog(
        vec![expected(
            "network.policy",
            &[1],
            SelectableExpectedPresence::Required,
        )?],
        limits,
    )?;
    source.register(&registration(4, "network.policy", &[1])?)?;
    source.freeze()?;
    source.begin_request(
        &request(8, "network.policy")?,
        coordinate(120),
        reply_range(),
    )?;
    let plan = source.to_plan()?;

    let (cold, restored) = SelectableCatalog::launch_pair_from_plan(&plan)?;
    assert!(Arc::ptr_eq(
        &cold.expectation.declarations,
        &restored.expectation.declarations,
    ));
    assert_eq!(cold.phase(), SelectableCatalogPhase::Registering);
    assert_eq!(cold.pending_request(), None);
    assert_eq!(restored.phase(), SelectableCatalogPhase::Frozen);
    assert_eq!(
        restored
            .pending_request()
            .map(SelectablePendingRequest::request),
        source
            .pending_request()
            .map(SelectablePendingRequest::request),
    );
    assert!(!Arc::ptr_eq(&cold.incarnation, &restored.incarnation));
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

    let first = catalog.begin_request(&request(10, "network.a")?, coordinate(10), reply_range())?;
    catalog.complete_request(&first, &reply(10)?)?;
    assert!(matches!(
        catalog.begin_request(&request(10, "network.b")?, coordinate(11), reply_range()),
        Err(SelectableCatalogError::SequenceNotIncreasing {
            kind: "request",
            ..
        })
    ));
    assert!(matches!(
        catalog.begin_request(&request(11, "network.a")?, coordinate(11), reply_range()),
        Err(SelectableCatalogError::SelectableRequestLimitExceeded { .. })
    ));

    let second =
        catalog.begin_request(&request(11, "network.b")?, coordinate(11), reply_range())?;
    catalog.complete_request(&second, &reply(11)?)?;
    assert!(matches!(
        catalog.begin_request(&request(12, "network.b")?, coordinate(12), reply_range()),
        Err(SelectableCatalogError::TotalRequestLimitExceeded { maximum: 2 })
    ));
    Ok(())
}
