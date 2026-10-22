//! Rejects accepting behavior and lost custody in the unavailable-token fixture.

use super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};
use super::{CONTRACTS, PANIC_ONLY_OWNER, REFUSED_CALL};

#[test]
fn unavailable_token_contract_rejects_acceptance_and_custody_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &CONTRACTS[0];
    let source = std::fs::read_to_string(
        crate::workspace::package_path(&crate::workspace_root().join("crates"), contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = read_companions(contract)?;
    assert!(
        source_pattern(super::super::construction_endpoint::UNAVAILABLE_RESERVATION).starts_with(
            &source_pattern("pub(crate) fn unavailable_reservation_for_test()")
        )
    );
    let rejects = |candidate: &str, evidence: &[String]| {
        let masked = mask_contract(contract, candidate, evidence);
        !crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty()
    };
    assert!(!rejects(&code, &companions));
    assert!(rejects(&code, &[]));
    assert_eq!(
        contract.identifiers,
        &[("retry_cleanup", 1), ("retry_reserved_publication", 2)]
    );
    assert_eq!(
        contract.expressions,
        &[(PANIC_ONLY_OWNER, 1), (REFUSED_CALL, 2)]
    );

    for (obligation, replacement) in [
        (
            "#[test] fn unavailable_canonical_handoff_keeps_same_pair_and_first_cause_twice() {",
            "fn unavailable_canonical_handoff_keeps_same_pair_and_first_cause_twice() {",
        ),
        (
            PANIC_ONLY_OWNER,
            "fn retry_cleanup(&mut self) -> Result<(), Self::Failure> { Ok(()) }",
        ),
        (
            PANIC_ONLY_OWNER,
            "fn retry_cleanup(&mut self) -> Result<(), Self::Failure> { foreign_cleanup(); panic!(); }",
        ),
        (
            "type PostBody = crate::ProductionVmConstructionPostBody;",
            "type PostBody = ForeignPostBody;",
        ),
        (
            "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { panic!(\"\"); }",
            "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { Ok(None) }",
        ),
        (
            "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { panic!(\"\"); }",
            "fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> { transfer_foreign_body(); panic!(\"\"); }",
        ),
        (
            REFUSED_CALL,
            "assert!(failure.retry_reserved_publication().is_ok());",
        ),
        (REFUSED_CALL, ""),
        (
            REFUSED_CALL,
            "loop { assert!(failure.retry_reserved_publication().is_err()); }",
        ),
        (
            REFUSED_CALL,
            "while again { assert!(failure.retry_reserved_publication().is_err()); }",
        ),
        (
            REFUSED_CALL,
            "for _ in 0..2 { assert!(failure.retry_reserved_publication().is_err()); }",
        ),
        (
            REFUSED_CALL,
            "thread::sleep(unbounded); assert!(failure.retry_reserved_publication().is_err());",
        ),
        (
            "unavailable_reservation_for_test()",
            "accepting_reservation()",
        ),
        ("std::ptr::eq(cause, self.first)", "cause.marker == 73"),
        ("self.token", "foreign_token"),
        ("self.body", "foreign_body"),
        (
            "returned.as_ref().expect(\"\")",
            "returned.take().expect(\"\")",
        ),
        ("assert!(!self.destroyed.load(Ordering::SeqCst));", ""),
        (
            "assert_eq!(self.cleanup_calls.load(Ordering::SeqCst), 0);",
            "",
        ),
        (
            "assert_eq!((retained.dev(), retained.ino()), self.file_identity);",
            "",
        ),
        (
            "failure.into_published_error().expect_err(\"\")",
            "failure.into_published_error().expect(\"\")",
        ),
        (
            "drop(owner); drop(reservation);",
            "drop(reservation); drop(owner);",
        ),
    ] {
        let changed = replace_one_obligation(&code, &source_pattern(obligation), replacement);
        assert_ne!(
            changed, code,
            "mutation did not find its target: {obligation}"
        );
        assert!(
            rejects(&changed, &companions),
            "changed negative fixture was masked: {replacement}"
        );
    }

    // Each call must refuse independently; changing only the second must fail too.
    let first =
        replace_one_obligation(&code, &source_pattern(REFUSED_CALL), "first_call_marker();");
    let second = replace_one_obligation(
        &first,
        &source_pattern(REFUSED_CALL),
        "assert!(failure.retry_reserved_publication().is_ok());",
    );
    let second = second.replace("first_call_marker();", REFUSED_CALL);
    assert_ne!(second, code);
    assert!(rejects(&second, &companions));

    for addition in [
        REFUSED_CALL,
        "impl ProductionVmCleanupReservation for AcceptingToken {}",
        "fn rerun() { retry_failed_test(); }",
        "fn rerun() { loop { retry_failed_test(); } }",
        "fn unrelated() { thread::sleep(unbounded); }",
    ] {
        let changed = format!("{code}\n{addition}");
        assert!(
            rejects(&changed, &companions),
            "extra behavior was masked: {addition}"
        );
    }

    for (index, unavailable_constructor, obligation, replacement) in [
        (
            0,
            true,
            "Box::new(CleanupReservation { queue: Weak::new(), index: usize::MAX,",
            "Box::new(CleanupReservation { queue: accepting_queue(), index: usize::MAX,",
        ),
        (
            0,
            false,
            "return Err((self, owner));",
            "return Ok(accepting_handoff());",
        ),
        (
            0,
            true,
            "index: usize::MAX, epoch: 0, observed: ProductionVmCleanupStage::BodyRetained, first_failure: None, terminal_history: None, report_reference: false,",
            "index: usize::MAX, epoch: 0, observed: ProductionVmCleanupStage::BodyRetained, first_failure: None, terminal_history: Some(foreign_terminal), report_reference: true,",
        ),
        (
            0,
            true,
            "PostBody = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::PostBody, ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn",
            "PostBody = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::PostBody, ReturnDestination = ForeignReturnDestination",
        ),
        (
            0,
            false,
            "self.publish_returned_owner(slot, owner)",
            "self.publish_returned_owner(slot, foreign_owner)",
        ),
        (
            1,
            false,
            "*returned = Some((reservation, owner));",
            "drop((reservation, owner));",
        ),
        (1, false, "if returned.is_some() { return Err(self); }", ""),
    ] {
        let mut changed = companions.clone();
        let evidence = crate::scrub_comments_and_strings(&changed[index]);
        assert_eq!(
            contract.companions[index].path,
            if index == 0 {
                "crates/crucible/control/crucible-daemon/src/lifecycle_cleanup/reservation.rs"
            } else {
                "crates/crucible/control/crucible-daemon/src/vm_lifecycle/construction/publication.rs"
            }
        );
        // Constructor mutations always select the complete original helper,
        // independently of other matching functions or required-clause order.
        let clause = if unavailable_constructor {
            let full = super::super::construction_endpoint::UNAVAILABLE_RESERVATION;
            assert!(
                contract.companions[index]
                    .required
                    .iter()
                    .any(|(required, count)| *required == full && *count == 1)
            );
            full
        } else {
            contract.companions[index]
                .required
                .iter()
                .find_map(|(clause, _)| {
                    source_pattern(clause)
                        .contains(&source_pattern(obligation))
                        .then_some(*clause)
                })
                .expect("companion mutation must address its required canonical clause")
        };
        let original_clause = crate::scrub_comments_and_strings(clause);
        let changed_clause =
            replace_one_obligation(&original_clause, &source_pattern(obligation), replacement);
        assert_ne!(
            changed_clause, original_clause,
            "clause mutation missed: {obligation}"
        );
        changed[index] =
            replace_one_obligation(&evidence, &source_pattern(clause), &changed_clause);
        assert_ne!(
            changed[index], evidence,
            "companion mutation missed: {obligation}"
        );
        if unavailable_constructor {
            let handoff = source_pattern(super::super::construction_endpoint::UNAVAILABLE_HANDOFF);
            assert!(source_pattern(&evidence).contains(&handoff));
            assert!(source_pattern(&changed[index]).contains(&handoff));
        }
        if obligation.starts_with("Box::new(CleanupReservation") {
            // The historical suffix still matches the other helper. Only the
            // genuine full reservation fact rejects this accepting constructor.
            let compact = source_pattern(&changed[index]);
            assert!(
                contract.companions[index]
                    .required
                    .iter()
                    .filter(|(required, _)| *required != clause)
                    .all(|(required, count)| compact
                        .match_indices(&source_pattern(required))
                        .count()
                        == *count)
            );
        }
        assert!(
            rejects(&code, &changed),
            "changed canonical provenance was masked: {replacement}"
        );
    }
    Ok(())
}
