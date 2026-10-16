//! Keeps custody republication distinct from cleanup and failed-test reruns.

use super::super::{
    Contract, mask_contract, read_companions, replace_one_obligation, source_pattern,
};
use super::CONTRACTS;

fn rejected(contract: &Contract, code: &str, companions: &[String]) -> bool {
    let masked = mask_contract(contract, code, companions);
    !crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty()
}

#[test]
fn publication_requires_same_pair_and_preserves_the_original_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &CONTRACTS[0];
    let source = std::fs::read_to_string(
        crate::workspace_root()
            .join("crates")
            .join(contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = read_companions(contract)?;
    assert_eq!(contract.identifiers, &[("retry_reserved_publication", 1)]);
    assert!(contract.expressions.is_empty());
    assert!(!rejected(contract, &code, &companions));
    assert!(rejected(contract, &code, &[]));

    for (obligation, replacement) in [
        (
            "let FailureStorage::Rejected { returned, .. } = &mut self.storage else { return Err(\"\"); };",
            "let FailureStorage::Rejected { returned, .. } = &mut other.storage else { return Err(\"\"); };",
        ),
        (
            "let returned = returned.get_mut().map_err(|_| \"\")?;",
            "let returned = other.get_mut().map_err(|_| \"\")?;",
        ),
        (
            "let Some((reservation, owner)) = returned.take() else",
            "let Some((reservation, owner)) = alternate.take() else",
        ),
        ("return Ok(None);", "return Ok(Some(foreign_receipt));"),
        (
            "match reservation.retain(owner)",
            "match foreign_token.retain(owner)",
        ),
        (
            "match reservation.retain(owner)",
            "match reservation.retain(foreign_owner)",
        ),
        (
            "Ok(handoff) => Ok(Some(handoff))",
            "Ok(handoff) => Ok(None)",
        ),
        (
            "*returned = Some((reservation, owner));",
            "*returned = None;",
        ),
        (
            "*returned = Some((reservation, owner));",
            "*returned = Some((foreign_token, owner));",
        ),
        (
            "*returned = Some((reservation, owner));",
            "*returned = Some((reservation, foreign_owner));",
        ),
        (
            "*returned = Some((reservation, owner)); Err(\"\")",
            "Err(\"\"); *returned = Some((reservation, owner));",
        ),
        (
            "match reservation.retain(owner)",
            "self.storage = foreign_storage; match reservation.retain(owner)",
        ),
        (
            "let FailureStorage::Rejected { returned, .. } = &mut self.storage else { return Err(\"\"); };",
            "let FailureStorage::Rejected { first, returned } = &mut self.storage else { return Err(\"\"); }; drop(std::mem::replace(first, LifecycleApiError::ConstructionCustodyUnavailable));",
        ),
        (
            "match reservation.retain(custody)",
            "match reservation.retain(foreign_custody)",
        ),
        (
            "match reservation.retain(self)",
            "match foreign_token.retain(self)",
        ),
    ] {
        let changed = replace_one_obligation(&code, &source_pattern(obligation), replacement);
        assert_ne!(changed, code, "mutation missed: {obligation}");
        assert!(
            rejected(contract, &changed, &companions),
            "changed custody operation was masked: {replacement}"
        );
    }

    for addition in [
        "reservation.retain(owner);",
        "fn retry_reserved_publication() {}",
        "fn rerun() { retry_failed_test(); }",
        "fn rerun() { loop { retry_failed_test(); } }",
        "fn unrelated() { thread::sleep(unbounded); }",
        "fn unrelated() { HostOperationSupervisor::new(foreign); }",
        "fn unrelated() { Instant::now(); }",
        "fn unrelated() { Box::new(foreign_owner); }",
        "fn unrelated() { owner.retry_cleanup(); }",
        "fn unrelated() { operation.complete(); }",
    ] {
        let changed = format!("{code}\n{addition}");
        assert!(
            rejected(contract, &changed, &companions),
            "added effect was masked: {addition}"
        );
    }
    Ok(())
}

#[test]
fn canonical_cell_and_source_receipt_obligations_reject_foreign_or_early_closure()
-> Result<(), Box<dyn std::error::Error>> {
    let contract = &CONTRACTS[0];
    let source = std::fs::read_to_string(
        crate::workspace_root()
            .join("crates")
            .join(contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = read_companions(contract)?;
    assert!(!rejected(contract, &code, &companions));

    for (index, obligation, replacement) in [
        (0, "self: Box<Self>, owner:", "self: &mut Self, owner:"),
        (
            1,
            "queue.slots.get(self.index)",
            "queue.slots.get(other_index)",
        ),
        (
            1,
            "self.publish_owner(slot, owner)",
            "self.publish_owner(slot, foreign_owner)",
        ),
        (
            1,
            "CleanupPhase::Reserved, CleanupPhase::Publishing",
            "CleanupPhase::Free, CleanupPhase::Publishing",
        ),
        (
            1,
            "cell.epoch != self.epoch || cell.owner.is_some()",
            "cell.owner.is_some()",
        ),
        (
            1,
            "cell.owner = Some(owner); cell.handoff = true; drop(cell); slot.publish(CleanupPhase::Queued); Ok(self)",
            "slot.publish(CleanupPhase::Queued); cell.owner = Some(owner); cell.handoff = true; drop(cell); Ok(self)",
        ),
        (
            1,
            "cell.owner = Some(owner); cell.handoff = true; drop(cell); slot.publish(CleanupPhase::Queued); Ok(self)",
            "cell.owner = Some(owner); cell.handoff = true; drop(cell); slot.publish(CleanupPhase::Free); Ok(self)",
        ),
        (
            1,
            "queue: Weak::clone(&self.queue), index, epoch,",
            "queue: Weak::clone(&foreign_queue), index, epoch,",
        ),
        (1, "cell.controls = Some(controls)", "drop(controls)"),
        (1, "checked_add(1)", "wrapping_add(1)"),
        (
            2,
            "CleanupPhase::Queued, CleanupPhase::Retrying",
            "CleanupPhase::Reserved, CleanupPhase::Retrying",
        ),
        (
            2,
            "CleanupPhase::OwnerDestroyed, CleanupPhase::Completing",
            "CleanupPhase::Publishing, CleanupPhase::Completing",
        ),
        (
            2,
            "Ordering::AcqRel, Ordering::Acquire",
            "Ordering::Relaxed, Ordering::Relaxed",
        ),
        (
            3,
            "owner.retry_reserved_publication()?",
            "foreign_owner.retry_reserved_publication()?",
        ),
        (
            3,
            "let Some(receipt) = published else { return Err(\"\"); };",
            "let Some(receipt) = published else { return Ok(true); };",
        ),
        (
            3,
            "*slot = Some(receipt); Ok(false)",
            "drop(receipt); Ok(true)",
        ),
        (
            3,
            "if owner.handoff_mut().is_none()",
            "if owner.handoff_mut().is_some()",
        ),
        (
            3,
            "let attempt = receipt.retry(); let stage = receipt.stage();",
            "let stage = Ok(ProductionVmCleanupStage::Complete); let attempt = Ok(());",
        ),
        (
            3,
            "&& !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete))",
            "&& false",
        ),
        (3, "self.retry_retained_source_installation()", "Ok(())"),
        (
            4,
            "factory.reserve_world_lifecycle_cleanup(controls)",
            "factory.reserve_world_lifecycle_cleanup(foreign_controls)",
        ),
        (
            4,
            "self.controls = Some(controls); Err(source)",
            "drop(controls); Err(source)",
        ),
        (5, "self.require_install_vacancy()?;", ""),
        (
            5,
            ".with_cleanup_reservation(reservation)",
            ".with_cleanup_reservation(foreign_token)",
        ),
        (6, "self.cleanup_reservation.take()", "Some(foreign_token)"),
        (4, "self.world.take()", "foreign_world.take()"),
        (4, "self.world.is_none()", "false"),
        (
            5,
            ".with_world_cleanup_loan(world)",
            ".with_world_cleanup_loan(foreign_world)",
        ),
        (6, "self._world_cleanup_loan = Some(world)", "drop(world)"),
        (
            7,
            "cleanup.reserve_for_world(controls)",
            "cleanup.reserve_for_world(foreign_controls)",
        ),
    ] {
        let mut changed = companions.clone();
        let evidence = crate::scrub_comments_and_strings(&changed[index]);
        changed[index] =
            replace_one_obligation(&evidence, &source_pattern(obligation), replacement);
        assert_ne!(
            changed[index], evidence,
            "companion mutation missed: {obligation}"
        );
        assert!(
            rejected(contract, &code, &changed),
            "changed provenance was masked: {replacement}"
        );
    }
    Ok(())
}
