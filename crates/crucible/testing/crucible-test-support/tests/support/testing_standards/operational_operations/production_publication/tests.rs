//! Keeps custody republication distinct from cleanup and failed-test reruns.

use super::super::{Contract, mask_contract, read_companions, replace_one_obligation, source_pattern};
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
        crate::workspace::package_path(&crate::workspace_root().join("crates"), contract.package)
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
        ("reservation.retain(self)", "foreign_token.retain(self)"),
        (
            "self.publish_cleanup_mode(false)",
            "self.publish_cleanup_mode(true)",
        ),
        (
            "self.publish_cleanup_mode(true)",
            "self.publish_cleanup_mode(false)",
        ),
        (
            "reservation.retain_returned(self)",
            "reservation.retain_returned(foreign_owner)",
        ),
        (
            "destination.deliver(self)",
            "destination.deliver(foreign_owner)",
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
        crate::workspace::package_path(&crate::workspace_root().join("crates"), contract.package)
            .join(format!("{}.rs", contract.target)),
    )?;
    let code = crate::scrub_comments_and_strings(&source);
    let companions = read_companions(contract)?;
    assert!(!rejected(contract, &code, &companions));

    for (scope, obligation, replacement) in [
        (
            "crucible-control-api/src/cleanup_owner.rs",
            r#"self: Box<Self>, owner:"#,
            r#"self: &mut Self, owner:"#,
        ),
        (
            "crucible-control-api/src/cleanup_owner.rs",
            r#"PostBody = Self::PostBody"#,
            r#"PostBody = ForeignPostBody"#,
        ),
        (
            "crucible-control-api/src/cleanup_owner.rs",
            r#"ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, Self::ReturnDestination>"#,
            r#"ProductionVmCleanupRetainResult<Self::Failure, Self::PostBody, ForeignReturn>"#,
        ),
        (
            "crucible-control-api/src/cleanup_owner.rs",
            r#"ReturnDestination = ReturnDestination"#,
            r#"ReturnDestination = ForeignReturn"#,
        ),
        (
            "crucible-control-api/src/cleanup_owner.rs",
            r#"Box<dyn ProductionVmCleanupOwner<Failure = Failure, PostBody = PostBody>>"#,
            r#"Box<dyn ProductionVmCleanupOwner<Failure = Failure, PostBody = ForeignPostBody>>"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"queue.slots.get(self.index)"#,
            r#"queue.slots.get(other_index)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"self.publish_owner(slot, owner)"#,
            r#"self.publish_owner(slot, foreign_owner)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"CleanupPhase::Reserved, CleanupPhase::Publishing"#,
            r#"CleanupPhase::Free, CleanupPhase::Publishing"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell.epoch != self.epoch || cell.owner.is_some()"#,
            r#"cell.owner.is_some()"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"slot.request_retirement(); cell.owner = Some(owner);"#,
            r#"slot.publish(CleanupPhase::Queued); cell.owner = Some(owner);"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"CleanupPhase::Publishing, CleanupPhase::Queued"#,
            r#"CleanupPhase::Publishing, CleanupPhase::Free"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"queue: Weak::clone(queue), index, epoch,"#,
            r#"queue: Weak::clone(foreign_queue), index, epoch,"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell: ReservedWorldCell { queue: Weak::clone(queue), index, epoch, }"#,
            r#"cell: ReservedWorldCell { queue: Weak::clone(queue), index, epoch: foreign_epoch, }"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"queue.slots.get(self.cell.index)"#,
            r#"queue.slots.get(foreign_index)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"borrow_reserved_cell(slot, self.cell.epoch)"#,
            r#"borrow_reserved_cell(slot, foreign_epoch)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell.controls.is_some()"#,
            r#"true"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"slot.cell.try_lock().ok()?"#,
            r#"slot.cell.lock().ok()?"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell.epoch != epoch || cell.owner.is_some()"#,
            r#"cell.owner.is_some()"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell.controls = Some(controls)"#,
            r#"drop(controls)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"cell.controls_bound = true"#,
            r#"cell.controls_bound = false"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"returned && slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Publishing)"#,
            r#"slot.claim(CleanupPhase::RetryingPrepared, CleanupPhase::Publishing)"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"if poisoned || was_quarantined"#,
            r#"if false"#,
        ),
        (
            "lifecycle_cleanup/reservation.rs",
            r#"!report_refs::register(slot, self.epoch)"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"checked_add(1)"#,
            r#"wrapping_add(1)"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"queue._pool.verify_retained_main()"#,
            r#"other_pool.verify_retained_main()"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"constructor_bytes < minimum_body || constructor_bytes > queue.constructor_bytes"#,
            r#"constructor_bytes < minimum_body"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"slot.external_return_reserved.load(Ordering::Acquire)"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"slot.report_references.load(Ordering::Acquire) != report_refs::CLOSED"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"slot.external_receivers.load(Ordering::Acquire) != 0"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"new_world_reservation(&self.queue, index, epoch)"#,
            r#"new_world_reservation(&foreign_queue, index, epoch)"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"build(input, reservation)"#,
            r#"build(input, foreign_reservation)"#,
        ),
        (
            "lifecycle_cleanup/prepared_producer.rs",
            r#"drop(cell); drop(service); drop(prepared); slot.publish(CleanupPhase::Reserved);"#,
            r#"slot.publish(CleanupPhase::Reserved); drop(cell); drop(service); drop(prepared);"#,
        ),
        (
            "crucible-daemon/src/lifecycle_cleanup.rs",
            r#"Ordering::AcqRel, Ordering::Acquire"#,
            r#"Ordering::Relaxed, Ordering::Relaxed"#,
        ),
        (
            "crucible-daemon/src/lifecycle_cleanup.rs",
            r#"prepared_constructor_control_bytes()? .checked_mul"#,
            r#"0u64.checked_mul"#,
        ),
        (
            "crucible-daemon/src/lifecycle_cleanup.rs",
            r#"Ok(source.max(target))"#,
            r#"Ok(source)"#,
        ),
        (
            "lifecycle_cleanup/driver.rs",
            r#"CleanupPhase::Queued, CleanupPhase::Retrying"#,
            r#"CleanupPhase::Reserved, CleanupPhase::Retrying"#,
        ),
        (
            "lifecycle_cleanup/driver.rs",
            r#"CleanupPhase::OwnerDestroyed, CleanupPhase::Completing"#,
            r#"CleanupPhase::Publishing, CleanupPhase::Completing"#,
        ),
        (
            "lifecycle_cleanup/driver.rs",
            r#"!slot.retirement_requested.load(Ordering::Acquire)"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/driver.rs",
            r#"cell.controls_bound != cell.controls.is_some()"#,
            r#"false"#,
        ),
        (
            "lifecycle_cleanup/driver.rs",
            r#"controls.close_after_owner_destruction()"#,
            r#"foreign_controls.close_after_owner_destruction()"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"service.queued_owner_borrowed = true; drop(cell); drop(service);"#,
            r#"service.queued_owner_borrowed = true;"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"service.queued_owner = Some(owner);"#,
            r#"drop(owner);"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"owner.retry_cleanup()"#,
            r#"foreign_owner.retry_cleanup()"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"owner.take_post_body()"#,
            r#"foreign_owner.take_post_body()"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"terminal::destroy_payload(slot, owner)"#,
            r#"terminal::destroy_payload(slot, foreign_owner)"#,
        ),
        (
            "lifecycle_cleanup/queued_owner.rs",
            r#"slot.body_destroyed_epoch.store(epoch, Ordering::Release)"#,
            r#"slot.completed_epoch.store(epoch, Ordering::Release)"#,
        ),
        (
            "source_construction/retained.rs",
            r#"owner.retry_reserved_publication()?"#,
            r#"foreign_owner.retry_reserved_publication()?"#,
        ),
        (
            "source_construction/retained.rs",
            r#"let Some(receipt) = published else { return Err(""); };"#,
            r#"let Some(receipt) = published else { return Ok(()); };"#,
        ),
        (
            "source_construction/retained.rs",
            r#"*slot = Some(SourceCleanupHandoff::new(receipt)); Ok(())"#,
            r#"drop(receipt); Ok(())"#,
        ),
        (
            "source_construction/retained.rs",
            r#"if owner.handoff_mut().is_none()"#,
            r#"if owner.handoff_mut().is_some()"#,
        ),
        (
            "source_construction/retained.rs",
            r#"let attempt = receipt.retry(); let stage = receipt.stage();"#,
            r#"let stage = Ok(ProductionVmCleanupStage::Complete); let attempt = Ok(());"#,
        ),
        (
            "source_construction/retained.rs",
            r#"&& !matches!(handoff.stage(), Ok(ProductionVmCleanupStage::Complete))"#,
            r#"&& false"#,
        ),
        (
            "source_construction/retained.rs",
            r#"&& !handoff.retain_post_body()"#,
            r#"&& false"#,
        ),
        (
            "source_construction/retained.rs",
            r#"self.retry_retained_source_installation()"#,
            r#"Ok(())"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"reservation.attach_controls(controls)"#,
            r#"reservation.attach_controls(foreign_controls)"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.reservation.as_ref().is_none_or(|reservation| !reservation.is_reserved())"#,
            r#"self.reservation.is_none()"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"*self.controls = Some(controls);"#,
            r#"drop(controls);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#".with_cleanup_reservation(reservation)"#,
            r#".with_cleanup_reservation(foreign_token)"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.world.take()"#,
            r#"foreign_world.take()"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.world.is_none()"#,
            r#"false"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#".with_world_cleanup_loan(world)"#,
            r#".with_world_cleanup_loan(foreign_world)"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"fn entered_world(&mut self) { drop(self.not_started.take()); }"#,
            r#"fn entered_world(&mut self) {}"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.returned_guard = guard;"#,
            r#"drop(guard);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.generation_storage = storage;"#,
            r#"drop(storage);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.factory = factory;"#,
            r#"drop(factory);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.reservation = reservation;"#,
            r#"drop(reservation);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.construction_custody = custody;"#,
            r#"drop(custody);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.world = world;"#,
            r#"drop(world);"#,
        ),
        (
            "pending_construction/prepared.rs",
            r#"self.target_storage = targets;"#,
            r#"drop(targets);"#,
        ),
        (
            "qemu_lifecycle_launcher/pending_construction.rs",
            r#"Self::new_prepaid(factory, reservation)"#,
            r#"Self::new_prepaid(foreign_factory, reservation)"#,
        ),
        (
            "qemu_lifecycle_launcher/pending_construction.rs",
            r#"self.controls = Some(controls);"#,
            r#"drop(controls);"#,
        ),
        (
            "crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            r#"self.require_install_vacancy()"#,
            r#"Ok(())"#,
        ),
        (
            "crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            r#"self.resources.retain_fork_target_factory()"#,
            r#"foreign_resources.retain_fork_target_factory()"#,
        ),
        (
            "crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            r#"self.resources.source_main_producer()"#,
            r#"foreign_resources.source_main_producer()"#,
        ),
        (
            "crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            r#"(factory, input), bytes, build,"#,
            r#"(foreign_factory, input), bytes, build,"#,
        ),
        (
            "crucible-daemon/src/qemu_campaign_lifecycle/source_construction.rs",
            r#"Err(((_, input), first))"#,
            r#"Err(((_, foreign_input), first))"#,
        ),
        (
            "crucible-daemon/src/qemu_lifecycle_launcher.rs",
            r#"self.cleanup_reservation.take()"#,
            r#"Some(foreign_token)"#,
        ),
        (
            "crucible-daemon/src/qemu_lifecycle_launcher.rs",
            r#"self._world_cleanup_loan = Some(world)"#,
            r#"drop(world)"#,
        ),
        (
            "crucible-daemon/src/qemu_lifecycle_launcher.rs",
            r#"reservation.service_preclaim().handle().prepared_selector()"#,
            r#"foreign_reservation.service_preclaim().handle().prepared_selector()"#,
        ),
        (
            "crucible-daemon/src/qemu_resource_guard.rs",
            r#"self.cleanup.as_ref().map(|cleanup| cleanup.source_main_producer())"#,
            r#"foreign_cleanup.as_ref().map(|cleanup| cleanup.source_main_producer())"#,
        ),
        (
            "linux_attempt_host/normal_pool.rs",
            r#"self.worlds[index] = Some(world);"#,
            r#"drop(world);"#,
        ),
        (
            "linux_attempt_host/normal_pool.rs",
            r#"admission_failure.take(), retained,"#,
            r#"None, retained,"#,
        ),
        (
            "linux_attempt_host/normal_pool.rs",
            r#"return Err(report(first, retained.err()));"#,
            r#"return prepare();"#,
        ),
        (
            "linux_attempt_host/normal_pool.rs",
            r#"original.wait_slice().map_err(|first| original_roster::original_error(first.into()))?; before_effects.prepare_world()"#,
            r#"other_guard.wait_slice().map_err(|first| original_roster::original_error(first.into()))?; before_effects.prepare_world()"#,
        ),
        (
            "native_pool/refusal.rs",
            r#"self._retained.as_mut()?._world.take()"#,
            r#"None"#,
        ),
        (
            "native_pool/refusal.rs",
            r#"retained.delivery.get_or_insert(error);"#,
            r#"drop(error);"#,
        ),
        (
            "native_pool/refusal.rs",
            r#"retained.receiver.get_or_insert(operation);"#,
            r#"drop(operation);"#,
        ),
        (
            "lifecycle_cleanup/body_return.rs",
            r#"cell.owner = Some(owner);"#,
            r#"cell.owner = Some(foreign_owner);"#,
        ),
        (
            "lifecycle_cleanup/body_return.rs",
            r#"slot.external_return_reserved.store(false, Ordering::Release);"#,
            r#"slot.external_return_reserved.store(true, Ordering::Release);"#,
        ),
        (
            "lifecycle_cleanup/body_return.rs",
            r#"if poisoned || phase == CleanupPhase::DestructionRefused as u8"#,
            r#"if false"#,
        ),
        (
            "lifecycle_cleanup/body_return.rs",
            r#"drop(queue); reservation"#,
            r#"drop(queue); foreign_reservation"#,
        ),
        (
            "lifecycle_cleanup/report_refs.rs",
            r#"(state < MAX_REFERENCES).then(|| state + 1)"#,
            r#"Some(state + 1)"#,
        ),
        (
            "lifecycle_cleanup/report_refs.rs",
            r#"if actual_epoch != epoch"#,
            r#"if false"#,
        ),
        (
            "lifecycle_cleanup/report_refs.rs",
            r#"slot.terminal_disposed.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            "lifecycle_cleanup/report_refs.rs",
            r#".compare_exchange(0, CLOSED, Ordering::AcqRel, Ordering::Acquire)"#,
            r#".compare_exchange(1, CLOSED, Ordering::AcqRel, Ordering::Acquire)"#,
        ),
        (
            "lifecycle_cleanup/prepared_service.rs",
            r#"Self { queue: Weak::clone(&self.queue), index: self.index, epoch: self.epoch, }"#,
            r#"Self { queue: Weak::clone(&foreign_queue), index: self.index, epoch: self.epoch, }"#,
        ),
        (
            "lifecycle_cleanup/prepared_service.rs",
            r#"self.queue.upgrade().ok_or_else(|| unavailable(""))"#,
            r#"foreign_queue.upgrade().ok_or_else(|| unavailable(""))"#,
        ),
    ] {
        let index = contract
            .companions
            .iter()
            .position(|binding| binding.path.ends_with(scope))
            .unwrap_or_else(|| panic!("reviewed companion is absent: {scope}"));
        let mut changed = companions.clone();
        let evidence = crate::scrub_comments_and_strings(&changed[index]);
        changed[index] =
            replace_one_obligation(&evidence, &source_pattern(obligation), replacement);
        assert_ne!(
            changed[index], evidence,
            "companion mutation missed in {scope}: {obligation}"
        );
        assert!(
            rejected(contract, &code, &changed),
            "changed provenance was masked in {scope}: {replacement}"
        );
    }
    Ok(())
}
