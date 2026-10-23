//! Rejects replay, foreign construction owners and premature native return.

use super::super::{Contract, mask_contract, read_companions, replace_one_obligation, source_pattern};
use super::CONTRACTS;

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

impl Fixture {
    fn load(index: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[index];
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(contract)?;
        let details =
            super::super::lifecycle_retirement::contract_diagnostics(contract, &code, &companions);
        assert!(details.is_empty(), "{}: {details:#?}", contract.target);
        let masked = mask_contract(contract, &code, &companions);
        assert_ne!(
            masked, code,
            "{} has no reviewed continuation",
            contract.target
        );
        assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        Ok(Self {
            contract,
            code,
            companions,
        })
    }

    fn rejects(&self, code: &str, companions: &[String]) {
        assert_eq!(
            mask_contract(self.contract, code, companions),
            code,
            "{} accepted changed custody",
            self.contract.target,
        );
        assert!(
            !crate::flaky_escape_failures("unreviewed", "unreviewed", code).is_empty(),
            "{} lost its executable continuation witness",
            self.contract.target,
        );
    }

    fn reject_local(&self, before: &str, after: &str) {
        let clause = self
            .contract
            .required
            .iter()
            .chain(self.contract.expressions)
            .find_map(|(part, _)| {
                source_pattern(part)
                    .contains(&source_pattern(before))
                    .then_some(*part)
            })
            .expect("the exact local custody fact is bound");
        let altered_clause = replace_one_obligation(
            &crate::scrub_comments_and_strings(clause),
            &source_pattern(before),
            after,
        );
        let changed = replace_one_obligation(&self.code, &source_pattern(clause), &altered_clause);
        assert_ne!(changed, self.code, "missing mutation input: {before}");
        self.rejects(&changed, &self.companions);
    }

    fn reject_companion(&self, suffix: &str, before: &str, after: &str) {
        let (index, code, changed) = self
            .contract
            .companions
            .iter()
            .enumerate()
            .filter(|(_, binding)| binding.path.ends_with(suffix))
            .find_map(|(index, binding)| {
                let clause = binding.required.iter().find_map(|(part, _)| {
                    source_pattern(part)
                        .contains(&source_pattern(before))
                        .then_some(*part)
                })?;
                let code = crate::scrub_comments_and_strings(&self.companions[index]);
                let altered_clause = replace_one_obligation(
                    &crate::scrub_comments_and_strings(clause),
                    &source_pattern(before),
                    after,
                );
                let changed =
                    replace_one_obligation(&code, &source_pattern(clause), &altered_clause);
                (changed != code).then_some((index, code, changed))
            })
            .expect("the exact native producer fact is bound");
        assert_ne!(
            changed, code,
            "missing producer mutation input: {suffix}: {before}"
        );
        let mut companions = self.companions.clone();
        companions[index] = changed;
        self.rejects(&self.code, &companions);
    }
}

#[test]
fn constructor_continuations_bind_actual_saved_owner_paths()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CONTRACTS.len(), 9);
    for index in 0..CONTRACTS.len() {
        let fixture = Fixture::load(index)?;
        fixture.rejects(&fixture.code, &[]);
    }
    Ok(())
}

#[test]
fn constructor_continuations_reject_replay_discarded_history_and_early_return()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(usize, &str, &str)] = &[
        (
            8,
            "SourceInstallationCleanupRefusal::new(attempt.err(), stage.err())",
            "SourceInstallationCleanupRefusal::new(None, stage.err())",
        ),
        (
            8,
            "SourceInstallationCleanupRefusal::new(attempt.err(), stage.err())",
            "SourceInstallationCleanupRefusal::new(attempt.err(), None)",
        ),
        (
            0,
            r#"self.worker_panic.is_some() || self.launch.is_some() || self.detached.is_some()"#,
            r#"false"#,
        ),
        (
            0,
            r#"if self.attempted && !self.proven_no_child"#,
            r#"if false"#,
        ),
        (
            0,
            r#"members.rollback_child(&self.node, child)"#,
            r#"members.rollback_child(&foreign.node, child)"#,
        ),
        (
            0,
            r#"self.first_rollback.get_or_insert(first);"#,
            r#"discard_rollback(first);"#,
        ),
        (
            1,
            r#"let stage = handoff.stage()"#,
            r#"let stage = foreign.stage()"#,
        ),
        (
            1,
            r#"self.construction = Some(failure);"#,
            r#"discard_original(failure);"#,
        ),
        (
            1,
            r#"self.resources.finish().map_err(Error::Aggregate)?; self.aggregate_released = true;"#,
            r#"self.aggregate_released = true; self.resources.finish().map_err(Error::Aggregate)?;"#,
        ),
        (
            1,
            r#"if self.advance_cleanup()? != ProductionVmCleanupStage::Complete"#,
            r#"if false"#,
        ),
        (2, r#"if !self.shutdown_complete"#, r#"if false"#),
        (
            2,
            r#"Err(observer) => { self.observer = Some(observer);"#,
            r#"Err(observer) => { discard_original(observer);"#,
        ),
        (
            2,
            r#"drop(self.terminal.take()); self.completed = true;"#,
            r#"self.completed = true; drop(self.terminal.take());"#,
        ),
        (
            2,
            r#"self.source = finalize_target_terminal::<F>(body);"#,
            r#"self.source = foreign_checkout();"#,
        ),
        (
            3,
            r#"if self.pre_body_closed { return Ok(()); }"#,
            r#"if false { return Ok(()); }"#,
        ),
        (3, r#"if !members.retry_native_loans()"#, r#"if false"#),
        (
            3,
            r#"if !recovered { return false; }"#,
            r#"if false { return false; }"#,
        ),
        (
            3,
            r#"self.aggregate_attempted = true; if let Err(first) = resources.finish()"#,
            r#"if let Err(first) = resources.finish()"#,
        ),
        (
            3,
            r#"self.first_readiness.get_or_insert(first);"#,
            r#"discard_first(first);"#,
        ),
        (
            4,
            r#"self.require_external_body_acceptance()?; self.close_target_nodes()?;"#,
            r#"self.close_target_nodes()?;"#,
        ),
        (
            4,
            r#"self.controls = Some(controls);"#,
            r#"discard_controls(controls);"#,
        ),
        (
            4,
            r#"if self.transferred || self.not_started.is_some()"#,
            r#"if self.world.is_none()"#,
        ),
        (
            4,
            r#"custody.retry_cleanup()?; self.body_cleanup_complete = true;"#,
            r#"self.body_cleanup_complete = true; custody.retry_cleanup()?;"#,
        ),
        (
            5,
            r#"let members = if self.members_closed { Ok(()) }"#,
            r#"let members = if false { Ok(()) }"#,
        ),
        (
            5,
            r#"self.members_closed = true; if let Some(guard)"#,
            r#"if let Some(guard)"#,
        ),
        (
            5,
            r#"let post = cleanup.wait_slice().map(|_| ());"#,
            r#"let post = Ok(());"#,
        ),
        (
            5,
            r#"self.history.cleanup_first.get_or_insert(first.into());"#,
            r#"discard_first(first);"#,
        ),
        (
            5,
            r#"self.history.cleanup_post.get_or_insert(post);"#,
            r#"discard_post(post);"#,
        ),
        (
            6,
            r#"drop(row.permit.take());"#,
            r#"retain_unused_permit();"#,
        ),
        (
            6,
            r#"let work = step(); let post = cleanup.wait_slice();"#,
            r#"let work = step(); let post = Ok(());"#,
        ),
        (
            6,
            r#"row.first_cleanup.get_or_insert(first);"#,
            r#"discard_first(first);"#,
        ),
        (6, r#"row.entered && row.cleanup.is_none()"#, r#"false"#),
        (
            6,
            r#"let prepared = prepare()?; row.entered = true;"#,
            r#"let prepared = prepare()?;"#,
        ),
        (
            7,
            r#"retirement, refusal: result.err(),"#,
            r#"retirement: foreign, refusal: result.err(),"#,
        ),
        (
            7,
            r#"Ok(body) if body.first_failure().is_none()"#,
            r#"Ok(body) if true"#,
        ),
        (
            7,
            r#"std::sync::Mutex::new(body)"#,
            r#"std::sync::Mutex::new(discarded_history())"#,
        ),
        (8, r#"!handoff.retain_post_body()"#, r#"false"#),
        (
            8,
            r#"let attempt = receipt.retry(); let stage = receipt.stage();"#,
            r#"let attempt = receipt.retry(); let stage = foreign.stage();"#,
        ),
        (
            8,
            r#"self.retained_install = Some(owner);"#,
            r#"discard_original(owner);"#,
        ),
        (8, r#"if self.lifecycle_outstanding"#, r#"if false"#),
    ];
    for (index, before, after) in cases {
        Fixture::load(*index)?.reject_local(before, after);
    }
    Ok(())
}

#[test]
fn constructor_continuations_reject_foreign_native_loans_and_missing_postcuts()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(usize, &str, &str, &str)] = &[
        (
            3,
            r#"qemu_hot_fork_world_resource.rs"#,
            r#"state.guard.recover_target_construction_storage(storage)"#,
            r#"true"#,
        ),
        (
            3,
            r#"qemu_resource_guard.rs"#,
            r#"host.quarantine();"#,
            r#"discard_retained_host();"#,
        ),
        (
            0,
            r#"original_roster/fork_target.rs"#,
            r#"self.returned |= returned;"#,
            r#"self.returned = true;"#,
        ),
        (
            0,
            r#"original_roster/fork_target.rs"#,
            r#"slot.fork_target.occupied != Some(self.epoch)"#,
            r#"false"#,
        ),
        (
            0,
            r#"original_roster/fork_target.rs"#,
            r#"self.entered.get_or_init("#,
            r#"self.entered.get_or_try_init("#,
        ),
        (
            0,
            r#"original_roster/fork_target.rs"#,
            r#"saved.is_some_and(|saved| Arc::ptr_eq(saved, &self.original))"#,
            r#"true"#,
        ),
        (
            0,
            r#"original_roster/fork_target.rs"#,
            r#"drop(state); cleanup.guard().map_err(Into::into)"#,
            r#"cleanup.guard().map_err(Into::into)"#,
        ),
        (
            1,
            r#"lifecycle_cleanup/reservation.rs"#,
            r#"cell.epoch != self.epoch || cell.owner.is_some() || cell.controls.is_some()"#,
            r#"false"#,
        ),
        (
            1,
            r#"construction/publication.rs"#,
            r#"*returned = Some((reservation, owner));"#,
            r#"drop((reservation, owner));"#,
        ),
        (
            2,
            r#"lifecycle_cleanup/prepared_retirement.rs"#,
            r#"if slot.epoch.load(Ordering::Acquire) != self.key.epoch"#,
            r#"if false"#,
        ),
        (
            3,
            r#"lifecycle_cleanup/prepared_service.rs"#,
            r#"slot.body_destroyed_epoch.load(Ordering::Acquire) < self.key.epoch"#,
            r#"false"#,
        ),
        (
            3,
            r#"qemu_lifecycle_launcher/target_construction.rs"#,
            r#"let post = cleanup.wait_slice();"#,
            r#"let post = Ok(());"#,
        ),
        (
            4,
            r#"pending_construction/prepared.rs"#,
            r#"fn entered_world(&mut self) { drop(self.not_started.take()); }"#,
            r#"fn entered_world(&mut self) {}"#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"controller.retained_cleanup()?"#,
            r#"foreign_controller.retained_cleanup()?"#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"slot.require_metadata_assignment_replacing_pending(extent, pending)?;"#,
            r#"discard_pending_metadata();"#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"slot.active == Some(self.generation) && slot.source_controller.as_ref().is_some_and(|saved| saved.same_owner(&controller))"#,
            r#"slot.active == Some(self.generation)"#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"let original = self.cleanup_entry()?; original.wait_slice()?; Ok(original)"#,
            r#"let original = self.cleanup_entry()?; Ok(original)"#,
        ),
        (
            4,
            r#"original_node.rs"#,
            r#"self.cleanup.get_or_init("#,
            r#"self.cleanup.get_or_try_init("#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"!controller.physical_owners_returned()"#,
            r#"false"#,
        ),
        (
            4,
            r#"original_roster.rs"#,
            r#"cleanup.complete()?; slot.cleanup = None; slot.source_controller = None; slot.source_cleanup_assigned = false;"#,
            r#"slot.source_controller = None; slot.source_cleanup_assigned = false; cleanup.complete()?; slot.cleanup = None;"#,
        ),
        (
            4,
            r#"pending_construction/post_body.rs"#,
            r#"PostBody::world(world, None)"#,
            r#"PostBody::history_only()"#,
        ),
        (
            5,
            r#"native_pool/ledger.rs"#,
            r#"world.cleanup.get_or_init("#,
            r#"world.cleanup.get_or_try_init("#,
        ),
        (
            6,
            r#"original_roster/fork_target.rs"#,
            r#"self.returned |= returned;"#,
            r#"self.returned = true;"#,
        ),
        (
            7,
            r#"lifecycle_cleanup/prepared_service.rs"#,
            r#"prepared.post_body_taken"#,
            r#"false"#,
        ),
        (
            8,
            r#"lifecycle_cleanup/reservation.rs"#,
            r#"if self.first_failure.is_none() { self.first_failure = cell.first_failure.take(); }"#,
            r#"discard_original_first();"#,
        ),
    ];
    for (index, suffix, before, after) in cases {
        Fixture::load(*index)?.reject_companion(suffix, before, after);
    }
    Ok(())
}
