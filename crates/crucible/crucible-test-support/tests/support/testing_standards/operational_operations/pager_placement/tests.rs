//! Requires the same Original, typed deferral and full retained physical journal.

use super::*;
use super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

impl Fixture {
    fn load(contract: &'static Contract) -> Result<Self, Box<dyn std::error::Error>> {
        let path = crate::workspace::package_path(
            &crate::workspace_root().join("crates"),
            contract.package,
        )
        .join(format!("{}.rs", contract.target));
        let source = std::fs::read_to_string(path)?;
        let code = crate::scrub_comments_and_strings(&source);
        let companions = read_companions(contract)?;
        let masked = mask_contract(contract, &code, &companions);
        assert_ne!(masked, code);
        assert!(crate::flaky_escape_failures("unreviewed", "unreviewed", &masked).is_empty());
        assert!(
            crate::flaky_escape_failures(contract.package, contract.target, &source).is_empty()
        );
        Ok(Self {
            contract,
            code,
            companions,
        })
    }

    fn rejects(&self, fact: &Companion, before: &str, after: &str) {
        let clause = fact
            .required
            .iter()
            .find_map(|(text, _)| {
                source_pattern(text)
                    .contains(&source_pattern(before))
                    .then_some(*text)
            })
            .expect("causal mutation must address actual reviewed ownership");
        let replacement = replace_one_obligation(
            &crate::scrub_comments_and_strings(clause),
            &source_pattern(before),
            after,
        );
        let mut code = self.code.clone();
        let mut evidence = self.companions.clone();
        let mut applied = false;
        if self.contract.required == fact.required {
            code = replace_one_obligation(&code, &source_pattern(clause), &replacement);
            assert_ne!(code, self.code);
            applied = true;
        }
        for (index, binding) in self.contract.companions.iter().enumerate() {
            if binding.path == fact.path && binding.required == fact.required {
                let original = crate::scrub_comments_and_strings(&self.companions[index]);
                evidence[index] =
                    replace_one_obligation(&original, &source_pattern(clause), &replacement);
                assert_ne!(evidence[index], original);
                applied = true;
            }
        }
        assert!(applied);
        assert_eq!(mask_contract(self.contract, &code, &evidence), code);
        assert!(!crate::flaky_escape_failures("unreviewed", "unreviewed", &code).is_empty());
    }
}

#[test]
fn placement_continuations_require_typed_pre_action_deferral_and_retained_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(&Companion, &str, &str)] = &[
        (
            &QUEUE,
            r#"queued.generation = generation;"#,
            r#"queued = new_receipt_with_new_original(generation);"#,
        ),
        (
            &QUEUE,
            r#"operations.begin(SourceOperationClass::Quiescence)?"#,
            r#"operations.begin(SourceOperationClass::Cleanup)?"#,
        ),
        (
            &QUEUE,
            r#"queued.capture.require_open()?;"#,
            r#"Ok::<(), RamError>(())?;"#,
        ),
        (
            &QUEUE,
            r#"queued.require_dispatch()?;"#,
            r#"Ok::<(), RamError>(())?;"#,
        ),
        (
            &QUEUE,
            r#"queued.dispatching = true;"#,
            r#"queued.dispatching = false;"#,
        ),
        (
            &QUEUE,
            r#"let work = self.run_queued_placement_inner(); finish_placement_dispatch(&self.queued_operation, work)"#,
            r#"self.run_queued_placement_inner()"#,
        ),
        (
            &QUEUE,
            r#"queued.operation.clone(), queued.generation, queued.completed_work.clone(),"#,
            r#"fresh_operation(), queued.generation, queued.completed_work.clone(),"#,
        ),
        (
            &QUEUE,
            r#"RamError::PlacementDeferred { status, .. }"#,
            r#"RamError::Native { status, .. }"#,
        ),
        (
            &QUEUE,
            r#"*status == -libc::EAGAIN || *status == -libc::EBUSY"#,
            r#"true"#,
        ),
        (
            &QUEUE,
            r#"Err(first) => Err(first),"#,
            r#"Err(first) => Err(RamError::Invariant("poison replaced first")),"#,
        ),
        (
            &QUEUE,
            r#"receipt.operation.complete()?; publish()?; queued.take();"#,
            r#"queued.take(); publish()?;"#,
        ),
        (&QUEUE, r#"expected != receipt.generation"#, r#"false"#),
        (&QUEUE_CAPTURE, r#"held.detached"#, r#"false"#),
        (
            &QUEUE_CAPTURE,
            r#"if self.capture.disposition_uncertain"#,
            r#"if false"#,
        ),
        (
            &QUEUE_CAPTURE,
            r#"self.capture.completed_receipt = self.receipt.take();"#,
            r#"drop(self.receipt.take());"#,
        ),
        (
            &QUEUE_CAPTURE,
            r#"receipt.generation != generation"#,
            r#"false"#,
        ),
        (&JOURNAL, r#"if self.unresolved()"#, r#"if false"#),
        (
            &JOURNAL,
            r#"self.first_negative.compare_exchange( 0, status,"#,
            r#"self.first_negative.swap(status,"#,
        ),
        (&JOURNAL, r#"token == 0"#, r#"true"#),
        (
            &JOURNAL,
            r#"!self.callback_post_failed.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            &JOURNAL,
            r#"!self.end_entered.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            &JOURNAL,
            r#"!self.action_completed.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            &JOURNAL,
            r#"value == -libc::EAGAIN || value == -libc::EBUSY"#,
            r#"value < 0"#,
        ),
        (
            &JOURNAL,
            r#"self.runner_entered.load(Ordering::Acquire) && !self.settled.load(Ordering::Acquire)"#,
            r#"false"#,
        ),
        (
            &WORK_OWNER,
            r#"self.claimed = Some(ClaimedFault { event, operation: None, });"#,
            r#"self.claimed = None;"#,
        ),
        (
            &WORK_OWNER,
            r#"claim.operation = Some(operation);"#,
            r#"drop(operation);"#,
        ),
        (
            &WORK_OWNER,
            r#"self.claimed.take(); self.receipt.clear_after_settlement();"#,
            r#"self.receipt.clear_after_settlement(); self.claimed.take();"#,
        ),
        (
            &WORK_OWNER,
            r#"let reservation = budget.reserve_bytes(extent)?;"#,
            r#"let reservation = unrelated_budget.reserve_bytes(extent)?;"#,
        ),
        (
            &WORK_OWNER,
            r#"std::mem::size_of::<FaultWorkAllocation>()"#,
            r#"std::mem::size_of::<()>()"#,
        ),
        (
            &WORK_OWNER,
            r#"std::ptr::eq(self, &placement.service.capture_work)"#,
            r#"true"#,
        ),
        (
            &WORK_OWNER,
            r#"body.lifecycle.load(Ordering::Acquire) != physical_end::LIFECYCLE_IDLE"#,
            r#"false"#,
        ),
        (&WORK_OWNER, r#"body.dispatch.unresolved()"#, r#"false"#),
        (
            &WORK_OWNER,
            r#"if body.pause.held() || work.unresolved()"#,
            r#"if false"#,
        ),
        (&WORK_OWNER, r#"if self.work.unresolved()"#, r#"if false"#),
        (
            &WORK_OWNER,
            r#"drop(work); returned.store(true, Ordering::Release);"#,
            r#"returned.store(true, Ordering::Release); drop(work);"#,
        ),
        (&WORK_OWNER, r#"std::mem::forget(body);"#, r#"drop(body);"#),
        (
            &WORK_OWNER,
            r#"std::mem::forget(reservation);"#,
            r#"drop(reservation);"#,
        ),
        (
            &DISPATCH,
            r#"Some(operation) => operation.clone(),"#,
            r#"Some(operation) => fresh_operation(),"#,
        ),
        (
            &DISPATCH,
            r#"journal.reset()?; loop {"#,
            r#"loop { journal.reset()?;"#,
        ),
        (
            &DISPATCH,
            r#"if journal.retry_before_action(status, self.token)"#,
            r#"if status < 0"#,
        ),
        (
            &DISPATCH,
            r#"RamError::PlacementDeferred { operation, status }"#,
            r#"RamError::Native { operation, status }"#,
        ),
        (
            &DISPATCH,
            r#"RamError::PlacementNotRetryable { operation, status }"#,
            r#"RamError::PlacementDeferred { operation, status }"#,
        ),
        (
            &DISPATCH,
            r#"operation.wait_slice()? .min(std::time::Duration::from_millis(10))"#,
            r#"fresh_operation().wait_slice()? .min(std::time::Duration::from_millis(10))"#,
        ),
        (
            &DISPATCH,
            r#"journal.callback_returned.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            &DISPATCH,
            r#"journal.action_completed.load(Ordering::Acquire)"#,
            r#"true"#,
        ),
        (
            &DISPATCH,
            r#"if ended.returned { self.token = 0;"#,
            r#"if ended.failure.is_none() { self.token = 0;"#,
        ),
        (
            &DISPATCH,
            r#"if let Some(error) = ended.failure { return Err(error); } gate_return?;"#,
            r#"gate_return?;"#,
        ),
        (
            &DISPATCH,
            r#"journal.action_completed.store(true, Ordering::Release);"#,
            r#"journal.settled.store(true, Ordering::Release);"#,
        ),
        (
            &DISPATCH,
            r#"let action = service.capture_work.admit_physical_action();"#,
            r#"let action = foreign.capture_work.admit_physical_action();"#,
        ),
        (
            &DISPATCH,
            r#"if let Err(post) = action.finish()"#,
            r#"if let Err(post) = Ok::<(), RamError>(())"#,
        ),
        (
            &DISPATCH,
            r#"service.lifetime.cleanup_failed(post.clone());"#,
            r#"drop(post.clone());"#,
        ),
        (
            &DISPATCH,
            r#"operation.wait_slice()?; check_health()"#,
            r#"operation.wait_slice()?; Ok(())"#,
        ),
        (
            &EVICTION,
            r#"state.version != self.selected.version"#,
            r#"false"#,
        ),
        (
            &EVICTION,
            r#"self.preservation = Effect::Started;"#,
            r#"self.preservation = Effect::Complete;"#,
        ),
        (
            &EVICTION,
            r#"let preservation = self.preservation.finish(result);"#,
            r#"let preservation = Ok(());"#,
        ),
        (
            &EVICTION,
            r#"operation.wait_slice().map(|_| ()).map_err(Into::into)"#,
            r#"Ok(())"#,
        ),
        (
            &EVICTION,
            r#"preservation?; post?; counted"#,
            r#"post?; preservation?; counted"#,
        ),
        (
            &EVICTION,
            r#"self.writeback = Some(service.operations.begin(SourceOperationClass::Writeback)?);"#,
            r#"let unretained = service.operations.begin(SourceOperationClass::Writeback)?;"#,
        ),
        (
            &EVICTION,
            r#"self.discard.finish(discarded)?;"#,
            r#"drop(discarded);"#,
        ),
        (
            &EVICTION,
            r#"if self.writeback.is_some() { self.writeback_post.check_complete()?; self.writeback_completion.check_complete()?; }"#,
            r#"if self.writeback.is_some() { self.writeback_completion.check_complete()?; }"#,
        ),
        (
            &EVICTION,
            r#"self.eviction = Some(EvictionJournal::new(coordinate, address, selected));"#,
            r#"self.eviction = None;"#,
        ),
        (
            &EVICTION,
            r#"journal.first_failure = Some(error.clone());"#,
            r#"journal.first_failure = None;"#,
        ),
        (
            &EVICTION,
            r#"self.fail(); return Err(error);"#,
            r#"self.eviction.take(); return Err(error);"#,
        ),
        (
            &END_RETURN,
            r#"if self.token == 0 { return Ok(false); }"#,
            r#"if self.token == 0 { return Ok(true); }"#,
        ),
        (&END_RETURN, r#"self.token != token"#, r#"false"#),
        (
            &END_RETURN,
            r#"self.schema_version != END_SCHEMA_VERSION"#,
            r#"false"#,
        ),
        (
            &END_RETURN,
            r#"self.complete_mask & self.required_mask != self.required_mask"#,
            r#"false"#,
        ),
        (&END_RETURN, r#"returned: false,"#, r#"returned: true,"#),
        (
            &END_RETURN,
            r#"self.returned |= output.return_complete != 0;"#,
            r#"self.returned = output.first_status == 0;"#,
        ),
        (
            &END_RETURN,
            r#"if self.first_failure.is_none()"#,
            r#"if true"#,
        ),
        (
            &END_RETURN,
            r#"if self.token == 0 || self.invoked"#,
            r#"if self.token == 0"#,
        ),
        (
            &END_RETURN,
            r#"self.invoked = true; dispatch.end_entered.store(true, Ordering::Release);"#,
            r#"dispatch.end_entered.store(true, Ordering::Release);"#,
        ),
        (
            &END_RETURN,
            r#"self.call_status = status; self.call_returned = true;"#,
            r#"self.call_status = 0; self.call_returned = true;"#,
        ),
        (
            &END_RETURN,
            r#"self.accept_snapshot(self.observation_output);"#,
            r#"self.returned = status == 0;"#,
        ),
        (
            &LIFECYCLE,
            r#"!std::ptr::eq(self, action.owner)"#,
            r#"false"#,
        ),
        (
            &LIFECYCLE,
            r#"custody.birth_entered = true; body.dispatch.begin_entered.store(true, Ordering::Release);"#,
            r#"body.dispatch.begin_entered.store(true, Ordering::Release);"#,
        ),
        (
            &LIFECYCLE,
            r#"let status = (service.native.begin)(generation, &mut custody.token);"#,
            r#"let status = (service.native.begin)(generation, &mut unretained_token);"#,
        ),
        (
            &LIFECYCLE,
            r#"LIFECYCLE_IDLE, LIFECYCLE_ACTION,"#,
            r#"LIFECYCLE_IDLE, LIFECYCLE_IDLE,"#,
        ),
        (
            &LIFECYCLE,
            r#"LIFECYCLE_IDLE, LIFECYCLE_CLEANUP,"#,
            r#"LIFECYCLE_ACTION, LIFECYCLE_CLEANUP,"#,
        ),
        (
            &LIFECYCLE,
            r#"custody.cleanup_held = true;"#,
            r#"custody.cleanup_held = false;"#,
        ),
        (
            &LIFECYCLE,
            r#"token == 0 || custody.token != token || !custody.returned"#,
            r#"token == 0 || custody.token != token"#,
        ),
        (
            &LIFECYCLE,
            r#"!body.scratch_returned.load(Ordering::Acquire) || work.unresolved()"#,
            r#"false"#,
        ),
        (
            &LIFECYCLE,
            r#"self.body.dispatch.callback_post_failed.store(true, Ordering::Release);"#,
            r#"self.body.dispatch.callback_post_failed.store(false, Ordering::Release);"#,
        ),
        (
            &END_CLEANUP,
            r#"token == 0 || custody.token != token || !custody.cleanup_held"#,
            r#"token == 0 || custody.token != token"#,
        ),
        (
            &END_CLEANUP,
            r#"custody.save_observation_attempt(attempt);"#,
            r#"drop(attempt);"#,
        ),
        (
            &END_CLEANUP,
            r#"custody.observe(native)"#,
            r#"custody.finish(native, &body.dispatch)"#,
        ),
        (
            &END_CLEANUP,
            r#"let post = operation.wait_slice().map(|_| ()).map_err(RamError::from);"#,
            r#"let post = Ok(());"#,
        ),
        (
            &END_CLEANUP,
            r#"let dispatch = if pre.is_ok() { Some(dispatch()) } else { None };"#,
            r#"let dispatch = Some(dispatch());"#,
        ),
        (
            &END_CLEANUP,
            r#"|| !joined.physical_returned"#,
            r#"|| false"#,
        ),
        (
            &END_CLEANUP,
            r#"|| !matches!(joined.post.as_ref(), Some(Ok(())))"#,
            r#"|| false"#,
        ),
        (
            &END_CLEANUP,
            r#"self.observation_post = Some(attempt.post.clone());"#,
            r#"self.observation_post = None;"#,
        ),
        (
            &CLEANUP_CALLER,
            r#"let mut admission = self.capture_work.admit_physical_cleanup()?;"#,
            r#"let mut admission = unchecked_cleanup();"#,
        ),
        (
            &CLEANUP_CALLER,
            r#"self.operations.begin(SourceOperationClass::Cleanup)"#,
            r#"self.operations.begin(SourceOperationClass::Quiescence)"#,
        ),
        (
            &CLEANUP_CALLER,
            r#"if !outcome.returned {"#,
            r#"if false {"#,
        ),
        (&CLEANUP_CALLER, r#"first.as_ref(),"#, r#"None,"#),
        (
            &CLEANUP_CALLER,
            r#"physical_returned = true; join = Some(joined.clone());"#,
            r#"join = Some(joined.clone());"#,
        ),
        (
            &CLEANUP_CALLER,
            r#"operation.wait_slice().map(|_| ())"#,
            r#"Ok(())"#,
        ),
        (
            &CLEANUP_CALLER,
            r#"Some(error) => Err(error.clone()),"#,
            r#"Some(error) => settlement,"#,
        ),
        (
            &DISPATCH,
            r#"self.operation.as_ref().ok_or("physical placement supervisor absent")?.progress(completed)?;"#,
            r#"fresh_operation().progress(completed)?;"#,
        ),
    ];
    for contract in CONTRACTS {
        let fixture = Fixture::load(contract)?;
        for (fact, before, after) in cases {
            fixture.rejects(fact, before, after);
        }
    }
    Ok(())
}

#[test]
fn queued_route_owned_expression_preserves_typed_body_receiver_and_multiplicity()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::load(&CONTRACTS[0])?;
    let (route, count) = QUEUE.required[7];
    assert_eq!(count, 1);
    assert_eq!(fixture.contract.expressions, &QUEUE.required[7..8]);
    let has_retry = |code: &str| {
        crate::flaky_escape_failures("unreviewed", "unreviewed", code)
            .iter()
            .any(|finding| finding.contains("`retry`"))
    };
    let rejects = |changed: &str| {
        assert_ne!(changed, fixture.code);
        assert!(has_retry(changed), "the genuine route witness must remain");
        assert_eq!(
            mask_contract(fixture.contract, changed, &fixture.companions),
            changed
        );
    };
    for (before, after) in [
        (
            r#"RamError::PlacementDeferred { status, .. }"#,
            r#"RamError::Native { status, .. }"#,
        ),
        (
            r#"*status == -libc::EAGAIN || *status == -libc::EBUSY"#,
            r#"true"#,
        ),
        (r#"retry()"#, r#"foreign.retry()"#),
        (r#"retry()"#, r#"fresh_original().complete()"#),
        (r#"retry()"#, r#"loop { retry() }"#),
        (r#"retry()"#, r#"renewed.progress(1)?; retry()"#),
        (r#"Err(error)"#, r#"Ok(())"#),
        (r#"retry: impl FnOnce()"#, r#"foreign: impl FnOnce()"#),
        (
            r#"if matches!"#,
            r#"fresh_original().wait_slice()?; if matches!"#,
        ),
    ] {
        let changed_route = replace_one_obligation(
            &crate::scrub_comments_and_strings(route),
            &source_pattern(before),
            after,
        );
        assert_ne!(source_pattern(&changed_route), source_pattern(route));
        rejects(&replace_one_obligation(
            &fixture.code,
            &source_pattern(route),
            &changed_route,
        ));
    }
    // Count the actual full function and its real closure receiver, so a second
    // copy or qualified call cannot reuse the one reviewed route's proof.
    rejects(&format!("{}\n{route}", fixture.code));
    rejects(&format!("{}\nforeign.retry();", fixture.code));
    for (required, count) in fixture.contract.required {
        let changed = if *count == 0 {
            format!("{}\n{required}", fixture.code)
        } else {
            replace_one_obligation(
                &fixture.code,
                &source_pattern(required),
                "removed_obligation();",
            )
        };
        rejects(&changed);
    }
    Ok(())
}
