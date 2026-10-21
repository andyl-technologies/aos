//! Rejects changed preparation owners and real no-process registry controls.

use super::*;
use super::super::super::{mask_contract, read_companions, replace_one_obligation, source_pattern};

struct Fixture {
    contract: &'static Contract,
    code: String,
    companions: Vec<String>,
}

fn has_escape(code: &str) -> bool {
    crate::flaky_escape_failures("unreviewed", "unreviewed", code)
        .iter()
        .any(|finding| finding.contains("`retry`") || finding.contains("`thread::sleep`"))
}

impl Fixture {
    fn load(index: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let contract = &CONTRACTS[index];
        let root = crate::workspace_root();
        let path = crate::workspace::package_path(&root.join("crates"), contract.package)
            .join(format!("{}.rs", contract.target));
        let code = crate::scrub_comments_and_strings(&std::fs::read_to_string(path)?);
        let companions = read_companions(contract)?;
        let details = super::super::super::lifecycle_retirement::contract_diagnostics(
            contract,
            &code,
            &companions,
        );
        assert!(details.is_empty(), "{}: {details:#?}", contract.target);
        assert!(has_escape(&code));
        assert!(!has_escape(&mask_contract(contract, &code, &companions)));
        assert!(crate::flaky_escape_failures(contract.package, contract.target, &code).is_empty());
        Ok(Self {
            contract,
            code,
            companions,
        })
    }

    fn rejects(&self, suffix: &str, before: &str, after: &str, reason: &str) {
        let mut code = self.code.clone();
        let mut companions = self.companions.clone();
        let local_path = format!(
            "crates/crucible/control/crucible-daemon/{}.rs",
            self.contract.target
        );
        let mut reached = false;
        for (binding, evidence) in self.contract.companions.iter().zip(&mut companions) {
            if !binding.path.ends_with(suffix) {
                continue;
            }
            let Some((clause, _)) = binding
                .required
                .iter()
                .find(|(clause, _)| source_pattern(clause).contains(&source_pattern(before)))
            else {
                continue;
            };
            let original = crate::scrub_comments_and_strings(clause);
            let changed = replace_one_obligation(&original, &source_pattern(before), after);
            assert_ne!(changed, original, "unreached mutation: {reason}");
            *evidence = replace_one_obligation(
                &crate::scrub_comments_and_strings(evidence),
                &source_pattern(clause),
                &changed,
            );
            if binding.path == local_path {
                code = replace_one_obligation(&code, &source_pattern(clause), &changed);
            }
            reached = true;
        }
        assert!(reached, "missing actual producer: {reason}");
        assert!(
            has_escape(&code),
            "lost actual continuation witness: {reason}"
        );
        assert!(
            has_escape(&mask_contract(self.contract, &code, &companions)),
            "changed ownership was classified: {reason}"
        );
    }
}

#[test]
fn pre_vm_owning_contracts_require_actual_source_and_registry_dispositions()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(CONTRACTS.len(), 2);
    let preparation = Fixture::load(0)?;
    for (path, before, after, reason) in [
        (
            "retained_node.rs",
            "if !receiver.retry_retained_helper()",
            "if receiver.retry_retained_helper()",
            "helper refusal ignored",
        ),
        (
            "retained_node.rs",
            "if !receiver.retry_retained_helper()",
            "if !foreign_receiver.retry_retained_helper()",
            "foreign helper receiver",
        ),
        (
            "retained_node.rs",
            "self.directory_closing = true; drop(self.contract.take()); drop(self.directory.take());",
            "drop(self.contract.take()); drop(self.directory.take()); self.directory_closing = true;",
            "directory unwind lost",
        ),
        (
            "retained_node.rs",
            "lease.abort_without_process()?",
            "discard(lease)",
            "actual borrowed lease return omitted",
        ),
        (
            "retained_node.rs",
            "self.lease = None; Err(CleanupError::Retained(\"fresh physical owners and local generation returned; diagnostic funding remains retained\",))",
            "self.lease = None; Ok(())",
            "local return substituted for unresolved funding",
        ),
        (
            "fresh_generation.rs",
            "self.retained_launch = Some(RetainedLaunch::Preparation(preparation));",
            "drop(preparation);",
            "owning transfer refusal lost",
        ),
        (
            "failed_launch.rs",
            "self.cleanup.retain_source_original(original);",
            "drop(original);",
            "helper Source Original discarded",
        ),
        (
            "failed_launch.rs",
            "if !self.child.reaped()",
            "if false",
            "RAM return before actual process reap",
        ),
        (
            "failed_launch.rs",
            "close_unconstructed(&mut self.child, self.supervisor.as_ref())",
            "close_unconstructed(&mut foreign_child, self.supervisor.as_ref())",
            "foreign child cleanup",
        ),
        (
            "shutdown_continuation.rs",
            "self.guard = Some(CleanupOriginal::Source(original));",
            "self.guard = None;",
            "saved Source guard lost",
        ),
        (
            "shutdown_continuation.rs",
            "if self.begin_attempted { return; }",
            "if false { return; }",
            "fresh Cleanup fallback after Source admission",
        ),
        (
            "shutdown_continuation.rs",
            "self.begin_returned && self.begin_failure.is_none()",
            "self.begin_returned",
            "Source refusal permits ladder effects",
        ),
        (
            "shutdown_continuation.rs",
            "let original = self.guard;",
            "let original = None;",
            "rung evades saved Original",
        ),
        (
            "shutdown_continuation.rs",
            "let after = original.and_then(|original| original.wait_slice().err());",
            "let after = None;",
            "independent original post omitted",
        ),
        (
            "shutdown_continuation.rs",
            "let (output, first) = match work",
            "let (output, first) = match replacement_work",
            "actual wait output discarded",
        ),
        (
            "shutdown_continuation.rs",
            "if returned { self.complete(); }",
            "self.complete();",
            "RAM disposition bypassed",
        ),
        (
            "shutdown_budget.rs",
            "let guard = self.guard.ok_or_else",
            "let guard = foreign_guard.ok_or_else",
            "new wait authority",
        ),
        (
            "shutdown_budget.rs",
            "guard.wait_for_change()",
            "unbounded_wait()",
            "wait escapes saved original",
        ),
        (
            "src/node/child.rs",
            "match self.child.try_wait()",
            "match foreign_child.try_wait()",
            "unrelated process status",
        ),
        (
            "src/node/child.rs",
            "Ok(Some(status)) => { self.mark_reaped(); Ok(Some(status)) }",
            "Ok(Some(status)) => { Ok(Some(status)) }",
            "actual reap not retained",
        ),
        (
            "src/node.rs",
            "if target.guard.is_some() { target.wait_for_live_exit() }",
            "if false { target.wait_for_live_exit() }",
            "saved-guard wait falls back",
        ),
        (
            "shutdown/continuation.rs",
            "self.next += 1; self.entered = Some(rung);",
            "self.entered = Some(rung);",
            "rung effects replayed",
        ),
        (
            "shutdown/continuation.rs",
            "self.attempts[index] = Some(QemuShutdownAttempt",
            "discarded_attempt = Some(QemuShutdownAttempt",
            "returned wait disposition lost",
        ),
        (
            "source_cleanup.rs",
            "let original = attempt.cleanup_entry()?;",
            "let original = fresh_cleanup()?;",
            "uncached Source cleanup",
        ),
        (
            "source_cleanup.rs",
            "!Arc::ptr_eq(&controller, &current) || !controller.cleanup_matches(&original)",
            "false",
            "foreign incarnation or Original accepted",
        ),
        (
            "spawn/helper_receiver.rs",
            "controller.with_spawned_helper(receiver, command, operation, body)",
            "controller.with_spawned_helper(foreign_receiver, command, operation, body)",
            "birth uses a different Source lender",
        ),
        (
            "original_node/helper_receiver.rs",
            "slot.lender = Some(receiver.clone());",
            "slot.lender = Some(foreign_receiver.clone());",
            "cleanup lender differs from actual birth",
        ),
        (
            "original_node/helper_receiver.rs",
            "self.slot.after = self.original.wait_slice().err();",
            "self.slot.after = None;",
            "independent creation post lost",
        ),
        (
            "original_node/helper_receiver.rs",
            "if self.first.is_none()",
            "if true",
            "initiating typed helper error replaced",
        ),
        (
            "original_node/helper_receiver.rs",
            "self.first_cleanup = Some(first);",
            "drop(first);",
            "initiating typed cleanup error discarded",
        ),
        (
            "src/node/child.rs",
            "child: source_child::OwnedNodeChild::Ordinary(child), reaped: false,",
            "child: source_child::OwnedNodeChild::Ordinary(foreign_child), reaped: false,",
            "different child installed at helper birth",
        ),
        (
            "src/node/child.rs",
            "child: source_child::OwnedNodeChild::Ordinary(child), reaped: false,",
            "child: source_child::OwnedNodeChild::Ordinary(child), reaped: true,",
            "new child marked physically reaped",
        ),
        (
            "node/source_child.rs",
            "Self::Ordinary(child) => child.try_wait()",
            "Self::Ordinary(child) => foreign_child.try_wait()",
            "ordinary child wait authority changed",
        ),
        (
            "node/source_child.rs",
            "Self::Ordinary(child) => child.try_wait()",
            "Self::Ordinary(child) => Ok(Some(forged_status))",
            "invented successful physical wait",
        ),
        (
            "shutdown_continuation.rs",
            "begin_attempted: false,",
            "begin_attempted: true,",
            "unentered owner starts already admitted",
        ),
        (
            "shutdown_continuation.rs",
            "begin_attempted: false, begin_returned: false, guard: None,",
            "begin_attempted: false, begin_returned: false, guard: Some(foreign_guard),",
            "unentered owner starts with foreign authority",
        ),
        (
            "shutdown/continuation.rs",
            "self.entered.is_some() || self.failure.is_some()",
            "self.failure.is_some()",
            "uncertain entered rung no longer stops replay",
        ),
        (
            "shutdown/continuation.rs",
            "self.entered.is_some() || self.failure.is_some()",
            "self.entered.is_some()",
            "saved terminal failure ignored",
        ),
        (
            "shutdown/continuation.rs",
            "next: 0, entered: None,",
            "next: 0, entered: Some(QemuShutdownRung::Reap),",
            "fresh ladder inherits an entered phase",
        ),
        (
            "shutdown_continuation.rs",
            "self.observations.iter().any(|(before, after)| before.is_some() || after.is_some())",
            "false",
            "independent Original posts excluded from failed health",
        ),
        (
            "shutdown_continuation.rs",
            "observations: self.observations,",
            "observations: [(None, None); 5],",
            "actual Original post projection erased",
        ),
        (
            "shutdown_continuation.rs",
            "Some(source) => Err(QemuNodeError::from_shutdown(source))",
            "Some(source) => Ok(())",
            "negative process health reported as success",
        ),
        (
            "shutdown/continuation.rs",
            "if self.failure.is_none() { self.failure = Some(Failure::Target(5)); }",
            "",
            "observation failure detached from actual typed health",
        ),
        (
            "shutdown/continuation.rs",
            "failures: self.failures.iter().flatten().cloned().collect(),",
            "failures: Vec::new(),",
            "retained shutdown report drops real failures",
        ),
        (
            "src/node/child.rs",
            "self.try_wait_natural_exit_raw().map_err(ChildNaturalWaitFailure::into_shutdown_error)",
            "self.try_wait_natural_exit_raw().map_err(foreign_formatter)",
            "public poll evades original diagnostic conversion",
        ),
        (
            "src/node/child.rs",
            "Err(source) => Err(ChildNaturalWaitFailure::Io(source))",
            "Err(source) => Err(ChildNaturalWaitFailure::AlreadyReaped)",
            "actual wait error replaced by unrelated disposition",
        ),
        (
            "src/node.rs",
            "Self::Io(source) => { QemuShutdownTargetError::new(\"poll natural QEMU exit\", source.to_string()) }",
            "Self::Io(source) => { QemuShutdownTargetError::new(\"poll natural QEMU exit\", foreign_source.to_string()) }",
            "public formatter substitutes foreign actual cause",
        ),
    ] {
        preparation.rejects(path, before, after, reason);
    }

    let registry = Fixture::load(1)?;
    for (path, before, after, reason) in [
        (
            "generation_resource/tests.rs",
            "let locked = registry.lock().expect(\"hold actual registry\");",
            "let locked = unrelated_registry.lock().expect(\"hold actual registry\");",
            "contention is not on actual lease registry",
        ),
        (
            "generation_resource/tests.rs",
            "assert!(!pending.finished);",
            "assert!(pending.finished);",
            "contended lease preservation lost",
        ),
        (
            "generation_resource/tests.rs",
            "assert_eq!(pending.identity(), &identity);",
            "assert_ne!(pending.identity(), &identity);",
            "same actual lease identity lost",
        ),
        (
            "generation_resource/tests.rs",
            "assert!(!locked.abandoned);",
            "assert!(locked.abandoned);",
            "real registry abandonment accepted",
        ),
        (
            "generation_resource/tests.rs",
            "let mut retry = owner.register_generation(identity)",
            "let mut retry = owner.register_generation(generation(2))",
            "different generation substituted for exact reissue",
        ),
        (
            "generation_resource/tests.rs",
            "retry.abort_without_process()",
            "foreign_lease.abort_without_process()",
            "foreign reissued lease returned",
        ),
        (
            "generation_resource/tests.rs",
            "assert!(!first.finished);",
            "assert!(first.finished);",
            "nonlatest refusal consumes original lease",
        ),
        (
            "generation_resource/tests.rs",
            "next.abort_without_process()",
            "first.abort_without_process()",
            "prior fence not restored first",
        ),
        (
            "generation_resource.rs",
            "abort_without_process(&mut self)",
            "abort_without_process(mut self)",
            "refusal consumes actual lease",
        ),
        (
            "generation_resource.rs",
            "let mut state = self.generations.try_lock()",
            "let mut state = self.generations.lock()",
            "contended cleanup blocks",
        ),
        (
            "generation_resource.rs",
            "row.latest == Some(self.identity.generation())",
            "true",
            "nonlatest abort accepted",
        ),
        (
            "generation_resource.rs",
            "state.nodes[index].latest = self.previous_generation;",
            "state.nodes[index].latest = None;",
            "previous generation lost",
        ),
        (
            "generation_resource.rs",
            "row.active[free] = Some(identity.generation());",
            "row.active[free] = None;",
            "issued lease lacks active cell",
        ),
        (
            "generation_resource.rs",
            "generations: Arc::clone(&self.generations)",
            "generations: Arc::clone(&foreign_registry)",
            "returned lease uses foreign registry",
        ),
    ] {
        registry.rejects(path, before, after, reason);
    }

    Ok(())
}

#[test]
fn fresh_native_continuation_requires_actual_return_and_same_saved_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let preparation = Fixture::load(0)?;
    for (path, before, after, reason) in [
        (
            "retained_node.rs",
            "native: NativeLaunchProgress::NotEntered,",
            "native: NativeLaunchProgress::Returned,",
            "preborn phase invents native return",
        ),
        (
            "retained_node.rs",
            "self.receiver.as_ref().is_some_and(|saved| saved.same_identity(&receiver))",
            "foreign_receiver.as_ref().is_some_and(|saved| saved.same_identity(&receiver))",
            "contract clone differs from saved receiver",
        ),
        (
            "retained_node.rs",
            "|| self.contract.is_none()",
            "|| false",
            "native call lacks retained contract",
        ),
        (
            "retained_node.rs",
            "Ok((directory, &mut self.native, &mut self.body))",
            "Ok((directory, &mut foreign_native, &mut self.body))",
            "entry journal is not same phase",
        ),
        (
            "retained_node.rs",
            "let matches = self.native == NativeLaunchProgress::Returned",
            "let matches = true",
            "uncertain entry can authenticate without return",
        ),
        (
            "retained_node.rs",
            "&& self.receiver.as_ref().is_some_and(|saved| saved.matches_controller(receiver))",
            "&& true",
            "foreign returned controller closes phase",
        ),
        (
            "retained_node.rs",
            "self.native = if matches { NativeLaunchProgress::AuthenticatedFailure } else { NativeLaunchProgress::Unresolved };",
            "self.native = NativeLaunchProgress::AuthenticatedFailure;",
            "unmatched failure becomes cleanup authority",
        ),
        (
            "retained_node.rs",
            "if self.native != NativeLaunchProgress::NotEntered { self.native = NativeLaunchProgress::Unresolved; }",
            "",
            "unexpected entered return loses uncertainty",
        ),
        (
            "retained_node.rs",
            "self.body = FreshPreparationBody::Unexpected(owner);",
            "drop(owner);",
            "unexpected actual owner dropped",
        ),
        (
            "retained_node.rs",
            "if !matches!(self.body, FreshPreparationBody::Empty)",
            "if false",
            "staged Node or foreign body disposed using empty controller",
        ),
        (
            "retained_node.rs",
            "NativeLaunchProgress::Entered | NativeLaunchProgress::Returned | NativeLaunchProgress::Unresolved",
            "NativeLaunchProgress::Returned | NativeLaunchProgress::Unresolved",
            "entered unreturned native call can dispose inputs",
        ),
        (
            "retained_node.rs",
            "if !self.native.observe_physical_return(|| receiver.retry_physical_cleanup())",
            "if false",
            "actual native physical refusal ignored",
        ),
        (
            "retained_node.rs",
            "if !self.native.observe_physical_return(|| receiver.retry_physical_cleanup())",
            "if !self.native.observe_physical_return(|| foreign_receiver.retry_physical_cleanup())",
            "different native cleanup recipient",
        ),
        (
            "retained_node.rs",
            "*self = if returned { Self::PhysicallyReturned } else { Self::AuthenticatedFailure };",
            "*self = Self::AuthenticatedFailure;",
            "physical success not retained before descriptor destruction",
        ),
        (
            "retained_node.rs",
            "drop(self.contract.take()); drop(self.directory.take());",
            "drop(self.directory.take()); drop(self.contract.take());",
            "actual descriptor-owner close order changed",
        ),
        (
            "retained_node.rs",
            "NativeLaunchProgress::PhysicallyReturned => lease.finish()?",
            "NativeLaunchProgress::PhysicallyReturned => lease.abort_without_process()?",
            "entered generation fence rewound",
        ),
        (
            "retained_node.rs",
            "NativeLaunchProgress::NotEntered => lease.abort_without_process()?",
            "NativeLaunchProgress::NotEntered => lease.finish()?",
            "unentered local return loses exact reusable generation",
        ),
        (
            "retained_node.rs",
            "body: FreshPreparationBody::Node(node), native: NativeLaunchProgress::Returned,",
            "body: FreshPreparationBody::Node(node), native: NativeLaunchProgress::NotEntered,",
            "four-owner transfer lacks actual native return",
        ),
        (
            "retained_node.rs",
            "} => Ok(PreparedFreshGeneration { lease, directory, node, contract, }),",
            "} => Ok(PreparedFreshGeneration { lease, directory, node, contract: foreign_contract, }),",
            "transfer substitutes another retained contract",
        ),
        (
            "fresh_generation.rs",
            "preparation.retain_contract(retained_contract)?;",
            "drop(retained_contract);",
            "actual clone leaves paid phase before native entry",
        ),
        (
            "fresh_generation.rs",
            "*native = retained_node::NativeLaunchProgress::Entered; let launched = self.owner.launch_fresh_node_for_node(node_id, &launch, admission);",
            "let launched = self.owner.launch_fresh_node_for_node(node_id, &launch, admission); *native = retained_node::NativeLaunchProgress::Entered;",
            "native entry recorded only after actual callback",
        ),
        (
            "fresh_generation.rs",
            "let launched = self.owner.launch_fresh_node_for_node(node_id, &launch, admission); *native = retained_node::NativeLaunchProgress::Returned;",
            "*native = retained_node::NativeLaunchProgress::Returned; let launched = self.owner.launch_fresh_node_for_node(node_id, &launch, admission);",
            "return recorded before actual callback",
        ),
        (
            "fresh_generation.rs",
            "*node_slot = retained_node::FreshPreparationBody::Node(node);",
            "drop(node);",
            "successful actual Node not retained before interpretation",
        ),
        (
            "fresh_generation.rs",
            "preparation.record_native_failure(&source); self.owner.quarantine_original_launch();",
            "self.owner.quarantine_original_launch(); preparation.record_native_failure(&source);",
            "error identity saved after fallible quarantine",
        ),
        (
            "fresh_generation.rs",
            "#[cfg(target_os = \"linux\")] if let crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeLaunch { source }",
            "#[cfg(all(target_os = \"linux\", feature = \"private-measurement-domain\"))] if let crucible_qemu_host::QemuLiveNodeStepGateError::OriginalNativeLaunch { source }",
            "ordinary Linux returned failure bypasses authentication",
        ),
        (
            "fresh_generation.rs",
            "preparation.retain_unexpected_owner(&mut error);",
            "drop(error);",
            "actual unrecognized returned body lost",
        ),
        (
            "original_node.rs",
            "if self.child_borrowed.load(std::sync::atomic::Ordering::Acquire) { return false; }",
            "",
            "live issued child borrow treated as returned",
        ),
        (
            "original_node.rs",
            "match owner.retry_cleanup()",
            "match foreign_owner.retry_cleanup()",
            "different actual native body cleaned",
        ),
        (
            "original_node.rs",
            "drop(retained); drop(returned); true",
            "drop(retained); true",
            "physical success before actual owner destruction",
        ),
        (
            "original_node.rs",
            "retained.first_cleanup = Some(first);",
            "drop(first);",
            "native first cleanup refusal discarded",
        ),
        (
            "original_node.rs",
            "retained.latest_cleanup = Some(first);",
            "drop(first);",
            "native independent later refusal discarded",
        ),
        (
            "original_node.rs",
            "let _ = self.primary.set(primary);",
            "drop(primary);",
            "initiating typed native refusal discarded",
        ),
        (
            "original_node.rs",
            "let _ = self.original_after.set(after);",
            "drop(after);",
            "independent original native post discarded",
        ),
        (
            "original_node.rs",
            "retained.owner = Some(owner); self.finish_child_borrow();",
            "self.finish_child_borrow(); retained.owner = Some(owner);",
            "receiver publishes return before exact owner",
        ),
        (
            "original_node.rs",
            "!Arc::ptr_eq(self, &current) || self.primary.get().is_some()",
            "self.primary.get().is_some()",
            "birth lender controller not authenticated",
        ),
        (
            "original_node.rs",
            "owner.require_source_cleanup(attempt.bound_source_cleanup_lender(failure));",
            "",
            "late returned Node falls back to ordinary Cleanup",
        ),
        (
            "node/failed_launch.rs",
            "let original = lender.clone().retained_original()",
            "let original = fresh_cleanup()",
            "general failed-owner cleanup replaces saved Original",
        ),
        (
            "node/failed_launch.rs",
            "self.retain_source_original(original)?;",
            "drop(original);",
            "general cleanup effects omit Source binding",
        ),
        (
            "node/failed_launch.rs",
            "self.source_cleanup = FailedSourceCleanup::Required(lender);",
            "self.source_cleanup = FailedSourceCleanup::Existing;",
            "required Source admission becomes ordinary fallback",
        ),
        (
            "node/failed_launch.rs",
            "FailedBody::Node(node) => node.child_shutdown.retain_source_original(original)",
            "FailedBody::Node(node) => drop(original)",
            "actual complete Node loses same Source guard",
        ),
        (
            "failed_launch/issued.rs",
            "lender: Some(self.lender.clone()), process_id,",
            "lender: Some(foreign_lender.clone()), process_id,",
            "born owner keeps unrelated Source lender",
        ),
        (
            "failed_launch/issued.rs",
            "body: Mutex::new(body), source_cleanup: FailedSourceCleanup::Required(self.lender.clone().ok_or(crate::linux_attempt_host::OriginalActorAccountError::Unavailable,),),",
            "body: Mutex::new(body), source_cleanup: FailedSourceCleanup::Existing,",
            "unwind owner return invents ordinary cleanup fallback",
        ),
        (
            "process_purpose/source_cleanup.rs",
            ".is_some_and(|controller| std::ptr::eq(controller.as_ref(), expected))",
            ".is_some_and(|_| true)",
            "late returned Node lender accepts foreign controller",
        ),
        (
            "original_node/issuer.rs",
            "owner.require_source_cleanup(self.attempt.bound_source_cleanup_lender(refusal));",
            "",
            "installed issuer returned Node drops Source requirement",
        ),
        (
            "original_node/issuer.rs",
            "source: self.attempt.retain_launch_refusal(source),",
            "source: foreign_attempt.retain_launch_refusal(source),",
            "typed return authenticates foreign attempt",
        ),
        (
            "src/node.rs",
            "if self.child_shutdown.entered() { return Ok(()); }",
            "if false { return Ok(()); }",
            "native Node replaces saved Source with target cleanup",
        ),
        (
            "src/node.rs",
            "if !self.child.reaped() { return process; }",
            "if false { return process; }",
            "complete Node RAM return precedes actual process reap",
        ),
        (
            "shutdown_continuation.rs",
            "pub(super) fn entered(&self) -> bool { self.begin_attempted }",
            "pub(super) fn entered(&self) -> bool { false }",
            "saved Source admission no longer protects Node cleanup",
        ),
        (
            "generation_resource.rs",
            "state.nodes[index].active[active] = None; self.finished = true;",
            "state.nodes[index].active[active] = None; state.nodes[index].latest = self.previous_generation; self.finished = true;",
            "physical finish rewinds entered generation fence",
        ),
        (
            "ram_control/cleanup_original.rs",
            "CleanupOrigin::Source(original) => original.checked_original()",
            "CleanupOrigin::Source(original) => Ok(original.original())",
            "RAM continuation bypasses same Source Original identity",
        ),
        (
            "ram_source/stop.rs",
            "let observed = worker.native.poll();",
            "let observed = Ok(NativeJoinObservation::Returned);",
            "native continuation invents worker join",
        ),
    ] {
        preparation.rejects(path, before, after, reason);
    }
    Ok(())
}

#[test]
fn physical_cleanup_guard_requires_a_pre_call_fence_and_the_real_drop_control()
-> Result<(), Box<dyn std::error::Error>> {
    let preparation = Fixture::load(0)?;
    for (path, before, after, reason) in [
        (
            "retained_node.rs",
            "*self = Self::Unresolved; let returned = poll();",
            "let returned = poll();",
            "actual cleanup unwind has no sticky uncertainty fence",
        ),
        (
            "retained_node.rs",
            "*self = Self::Unresolved; let returned = poll();",
            "let returned = poll(); *self = Self::Unresolved;",
            "uncertainty is recorded only after cleanup returns",
        ),
        (
            "retained_node.rs",
            "let returned = poll();",
            "let returned = true;",
            "guard invents physical completion without the actual callback",
        ),
        (
            "retained_node.rs",
            "*self = if returned { Self::PhysicallyReturned } else { Self::AuthenticatedFailure };",
            "*self = Self::PhysicallyReturned;",
            "normal false cleanup becomes physical return",
        ),
        (
            "retained_node.rs",
            "Self::PhysicallyReturned } else { Self::AuthenticatedFailure",
            "Self::PhysicallyReturned } else { Self::Unresolved",
            "normal false loses its same authenticated continuation",
        ),
        (
            "retained_node.rs",
            "Self::AuthenticatedFailure }; returned",
            "Self::AuthenticatedFailure }; true",
            "guard status disagrees with its actual physical disposition",
        ),
        (
            "retained_node.rs",
            "if !self.native.observe_physical_return(|| receiver.retry_physical_cleanup())",
            "if !foreign_native.observe_physical_return(|| receiver.retry_physical_cleanup())",
            "actual receiver callback is fenced by a different phase",
        ),
        (
            "retained_node/tests.rs",
            "drop(Some(UncertainOwner));",
            "drop(None::<UncertainOwner>);",
            "control no longer executes an actual owner destructor",
        ),
        (
            "retained_node/tests.rs",
            "first.downcast_ref::<&str>()",
            "foreign_panic.downcast_ref::<&str>()",
            "control discards the actual outward panic payload",
        ),
        (
            "retained_node/tests.rs",
            "for _ in 0..2",
            "for _ in 0..0",
            "control omits repeated actual sticky refusal",
        ),
        (
            "retained_node/tests.rs",
            "fixture.preparation.finish()",
            "foreign_preparation.finish()",
            "control observes a different phase after destructor unwind",
        ),
        (
            "retained_node/tests.rs",
            ".observe_physical_return(|| false)",
            ".observe_physical_return(|| true)",
            "control does not observe the actual normal false branch",
        ),
        (
            "retained_node/tests.rs",
            "fixture.assert_same_owners()?;",
            "Ok::<(), Box<dyn std::error::Error>>(())?;",
            "destructor control no longer verifies its retained lease and descriptors",
        ),
        (
            "retained_node/tests.rs",
            ".open_vmstate_for_hot_fork()?",
            ".open_foreign_vmstate()?",
            "control reads a foreign descriptor instead of its same pinned VMState",
        ),
    ] {
        preparation.rejects(path, before, after, reason);
    }
    Ok(())
}
